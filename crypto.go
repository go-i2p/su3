package su3

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"hash"
	"math/big"
	"time"

	"github.com/go-i2p/crypto/rand"

	"github.com/samber/oops"
)

// NewSigningCertificate creates a self-signed X.509 certificate for SU3 file signing.
// It generates a certificate with the specified signer ID and RSA private key for use in
// I2P reseed operations. The certificate is valid for 10 years and includes proper key usage
// extensions for digital signatures.
//
// Parameters:
//   - signerID: The common name and subject key ID for the certificate
//   - privateKey: The RSA private key used to sign the certificate
//
// Returns the DER-encoded certificate bytes or an error if generation fails.
func NewSigningCertificate(signerID string, privateKey *rsa.PrivateKey) ([]byte, error) {
	if privateKey == nil {
		log.Error("Private key cannot be nil for certificate generation")
		return nil, oops.Errorf("private key cannot be nil")
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.CryptoInt(rand.Reader, serialNumberLimit)
	if err != nil {
		log.WithError(err).Error("Failed to generate certificate serial number")
		return nil, oops.Errorf("generating certificate serial number: %w", err)
	}

	var subjectKeyId []byte
	isCA := true
	// Configure certificate authority status based on signer ID presence
	// Empty signer IDs create non-CA certificates to prevent auto-generation issues
	if signerID != "" {
		subjectKeyId = []byte(signerID)
	} else {
		// When signerID is empty, create non-CA certificate to prevent auto-generation of SubjectKeyId
		subjectKeyId = []byte("")
		isCA = false
	}

	template := &x509.Certificate{
		BasicConstraintsValid: true,
		IsCA:                  isCA,
		SubjectKeyId:          subjectKeyId,
		SerialNumber:          serialNumber,
		Subject: pkix.Name{
			Organization:       []string{"I2P Anonymous Network"},
			OrganizationalUnit: []string{"I2P"},
			Locality:           []string{"XX"},
			StreetAddress:      []string{"XX"},
			Country:            []string{"XX"},
			CommonName:         signerID,
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().AddDate(10, 0, 0),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
	}

	publicKey := &privateKey.PublicKey

	// Create self-signed certificate using template as both subject and issuer
	// This generates a root certificate suitable for SU3 file signing operations
	parent := template
	cert, err := x509.CreateCertificate(rand.Reader, template, parent, publicKey, privateKey)
	if err != nil {
		log.WithError(err).Error("Failed to create X.509 certificate")
		return nil, oops.Errorf("creating certificate: %w", err)
	}

	log.WithField("signer_id", signerID).Debug("Successfully generated signing certificate")
	return cert, nil
}

// checkSignature verifies a digital signature against signed data using the specified certificate.
// It supports RSA, DSA, and ECDSA signature algorithms with various hash functions (SHA1, SHA256, SHA384, SHA512).
// This function extends the standard x509 signature verification to support additional algorithms needed for SU3 files.
func checkSignature(c *x509.Certificate, algo x509.SignatureAlgorithm, signed, signature []byte) error {
	if c == nil {
		log.Error("Certificate is nil during signature verification")
		return oops.Errorf("certificate is nil")
	}

	var hashType crypto.Hash

	// Map signature algorithm to appropriate hash function
	// Each algorithm specifies both the signature method and hash type
	switch algo {
	case x509.SHA1WithRSA, x509.DSAWithSHA1, x509.ECDSAWithSHA1:
		hashType = crypto.SHA1
	case x509.SHA256WithRSA, x509.DSAWithSHA256, x509.ECDSAWithSHA256:
		hashType = crypto.SHA256
	case x509.SHA384WithRSA, x509.ECDSAWithSHA384:
		hashType = crypto.SHA384
	case x509.SHA512WithRSA, x509.ECDSAWithSHA512:
		hashType = crypto.SHA512
	default:
		log.WithField("algorithm", algo).Error("Unsupported signature algorithm")
		return x509.ErrUnsupportedAlgorithm
	}

	if !hashType.Available() {
		log.WithField("hash_type", hashType).Error("Hash type not available")
		return x509.ErrUnsupportedAlgorithm
	}
	h := hashType.New()

	h.Write(signed)
	digest := h.Sum(nil)

	// Verify signature based on public key algorithm type
	// Each algorithm has different signature formats and verification procedures
	switch pub := c.PublicKey.(type) {
	case *rsa.PublicKey:
		// the digest is already hashed, so we force a 0 here
		err := rsa.VerifyPKCS1v15(pub, 0, digest, signature)
		if err != nil {
			log.WithError(err).Error("RSA signature verification failed")
		}
		return err
	case *dsa.PublicKey:
		dsaSig := new(dsaSignature)
		if _, err := asn1.Unmarshal(signature, dsaSig); err != nil {
			log.WithError(err).Error("Failed to unmarshal DSA signature")
			return oops.Errorf("unmarshaling DSA signature: %w", err)
		}
		// Validate DSA signature components are positive integers
		// Zero or negative values indicate malformed or invalid signatures
		if dsaSig.R.Sign() <= 0 || dsaSig.S.Sign() <= 0 {
			log.WithField("r_sign", dsaSig.R.Sign()).WithField("s_sign", dsaSig.S.Sign()).Error("DSA signature contained zero or negative values")
			return oops.Errorf("DSA signature contained zero or negative values")
		}
		if !dsa.Verify(pub, digest, dsaSig.R, dsaSig.S) {
			log.Error("DSA signature verification failed")
			return oops.Errorf("DSA verification failure")
		}
		return nil
	case *ecdsa.PublicKey:
		ecdsaSig := new(ecdsaSignature)
		if _, err := asn1.Unmarshal(signature, ecdsaSig); err != nil {
			log.WithError(err).Error("Failed to unmarshal ECDSA signature")
			return oops.Errorf("unmarshaling ECDSA signature: %w", err)
		}
		// Validate ECDSA signature components are positive integers
		// Similar validation to DSA as both use R,S component pairs
		if ecdsaSig.R.Sign() <= 0 || ecdsaSig.S.Sign() <= 0 {
			log.WithField("r_sign", ecdsaSig.R.Sign()).WithField("s_sign", ecdsaSig.S.Sign()).Error("ECDSA signature contained zero or negative values")
			return oops.Errorf("ECDSA signature contained zero or negative values")
		}
		if !ecdsa.Verify(pub, digest, ecdsaSig.R, ecdsaSig.S) {
			log.Error("ECDSA signature verification failed")
			return oops.Errorf("ECDSA verification failure")
		}
		return nil
	}
	log.WithField("public_key_type", fmt.Sprintf("%T", c.PublicKey)).Error("Unsupported public key algorithm")
	return x509.ErrUnsupportedAlgorithm
}

// getHashForSignatureType returns the appropriate hash.Hash implementation for the given signature type.
// This centralizes the hash algorithm selection logic used by both parsing and creation code paths.
//
// This function replaces the duplicate switch statements in reader.go and su3_struct.go to ensure
// consistent hash algorithm selection across the codebase.
func getHashForSignatureType(sigType SignatureType) (hash.Hash, error) {
	switch sigType {
	case DSA_SHA1:
		return sha1.New(), nil
	case ECDSA_SHA256_P256, RSA_SHA256_2048:
		return sha256.New(), nil
	case ECDSA_SHA384_P384, RSA_SHA384_3072:
		return sha512.New384(), nil
	case ECDSA_SHA512_P521, RSA_SHA512_4096, EdDSA_SHA512_Ed25519ph:
		return sha512.New(), nil
	default:
		log.WithField("signature_type", sigType).Error("Unsupported signature type for hash selection")
		return nil, ErrUnsupportedSignatureType
	}
}

// getCryptoHashForSignatureType returns the appropriate crypto.Hash constant for the given signature type.
// This is used when we need the hash type constant rather than a hash.Hash instance.
//
// This function complements getHashForSignatureType and ensures consistent hash type mapping
// across both parsing and creation code paths.
func getCryptoHashForSignatureType(sigType SignatureType) (crypto.Hash, error) {
	switch sigType {
	case DSA_SHA1:
		return crypto.SHA1, nil
	case ECDSA_SHA256_P256, RSA_SHA256_2048:
		return crypto.SHA256, nil
	case ECDSA_SHA384_P384, RSA_SHA384_3072:
		return crypto.SHA384, nil
	case ECDSA_SHA512_P521, RSA_SHA512_4096, EdDSA_SHA512_Ed25519ph:
		return crypto.SHA512, nil
	default:
		log.WithField("signature_type", sigType).Error("Unsupported signature type for crypto hash selection")
		return 0, ErrUnsupportedSignatureType
	}
}
