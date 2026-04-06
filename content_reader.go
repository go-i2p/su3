package su3

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/asn1"
	"errors"
	"hash"
	"io"
	"math/big"

	goi2ped25519 "github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/logger"
	"github.com/samber/oops"
)

// dsaSignature represents the ASN.1 DER structure of a DSA signature
type dsaSignature struct {
	R, S *big.Int
}

// contentReader provides access to the content of an SU3 file with signature verification.
// Moved from: su3.go
type contentReader struct {
	su3      *SU3
	reader   *fixedLengthReader
	hash     hash.Hash
	finished bool
}

// Read implements io.Reader interface for contentReader.
// It reads the SU3 file content and performs signature verification when finished.
// Moved from: su3.go
func (r *contentReader) Read(p []byte) (n int, err error) {
	r.su3.mut.Lock()
	defer r.su3.mut.Unlock()

	if r.finished {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.Read"}).Warn("Attempt to read content after finishing")
		return 0, oops.Errorf("out of bytes, maybe you read the signature before you read the content")
	}

	if err := r.ensureReaderInitialized(); err != nil {
		return 0, err
	}

	l, err := r.readContentBytes(p)
	if err != nil && !errors.Is(err, io.EOF) {
		return l, err
	}

	r.updateHashWithBytes(p[:l])

	if r.finished {
		if verifyErr := r.performSignatureVerification(); verifyErr != nil {
			return l, verifyErr
		}
	}

	return l, err
}

// ensureReaderInitialized initializes the fixed-length reader if not already done.
func (r *contentReader) ensureReaderInitialized() error {
	if r.reader == nil {
		r.reader = &fixedLengthReader{
			length:    r.su3.ContentLength,
			readSoFar: 0,
			reader:    r.su3.reader,
		}
		log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.ensureReaderInitialized", "content_length": r.su3.ContentLength}).Debug("Initialized content reader")
	}
	return nil
}

// readContentBytes reads content bytes from the underlying reader and handles EOF conditions.
func (r *contentReader) readContentBytes(p []byte) (int, error) {
	l, err := r.reader.Read(p)

	if err != nil && !errors.Is(err, io.EOF) {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.readContentBytes"}).WithError(err).Error("Error reading content")
		return l, oops.Errorf("reading content: %w", err)
	} else if errors.Is(err, io.EOF) && r.reader.readSoFar != r.su3.ContentLength {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.readContentBytes"}).Error("Content shorter than expected")
		return l, ErrMissingContent
	} else if errors.Is(err, io.EOF) {
		r.finished = true
		log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.readContentBytes"}).Debug("Finished reading content")
	}

	return l, err
}

// updateHashWithBytes writes the read bytes to the hash if it's available.
func (r *contentReader) updateHashWithBytes(data []byte) {
	if r.hash != nil {
		r.hash.Write(data)
	}
}

// performSignatureVerification verifies the signature after content reading is complete.
func (r *contentReader) performSignatureVerification() error {
	if r.su3.publicKey == nil {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.performSignatureVerification"}).Error("No public key provided for signature verification")
		return ErrInvalidSignature
	}

	// Check if signature reader is properly initialized
	if r.su3.signatureReader == nil {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.performSignatureVerification"}).Error("Signature reader not initialized")
		return ErrInvalidSignature
	}

	r.su3.signatureReader.getBytes()
	if r.su3.signatureReader.err != nil {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.performSignatureVerification"}).WithError(r.su3.signatureReader.err).Error("Failed to get signature bytes")
		return r.su3.signatureReader.err
	}

	log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.performSignatureVerification", "signature_type": r.su3.SignatureType}).Debug("Verifying signature")
	return r.verifySignatureByType()
}

// verifySignatureByType performs signature verification based on the signature type.
func (r *contentReader) verifySignatureByType() error {
	switch r.su3.SignatureType {
	case RSA_SHA256_2048:
		return r.verifyRSASignature(crypto.SHA256)
	case RSA_SHA384_3072:
		return r.verifyRSASignature(crypto.SHA384)
	case RSA_SHA512_4096:
		return r.verifyRSASignature(crypto.SHA512)
	case DSA_SHA1:
		return r.verifyDSASignature()
	case ECDSA_SHA256_P256:
		return r.verifyECDSASignature("ECDSA-SHA256-P256")
	case ECDSA_SHA384_P384:
		return r.verifyECDSASignature("ECDSA-SHA384-P384")
	case ECDSA_SHA512_P521:
		return r.verifyECDSASignature("ECDSA-SHA512-P521")
	case EdDSA_SHA512_Ed25519ph:
		return r.verifyEdDSASignature()
	default:
		log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.verifySignatureByType", "signature_type": r.su3.SignatureType}).Error("Unsupported signature type")
		return ErrUnsupportedSignatureType
	}
}

// verifyRSASignature verifies RSA signatures with the specified hash algorithm.
// The digest is already computed by the contentReader's hash, so we pass hash=0
// to rsa.VerifyPKCS1v15 for raw PKCS#1 v1.5 verification without DigestInfo.
// This matches how I2P reseed servers sign SU3 files.
func (r *contentReader) verifyRSASignature(hashAlgorithm crypto.Hash) error {
	pubKey, ok := r.su3.publicKey.(*rsa.PublicKey)
	if !ok {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.verifyRSASignature"}).Error("Invalid public key type")
		return ErrInvalidPublicKey
	}

	// Use hash=0 because the digest is already hashed; reseed servers sign
	// without the DigestInfo ASN.1 prefix in the PKCS#1 v1.5 block.
	err := rsa.VerifyPKCS1v15(pubKey, 0, r.hash.Sum(nil), r.su3.signatureReader.bytes)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.verifyRSASignature"}).WithError(err).Error("Signature verification failed")
		return ErrInvalidSignature
	}
	log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.verifyRSASignature"}).Debug("Signature verified successfully")
	return nil
}

// verifyDSASignature verifies DSA-SHA1 signatures.
//
// Deprecated: DSA-SHA1 is a Legacy algorithm in the I2P spec and crypto/dsa
// was deprecated in Go 1.21. This function will be removed once DSA_SHA1
// support is dropped.
func (r *contentReader) verifyDSASignature() error {
	pubKey, ok := r.su3.publicKey.(*dsa.PublicKey)
	if !ok {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.verifyDSASignature"}).Error("Invalid public key type")
		return ErrInvalidPublicKey
	}

	sigBytes := r.su3.signatureReader.bytes
	if len(sigBytes) < 8 {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.verifyDSASignature"}).Error("DSA signature too short")
		return ErrInvalidSignature
	}

	var dsaSig dsaSignature
	_, err := asn1.Unmarshal(sigBytes, &dsaSig)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.verifyDSASignature"}).WithError(err).Error("Failed to parse DSA signature DER encoding")
		return ErrInvalidSignature
	}

	verified := dsa.Verify(pubKey, r.hash.Sum(nil), dsaSig.R, dsaSig.S)
	if !verified {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.verifyDSASignature"}).Error("DSA signature verification failed")
		return ErrInvalidSignature
	}
	log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.verifyDSASignature"}).Debug("DSA signature verified successfully")
	return nil
}

// verifyECDSASignature verifies ECDSA signatures using raw fixed-length R||S encoding.
// Matches the I2P common-structures specification: P-256 = 64 bytes, P-384 = 96 bytes,
// P-521 = 132 bytes. The signature is split at the midpoint into R and S components.
func (r *contentReader) verifyECDSASignature(curveType string) error {
	pubKey, ok := r.su3.publicKey.(*ecdsa.PublicKey)
	if !ok {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.verifyECDSASignature"}).Error("Invalid public key type")
		return ErrInvalidPublicKey
	}

	sigBytes := r.su3.signatureReader.bytes
	keyBytes := (pubKey.Curve.Params().BitSize + 7) / 8
	if len(sigBytes) != 2*keyBytes {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.verifyECDSASignature", "curve_type": curveType}).Error("ECDSA signature length does not match raw R||S encoding for curve")
		return ErrInvalidSignature
	}

	rInt := new(big.Int).SetBytes(sigBytes[:keyBytes])
	sInt := new(big.Int).SetBytes(sigBytes[keyBytes:])

	if !ecdsa.Verify(pubKey, r.hash.Sum(nil), rInt, sInt) {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.verifyECDSASignature", "curve_type": curveType}).Error("ECDSA signature verification failed")
		return ErrInvalidSignature
	}
	log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.verifyECDSASignature", "curve_type": curveType}).Debug("ECDSA signature verified successfully")
	return nil
}

// verifyEdDSASignature verifies EdDSA-SHA512-Ed25519ph signatures.
// Uses go-i2p/crypto/ed25519.Ed25519Verifier.VerifyHash which applies
// ed25519.Verify against the SHA-512 digest of (header bytes || content bytes),
// matching the I2P Ed25519ph convention used throughout go-i2p.
func (r *contentReader) verifyEdDSASignature() error {
	pubKey, ok := r.su3.publicKey.(ed25519.PublicKey)
	if !ok {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.verifyEdDSASignature"}).Error("Invalid public key type")
		return ErrInvalidPublicKey
	}

	// Construct a go-i2p/crypto verifier from the raw public key bytes and
	// verify the SHA-512 digest (header bytes || content bytes) directly.
	verifier, err := goi2ped25519.Ed25519PublicKey(pubKey).NewVerifier()
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.verifyEdDSASignature"}).WithError(err).Error("Failed to create Ed25519 verifier")
		return ErrInvalidPublicKey
	}
	if err := verifier.VerifyHash(r.hash.Sum(nil), r.su3.signatureReader.bytes); err != nil {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.verifyEdDSASignature"}).Error("EdDSA-SHA512-Ed25519ph signature verification failed")
		return ErrInvalidSignature
	}

	log.WithFields(logger.Fields{"pkg": "su3", "func": "contentReader.verifyEdDSASignature"}).Debug("EdDSA-SHA512-Ed25519ph signature verified successfully")
	return nil
}
