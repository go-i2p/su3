package su3

import (
	"crypto"
	"crypto/dsa"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"hash"
	"io"
	"math/big"

	"github.com/samber/oops"
)

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
		log.Warn("Attempt to read content after finishing")
		return 0, oops.Errorf("out of bytes, maybe you read the signature before you read the content")
	}

	if r.reader == nil {
		r.reader = &fixedLengthReader{
			length:    r.su3.ContentLength,
			readSoFar: 0,
			reader:    r.su3.reader,
		}
		log.WithField("content_length", r.su3.ContentLength).Debug("Initialized content reader")
	}

	l, err := r.reader.Read(p)

	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Error reading content")
		return l, oops.Errorf("reading content: %w", err)
	} else if errors.Is(err, io.EOF) && r.reader.readSoFar != r.su3.ContentLength {
		log.Error("Content shorter than expected")
		return l, ErrMissingContent
	} else if errors.Is(err, io.EOF) {
		r.finished = true
		log.Debug("Finished reading content")
	}

	if r.hash != nil {
		r.hash.Write(p[:l])
	}

	if r.finished {
		if r.su3.publicKey == nil {
			log.Error("No public key provided for signature verification")
			return l, ErrInvalidSignature
		}
		r.su3.signatureReader.getBytes()
		if r.su3.signatureReader.err != nil {
			log.WithError(r.su3.signatureReader.err).Error("Failed to get signature bytes")
			return l, r.su3.signatureReader.err
		}
		log.WithField("signature_type", r.su3.SignatureType).Debug("Verifying signature")
		// TODO support all signature types
		switch r.su3.SignatureType {
		case RSA_SHA256_2048:
			var pubKey *rsa.PublicKey
			if k, ok := r.su3.publicKey.(*rsa.PublicKey); !ok {
				log.Error("Invalid public key type")
				return l, ErrInvalidPublicKey
			} else {
				pubKey = k
			}
			err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, r.hash.Sum(nil), r.su3.signatureReader.bytes)
			if err != nil {
				log.WithError(err).Error("Signature verification failed")
				return l, ErrInvalidSignature
			}
			log.Debug("Signature verified successfully")
		case RSA_SHA384_3072:
			var pubKey *rsa.PublicKey
			if k, ok := r.su3.publicKey.(*rsa.PublicKey); !ok {
				log.Error("Invalid public key type")
				return l, ErrInvalidPublicKey
			} else {
				pubKey = k
			}
			err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA384, r.hash.Sum(nil), r.su3.signatureReader.bytes)
			if err != nil {
				log.WithError(err).Error("Signature verification failed")
				return l, ErrInvalidSignature
			}
			log.Debug("Signature verified successfully")
		case RSA_SHA512_4096:
			var pubKey *rsa.PublicKey
			if k, ok := r.su3.publicKey.(*rsa.PublicKey); !ok {
				log.Error("Invalid public key type")
				return l, ErrInvalidPublicKey
			} else {
				pubKey = k
			}
			err := rsa.VerifyPKCS1v15(pubKey, crypto.SHA512, r.hash.Sum(nil), r.su3.signatureReader.bytes)
			if err != nil {
				log.WithError(err).Error("Signature verification failed")
				return l, ErrInvalidSignature
			}
			log.Debug("Signature verified successfully")
		case DSA_SHA1:
			var pubKey *dsa.PublicKey
			if k, ok := r.su3.publicKey.(*dsa.PublicKey); !ok {
				log.Error("Invalid public key type")
				return l, ErrInvalidPublicKey
			} else {
				pubKey = k
			}
			// DSA signature is (r,s) pair, need to extract from DER encoding
			sigBytes := r.su3.signatureReader.bytes
			if len(sigBytes) < 8 {
				log.Error("DSA signature too short")
				return l, ErrInvalidSignature
			}
			// For DSA, signature is typically DER-encoded (r,s) pair
			// This is a simplified implementation - production would need proper ASN.1 DER parsing
			rVal := new(big.Int).SetBytes(sigBytes[:len(sigBytes)/2])
			sVal := new(big.Int).SetBytes(sigBytes[len(sigBytes)/2:])
			verified := dsa.Verify(pubKey, r.hash.Sum(nil), rVal, sVal)
			if !verified {
				log.Error("DSA signature verification failed")
				return l, ErrInvalidSignature
			}
			log.Debug("DSA signature verified successfully")
		case ECDSA_SHA256_P256:
			var pubKey *ecdsa.PublicKey
			if k, ok := r.su3.publicKey.(*ecdsa.PublicKey); !ok {
				log.Error("Invalid public key type")
				return l, ErrInvalidPublicKey
			} else {
				pubKey = k
			}
			// ECDSA signature is (r,s) pair
			sigBytes := r.su3.signatureReader.bytes
			if len(sigBytes) < 8 {
				log.Error("ECDSA signature too short")
				return l, ErrInvalidSignature
			}
			rVal := new(big.Int).SetBytes(sigBytes[:len(sigBytes)/2])
			sVal := new(big.Int).SetBytes(sigBytes[len(sigBytes)/2:])
			verified := ecdsa.Verify(pubKey, r.hash.Sum(nil), rVal, sVal)
			if !verified {
				log.Error("ECDSA-SHA256-P256 signature verification failed")
				return l, ErrInvalidSignature
			}
			log.Debug("ECDSA-SHA256-P256 signature verified successfully")
		case ECDSA_SHA384_P384:
			var pubKey *ecdsa.PublicKey
			if k, ok := r.su3.publicKey.(*ecdsa.PublicKey); !ok {
				log.Error("Invalid public key type")
				return l, ErrInvalidPublicKey
			} else {
				pubKey = k
			}
			sigBytes := r.su3.signatureReader.bytes
			if len(sigBytes) < 8 {
				log.Error("ECDSA signature too short")
				return l, ErrInvalidSignature
			}
			rVal := new(big.Int).SetBytes(sigBytes[:len(sigBytes)/2])
			sVal := new(big.Int).SetBytes(sigBytes[len(sigBytes)/2:])
			verified := ecdsa.Verify(pubKey, r.hash.Sum(nil), rVal, sVal)
			if !verified {
				log.Error("ECDSA-SHA384-P384 signature verification failed")
				return l, ErrInvalidSignature
			}
			log.Debug("ECDSA-SHA384-P384 signature verified successfully")
		case ECDSA_SHA512_P521:
			var pubKey *ecdsa.PublicKey
			if k, ok := r.su3.publicKey.(*ecdsa.PublicKey); !ok {
				log.Error("Invalid public key type")
				return l, ErrInvalidPublicKey
			} else {
				pubKey = k
			}
			sigBytes := r.su3.signatureReader.bytes
			if len(sigBytes) < 8 {
				log.Error("ECDSA signature too short")
				return l, ErrInvalidSignature
			}
			rVal := new(big.Int).SetBytes(sigBytes[:len(sigBytes)/2])
			sVal := new(big.Int).SetBytes(sigBytes[len(sigBytes)/2:])
			verified := ecdsa.Verify(pubKey, r.hash.Sum(nil), rVal, sVal)
			if !verified {
				log.Error("ECDSA-SHA512-P521 signature verification failed")
				return l, ErrInvalidSignature
			}
			log.Debug("ECDSA-SHA512-P521 signature verified successfully")
		case EdDSA_SHA512_Ed25519ph:
			var pubKey ed25519.PublicKey
			if k, ok := r.su3.publicKey.(ed25519.PublicKey); !ok {
				log.Error("Invalid public key type")
				return l, ErrInvalidPublicKey
			} else {
				pubKey = k
			}
			verified := ed25519.Verify(pubKey, r.hash.Sum(nil), r.su3.signatureReader.bytes)
			if !verified {
				log.Error("EdDSA-SHA512-Ed25519ph signature verification failed")
				return l, ErrInvalidSignature
			}
			log.Debug("EdDSA-SHA512-Ed25519ph signature verified successfully")
		default:
			log.WithField("signature_type", r.su3.SignatureType).Error("Unsupported signature type")
			return l, ErrUnsupportedSignatureType
		}
	}

	return l, err
}
