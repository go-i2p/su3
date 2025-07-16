package su3

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"hash"
	"io"

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
		default:
			log.WithField("signature_type", r.su3.SignatureType).Error("Unsupported signature type")
			return l, ErrUnsupportedSignatureType
		}
	}

	return l, err
}
