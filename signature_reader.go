package su3

import (
	"bytes"
	"io"

	"github.com/samber/oops"
)

// signatureReader provides access to the signature bytes of an SU3 file.
// Moved from: su3.go
type signatureReader struct {
	su3    *SU3
	bytes  []byte
	err    error
	reader io.Reader
}

// getBytes reads and caches the signature bytes from the SU3 file.
// Note: This method should only be called while holding the SU3 mutex.
// Moved from: su3.go
func (r *signatureReader) getBytes() {
	log.Debug("Getting signature bytes")

	if err := r.consumeRemainingContent(); err != nil {
		r.err = err
		return
	}

	if err := r.validateSignatureBounds(); err != nil {
		r.err = err
		return
	}

	sigBytes, err := r.readSignatureBytes()
	if err != nil {
		r.err = err
		return
	}

	r.finalizeSignatureReader(sigBytes)
}

// consumeRemainingContent handles any unread content before reading signature.
// This ensures the stream is positioned correctly for signature reading.
func (r *signatureReader) consumeRemainingContent() error {
	// If content hasn't been read yet, throw it away.
	// Note: We can safely access contentReader.finished here because
	// this method is only called while holding the SU3 mutex.
	if !r.su3.contentReader.finished {
		log.Warn("Content not fully read, reading remaining content")
		// Calculate how much content remains to be read
		var remainingLength uint64
		if r.su3.contentReader.reader == nil {
			// Content reader never initialized, need to read all content
			remainingLength = r.su3.ContentLength
		} else {
			// Content reader partially read, read remaining content
			remainingLength = r.su3.ContentLength - r.su3.contentReader.reader.readSoFar
		}

		// Read remaining content directly from the underlying reader to avoid mutex deadlock
		if remainingLength > 0 {
			contentReader := &fixedLengthReader{
				length:    remainingLength,
				readSoFar: 0,
				reader:    r.su3.reader,
			}
			_, err := io.ReadAll(contentReader)
			if err != nil {
				log.WithError(err).Error("Failed to read remaining content")
				return oops.Errorf("reading content: %w", err)
			}
		}
		// Mark content as finished
		r.su3.contentReader.finished = true
		log.Debug("Marked content reader as finished after consuming remaining content")
	}
	return nil
}

// validateSignatureBounds checks if signature length is within acceptable limits.
// Defense in depth: additional bounds check before buffer allocation.
func (r *signatureReader) validateSignatureBounds() error {
	if r.su3.SignatureLength > maxSignatureLength {
		log.WithField("signature_length", r.su3.SignatureLength).WithField("max_signature_length", maxSignatureLength).Error("Signature length exceeds maximum allowed size")
		return ErrSignatureLengthTooLarge
	}
	return nil
}

// readSignatureBytes reads the signature data from the underlying reader.
// This is more efficient than ioutil.ReadAll which may allocate additional buffers
// and is especially beneficial for large signatures (e.g., RSA-4096).
func (r *signatureReader) readSignatureBytes() ([]byte, error) {
	reader := &fixedLengthReader{
		length:    uint64(r.su3.SignatureLength),
		readSoFar: 0,
		reader:    r.su3.reader,
	}

	sigBytes := make([]byte, r.su3.SignatureLength)
	totalRead := 0

	for totalRead < int(r.su3.SignatureLength) {
		n, err := reader.Read(sigBytes[totalRead:])
		totalRead += n

		if err != nil {
			if err == io.EOF {
				// EOF before reading all signature bytes means missing signature
				log.WithField("expected", r.su3.SignatureLength).WithField("actual", totalRead).Error("Signature shorter than expected")
				return nil, ErrMissingSignature
			}
			log.WithError(err).Error("Failed to read signature")
			return nil, oops.Errorf("reading signature: %w", err)
		}
	}

	return r.verifySignatureBytesRead(sigBytes, totalRead)
}

// verifySignatureBytesRead ensures we read the expected amount of signature data.
func (r *signatureReader) verifySignatureBytesRead(sigBytes []byte, totalRead int) ([]byte, error) {
	if totalRead != int(r.su3.SignatureLength) {
		log.WithField("expected", r.su3.SignatureLength).WithField("actual", totalRead).Error("Signature shorter than expected")
		return nil, ErrMissingSignature
	}
	return sigBytes, nil
}

// finalizeSignatureReader configures the reader with the signature bytes.
func (r *signatureReader) finalizeSignatureReader(sigBytes []byte) {
	r.bytes = sigBytes
	r.reader = bytes.NewReader(sigBytes)
	log.WithField("signature_length", len(sigBytes)).Debug("Signature bytes read successfully")
}

// Read implements io.Reader interface for signatureReader.
// It reads the signature bytes from the SU3 file.
// Moved from: su3.go
func (r *signatureReader) Read(p []byte) (n int, err error) {
	r.su3.mut.Lock()
	defer r.su3.mut.Unlock()
	if len(r.bytes) == 0 {
		log.Debug("Signature bytes not yet read, getting bytes")
		r.getBytes()
	}
	if r.err != nil {
		log.WithError(r.err).Error("Error encountered while getting signature bytes")
		return 0, r.err
	}
	// return r.reader.Read(p)
	n, err = r.reader.Read(p)
	log.WithField("bytes_read", n).Debug("Read from signature")
	return n, err
}
