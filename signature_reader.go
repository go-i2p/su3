package su3

import (
	"bytes"
	"io"
	"io/ioutil"

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
			_, err := ioutil.ReadAll(contentReader)
			if err != nil {
				log.WithError(err).Error("Failed to read remaining content")
				r.err = oops.Errorf("reading content: %w", err)
				return
			}
		}
		// Mark content as finished
		r.su3.contentReader.finished = true
		log.Debug("Marked content reader as finished after consuming remaining content")
	}

	// Read signature directly into a pre-allocated buffer of known size.
	// This is more efficient than ioutil.ReadAll which may allocate additional buffers
	// and is especially beneficial for large signatures (e.g., RSA-4096).
	reader := &fixedLengthReader{
		length:    uint64(r.su3.SignatureLength),
		readSoFar: 0,
		reader:    r.su3.reader,
	}

	// Defense in depth: additional bounds check before buffer allocation
	if r.su3.SignatureLength > maxSignatureLength {
		log.WithField("signature_length", r.su3.SignatureLength).WithField("max_signature_length", maxSignatureLength).Error("Signature length exceeds maximum allowed size")
		r.err = ErrSignatureLengthTooLarge
		return
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
				r.err = ErrMissingSignature
				return
			}
			log.WithError(err).Error("Failed to read signature")
			r.err = oops.Errorf("reading signature: %w", err)
			return
		}
	}

	// Verify we read the expected amount
	if totalRead != int(r.su3.SignatureLength) {
		log.WithField("expected", r.su3.SignatureLength).WithField("actual", totalRead).Error("Signature shorter than expected")
		r.err = ErrMissingSignature
	} else {
		r.bytes = sigBytes
		r.reader = bytes.NewReader(sigBytes)
		log.WithField("signature_length", len(sigBytes)).Debug("Signature bytes read successfully")
	}
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
