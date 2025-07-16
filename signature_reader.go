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
// Moved from: su3.go
func (r *signatureReader) getBytes() {
	log.Debug("Getting signature bytes")
	// If content hasn't been read yet, throw it away.
	if !r.su3.contentReader.finished {
		log.Warn("Content not fully read, reading remaining content")
		_, err := ioutil.ReadAll(r.su3.contentReader)
		if err != nil {
			log.WithError(err).Error("Failed to read remaining content")
			r.err = oops.Errorf("reading content: %w", err)
			return
		}
	}

	// Read signature.
	reader := &fixedLengthReader{
		length:    uint64(r.su3.SignatureLength),
		readSoFar: 0,
		reader:    r.su3.reader,
	}
	sigBytes, err := ioutil.ReadAll(reader)

	if err != nil {
		log.WithError(err).Error("Failed to read signature")
		r.err = oops.Errorf("reading signature: %w", err)
	} else if reader.readSoFar != uint64(r.su3.SignatureLength) {
		log.Error("Signature shorter than expected")
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
