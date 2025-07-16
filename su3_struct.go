package su3

import (
	"io"
	"sync"
)

// SU3 represents a parsed SU3 file with its metadata and content readers.
// Moved from: su3.go
type SU3 struct {
	SignatureType   SignatureType
	SignatureLength uint16
	ContentLength   uint64
	FileType        FileType
	ContentType     ContentType
	Version         string
	SignerID        string
	mut             sync.Mutex
	reader          io.Reader
	publicKey       interface{}
	contentReader   *contentReader
	signatureReader *signatureReader
}

// Content returns an io.Reader for accessing the SU3 file content.
// The publicKey parameter is used for signature verification.
// Moved from: su3.go
func (su3 *SU3) Content(publicKey interface{}) io.Reader {
	log.WithField("signer_id", su3.SignerID).Debug("Accessing SU3 content")
	su3.publicKey = publicKey
	return su3.contentReader
}

// Signature returns an io.Reader for accessing the SU3 file signature.
// Moved from: su3.go
func (su3 *SU3) Signature() io.Reader {
	log.Debug("Accessing SU3 signature")
	return su3.signatureReader
}
