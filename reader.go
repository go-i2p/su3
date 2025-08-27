package su3

import (
	"bytes"
	"io"
	"sync"

	"github.com/sirupsen/logrus"
)

// Read parses an SU3 file from the provided io.Reader and returns a *SU3 instance.
// The returned SU3 contains metadata about the file and provides access to content and signature.
// Moved from: su3.go
func Read(reader io.Reader) (su3 *SU3, err error) {
	log.Debug("Starting to read SU3 file")
	var buff bytes.Buffer

	if err := readAndValidateMagicBytes(reader, &buff); err != nil {
		return nil, err
	}

	if err := readFileFormatHeader(reader, &buff); err != nil {
		return nil, err
	}

	su3 = &SU3{
		mut:    sync.Mutex{},
		reader: reader,
	}

	sigType, err := readSignatureInfo(reader, su3, &buff)
	if err != nil {
		return nil, err
	}

	verLen, signIDLen, err := readLengthFields(reader, su3, &buff)
	if err != nil {
		return nil, err
	}

	if err := readFileMetadata(reader, su3, &buff); err != nil {
		return nil, err
	}

	if err := readUnusedBytes28To39(reader, &buff); err != nil {
		return nil, err
	}

	if err := readVersionAndSignerID(reader, su3, &buff, verLen, signIDLen); err != nil {
		return nil, err
	}

	if err := initializeReaders(su3, sigType, &buff); err != nil {
		return nil, err
	}

	log.WithFields(logrus.Fields{
		"signature_type": su3.SignatureType,
		"file_type":      su3.FileType,
		"content_type":   su3.ContentType,
		"version":        su3.Version,
		"signer_id":      su3.SignerID,
	}).Debug("SU3 file read successfully")

	return su3, nil
}

// initializeReaders creates and configures the content and signature readers.
// Moved from: su3.go
func initializeReaders(su3 *SU3, sigType SignatureType, buff *bytes.Buffer) error {
	su3.contentReader = &contentReader{
		su3: su3,
	}
	log.Debug("Content reader initialized")

	// Use centralized hash algorithm selection to ensure consistency
	hash, err := getHashForSignatureType(sigType)
	if err != nil {
		return err
	}
	su3.contentReader.hash = hash

	log.WithField("signature_type", sigType).Debug("Hash algorithm selected for content reader")

	if su3.contentReader.hash != nil {
		su3.contentReader.hash.Write(buff.Bytes())
		log.Debug("Wrote header to content hash")
	}

	su3.signatureReader = &signatureReader{
		su3: su3,
	}

	return nil
}
