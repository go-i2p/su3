package su3

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"strings"

	"github.com/samber/oops"
)

// readAndValidateMagicBytes reads and validates the SU3 file magic bytes.
// Moved from: su3.go
func readAndValidateMagicBytes(reader io.Reader, buff *bytes.Buffer) error {
	mbytes := make([]byte, len(magicBytes))
	l, err := reader.Read(mbytes)
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read magic bytes")
		return oops.Errorf("reading magic bytes: %w", err)
	}
	if l != len(mbytes) {
		log.Error("Missing magic bytes")
		return ErrMissingMagicBytes
	}
	if string(mbytes) != magicBytes {
		log.Error("Invalid magic bytes")
		return ErrMissingMagicBytes
	}
	buff.Write(mbytes)
	log.Debug("Magic bytes verified")
	return nil
}

// readFileFormatHeader reads the unused byte 6 and file format version.
// Moved from: su3.go
func readFileFormatHeader(reader io.Reader, buff *bytes.Buffer) error {
	unused := [1]byte{}

	// Unused byte 6.
	l, err := reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read unused byte 6")
		return oops.Errorf("reading unused byte 6: %w", err)
	}
	if l != 1 {
		log.Error("Missing unused byte 6")
		return ErrMissingUnusedByte6
	}
	buff.Write(unused[:])
	log.Debug("Read unused byte 6")

	// SU3 file format version (always 0).
	l, err = reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read SU3 file format version")
		return oops.Errorf("reading SU3 file format version: %w", err)
	}
	if l != 1 {
		log.Error("Missing SU3 file format version")
		return ErrMissingFileFormatVersion
	}
	if unused[0] != 0x00 {
		log.Error("Invalid SU3 file format version")
		return ErrMissingFileFormatVersion
	}
	buff.Write(unused[:])
	log.Debug("SU3 file format version verified")

	return nil
}

// readSignatureInfo reads signature type and length, returning the signature type.
// Moved from: su3.go
func readSignatureInfo(reader io.Reader, su3 *SU3, buff *bytes.Buffer) (SignatureType, error) {
	// Signature type.
	sigTypeBytes := [2]byte{}
	l, err := reader.Read(sigTypeBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read signature type")
		return "", oops.Errorf("reading signature type: %w", err)
	}
	if l != 2 {
		log.Error("Missing signature type")
		return "", ErrMissingSignatureType
	}
	sigType, ok := sigTypes[sigTypeBytes]
	if !ok {
		log.WithField("signature_type", sigTypeBytes).Error("Unsupported signature type")
		return "", ErrUnsupportedSignatureType
	}
	su3.SignatureType = sigType
	buff.Write(sigTypeBytes[:])
	log.WithField("signature_type", sigType).Debug("Signature type read")

	// Signature length.
	sigLengthBytes := [2]byte{}
	l, err = reader.Read(sigLengthBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read signature length")
		return "", oops.Errorf("reading signature length: %w", err)
	}
	if l != 2 {
		log.Error("Missing signature length")
		return "", ErrMissingSignatureLength
	}
	sigLen := binary.BigEndian.Uint16(sigLengthBytes[:])

	// Validate signature length matches expected length for signature type
	if err := validateSignatureLength(sigType, sigLen); err != nil {
		log.WithFields(map[string]interface{}{
			"signature_type":   sigType,
			"signature_length": sigLen,
		}).Error("Invalid signature length for signature type")
		return "", err
	}

	su3.SignatureLength = sigLen
	buff.Write(sigLengthBytes[:])
	log.WithField("signature_length", sigLen).Debug("Signature length read")

	return sigType, nil
}

// readLengthFields reads various length fields including version and signer ID lengths.
// Moved from: su3.go
func readLengthFields(reader io.Reader, su3 *SU3, buff *bytes.Buffer) (uint16, uint16, error) {
	unused := [1]byte{}

	// Unused byte 12.
	l, err := reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read unused byte 12")
		return 0, 0, oops.Errorf("reading unused byte 12: %w", err)
	}
	if l != 1 {
		log.Error("Missing unused byte 12")
		return 0, 0, ErrMissingUnusedByte12
	}
	buff.Write(unused[:])
	log.Debug("Read unused byte 12")

	// Version length.
	verLengthBytes := [1]byte{}
	l, err = reader.Read(verLengthBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read version length")
		return 0, 0, oops.Errorf("reading version length: %w", err)
	}
	if l != 1 {
		log.Error("Missing version length")
		return 0, 0, ErrMissingVersionLength
	}
	verLen := uint16(verLengthBytes[0])
	if verLen < 16 {
		log.WithField("version_length", verLen).Error("Version length too short")
		return 0, 0, ErrVersionTooShort
	}
	buff.Write(verLengthBytes[:])
	log.WithField("version_length", verLen).Debug("Version length read")

	// Unused byte 14.
	l, err = reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read unused byte 14")
		return 0, 0, oops.Errorf("reading unused byte 14: %w", err)
	}
	if l != 1 {
		log.Error("Missing unused byte 14")
		return 0, 0, ErrMissingUnusedByte14
	}
	buff.Write(unused[:])
	log.Debug("Read unused byte 14")

	// Signer ID length.
	sigIDLengthBytes := [1]byte{}
	l, err = reader.Read(sigIDLengthBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read signer ID length")
		return 0, 0, oops.Errorf("reading signer id length: %w", err)
	}
	if l != 1 {
		log.Error("Missing signer ID length")
		return 0, 0, ErrMissingSignerIDLength
	}
	signIDLen := uint16(sigIDLengthBytes[0])
	buff.Write(sigIDLengthBytes[:])
	log.WithField("signer_id_length", signIDLen).Debug("Signer ID length read")

	return verLen, signIDLen, nil
}

// readContentLength reads and validates the 8-byte content length field.
func readContentLength(reader io.Reader, su3 *SU3, buff *bytes.Buffer) error {
	contentLengthBytes := [8]byte{}
	l, err := reader.Read(contentLengthBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read content length")
		return oops.Errorf("reading content length: %w", err)
	}
	if l != 8 {
		log.Error("Missing content length")
		return ErrMissingContentLength
	}
	contentLen := binary.BigEndian.Uint64(contentLengthBytes[:])
	if contentLen > maxContentLength {
		log.WithField("content_length", contentLen).WithField("max_content_length", maxContentLength).Error("Content length exceeds maximum allowed size")
		return ErrContentLengthTooLarge
	}
	su3.ContentLength = contentLen
	buff.Write(contentLengthBytes[:])
	log.WithField("content_length", contentLen).Debug("Content length read")
	return nil
}

// readFileType reads and validates the 1-byte file type field.
func readFileType(reader io.Reader, su3 *SU3, buff *bytes.Buffer) error {
	fileTypeBytes := [1]byte{}
	l, err := reader.Read(fileTypeBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read file type")
		return oops.Errorf("reading file type: %w", err)
	}
	if l != 1 {
		log.Error("Missing file type")
		return ErrMissingFileType
	}
	fileType, ok := fileTypes[fileTypeBytes[0]]
	if !ok {
		log.WithField("file_type_byte", fileTypeBytes[0]).Error("Invalid file type")
		return ErrMissingFileType
	}
	su3.FileType = fileType
	buff.Write(fileTypeBytes[:])
	log.WithField("file_type", fileType).Debug("File type read")
	return nil
}

// readContentType reads and validates the 1-byte content type field.
func readContentType(reader io.Reader, su3 *SU3, buff *bytes.Buffer) error {
	contentTypeBytes := [1]byte{}
	l, err := reader.Read(contentTypeBytes[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read content type")
		return oops.Errorf("reading content type: %w", err)
	}
	if l != 1 {
		log.Error("Missing content type")
		return ErrMissingContentType
	}
	contentType, ok := contentTypes[contentTypeBytes[0]]
	if !ok {
		log.WithField("content_type_byte", contentTypeBytes[0]).Error("Invalid content type")
		return ErrMissingContentType
	}
	su3.ContentType = contentType
	buff.Write(contentTypeBytes[:])
	log.WithField("content_type", contentType).Debug("Content type read")
	return nil
}

// readFileMetadata reads content length, file type, and content type.
// Moved from: su3.go
func readFileMetadata(reader io.Reader, su3 *SU3, buff *bytes.Buffer) error {
	unused := [1]byte{}

	if err := readContentLength(reader, su3, buff); err != nil {
		return err
	}

	// Unused byte 24.
	l, err := reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read unused byte 24")
		return oops.Errorf("reading unused byte 24: %w", err)
	}
	if l != 1 {
		log.Error("Missing unused byte 24")
		return ErrMissingUnusedByte24
	}
	buff.Write(unused[:])
	log.Debug("Read unused byte 24")

	if err := readFileType(reader, su3, buff); err != nil {
		return err
	}

	// Unused byte 26.
	l, err = reader.Read(unused[:])
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Error("Failed to read unused byte 26")
		return oops.Errorf("reading unused byte 26: %w", err)
	}
	if l != 1 {
		log.Error("Missing unused byte 26")
		return ErrMissingUnusedByte26
	}
	buff.Write(unused[:])
	log.Debug("Read unused byte 26")

	return readContentType(reader, su3, buff)
}

// readUnusedBytes28To39 reads the 12 unused bytes in the range 28-39.
// Moved from: su3.go
func readUnusedBytes28To39(reader io.Reader, buff *bytes.Buffer) error {
	unused := [1]byte{}
	for i := 0; i < 12; i++ {
		l, err := reader.Read(unused[:])
		if err != nil && !errors.Is(err, io.EOF) {
			log.WithError(err).Error("Failed to read unused bytes 28-39")
			return oops.Errorf("reading unused bytes 28-39: %w", err)
		}
		if l != 1 {
			log.WithField("byte_number", 28+i).Error("Missing unused byte")
			return ErrMissingUnusedBytes28To39
		}
		buff.Write(unused[:])
	}
	log.Debug("Read unused bytes 28-39")
	return nil
}

// readFixedLengthField reads exactly length bytes from reader, writes them to
// buff, and returns the raw bytes. missingErr is returned when fewer than
// length bytes were available.
func readFixedLengthField(reader io.Reader, buff *bytes.Buffer, name string, length uint16, missingErr error) ([]byte, error) {
	data := make([]byte, length)
	l, err := reader.Read(data)
	if err != nil && !errors.Is(err, io.EOF) {
		log.WithError(err).Errorf("Failed to read %s", name)
		return nil, oops.Errorf("reading %s: %w", name, err)
	}
	if l != int(length) {
		log.Errorf("Missing %s", name)
		return nil, missingErr
	}
	buff.Write(data)
	return data, nil
}

// readVersionAndSignerID reads the version and signer ID strings.
// Moved from: su3.go
func readVersionAndSignerID(reader io.Reader, su3 *SU3, buff *bytes.Buffer, verLen, signIDLen uint16) error {
	versionBytes, err := readFixedLengthField(reader, buff, "version", verLen, ErrMissingVersion)
	if err != nil {
		return err
	}
	su3.Version = strings.TrimRight(string(versionBytes), "\x00")
	log.WithField("version", su3.Version).Debug("Version read")

	signerIDBytes, err := readFixedLengthField(reader, buff, "signer id", signIDLen, ErrMissingSignerID)
	if err != nil {
		return err
	}
	su3.SignerID = string(signerIDBytes)
	log.WithField("signer_id", su3.SignerID).Debug("Signer ID read")

	return nil
}

// validateSignatureLength checks if the signature length is valid for the given signature type
func validateSignatureLength(sigType SignatureType, sigLen uint16) error {
	switch sigType {
	case RSA_SHA256_2048:
		if sigLen != 256 {
			return ErrInvalidSignatureLength
		}
	case RSA_SHA384_3072:
		if sigLen != 384 {
			return ErrInvalidSignatureLength
		}
	case RSA_SHA512_4096:
		if sigLen != 512 {
			return ErrInvalidSignatureLength
		}
	case DSA_SHA1:
		// DSA signatures in DER format are typically 40-48 bytes, allow some range
		if sigLen < 40 || sigLen > 72 {
			return ErrInvalidSignatureLength
		}
	case ECDSA_SHA256_P256:
		// P-256 raw R||S: 2 * 32 bytes = 64 bytes (I2P common-structures spec)
		if sigLen != 64 {
			return ErrInvalidSignatureLength
		}
	case ECDSA_SHA384_P384:
		// P-384 raw R||S: 2 * 48 bytes = 96 bytes (I2P common-structures spec)
		if sigLen != 96 {
			return ErrInvalidSignatureLength
		}
	case ECDSA_SHA512_P521:
		// P-521 raw R||S: 2 * 66 bytes = 132 bytes (I2P common-structures spec)
		if sigLen != 132 {
			return ErrInvalidSignatureLength
		}
	case EdDSA_SHA512_Ed25519ph:
		if sigLen != 64 {
			return ErrInvalidSignatureLength
		}
	default:
		// Unknown signature type, this should have been caught earlier
		return ErrUnsupportedSignatureType
	}
	return nil
}
