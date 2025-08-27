package su3

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/binary"
	"io"
	"strconv"
	"sync"
	"time"

	"github.com/samber/oops"
)

// SU3 represents a parsed SU3 file with its metadata and content readers.
// Extended to support both reading existing SU3 files and creating new ones.
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

	// Additional fields for SU3 creation
	content   []byte // Content data for creating SU3 files
	signature []byte // Signature data for created SU3 files
}

// Content returns an io.Reader for accessing the SU3 file content.
// The publicKey parameter is used for signature verification.
// Moved from: su3.go
/**
**Important Note on Read Order**: If you want to read both content and signature,
the Content() io.Reader MUST be read *before* the Signature() io.Reader. This
limitation exists because SU3 files are a streaming format where content and
signature are sequential in the file. When you read the signature first, the
signature reader consumes any remaining content bytes to position the stream
correctly. If you then try to read content, those bytes are no longer available.

However, if you only need the signature (for verification without content access),
you can read Signature() directly without calling Content().

For clarification on this behavior, see TestReadSignatureFirst.
*/
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

// New creates a new SU3 file with default settings and current timestamp.
// The file is initialized with RSA-SHA512 signature type and a Unix timestamp version.
// Additional fields must be set before signing and distribution.
func New() *SU3 {
	return &SU3{
		Version:       strconv.FormatInt(time.Now().Unix(), 10),
		SignatureType: RSA_SHA512_4096,
		FileType:      ZIP,
		ContentType:   UNKNOWN,
		mut:           sync.Mutex{},
	}
}

// SetContent sets the content data for the SU3 file.
func (su3 *SU3) SetContent(content []byte) {
	su3.mut.Lock()
	defer su3.mut.Unlock()
	su3.content = make([]byte, len(content))
	copy(su3.content, content)
	su3.ContentLength = uint64(len(content))
	log.WithField("content_length", len(content)).Debug("Content set for SU3 file")
}

// SetSignerID sets the signer ID for the SU3 file.
func (su3 *SU3) SetSignerID(signerID string) {
	su3.mut.Lock()
	defer su3.mut.Unlock()
	su3.SignerID = signerID
	log.WithField("signer_id", signerID).Debug("Signer ID set for SU3 file")
}

// SetVersion sets the version string for the SU3 file.
func (su3 *SU3) SetVersion(version string) {
	su3.mut.Lock()
	defer su3.mut.Unlock()
	su3.Version = version
	log.WithField("version", version).Debug("Version set for SU3 file")
}

// SetFileType sets the file type for the SU3 file.
func (su3 *SU3) SetFileType(fileType FileType) {
	su3.mut.Lock()
	defer su3.mut.Unlock()
	su3.FileType = fileType
	log.WithField("file_type", fileType).Debug("File type set for SU3 file")
}

// SetContentType sets the content type for the SU3 file.
func (su3 *SU3) SetContentType(contentType ContentType) {
	su3.mut.Lock()
	defer su3.mut.Unlock()
	su3.ContentType = contentType
	log.WithField("content_type", contentType).Debug("Content type set for SU3 file")
}

// SetSignatureType sets the signature type for the SU3 file.
func (su3 *SU3) SetSignatureType(signatureType SignatureType) {
	su3.mut.Lock()
	defer su3.mut.Unlock()
	su3.SignatureType = signatureType
	log.WithField("signature_type", signatureType).Debug("Signature type set for SU3 file")
}

// Sign cryptographically signs the SU3 file using the provided RSA private key.
// The signature covers the file header and content but not the signature itself.
// The signature length is automatically determined by the RSA key size.
// Returns an error if the private key is nil or signature generation fails.
func (su3 *SU3) Sign(privateKey *rsa.PrivateKey) error {
	su3.mut.Lock()
	defer su3.mut.Unlock()

	if privateKey == nil {
		log.Error("Private key cannot be nil for SU3 signing")
		return oops.Errorf("private key cannot be nil")
	}

	// Pre-calculate signature length to ensure header consistency
	keySize := privateKey.Size()          // Returns key size in bytes
	su3.signature = make([]byte, keySize) // Temporary signature with correct length
	su3.SignatureLength = uint16(keySize)

	var hashType crypto.Hash
	// Select appropriate hash algorithm based on signature type
	switch su3.SignatureType {
	case DSA_SHA1:
		hashType = crypto.SHA1
	case ECDSA_SHA256_P256, RSA_SHA256_2048:
		hashType = crypto.SHA256
	case ECDSA_SHA384_P384, RSA_SHA384_3072:
		hashType = crypto.SHA384
	case ECDSA_SHA512_P521, RSA_SHA512_4096, EdDSA_SHA512_Ed25519ph:
		hashType = crypto.SHA512
	default:
		log.WithField("signature_type", su3.SignatureType).Error("Unknown signature type for SU3 signing")
		return oops.Errorf("unknown signature type: %s", su3.SignatureType)
	}

	h := hashType.New()

	// Hash the header first (same as what initializeReaders does with buff.Bytes())
	headerBytes := su3.HeaderBytes()
	h.Write(headerBytes)

	// Then hash the content (same as what the contentReader does during Read())
	h.Write(su3.content)

	digest := h.Sum(nil)

	// Generate RSA signature using PKCS#1 v1.5 padding scheme
	// Use the hashType parameter, not 0, to match what the verifier expects
	sig, err := rsa.SignPKCS1v15(rand.Reader, privateKey, hashType, digest)
	if err != nil {
		log.WithError(err).Error("Failed to generate RSA signature for SU3 file")
		return oops.Errorf("generating RSA signature: %w", err)
	}

	su3.signature = sig
	su3.SignatureLength = uint16(len(sig))

	log.WithField("signature_length", len(sig)).Debug("SU3 file signed successfully")
	return nil
}

// HeaderBytes generates just the SU3 header without content or signature.
// This is used for signature generation and matches what the parser stores in buff.Bytes().
func (su3 *SU3) HeaderBytes() []byte {
	var (
		buf = new(bytes.Buffer)

		skip    [1]byte
		bigSkip [12]byte

		versionBytes    = []byte(su3.Version)
		signerIDBytes   = []byte(su3.SignerID)
		signatureLength = su3.SignatureLength
		signerIDLength  = uint8(len(signerIDBytes))
		contentLength   = uint64(len(su3.content))
	)

	// Ensure version field meets minimum length requirement by zero-padding
	minVersionLength := 16
	if len(versionBytes) < minVersionLength {
		paddedVersion := make([]byte, minVersionLength)
		copy(paddedVersion, versionBytes)
		versionBytes = paddedVersion
	}
	versionLength := uint8(len(versionBytes)) // Use the padded length (always 16)

	// Write SU3 file header in big-endian binary format (same format as parser expects)
	binary.Write(buf, binary.BigEndian, []byte(magicBytes))
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, uint8(0)) // Format version

	// Write signature type as 2-byte value
	sigTypeBytes, ok := sigTypesReverse[su3.SignatureType]
	if !ok {
		log.WithField("signature_type", su3.SignatureType).Error("Unknown signature type in HeaderBytes")
		sigTypeBytes = sigTypesReverse[RSA_SHA512_4096] // Default fallback
	}
	binary.Write(buf, binary.BigEndian, sigTypeBytes)

	binary.Write(buf, binary.BigEndian, signatureLength)
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, versionLength) // Use padded length (16), not original length
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, signerIDLength)
	binary.Write(buf, binary.BigEndian, contentLength)
	binary.Write(buf, binary.BigEndian, skip)

	// Write file type as 1-byte value
	fileTypeByte, ok := fileTypesReverse[su3.FileType]
	if !ok {
		log.WithField("file_type", su3.FileType).Error("Unknown file type in HeaderBytes")
		fileTypeByte = fileTypesReverse[ZIP] // Default fallback
	}
	binary.Write(buf, binary.BigEndian, fileTypeByte)
	binary.Write(buf, binary.BigEndian, skip)

	// Write content type as 1-byte value
	contentTypeByte, ok := contentTypesReverse[su3.ContentType]
	if !ok {
		log.WithField("content_type", su3.ContentType).Error("Unknown content type in HeaderBytes")
		contentTypeByte = contentTypesReverse[UNKNOWN] // Default fallback
	}
	binary.Write(buf, binary.BigEndian, contentTypeByte)
	binary.Write(buf, binary.BigEndian, bigSkip)
	binary.Write(buf, binary.BigEndian, versionBytes) // Write padded version bytes
	binary.Write(buf, binary.BigEndian, signerIDBytes)

	// NOTE: Content and signature are NOT included in HeaderBytes - they are separate

	return buf.Bytes()
}

// BodyBytes generates the binary representation of the SU3 file without the signature.
// This includes the magic header, metadata fields, and content data in the proper SU3 format.
func (su3 *SU3) BodyBytes() []byte {
	var (
		buf = new(bytes.Buffer)

		skip    [1]byte
		bigSkip [12]byte

		versionBytes    = []byte(su3.Version)
		signerIDBytes   = []byte(su3.SignerID)
		signatureLength = su3.SignatureLength
		signerIDLength  = uint8(len(signerIDBytes))
		contentLength   = uint64(len(su3.content))
	)

	// Ensure version field meets minimum length requirement by zero-padding
	minVersionLength := 16
	if len(versionBytes) < minVersionLength {
		paddedVersion := make([]byte, minVersionLength)
		copy(paddedVersion, versionBytes)
		versionBytes = paddedVersion
	}
	versionLength := uint8(len(versionBytes)) // Use the padded length (always 16)

	// Write SU3 file header in big-endian binary format
	binary.Write(buf, binary.BigEndian, []byte(magicBytes))
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, uint8(0)) // Format version

	// Write signature type as 2-byte value
	sigTypeBytes, ok := sigTypesReverse[su3.SignatureType]
	if !ok {
		log.WithField("signature_type", su3.SignatureType).Error("Unknown signature type in BodyBytes")
		sigTypeBytes = sigTypesReverse[RSA_SHA512_4096] // Default fallback
	}
	binary.Write(buf, binary.BigEndian, sigTypeBytes)

	binary.Write(buf, binary.BigEndian, signatureLength)
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, versionLength)
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, signerIDLength)
	binary.Write(buf, binary.BigEndian, contentLength)
	binary.Write(buf, binary.BigEndian, skip)

	// Write file type as 1-byte value
	fileTypeByte, ok := fileTypesReverse[su3.FileType]
	if !ok {
		log.WithField("file_type", su3.FileType).Error("Unknown file type in BodyBytes")
		fileTypeByte = fileTypesReverse[ZIP] // Default fallback
	}
	binary.Write(buf, binary.BigEndian, fileTypeByte)
	binary.Write(buf, binary.BigEndian, skip)

	// Write content type as 1-byte value
	contentTypeByte, ok := contentTypesReverse[su3.ContentType]
	if !ok {
		log.WithField("content_type", su3.ContentType).Error("Unknown content type in BodyBytes")
		contentTypeByte = contentTypesReverse[UNKNOWN] // Default fallback
	}
	binary.Write(buf, binary.BigEndian, contentTypeByte)
	binary.Write(buf, binary.BigEndian, bigSkip)
	binary.Write(buf, binary.BigEndian, versionBytes)
	binary.Write(buf, binary.BigEndian, signerIDBytes)
	binary.Write(buf, binary.BigEndian, su3.content)

	return buf.Bytes()
}

// MarshalBinary serializes the complete SU3 file including signature to binary format.
// This produces the final SU3 file data that can be written to disk or transmitted.
// The signature must be set before calling this method for a valid SU3 file.
func (su3 *SU3) MarshalBinary() ([]byte, error) {
	su3.mut.Lock()
	defer su3.mut.Unlock()

	if su3.signature == nil {
		log.Error("Cannot marshal SU3 file without signature")
		return nil, oops.Errorf("signature is required before marshaling")
	}

	buf := bytes.NewBuffer(su3.BodyBytes())
	binary.Write(buf, binary.BigEndian, su3.signature)

	log.WithField("total_size", buf.Len()).Debug("SU3 file marshaled successfully")
	return buf.Bytes(), nil
}
