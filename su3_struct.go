package su3

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/binary"
	"io"
	"math/big"
	"strconv"
	"sync"
	"time"

	goi2ped25519 "github.com/go-i2p/crypto/ed25519"
	"github.com/go-i2p/crypto/rand"

	"github.com/go-i2p/logger"
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
// The publicKey parameter is used for signature verification during reading.
// If publicKey is nil, content can be read but ErrInvalidSignature will be returned.
//
// CRITICAL READ ORDER REQUIREMENT:
// If you want to read both content and signature, the Content() io.Reader MUST
// be read *before* the Signature() io.Reader. This limitation exists because
// SU3 files are a streaming format where content and signature are sequential.
//
// SIDE EFFECTS OF READING SIGNATURE() FIRST:
// When you read from Signature() before reading Content(), the signature reader
// will automatically consume and discard ALL remaining content bytes to position
// the stream correctly for signature reading. This means:
//   - Any unread content data is permanently lost
//   - Subsequent calls to Content() will return an empty reader
//   - No error is generated, but content access is no longer possible
//
// WORKAROUNDS:
//  1. Always read Content() before Signature() if you need both
//  2. If you only need signature verification without content access,
//     you can safely read Signature() directly
//  3. For scenarios requiring signature-first access, consider using
//     bytes.Buffer or similar to fully buffer the SU3 data first
//
// EXAMPLE - Correct order for accessing both:
//
//	contentReader := su3File.Content(publicKey)
//	content, err := io.ReadAll(contentReader)  // Read content first
//	if err != nil { /* handle error */ }
//
//	signatureReader := su3File.Signature()     // Now safe to read signature
//	signature, err := io.ReadAll(signatureReader)
//
// For test cases demonstrating this behavior, see TestReadSignatureFirst.
// Moved from: su3.go
func (su3 *SU3) Content(publicKey interface{}) io.Reader {
	log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.Content", "signer_id": su3.SignerID}).Debug("Accessing SU3 content")
	su3.publicKey = publicKey
	return su3.contentReader
}

// Signature returns an io.Reader for accessing the SU3 file signature bytes.
//
// IMPORTANT STREAMING BEHAVIOR:
// Reading from this signature reader will automatically consume any unread
// content bytes from the underlying stream to correctly position for signature
// reading. This has the following implications:
//
//   - If Content() has not been fully read, all remaining content data
//     will be discarded when Signature() is first accessed
//   - This makes subsequent Content() calls return empty readers
//   - No error occurs, but content access becomes impossible
//
// USAGE PATTERNS:
// 1. Signature-only access (safe): Call Signature() directly without Content()
// 2. Both content and signature: Read Content() completely before Signature()
// 3. Manual verification workflows: Read signature bytes for custom crypto
//
// The signature reader provides the raw signature bytes as stored in the SU3 file.
// For automatic signature verification, use Content(publicKey) instead.
//
// Moved from: su3.go
func (su3 *SU3) Signature() io.Reader {
	log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.Signature"}).Debug("Accessing SU3 signature")
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
	log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.SetContent", "content_length": len(content)}).Debug("Content set for SU3 file")
}

// SetSignerID sets the signer ID for the SU3 file.
func (su3 *SU3) SetSignerID(signerID string) {
	su3.mut.Lock()
	defer su3.mut.Unlock()
	su3.SignerID = signerID
	log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.SetSignerID", "signer_id": signerID}).Debug("Signer ID set for SU3 file")
}

// SetVersion sets the version string for the SU3 file.
// Returns ErrVersionTooLong if version exceeds 255 bytes (the protocol maximum).
func (su3 *SU3) SetVersion(version string) error {
	if len(version) > 255 {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.SetVersion", "version_length": len(version)}).Error("Version string exceeds maximum allowed length")
		return ErrVersionTooLong
	}
	su3.mut.Lock()
	defer su3.mut.Unlock()
	su3.Version = version
	log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.SetVersion", "version": version}).Debug("Version set for SU3 file")
	return nil
}

// SetFileType sets the file type for the SU3 file.
func (su3 *SU3) SetFileType(fileType FileType) {
	su3.mut.Lock()
	defer su3.mut.Unlock()
	su3.FileType = fileType
	log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.SetFileType", "file_type": fileType}).Debug("File type set for SU3 file")
}

// SetContentType sets the content type for the SU3 file.
func (su3 *SU3) SetContentType(contentType ContentType) {
	su3.mut.Lock()
	defer su3.mut.Unlock()
	su3.ContentType = contentType
	log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.SetContentType", "content_type": contentType}).Debug("Content type set for SU3 file")
}

// SetSignatureType sets the signature type for the SU3 file.
func (su3 *SU3) SetSignatureType(signatureType SignatureType) {
	su3.mut.Lock()
	defer su3.mut.Unlock()
	su3.SignatureType = signatureType
	log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.SetSignatureType", "signature_type": signatureType}).Debug("Signature type set for SU3 file")
}

// getExpectedRSAKeySize returns the expected RSA key size in bytes for a given signature type.
// Returns 0 for non-RSA signature types, and an error for invalid signature types.
func getExpectedRSAKeySize(signatureType SignatureType) (int, error) {
	switch signatureType {
	case RSA_SHA256_2048:
		return 256, nil // 2048 bits = 256 bytes
	case RSA_SHA384_3072:
		return 384, nil // 3072 bits = 384 bytes
	case RSA_SHA512_4096:
		return 512, nil // 4096 bits = 512 bytes
	case DSA_SHA1, ECDSA_SHA256_P256, ECDSA_SHA384_P384, ECDSA_SHA512_P521, EdDSA_SHA512_Ed25519ph:
		return 0, nil // Non-RSA signature types don't have fixed key size requirements
	default:
		return 0, oops.Errorf("unknown signature type: %s", signatureType)
	}
}

// Sign cryptographically signs the SU3 file using the provided RSA private key.
// The signature covers the file header and content but not the signature itself.
// The signature length is automatically determined by the RSA key size.
// Returns an error if the private key is nil or signature generation fails.
func (su3 *SU3) Sign(privateKey *rsa.PrivateKey) error {
	su3.mut.Lock()
	defer su3.mut.Unlock()

	if privateKey == nil {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.Sign"}).Error("Private key cannot be nil for SU3 signing")
		return oops.Errorf("private key cannot be nil")
	}

	// Validate RSA key size matches declared signature type
	keySize := privateKey.Size() // Returns key size in bytes
	expectedKeySize, err := getExpectedRSAKeySize(su3.SignatureType)
	if err != nil {
		return err
	}
	if expectedKeySize > 0 && keySize != expectedKeySize {
		log.WithFields(logger.Fields{
			"pkg":               "su3",
			"func":              "SU3.Sign",
			"signature_type":    su3.SignatureType,
			"expected_key_size": expectedKeySize,
			"actual_key_size":   keySize,
		}).Error("RSA key size does not match declared signature type")
		return oops.Errorf("RSA key size %d bytes does not match signature type %s (expected %d bytes)", keySize, su3.SignatureType, expectedKeySize)
	}

	// Pre-calculate signature length to ensure header consistency
	su3.signature = make([]byte, keySize) // Temporary signature with correct length
	su3.SignatureLength = uint16(keySize)

	// Use centralized hash algorithm selection to ensure consistency
	hashType, err := getCryptoHashForSignatureType(su3.SignatureType)
	if err != nil {
		return err
	}

	h := hashType.New()

	// Hash the header first (same as what initializeReaders does with buff.Bytes())
	headerBytes := su3.HeaderBytes()
	h.Write(headerBytes)

	// Then hash the content (same as what the contentReader does during Read())
	h.Write(su3.content)

	digest := h.Sum(nil)

	// Generate RSA signature using PKCS#1 v1.5 padding scheme
	// Use hash=0 for raw signing without DigestInfo prefix, matching how
	// I2P reseed servers sign and how verifyRSASignature verifies.
	sig, err := rsa.SignPKCS1v15(rand.Reader, privateKey, 0, digest)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.Sign"}).WithError(err).Error("Failed to generate RSA signature for SU3 file")
		return oops.Errorf("generating RSA signature: %w", err)
	}

	su3.signature = sig
	su3.SignatureLength = uint16(len(sig))

	log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.Sign", "signature_length": len(sig)}).Debug("SU3 file signed successfully")
	return nil
}

// ecdsaSignatureParams returns the expected SU3 SignatureType and raw key byte
// width for the given ECDSA private key's curve.
func ecdsaSignatureParams(key *ecdsa.PrivateKey) (SignatureType, int, error) {
	keyBytes := (key.Curve.Params().BitSize + 7) / 8
	switch keyBytes {
	case 32:
		return ECDSA_SHA256_P256, keyBytes, nil
	case 48:
		return ECDSA_SHA384_P384, keyBytes, nil
	case 66:
		return ECDSA_SHA512_P521, keyBytes, nil
	default:
		return "", 0, oops.Errorf("unsupported ECDSA curve size: %d bits", key.Curve.Params().BitSize)
	}
}

// SignECDSA signs the SU3 file using the provided ECDSA private key.
// Produces raw fixed-length R||S encoding matching the I2P common-structures
// specification: P-256 = 64 bytes, P-384 = 96 bytes, P-521 = 132 bytes.
// SignatureType must be set to the appropriate ECDSA variant before calling.
func (su3 *SU3) SignECDSA(key *ecdsa.PrivateKey) error {
	su3.mut.Lock()
	defer su3.mut.Unlock()

	if key == nil {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.SignECDSA"}).Error("ECDSA private key cannot be nil for SU3 signing")
		return oops.Errorf("private key cannot be nil")
	}

	expectedType, keyBytes, err := ecdsaSignatureParams(key)
	if err != nil {
		return err
	}
	if su3.SignatureType != expectedType {
		return oops.Errorf("declared signature type %s does not match ECDSA key curve (expected %s)", su3.SignatureType, expectedType)
	}

	// Raw R||S length is fixed, so the header is stable before hashing.
	su3.SignatureLength = uint16(2 * keyBytes)
	su3.signature = make([]byte, 2*keyBytes)

	hashType, err := getCryptoHashForSignatureType(su3.SignatureType)
	if err != nil {
		return err
	}
	h := hashType.New()
	h.Write(su3.HeaderBytes())
	h.Write(su3.content)
	digest := h.Sum(nil)

	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.SignECDSA"}).WithError(err).Error("Failed to generate ECDSA signature")
		return oops.Errorf("generating ECDSA signature: %w", err)
	}

	sig := make([]byte, 2*keyBytes)
	new(big.Int).Set(r).FillBytes(sig[:keyBytes])
	new(big.Int).Set(s).FillBytes(sig[keyBytes:])
	su3.signature = sig

	log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.SignECDSA", "signature_length": len(sig)}).Debug("SU3 file signed with ECDSA successfully")
	return nil
}

// SignEdDSA signs the SU3 file using the provided Ed25519 private key.
// Requires SignatureType to be EdDSA_SHA512_Ed25519ph.
// The signature covers SHA-512(header bytes || content), consistent with
// the verifyEdDSASignature path in content_reader.go.
func (su3 *SU3) SignEdDSA(key ed25519.PrivateKey) error {
	su3.mut.Lock()
	defer su3.mut.Unlock()

	if key == nil {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.SignEdDSA"}).Error("EdDSA private key cannot be nil for SU3 signing")
		return oops.Errorf("private key cannot be nil")
	}
	if su3.SignatureType != EdDSA_SHA512_Ed25519ph {
		return oops.Errorf("signature type must be EdDSA_SHA512_Ed25519ph for EdDSA signing, got %s", su3.SignatureType)
	}

	// Ed25519 signatures are always 64 bytes; set upfront so the header is stable.
	su3.SignatureLength = 64
	su3.signature = make([]byte, 64)

	hashType, err := getCryptoHashForSignatureType(su3.SignatureType)
	if err != nil {
		return err
	}
	h := hashType.New()
	h.Write(su3.HeaderBytes())
	h.Write(su3.content)
	digest := h.Sum(nil)

	signer, err := goi2ped25519.Ed25519PrivateKey(key).NewSigner()
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.SignEdDSA"}).WithError(err).Error("Failed to create EdDSA signer")
		return oops.Errorf("creating EdDSA signer: %w", err)
	}
	sig, err := signer.SignHash(digest)
	if err != nil {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.SignEdDSA"}).WithError(err).Error("Failed to generate EdDSA signature")
		return oops.Errorf("generating EdDSA signature: %w", err)
	}

	su3.signature = sig
	su3.SignatureLength = uint16(len(sig))

	log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.SignEdDSA", "signature_length": len(sig)}).Debug("SU3 file signed with EdDSA successfully")
	return nil
}

// encodeHeader writes all SU3 header fields (excluding content and signature) into buf.
// This is the single source of truth for the binary header format, shared by
// HeaderBytes and BodyBytes to prevent the two paths from drifting out of sync.
func (su3 *SU3) encodeHeader(buf *bytes.Buffer) {
	versionBytes := []byte(su3.Version)
	signerIDBytes := []byte(su3.SignerID)
	skip := [1]byte{}
	bigSkip := [12]byte{}

	if len(versionBytes) < 16 {
		padded := make([]byte, 16)
		copy(padded, versionBytes)
		versionBytes = padded
	}

	sigTypeBytes, ok := sigTypesReverse[su3.SignatureType]
	if !ok {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.encodeHeader", "signature_type": su3.SignatureType}).Error("Unknown signature type in header encoding")
		sigTypeBytes = sigTypesReverse[RSA_SHA512_4096]
	}
	fileTypeByte, ok := fileTypesReverse[su3.FileType]
	if !ok {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.encodeHeader", "file_type": su3.FileType}).Error("Unknown file type in header encoding")
		fileTypeByte = fileTypesReverse[ZIP]
	}
	contentTypeByte, ok := contentTypesReverse[su3.ContentType]
	if !ok {
		log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.encodeHeader", "content_type": su3.ContentType}).Error("Unknown content type in header encoding")
		contentTypeByte = contentTypesReverse[UNKNOWN]
	}

	binary.Write(buf, binary.BigEndian, []byte(magicBytes))
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, uint8(0)) // Format version
	binary.Write(buf, binary.BigEndian, sigTypeBytes)
	binary.Write(buf, binary.BigEndian, su3.SignatureLength)
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, uint8(len(versionBytes)))
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, uint8(len(signerIDBytes)))
	binary.Write(buf, binary.BigEndian, uint64(len(su3.content)))
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, fileTypeByte)
	binary.Write(buf, binary.BigEndian, skip)
	binary.Write(buf, binary.BigEndian, contentTypeByte)
	binary.Write(buf, binary.BigEndian, bigSkip)
	binary.Write(buf, binary.BigEndian, versionBytes)
	binary.Write(buf, binary.BigEndian, signerIDBytes)
}

// HeaderBytes generates just the SU3 header without content or signature.
// This is used for signature generation and matches what the parser stores in buff.Bytes().
func (su3 *SU3) HeaderBytes() []byte {
	buf := new(bytes.Buffer)
	su3.encodeHeader(buf)
	return buf.Bytes()
}

// BodyBytes generates the binary representation of the SU3 file without the signature.
// This includes the magic header, metadata fields, and content data in the proper SU3 format.
func (su3 *SU3) BodyBytes() []byte {
	buf := new(bytes.Buffer)
	su3.encodeHeader(buf)
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
		log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.MarshalBinary"}).Error("Cannot marshal SU3 file without signature")
		return nil, oops.Errorf("signature is required before marshaling")
	}

	buf := bytes.NewBuffer(su3.BodyBytes())
	binary.Write(buf, binary.BigEndian, su3.signature)

	log.WithFields(logger.Fields{"pkg": "su3", "func": "SU3.MarshalBinary", "total_size": buf.Len()}).Debug("SU3 file marshaled successfully")
	return buf.Bytes(), nil
}
