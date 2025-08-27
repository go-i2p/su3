package su3

import (
	"bytes"
	"github.com/go-i2p/crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestHeaderBytesVsParserHeader - Compare our generated header with what the parser expects
func TestHeaderBytesVsParserHeader(t *testing.T) {
	// Generate test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// Create SU3 file
	originalFile := New()
	testContent := []byte("Test content")
	originalFile.SetContent(testContent)
	originalFile.SetSignerID("debug@example.com")
	originalFile.SetVersion("1.0.0")
	originalFile.SetFileType(ZIP)
	originalFile.SetContentType(RESEED)
	originalFile.SetSignatureType(RSA_SHA256_2048)

	// Sign the file
	err = originalFile.Sign(privateKey)
	assert.NoError(t, err)

	// Generate our header
	ourHeader := originalFile.HeaderBytes()
	t.Logf("Our header length: %d", len(ourHeader))

	// Marshal and parse back to see what the parser creates
	data, err := originalFile.MarshalBinary()
	assert.NoError(t, err)

	reader := bytes.NewReader(data)
	parsedFile, err := Read(reader)
	assert.NoError(t, err)

	// To get the parser's header, I need to understand how the parser builds buff.Bytes()
	// Let me build what the parser should have generated during reading...

	// The parser builds the header incrementally. Let me reproduce that:
	var parserBuff bytes.Buffer

	// From readAndValidateMagicBytes
	parserBuff.Write([]byte(magicBytes))

	// From readFileFormatHeader
	parserBuff.WriteByte(0) // unused byte 6
	parserBuff.WriteByte(0) // format version

	// From readSignatureInfo
	sigTypeBytes, ok := sigTypesReverse[parsedFile.SignatureType]
	assert.True(t, ok)
	parserBuff.Write(sigTypeBytes[:])

	// Signature length as big endian uint16
	sigLenBytes := make([]byte, 2)
	sigLenBytes[0] = byte(parsedFile.SignatureLength >> 8)
	sigLenBytes[1] = byte(parsedFile.SignatureLength & 0xFF)
	parserBuff.Write(sigLenBytes)

	// From readLengthFields
	parserBuff.WriteByte(0)                              // unused byte 12
	parserBuff.WriteByte(byte(len(parsedFile.Version)))  // version length
	parserBuff.WriteByte(0)                              // unused byte 14
	parserBuff.WriteByte(byte(len(parsedFile.SignerID))) // signer ID length

	// Content length as big endian uint64
	contentLenBytes := make([]byte, 8)
	contentLen := parsedFile.ContentLength
	for i := 7; i >= 0; i-- {
		contentLenBytes[i] = byte(contentLen & 0xFF)
		contentLen >>= 8
	}
	parserBuff.Write(contentLenBytes)

	// From readFileMetadata
	parserBuff.WriteByte(0) // unused byte 24

	fileTypeByte, ok := fileTypesReverse[parsedFile.FileType]
	assert.True(t, ok)
	parserBuff.WriteByte(fileTypeByte)

	parserBuff.WriteByte(0) // unused byte 26

	contentTypeByte, ok := contentTypesReverse[parsedFile.ContentType]
	assert.True(t, ok)
	parserBuff.WriteByte(contentTypeByte)

	// From readUnusedBytes28To39
	for i := 0; i < 12; i++ {
		parserBuff.WriteByte(0)
	}

	// From readVersionAndSignerID
	versionBytes := []byte(parsedFile.Version)
	if len(versionBytes) < 16 {
		paddedVersion := make([]byte, 16)
		copy(paddedVersion, versionBytes)
		versionBytes = paddedVersion
	}
	parserBuff.Write(versionBytes)
	parserBuff.Write([]byte(parsedFile.SignerID))

	parserHeader := parserBuff.Bytes()
	t.Logf("Parser header length: %d", len(parserHeader))

	// Compare the headers
	if !bytes.Equal(ourHeader, parserHeader) {
		t.Logf("Headers don't match!")
		t.Logf("Our header: %x", ourHeader)
		t.Logf("Parser header: %x", parserHeader)

		// Find the first difference
		minLen := len(ourHeader)
		if len(parserHeader) < minLen {
			minLen = len(parserHeader)
		}

		for i := 0; i < minLen; i++ {
			if ourHeader[i] != parserHeader[i] {
				t.Logf("First difference at byte %d: our=0x%02x, parser=0x%02x", i, ourHeader[i], parserHeader[i])
				break
			}
		}
	} else {
		t.Log("Headers match perfectly!")
	}
}
