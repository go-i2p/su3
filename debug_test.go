package su3

import (
	"bytes"
	"crypto"
	"github.com/go-i2p/crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestSU3RoundTripDebug - simplified version to debug the round-trip issue
func TestSU3RoundTripDebug(t *testing.T) {
	// Generate test RSA key and certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	certDER, err := NewSigningCertificate("debug@example.com", privateKey)
	assert.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	assert.NoError(t, err)

	// Create and setup original SU3 file
	originalFile := New()
	testContent := []byte("Test content")
	originalFile.SetContent(testContent)
	originalFile.SetSignerID("debug@example.com")
	originalFile.SetVersion("1.0.0")
	originalFile.SetFileType(ZIP)
	originalFile.SetContentType(RESEED)
	originalFile.SetSignatureType(RSA_SHA256_2048) // Use 2048-bit for our 2048-bit key

	// Sign the file
	err = originalFile.Sign(privateKey)
	assert.NoError(t, err)

	// Get header bytes that would be hashed during signing
	signingHeaderBytes := originalFile.HeaderBytes()
	t.Logf("Signing header bytes length: %d", len(signingHeaderBytes))
	t.Logf("Signing header bytes: %x", signingHeaderBytes)

	// Marshal to binary
	data, err := originalFile.MarshalBinary()
	assert.NoError(t, err)
	t.Logf("Total marshaled size: %d", len(data))

	// Now parse it back and compare the header bytes that would be hashed
	reader := bytes.NewReader(data)

	// I need to modify the reader temporarily to capture buff.Bytes()
	// Let me create a different approach - let me look at the parsed header bytes directly
	parsedFile, err := Read(reader)
	assert.NoError(t, err)

	t.Logf("Original signing header: %x", signingHeaderBytes[:40]) // First 40 bytes (fixed header)
	t.Logf("Parsed file version: %s", parsedFile.Version)
	t.Logf("Parsed file signer: %s", parsedFile.SignerID)

	// The issue is: I can't directly access buff.Bytes() from the parsed file
	// But I can recreate the header bytes the same way HeaderBytes() does

	// Try to read content with signature verification
	reader2 := bytes.NewReader(data)
	parsedFile2, err := Read(reader2)
	assert.NoError(t, err)

	contentReader := parsedFile2.Content(cert.PublicKey)
	actualContent, err := io.ReadAll(contentReader)
	t.Logf("Content read with verification error: %v", err)

	if err != nil {
		t.Logf("Signature verification failed, but let me check header bytes manually")

		// Create the header bytes the same way the parser would have built them
		var parsingBuffer bytes.Buffer

		// Write magic bytes
		parsingBuffer.Write([]byte("I2Psu3"))

		// Write unused byte 6
		parsingBuffer.WriteByte(0x00)

		// Write file format (always 0)
		parsingBuffer.WriteByte(0x00)

		// Write signature type (2 bytes)
		sigTypeBytes, _ := sigTypesReverse[originalFile.SignatureType]
		parsingBuffer.Write(sigTypeBytes[:])

		// Write signature length (2 bytes big endian)
		sigLen := uint16(len(originalFile.signature))
		parsingBuffer.WriteByte(byte(sigLen >> 8))
		parsingBuffer.WriteByte(byte(sigLen & 0xFF))

		// Write unused byte 12
		parsingBuffer.WriteByte(0x00)

		// Write version length
		versionBytes := originalFile.Version
		if len(versionBytes) < 16 {
			temp := make([]byte, 16)
			copy(temp, versionBytes)
			versionBytes = string(temp)
		}
		verLen := uint8(len(originalFile.Version)) // Original length, not padded
		parsingBuffer.WriteByte(verLen)

		// Write unused byte 14
		parsingBuffer.WriteByte(0x00)

		// Write signer ID length
		signerLen := uint8(len(originalFile.SignerID))
		parsingBuffer.WriteByte(signerLen)

		// Write content length (8 bytes big endian)
		contentLen := uint64(len(originalFile.content))
		contentLenBytes := make([]byte, 8)
		for i := 0; i < 8; i++ {
			contentLenBytes[i] = byte(contentLen >> (56 - 8*i))
		}
		parsingBuffer.Write(contentLenBytes)

		// Write unused byte 24
		parsingBuffer.WriteByte(0x00)

		// Write file type
		fileTypeByte, _ := fileTypesReverse[originalFile.FileType]
		parsingBuffer.WriteByte(fileTypeByte)

		// Write unused byte 26
		parsingBuffer.WriteByte(0x00)

		// Write content type
		contentTypeByte, _ := contentTypesReverse[originalFile.ContentType]
		parsingBuffer.WriteByte(contentTypeByte)

		// Write 12 unused bytes (28-39)
		unusedBytes := make([]byte, 12)
		parsingBuffer.Write(unusedBytes)

		// Write version (padded to 16 bytes with nulls)
		versionPadded := make([]byte, 16)
		copy(versionPadded, originalFile.Version)
		parsingBuffer.Write(versionPadded)

		// Write signer ID (raw bytes, no padding)
		parsingBuffer.Write([]byte(originalFile.SignerID))

		parsingHeaderBytes := parsingBuffer.Bytes()
		t.Logf("Reconstructed parsing header length: %d", len(parsingHeaderBytes))
		t.Logf("Reconstructed parsing header: %x", parsingHeaderBytes)

		t.Logf("Header bytes match: %v", bytes.Equal(signingHeaderBytes, parsingHeaderBytes))

		if !bytes.Equal(signingHeaderBytes, parsingHeaderBytes) {
			t.Logf("Header mismatch found!")
			t.Logf("Signing header  : %x", signingHeaderBytes)
			t.Logf("Parsing header  : %x", parsingHeaderBytes)

			// Find the first difference
			minLen := len(signingHeaderBytes)
			if len(parsingHeaderBytes) < minLen {
				minLen = len(parsingHeaderBytes)
			}
			for i := 0; i < minLen; i++ {
				if signingHeaderBytes[i] != parsingHeaderBytes[i] {
					t.Logf("First difference at byte %d: signing=0x%02x, parsing=0x%02x", i, signingHeaderBytes[i], parsingHeaderBytes[i])
					break
				}
			}
		}
	} else {
		assert.Equal(t, testContent, actualContent)
		t.Log("SUCCESS: Round-trip with signature verification works!")
	}
}

func TestHashDebug(t *testing.T) {
	// Generate test RSA key and certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	certDER, err := NewSigningCertificate("debug@example.com", privateKey)
	assert.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	assert.NoError(t, err)

	// Create and setup original SU3 file
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

	// Marshal and then parse back
	data, err := originalFile.MarshalBinary()
	assert.NoError(t, err)

	// Parse it back
	reader := bytes.NewReader(data)
	_, err = Read(reader)
	assert.NoError(t, err)

	// Now let's manually simulate what the content reader does during verification

	// Step 1: Create the same hash the content reader would create
	reader2 := bytes.NewReader(data)
	_, err = Read(reader2)
	assert.NoError(t, err)

	// The contentReader hash gets initialized with the header and then accumulates content
	// Let me verify this by reading the content WITHOUT signature verification first
	reader3 := bytes.NewReader(data)
	_, err = Read(reader3) // This will set up contentReader.hash
	assert.NoError(t, err)

	// Try to get access to the hash, but the contentReader is private...
	// Instead, let me manually recreate what the content reader hash calculation would be:

	// During parsing, the header bytes were accumulated in buff, and then written to hash
	headerBytes := originalFile.HeaderBytes() // We know these are identical to what was parsed

	// Create hash same way as content reader
	verificationHash := sha256.New()
	verificationHash.Write(headerBytes) // Header written first during reader initialization
	verificationHash.Write(testContent) // Content written during Read() calls
	verificationDigest := verificationHash.Sum(nil)

	t.Logf("Verification hash digest: %x", verificationDigest)

	// Now let's recreate the signing hash
	signingHash := sha256.New()
	signingHash.Write(headerBytes)
	signingHash.Write(testContent)
	signingDigest := signingHash.Sum(nil)

	t.Logf("Signing hash digest:     %x", signingDigest)
	t.Logf("Hash digests match: %v", bytes.Equal(verificationDigest, signingDigest))

	// Now manually verify the signature like the content reader would
	pubKey := cert.PublicKey.(*rsa.PublicKey)
	verifyErr := rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, verificationDigest, originalFile.signature)
	t.Logf("Manual verification result: %v", verifyErr)

	// Now let's check if the signature bytes in the parsed file are the same
	reader4 := bytes.NewReader(data)
	parsedFile4, err := Read(reader4)
	assert.NoError(t, err)

	// Try to trigger the signature reader to load the bytes
	contentReader4 := parsedFile4.Content(cert.PublicKey)
	contentBytes4, readErr := io.ReadAll(contentReader4)
	t.Logf("Content read result: %v", readErr)

	if readErr != nil {
		t.Log("Content read failed - signature verification failed in content reader")

		// The error occurred, but the signature was loaded. Let me check if I can access the signature bytes
		// Unfortunately signatureReader is private, so I can't directly compare

		// But I can try a different approach - let me see what happens if I use a content reader
		// WITHOUT providing a public key (no verification)
		reader5 := bytes.NewReader(data)
		parsedFile5, err := Read(reader5)
		assert.NoError(t, err)

		contentReaderNoVerify := parsedFile5.Content(nil)
		contentBytesNoVerify, noVerifyErr := io.ReadAll(contentReaderNoVerify)
		t.Logf("Content read without verification: %v", noVerifyErr)
		t.Logf("Content matches: %v", bytes.Equal(testContent, contentBytesNoVerify))

	} else {
		t.Log("SUCCESS: Content reader verification worked!")
		t.Logf("Content matches: %v", bytes.Equal(testContent, contentBytes4))
	}

	if verifyErr == nil {
		t.Log("SUCCESS: Manual verification works!")
	} else {
		t.Log("Manual verification also fails, signature might be wrong")
	}
}
