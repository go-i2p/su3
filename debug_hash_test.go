package su3

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestDebugContentReaderHash - Debug what the content reader is actually hashing
func TestDebugContentReaderHash(t *testing.T) {
	// Generate test RSA key and certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	certDER, err := NewSigningCertificate("debug@test.com", privateKey)
	assert.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	assert.NoError(t, err)

	// Create and sign SU3 file
	su3File := New()
	testContent := []byte("Debug test content")
	su3File.SetContent(testContent)
	su3File.SetSignerID("debug@test.com")
	su3File.SetVersion("1.0")
	su3File.SetFileType(ZIP)
	su3File.SetContentType(RESEED)
	su3File.SetSignatureType(RSA_SHA256_2048)

	err = su3File.Sign(privateKey)
	assert.NoError(t, err)

	// Get the signing hash for comparison
	signingHeaderBytes := su3File.HeaderBytes()
	signingHash := sha256.New()
	signingHash.Write(signingHeaderBytes)
	signingHash.Write(testContent)
	signingDigest := signingHash.Sum(nil)
	t.Logf("Signing digest: %x", signingDigest)
	t.Logf("Signing header length: %d", len(signingHeaderBytes))
	t.Logf("Signature length: %d", len(su3File.signature))

	// Marshal and parse
	data, err := su3File.MarshalBinary()
	assert.NoError(t, err)

	reader := bytes.NewReader(data)
	_, err = Read(reader)
	assert.NoError(t, err)

	// Now I need to examine what the content reader will hash
	// The content reader gets initialized with a hash in initializeReaders()
	// Let me simulate what happens there

	// First, let me see what header bytes the parser accumulated
	reader2 := bytes.NewReader(data)

	// I'll simulate the parsing process to see what goes into buff
	var parsingBuff bytes.Buffer

	// Magic bytes
	magicBytesData := make([]byte, 6)
	reader2.Read(magicBytesData)
	parsingBuff.Write(magicBytesData)
	t.Logf("Magic bytes: %x", magicBytesData)

	// Read the rest of the header manually to build the exact buffer
	// that the parser would create
	headerData := make([]byte, 34) // remaining header after magic
	reader2.Read(headerData)
	parsingBuff.Write(headerData)

	// Read version and signer ID
	_ = int(headerData[7])          // byte 13 (7th in remaining header)
	signerLen := int(headerData[9]) // byte 15 (9th in remaining header)

	versionData := make([]byte, 16) // version is always padded to 16
	reader2.Read(versionData)
	parsingBuff.Write(versionData)

	signerData := make([]byte, signerLen)
	reader2.Read(signerData)
	parsingBuff.Write(signerData)

	parsingHeaderBytes := parsingBuff.Bytes()
	t.Logf("Parsing header length: %d", len(parsingHeaderBytes))
	t.Logf("Parsing header: %x", parsingHeaderBytes[:50]) // first 50 bytes

	// Compare headers
	t.Logf("Headers match: %v", bytes.Equal(signingHeaderBytes, parsingHeaderBytes))

	// Simulate the content reader hash calculation
	verificationHash := sha256.New()
	verificationHash.Write(parsingHeaderBytes)
	verificationHash.Write(testContent)
	verificationDigest := verificationHash.Sum(nil)
	t.Logf("Verification digest: %x", verificationDigest)

	t.Logf("Digests match: %v", bytes.Equal(signingDigest, verificationDigest))

	// Test manual verification with both digests
	publicKey := cert.PublicKey.(*rsa.PublicKey)

	signingVerifyErr := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, signingDigest, su3File.signature)
	t.Logf("Manual verify with signing digest: %v", signingVerifyErr)

	verificationVerifyErr := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, verificationDigest, su3File.signature)
	t.Logf("Manual verify with verification digest: %v", verificationVerifyErr)

	if !bytes.Equal(signingHeaderBytes, parsingHeaderBytes) {
		t.Log("Header mismatch detected!")
		// Find first difference
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
}
