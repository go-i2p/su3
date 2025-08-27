package su3

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestCompleteRoundTrip - Create, sign, marshal, parse, and verify an SU3 file
func TestCompleteRoundTrip(t *testing.T) {
	// Generate test RSA key and certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	certDER, err := NewSigningCertificate("test@roundtrip.com", privateKey)
	assert.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	assert.NoError(t, err)

	// Create SU3 file
	originalFile := New()
	testContent := []byte("Round trip test content for SU3 file verification")
	originalFile.SetContent(testContent)
	originalFile.SetSignerID("test@roundtrip.com")
	originalFile.SetVersion("2.0.1")
	originalFile.SetFileType(ZIP)
	originalFile.SetContentType(RESEED)
	originalFile.SetSignatureType(RSA_SHA256_2048)

	// Sign the file
	err = originalFile.Sign(privateKey)
	assert.NoError(t, err)
	t.Logf("Original file signed with signature length: %d", len(originalFile.signature))

	// Marshal to binary data
	data, err := originalFile.MarshalBinary()
	assert.NoError(t, err)
	t.Logf("SU3 file marshaled to %d bytes", len(data))

	// Parse the binary data back
	reader := bytes.NewReader(data)
	parsedFile, err := Read(reader)
	assert.NoError(t, err)
	t.Logf("SU3 file parsed successfully")
	t.Logf("Parsed version: %s", parsedFile.Version)
	t.Logf("Parsed signer: %s", parsedFile.SignerID)
	t.Logf("Parsed signature type: %s", parsedFile.SignatureType)
	t.Logf("Parsed signature length: %d", parsedFile.SignatureLength)

	// Verify metadata matches
	assert.Equal(t, originalFile.Version, parsedFile.Version)
	assert.Equal(t, originalFile.SignerID, parsedFile.SignerID)
	assert.Equal(t, originalFile.SignatureType, parsedFile.SignatureType)
	assert.Equal(t, originalFile.FileType, parsedFile.FileType)
	assert.Equal(t, originalFile.ContentType, parsedFile.ContentType)
	assert.Equal(t, originalFile.SignatureLength, parsedFile.SignatureLength)

	// Now the critical test: read content with signature verification
	reader2 := bytes.NewReader(data)
	parsedFile2, err := Read(reader2)
	assert.NoError(t, err)

	contentReader := parsedFile2.Content(cert.PublicKey)
	actualContent, err := io.ReadAll(contentReader)
	if err != nil {
		t.Fatalf("Content reading with signature verification failed: %v", err)
	}

	// Verify content matches
	assert.Equal(t, testContent, actualContent)
	t.Log("SUCCESS: Complete round-trip with signature verification works!")
}
