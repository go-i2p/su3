package su3

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestBasicRSASigning - Verify that basic RSA signing works with our keys
func TestBasicRSASigning(t *testing.T) {
	// Generate test RSA key and certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	certDER, err := NewSigningCertificate("basic@example.com", privateKey)
	assert.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	assert.NoError(t, err)

	// Test data
	testData := []byte("Hello, World!")

	// Create hash
	h := sha256.New()
	h.Write(testData)
	digest := h.Sum(nil)
	t.Logf("Test digest: %x", digest)

	// Sign the hash
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey, 0, digest)
	assert.NoError(t, err)
	t.Logf("Signature length: %d", len(signature))

	// Verify the signature
	pubKey := cert.PublicKey.(*rsa.PublicKey)
	err = rsa.VerifyPKCS1v15(pubKey, 0, digest, signature)
	t.Logf("Basic verification result: %v", err)
	assert.NoError(t, err)

	// Also try with crypto.SHA256 instead of 0
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest, signature)
	t.Logf("Verification with crypto.SHA256: %v", err)

	// Try signing with crypto.SHA256
	signature2, err := rsa.SignPKCS1v15(rand.Reader, privateKey, crypto.SHA256, digest)
	assert.NoError(t, err)

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, digest, signature2)
	t.Logf("Verification of SHA256-signed with SHA256: %v", err)
	assert.NoError(t, err)
}
