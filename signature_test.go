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

// TestValidSignatureGeneration - Test that we can create a valid signature that verifies
func TestValidSignatureGeneration(t *testing.T) {
	// Generate test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	publicKey := &privateKey.PublicKey

	// Create SU3 file with specific content
	su3File := New()
	testContent := []byte("Hello world test content")
	su3File.SetContent(testContent)
	su3File.SetSignerID("test@example.com")
	su3File.SetVersion("1.0.0")
	su3File.SetFileType(ZIP)
	su3File.SetContentType(RESEED)
	su3File.SetSignatureType(RSA_SHA256_2048)

	// Sign the file
	err = su3File.Sign(privateKey)
	assert.NoError(t, err)
	t.Logf("Generated signature length: %d", len(su3File.signature))

	// Now verify the signature manually using the same process
	headerBytes := su3File.HeaderBytes()
	t.Logf("Header bytes length: %d", len(headerBytes))

	// Hash header + content (same as signing process)
	h := sha256.New()
	h.Write(headerBytes)
	h.Write(testContent)
	digest := h.Sum(nil)
	t.Logf("Digest: %x", digest)

	// Verify signature
	err = rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, digest, su3File.signature)
	assert.NoError(t, err, "Signature should verify correctly")
	t.Log("SUCCESS: Manual signature verification passed!")

	// Now test with the certificate approach
	certDER, err := NewSigningCertificate("test@example.com", privateKey)
	assert.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	assert.NoError(t, err)

	// Verify again using the certificate's public key
	certPublicKey := cert.PublicKey.(*rsa.PublicKey)
	err = rsa.VerifyPKCS1v15(certPublicKey, crypto.SHA256, digest, su3File.signature)
	assert.NoError(t, err, "Signature should verify with certificate public key")
	t.Log("SUCCESS: Certificate-based signature verification passed!")
}
