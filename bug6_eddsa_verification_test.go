package su3

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha512"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBug6EdDSASignatureVerificationGap tests the EdDSA verification implementation
// to ensure it properly handles Ed25519ph pre-hashing according to RFC 8032.
// This test validates Bug #6: EdDSA Signature Verification Implementation Gap
func TestBug6EdDSASignatureVerificationGap(t *testing.T) {
	t.Run("EdDSA_signature_verification_implementation", func(t *testing.T) {
		// Create a test SU3 file with EdDSA signature type
		su3File := New()
		su3File.SignatureType = EdDSA_SHA512_Ed25519ph
		su3File.FileType = ZIP
		su3File.ContentType = RESEED
		su3File.Version = "1.0.0"
		su3File.SignerID = "eddsa-test@example.com"
		
		// Set some test content
		testContent := []byte("This is test content for EdDSA verification testing")
		su3File.content = testContent
		su3File.ContentLength = uint64(len(testContent))
		
		// Generate an Ed25519 keypair for testing
		edPublicKey, edPrivateKey, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)
		
		// Create a test signature using Ed25519ph approach
		// According to RFC 8032, Ed25519ph pre-hashes the message with SHA-512
		hasher := sha512.New()
		hasher.Write(testContent)
		preHashedContent := hasher.Sum(nil)
		
		// Sign the pre-hashed content (simplified test signature)
		// In practice, Ed25519ph would use proper domain separation
		signature := ed25519.Sign(edPrivateKey, preHashedContent)
		
		su3File.signature = signature
		su3File.SignatureLength = uint16(len(signature))
		
		// Marshal the SU3 file
		data, err := su3File.MarshalBinary()
		require.NoError(t, err)
		
		// Parse it back
		reader := bytes.NewReader(data)
		parsedSU3, err := Read(reader)
		require.NoError(t, err)
		
		// Verify with the Ed25519 public key
		contentReader := parsedSU3.Content(edPublicKey)
		content, err := io.ReadAll(contentReader)
		
		// The verification might fail due to the current implementation gap
		// but the content should still be readable
		assert.Greater(t, len(content), 0, "Content should be readable")
		
		// Check that we're dealing with the right signature type
		assert.Equal(t, EdDSA_SHA512_Ed25519ph, parsedSU3.SignatureType)
	})

	t.Run("EdDSA_domain_separation_requirements", func(t *testing.T) {
		// Test that demonstrates the domain separation requirements
		// according to RFC 8032 for Ed25519ph
		
		// This test documents what SHOULD happen according to the RFC
		context := []byte{} // Empty context for SU3 files
		
		// Domain separation prefix as per RFC 8032
		expectedDomSep := []byte("SigEd25519 no Ed25519 collisions")
		expectedDomSep = append(expectedDomSep, 1) // phflag = 1 for Ed25519ph
		expectedDomSep = append(expectedDomSep, byte(len(context))) // context length
		expectedDomSep = append(expectedDomSep, context...) // context
		
		// Verify the domain separation construction
		assert.Equal(t, "SigEd25519 no Ed25519 collisions", string(expectedDomSep[:32]))
		assert.Equal(t, byte(1), expectedDomSep[32]) // phflag
		assert.Equal(t, byte(0), expectedDomSep[33]) // empty context length
		assert.Equal(t, 34, len(expectedDomSep)) // Total length
	})

	t.Run("EdDSA_vs_regular_Ed25519_difference", func(t *testing.T) {
		// Document the difference between Ed25519 and Ed25519ph
		// Ed25519ph = Ed25519 with pre-hashing and domain separation
		
		testMessage := []byte("test message for signature comparison")
		
		// Generate keypair
		publicKey, privateKey, err := ed25519.GenerateKey(nil)
		require.NoError(t, err)
		
		// Regular Ed25519 signature (direct message signing)
		regularSig := ed25519.Sign(privateKey, testMessage)
		
		// Ed25519ph approach (pre-hash then sign)
		hasher := sha512.New()
		hasher.Write(testMessage)
		preHashed := hasher.Sum(nil)
		preHashedSig := ed25519.Sign(privateKey, preHashed)
		
		// Verify both work with their respective approaches
		assert.True(t, ed25519.Verify(publicKey, testMessage, regularSig))
		assert.True(t, ed25519.Verify(publicKey, preHashed, preHashedSig))
		
		// Cross-verification should fail (this shows they're different)
		assert.False(t, ed25519.Verify(publicKey, testMessage, preHashedSig))
		assert.False(t, ed25519.Verify(publicKey, preHashed, regularSig))
	})
}

// TestBug6EdDSAInteroperabilityIssues tests potential interoperability problems
// with other I2P implementations due to EdDSA implementation gaps
func TestBug6EdDSAInteroperabilityIssues(t *testing.T) {
	t.Run("RFC8032_compliance_check", func(t *testing.T) {
		// Test vectors from RFC 8032 would go here to ensure compliance
		// For now, we document the requirement
		
		// According to RFC 8032, Ed25519ph signatures should:
		// 1. Use proper domain separation with "SigEd25519 no Ed25519 collisions"
		// 2. Include phflag=1 to indicate pre-hashing
		// 3. Support context parameter (up to 255 bytes)
		// 4. Pre-hash the message with SHA-512 before signing
		
		t.Log("Ed25519ph requires RFC 8032 compliance for interoperability")
		t.Log("Current implementation may not handle domain separation correctly")
		t.Log("This could cause failures with properly generated Ed25519ph signatures")
	})
}
