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

// TestNewSigningCertificate tests certificate generation functionality
func TestNewSigningCertificate(t *testing.T) {
	tests := []struct {
		name        string
		signerID    string
		keySize     int
		expectError bool
	}{
		{
			name:        "Valid certificate with email signer ID",
			signerID:    "test@example.com",
			keySize:     2048,
			expectError: false,
		},
		{
			name:        "Valid certificate with I2P domain",
			signerID:    "test@mail.i2p",
			keySize:     2048,
			expectError: false,
		},
		{
			name:        "Valid certificate with empty signer ID",
			signerID:    "",
			keySize:     2048,
			expectError: false,
		},
		{
			name:        "Valid certificate with 4096-bit key",
			signerID:    "test@example.com",
			keySize:     4096,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate test RSA key
			privateKey, err := rsa.GenerateKey(rand.Reader, tt.keySize)
			assert.NoError(t, err)

			// Test certificate creation
			certDER, err := NewSigningCertificate(tt.signerID, privateKey)
			if tt.expectError {
				assert.Error(t, err)
				return
			}

			assert.NoError(t, err)
			assert.NotEmpty(t, certDER)

			// Parse the certificate to verify it's valid
			cert, err := x509.ParseCertificate(certDER)
			assert.NoError(t, err)

			// Verify certificate properties
			assert.Equal(t, tt.signerID, cert.Subject.CommonName)
			assert.True(t, cert.BasicConstraintsValid)

			if tt.signerID != "" {
				assert.True(t, cert.IsCA)
				assert.Equal(t, []byte(tt.signerID), cert.SubjectKeyId)
			} else {
				assert.False(t, cert.IsCA)
				assert.Empty(t, cert.SubjectKeyId)
			}

			// Verify organization details
			expectedOrg := []string{"I2P Anonymous Network"}
			assert.Equal(t, expectedOrg, cert.Subject.Organization)

			expectedOU := []string{"I2P"}
			assert.Equal(t, expectedOU, cert.Subject.OrganizationalUnit)

			// Verify key usage
			expectedKeyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign
			assert.Equal(t, expectedKeyUsage, cert.KeyUsage)

			// Verify the public key matches
			certPubKey, ok := cert.PublicKey.(*rsa.PublicKey)
			assert.True(t, ok)
			assert.Equal(t, privateKey.PublicKey.N, certPubKey.N)
			assert.Equal(t, privateKey.PublicKey.E, certPubKey.E)
		})
	}
}

func TestNewSigningCertificate_NilPrivateKey(t *testing.T) {
	_, err := NewSigningCertificate("test@example.com", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "private key cannot be nil")
}

// TestNew tests the SU3 constructor
func TestNew(t *testing.T) {
	su3File := New()

	assert.NotNil(t, su3File)
	assert.Equal(t, RSA_SHA512_4096, su3File.SignatureType)
	assert.Equal(t, ZIP, su3File.FileType)
	assert.Equal(t, UNKNOWN, su3File.ContentType)
	assert.NotEmpty(t, su3File.Version)

	// Version should be a Unix timestamp string
	assert.GreaterOrEqual(t, len(su3File.Version), 10)
}

// TestSU3Creation tests the complete SU3 creation workflow
func TestSU3Creation(t *testing.T) {
	// Generate test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// Create new SU3 file
	su3File := New()

	// Set properties
	testContent := []byte("This is test content for SU3 creation")
	su3File.SetContent(testContent)
	su3File.SetSignerID("test@example.com")
	su3File.SetVersion("1.0.0")
	su3File.SetFileType(ZIP)
	su3File.SetContentType(RESEED)
	su3File.SetSignatureType(RSA_SHA256_2048) // Use 2048-bit for our 2048-bit key

	// Verify properties were set
	assert.Equal(t, "test@example.com", su3File.SignerID)
	assert.Equal(t, "1.0.0", su3File.Version)
	assert.Equal(t, ZIP, su3File.FileType)
	assert.Equal(t, RESEED, su3File.ContentType)
	assert.Equal(t, RSA_SHA256_2048, su3File.SignatureType)
	assert.Equal(t, uint64(len(testContent)), su3File.ContentLength)

	// Sign the file
	err = su3File.Sign(privateKey)
	assert.NoError(t, err)
	assert.NotEmpty(t, su3File.signature)
	assert.Equal(t, uint16(256), su3File.SignatureLength) // 2048-bit RSA = 256 bytes

	// Marshal to binary
	data, err := su3File.MarshalBinary()
	assert.NoError(t, err)
	assert.NotEmpty(t, data)

	// Should start with magic bytes
	assert.True(t, bytes.HasPrefix(data, []byte(magicBytes)))

	// Should end with signature
	expectedSigStart := len(data) - len(su3File.signature)
	assert.Equal(t, su3File.signature, data[expectedSigStart:])
}

// TestSU3RoundTrip tests creating, marshaling, and then reading back an SU3 file
func TestSU3RoundTrip(t *testing.T) {
	// Generate test RSA key and certificate
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	certDER, err := NewSigningCertificate("roundtrip@example.com", privateKey)
	assert.NoError(t, err)

	cert, err := x509.ParseCertificate(certDER)
	assert.NoError(t, err)

	// Create and setup original SU3 file
	originalFile := New()
	testContent := []byte("This is test content for round-trip testing with more data")
	originalFile.SetContent(testContent)
	originalFile.SetSignerID("roundtrip@example.com")
	originalFile.SetVersion("2.1.0")
	originalFile.SetFileType(ZIP)
	originalFile.SetContentType(RESEED)
	originalFile.SetSignatureType(RSA_SHA256_2048) // Use 2048-bit for our 2048-bit key

	// Sign the file
	err = originalFile.Sign(privateKey)
	assert.NoError(t, err)

	// Marshal to binary
	data, err := originalFile.MarshalBinary()
	assert.NoError(t, err)

	// Parse the binary data back using existing Read function
	reader := bytes.NewReader(data)
	parsedFile, err := Read(reader)
	assert.NoError(t, err)

	// Verify metadata matches
	assert.Equal(t, originalFile.SignatureType, parsedFile.SignatureType)
	assert.Equal(t, originalFile.FileType, parsedFile.FileType)
	assert.Equal(t, originalFile.ContentType, parsedFile.ContentType)
	assert.Equal(t, originalFile.Version, parsedFile.Version)
	assert.Equal(t, originalFile.SignerID, parsedFile.SignerID)
	assert.Equal(t, originalFile.ContentLength, parsedFile.ContentLength)
	assert.Equal(t, originalFile.SignatureLength, parsedFile.SignatureLength)

	// Read and verify content with signature verification
	contentReader := parsedFile.Content(cert.PublicKey)
	actualContent, err := io.ReadAll(contentReader)
	assert.NoError(t, err) // Signature should be valid
	assert.Equal(t, testContent, actualContent)
}

func TestSU3Sign_InvalidInputs(t *testing.T) {
	su3File := New()
	su3File.SetContent([]byte("test content"))

	tests := []struct {
		name        string
		privateKey  *rsa.PrivateKey
		sigType     SignatureType
		expectError bool
		errorText   string
	}{
		{
			name:        "Nil private key",
			privateKey:  nil,
			sigType:     RSA_SHA512_4096,
			expectError: true,
			errorText:   "private key cannot be nil",
		},
		{
			name:        "Unknown signature type",
			sigType:     SignatureType("UNKNOWN_SIG_TYPE"),
			expectError: true,
			errorText:   "unknown signature type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testFile := New()
			testFile.SetContent([]byte("test content"))
			testFile.SetSignatureType(tt.sigType)

			var privateKey *rsa.PrivateKey
			if tt.name != "Nil private key" {
				var err error
				privateKey, err = rsa.GenerateKey(rand.Reader, 2048)
				assert.NoError(t, err)
			}

			err := testFile.Sign(privateKey)
			if tt.expectError {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.errorText)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestSU3MarshalBinary_WithoutSignature(t *testing.T) {
	su3File := New()
	su3File.SetContent([]byte("test content"))

	// Try to marshal without signing
	_, err := su3File.MarshalBinary()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "signature is required")
}

func TestSU3BodyBytes(t *testing.T) {
	su3File := New()
	su3File.SetContent([]byte("test content"))
	su3File.SetSignerID("test@example.com")
	su3File.SetVersion("1.0.0")
	su3File.SetFileType(ZIP)
	su3File.SetContentType(RESEED)
	su3File.SetSignatureType(RSA_SHA512_4096)

	// Set a temporary signature length for BodyBytes calculation
	su3File.SignatureLength = 256

	bodyBytes := su3File.BodyBytes()
	assert.NotEmpty(t, bodyBytes)

	// Should start with magic bytes
	assert.True(t, bytes.HasPrefix(bodyBytes, []byte(magicBytes)))

	// Should not include signature (that's added in MarshalBinary)
	// The body should end with the content, not the signature
	contentStart := len(bodyBytes) - len(su3File.content)
	assert.Equal(t, su3File.content, bodyBytes[contentStart:])
}

func TestSU3VersionPadding(t *testing.T) {
	su3File := New()
	su3File.SetVersion("123")     // Shorter than minimum length
	su3File.SignatureLength = 256 // Set for BodyBytes calculation

	bodyBytes := su3File.BodyBytes()
	assert.NotEmpty(t, bodyBytes)

	// Version should be padded to at least 16 bytes
	// We can't easily extract and check the version field from the binary,
	// but we can ensure no error occurs and the body is generated
	assert.Greater(t, len(bodyBytes), 40) // Should be longer than just the header
}

func TestSU3SetterMethods(t *testing.T) {
	su3File := New()

	// Test all setter methods
	su3File.SetContent([]byte("test content data"))
	su3File.SetSignerID("setter@example.com")
	su3File.SetVersion("3.2.1")
	su3File.SetFileType(XML)
	su3File.SetContentType(PLUGIN)
	su3File.SetSignatureType(RSA_SHA256_2048)

	// Verify all values are set correctly
	assert.Equal(t, uint64(17), su3File.ContentLength) // len("test content data")
	assert.Equal(t, "setter@example.com", su3File.SignerID)
	assert.Equal(t, "3.2.1", su3File.Version)
	assert.Equal(t, XML, su3File.FileType)
	assert.Equal(t, PLUGIN, su3File.ContentType)
	assert.Equal(t, RSA_SHA256_2048, su3File.SignatureType)
}

// TestSU3CompatibilityWithReseedTools tests compatibility with the reseed-tools format
func TestSU3CompatibilityWithReseedTools(t *testing.T) {
	// Generate test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// Create SU3 file similar to how reseed-tools would create it
	su3File := New()
	su3File.SetContent([]byte("Reseed data content for compatibility testing"))
	su3File.SetSignerID("reseed@example.com")
	su3File.SetFileType(ZIP)
	su3File.SetContentType(RESEED)
	su3File.SetSignatureType(RSA_SHA512_4096)

	// Sign and marshal
	err = su3File.Sign(privateKey)
	assert.NoError(t, err)

	data, err := su3File.MarshalBinary()
	assert.NoError(t, err)

	// Parse back using our reader
	reader := bytes.NewReader(data)
	parsedFile, err := Read(reader)
	assert.NoError(t, err)

	// Verify key fields match
	assert.Equal(t, RESEED, parsedFile.ContentType)
	assert.Equal(t, ZIP, parsedFile.FileType)
	assert.Equal(t, RSA_SHA512_4096, parsedFile.SignatureType)
	assert.Equal(t, "reseed@example.com", parsedFile.SignerID)
}
