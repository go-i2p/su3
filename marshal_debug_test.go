package su3

import (
	"github.com/go-i2p/crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestMarshalBinaryDebug - Check what bytes are actually written during marshaling
func TestMarshalBinaryDebug(t *testing.T) {
	// Generate test RSA key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NoError(t, err)

	// Create SU3 file
	su3File := New()
	su3File.SetContent([]byte("test"))
	su3File.SetSignerID("debug@test.com")
	su3File.SetVersion("1.0")
	su3File.SetFileType(ZIP)
	su3File.SetContentType(RESEED)
	su3File.SetSignatureType(RSA_SHA256_2048)

	err = su3File.Sign(privateKey)
	assert.NoError(t, err)

	// Check header bytes for signing
	headerBytes := su3File.HeaderBytes()
	t.Logf("HeaderBytes version length at byte 13: 0x%02x (%d)", headerBytes[13], headerBytes[13])

	// Marshal and check what's actually written
	data, err := su3File.MarshalBinary()
	assert.NoError(t, err)

	t.Logf("MarshalBinary version length at byte 13: 0x%02x (%d)", data[13], data[13])
	t.Logf("First 20 bytes of marshaled data: %x", data[:20])

	// Check if HeaderBytes and MarshalBinary match for the header portion
	headerFromMarshal := data[:len(headerBytes)]
	t.Logf("Header bytes from HeaderBytes(): %x", headerBytes[:20])
	t.Logf("Header bytes from MarshalBinary: %x", headerFromMarshal[:20])
	t.Logf("Headers match: %v", string(headerBytes) == string(headerFromMarshal))
}
