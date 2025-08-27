package su3

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestBug5ReadOrderDocumentationBehavior validates that the documented behavior
// for read order restrictions matches the actual implementation.
// This test verifies Bug #5: Read Order Documentation vs Implementation Behavior
func TestBug5ReadOrderDocumentationBehavior(t *testing.T) {
	// Use a real SU3 file from testdata
	data, err := os.ReadFile("testdata/reseed-i2pgit.su3")
	require.NoError(t, err)

	t.Run("Signature_first_discards_content", func(t *testing.T) {
		// Parse the SU3 file
		reader := bytes.NewReader(data)
		parsedSU3, err := Read(reader)
		require.NoError(t, err)

		// First read signature (this should consume content according to docs)
		signatureReader := parsedSU3.Signature()
		signatureData, err := io.ReadAll(signatureReader)
		require.NoError(t, err)
		assert.Greater(t, len(signatureData), 0, "Signature should contain data")

		// Now try to read content - should be empty according to documentation
		contentReader := parsedSU3.Content(nil) // nil key for this test
		contentData, err := io.ReadAll(contentReader)

		// Content should be empty because signature reader consumed it
		// But the error should indicate this specific problem
		assert.Empty(t, contentData, "Content should be empty after reading signature first")
		if err != nil {
			// The error message suggests this scenario was detected
			assert.Contains(t, err.Error(), "maybe you read the signature before you read the content")
		}
	})

	t.Run("Content_first_then_signature_works", func(t *testing.T) {
		// Parse the SU3 file again
		reader := bytes.NewReader(data)
		parsedSU3, err := Read(reader)
		require.NoError(t, err)

		// First read content (correct order according to documentation)
		contentReader := parsedSU3.Content(nil) // nil key for this test
		contentData, err := io.ReadAll(contentReader)
		require.Error(t, err) // Should error due to nil key
		assert.Contains(t, err.Error(), "invalid signature", "Should get signature error with nil key")
		assert.Greater(t, len(contentData), 0, "Content should be readable despite signature error")

		// Now read signature - should work fine
		signatureReader := parsedSU3.Signature()
		signatureData, err := io.ReadAll(signatureReader)
		require.NoError(t, err)
		assert.Greater(t, len(signatureData), 0, "Signature should contain data")
	})

	t.Run("Signature_only_access_works", func(t *testing.T) {
		// Parse the SU3 file again
		reader := bytes.NewReader(data)
		parsedSU3, err := Read(reader)
		require.NoError(t, err)

		// Read only signature (documented as safe pattern)
		signatureReader := parsedSU3.Signature()
		signatureData, err := io.ReadAll(signatureReader)
		require.NoError(t, err)
		assert.Greater(t, len(signatureData), 0, "Signature should contain data")

		// Don't read content at all - this is the "signature-only" pattern
		// mentioned in the documentation
	})

	t.Run("Signature_reader_has_state", func(t *testing.T) {
		// Parse the SU3 file again
		reader := bytes.NewReader(data)
		parsedSU3, err := Read(reader)
		require.NoError(t, err)

		// Get the signature reader
		signatureReader := parsedSU3.Signature()

		// Read signature first time
		signatureData1, err := io.ReadAll(signatureReader)
		require.NoError(t, err)
		assert.Greater(t, len(signatureData1), 0, "Signature should contain data")

		// Try to read signature second time from the same reader - should be empty
		// because readers have state and are exhausted after reading
		signatureData2, err := io.ReadAll(signatureReader)
		require.NoError(t, err) // No error, but...
		assert.Empty(t, signatureData2, "Second read from same reader should be empty (readers have state)")

		// This demonstrates that signature readers have state like any io.Reader
		// If you need multiple reads, you need to get the reader fresh each time
		// OR copy the data when you first read it
	})
}

// TestBug5WorkaroundPatterns validates the workaround patterns mentioned in the documentation
func TestBug5WorkaroundPatterns(t *testing.T) {
	// Use a real SU3 file from testdata
	data, err := os.ReadFile("testdata/reseed-i2pgit.su3")
	require.NoError(t, err)

	t.Run("Buffering_workaround_for_signature_first", func(t *testing.T) {
		// This demonstrates the buffering workaround mentioned in the documentation

		// First, read the entire SU3 data into a buffer (as suggested in docs)
		originalReader := bytes.NewReader(data)
		bufferedData, err := io.ReadAll(originalReader)
		require.NoError(t, err)

		// Now we can parse multiple times from the buffer
		// First parse: read signature first
		reader1 := bytes.NewReader(bufferedData)
		parsedSU3_1, err := Read(reader1)
		require.NoError(t, err)

		signatureReader := parsedSU3_1.Signature()
		signatureData, err := io.ReadAll(signatureReader)
		require.NoError(t, err)
		assert.Greater(t, len(signatureData), 0)

		// Second parse: read content first
		reader2 := bytes.NewReader(bufferedData)
		parsedSU3_2, err := Read(reader2)
		require.NoError(t, err)

		contentReader := parsedSU3_2.Content(nil)
		contentData, err := io.ReadAll(contentReader)
		require.Error(t, err) // Expected due to nil key
		assert.Contains(t, err.Error(), "invalid signature")
		assert.Greater(t, len(contentData), 0, "Content should be accessible when read first")
	})
}
