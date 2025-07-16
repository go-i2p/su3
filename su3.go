// Package su3 implements reading the SU3 file format.
//
// SU3 files provide content that is signed by a known identity.
// They are used to distribute many types of data, including reseed files,
// plugins, blocklists, and more.
//
// See: https://geti2p.net/spec/updates#su3-file-specification
//
// The Read() function takes an io.Reader, and it returns a *SU3. The *SU3 contains
// the SU3 file metadata, such as the type of the content and the signer ID.
// In order to get the file contents, one must pass in the public key associated
// with the file's signer, so that the signature can be validated. The content
// can still be read without passing in the key, but after returning the full
// content the error ErrInvalidSignature will be returned.
//
// Example usage:
//
//	    // Let's say we are reading an SU3 file from an HTTP body, which is an io.Reader.
//	    su3File, err := su3.Read(body)
//	    if err != nil {
//	        // Handle error.
//	    }
//	    // Look up this signer's key.
//	    key := somehow_lookup_the_key(su3File.SignerID)
//	    // Read the content.
//	    contentReader := su3File.Content(key)
//	    bytes, err := ioutil.ReadAll(contentReader)
//	    if errors.Is(err, su3.ErrInvalidSignature) {
//		       // The signature is invalid, OR a nil key was provided.
//	    } else if err != nil {
//	        // Handle error.
//	    }
//
// If you want to parse from a []byte, you can wrap it like this:
//
//	mySU3FileBytes := []byte{0x00, 0x01, 0x02, 0x03}
//	su3File, err := su3.Read(bytes.NewReader(mySU3FileBytes))
//
// One of the advantages of this library's design is that you can avoid buffering
// the file contents in memory. Here's how you would stream from an HTTP body
// directly to disk:
//
//	    su3File, err := su3.Read(body)
//	    if err != nil {
//		       // Handle error.
//	    }
//	    // Look up this signer's key.
//	    key := somehow_lookup_the_key(su3File.SignerID)
//	    // Stream directly to disk.
//	    f, err := os.Create("my_file.txt")
//	    if err != nil {
//		       // Handle error.
//	    }
//	    _, err := io.Copy(f, su3File.Content(key))
//	    if errors.Is(err, su3.ErrInvalidSignature) {
//		       // The signature is invalid, OR a nil key was provided.
//	        // Don't trust the file, delete it!
//	    } else if err != nil {
//	        // Handle error.
//	    }
//
// Note: if you want to read the content, the Content() io.Reader must be read
// *before* the Signature() io.Reader. If you read the signature first, the
// content bytes will be thrown away. If you then attempt to read the content,
// you will get an error. For clarification, see TestReadSignatureFirst.
package su3

import "github.com/go-i2p/logger"

var log = logger.GetGoI2PLogger()
