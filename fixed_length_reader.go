package su3

import (
	"io"
)

// fixedLengthReader is a wrapper around io.Reader that limits reading to a fixed number of bytes.
// Moved from: su3.go
type fixedLengthReader struct {
	length    uint64
	readSoFar uint64
	reader    io.Reader
}

// Read implements io.Reader interface for fixedLengthReader.
// It ensures that no more than the specified length of bytes can be read.
// Moved from: su3.go
func (r *fixedLengthReader) Read(p []byte) (n int, err error) {
	if r.readSoFar >= r.length {
		log.Debug("Fixed length reader: EOF reached")
		return 0, io.EOF
	}
	if uint64(len(p)) > r.length-r.readSoFar {
		p = p[:r.length-r.readSoFar]
	}
	n, err = r.reader.Read(p)
	r.readSoFar += uint64(n)
	log.WithField("bytes_read", n).
		WithField("total_read", r.readSoFar).
		WithField("total_length", r.length).
		Debug("Fixed length reader: Read operation")
	return n, err
}
