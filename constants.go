package su3

import "github.com/samber/oops"

// magicBytes represents the SU3 file format magic bytes.
// Moved from: su3.go
const magicBytes = "I2Psu3"

// SignatureType constants define supported signature algorithms.
// Moved from: su3.go
const (
	DSA_SHA1               SignatureType = "DSA-SHA1"
	ECDSA_SHA256_P256      SignatureType = "ECDSA-SHA256-P256"
	ECDSA_SHA384_P384      SignatureType = "ECDSA-SHA384-P384"
	ECDSA_SHA512_P521      SignatureType = "ECDSA-SHA512-P521"
	RSA_SHA256_2048        SignatureType = "RSA-SHA256-2048"
	RSA_SHA384_3072        SignatureType = "RSA-SHA384-3072"
	RSA_SHA512_4096        SignatureType = "RSA-SHA512-4096"
	EdDSA_SHA512_Ed25519ph SignatureType = "EdDSA-SHA512-Ed25519ph"
)

// FileType constants define supported file types.
// Moved from: su3.go
const (
	ZIP      FileType = "zip"
	XML      FileType = "xml"
	HTML     FileType = "html"
	XML_GZIP FileType = "xml.gz"
	TXT_GZIP FileType = "txt.gz"
	DMG      FileType = "dmg"
	EXE      FileType = "exe"
)

// ContentType constants define supported content types.
// Moved from: su3.go
const (
	UNKNOWN       ContentType = "unknown"
	ROUTER_UPDATE ContentType = "router_update"
	PLUGIN        ContentType = "plugin"
	RESEED        ContentType = "reseed"
	NEWS          ContentType = "news"
	BLOCKLIST     ContentType = "blocklist"
)

// Error variables define all possible errors that can occur during SU3 processing.
// Moved from: su3.go
var (
	ErrMissingMagicBytes        = oops.Errorf("missing magic bytes")
	ErrMissingUnusedByte6       = oops.Errorf("missing unused byte 6")
	ErrMissingFileFormatVersion = oops.Errorf("missing or incorrect file format version")
	ErrMissingSignatureType     = oops.Errorf("missing or invalid signature type")
	ErrUnsupportedSignatureType = oops.Errorf("unsupported signature type")
	ErrMissingSignatureLength   = oops.Errorf("missing signature length")
	ErrMissingUnusedByte12      = oops.Errorf("missing unused byte 12")
	ErrMissingVersionLength     = oops.Errorf("missing version length")
	ErrVersionTooShort          = oops.Errorf("version length too short")
	ErrMissingUnusedByte14      = oops.Errorf("missing unused byte 14")
	ErrMissingSignerIDLength    = oops.Errorf("missing signer ID length")
	ErrMissingContentLength     = oops.Errorf("missing content length")
	ErrMissingUnusedByte24      = oops.Errorf("missing unused byte 24")
	ErrMissingFileType          = oops.Errorf("missing or invalid file type")
	ErrMissingUnusedByte26      = oops.Errorf("missing unused byte 26")
	ErrMissingContentType       = oops.Errorf("missing or invalid content type")
	ErrMissingUnusedBytes28To39 = oops.Errorf("missing unused bytes 28-39")
	ErrMissingVersion           = oops.Errorf("missing version")
	ErrMissingSignerID          = oops.Errorf("missing signer ID")
	ErrMissingContent           = oops.Errorf("missing content")
	ErrMissingSignature         = oops.Errorf("missing signature")
	ErrInvalidPublicKey         = oops.Errorf("invalid public key")
	ErrInvalidSignature         = oops.Errorf("invalid signature")
)

// Mapping tables for converting bytes to enumerated types.
// Moved from: su3.go
var sigTypes = map[[2]byte]SignatureType{
	{0x00, 0x00}: DSA_SHA1,
	{0x00, 0x01}: ECDSA_SHA256_P256,
	{0x00, 0x02}: ECDSA_SHA384_P384,
	{0x00, 0x03}: ECDSA_SHA512_P521,
	{0x00, 0x04}: RSA_SHA256_2048,
	{0x00, 0x05}: RSA_SHA384_3072,
	{0x00, 0x06}: RSA_SHA512_4096,
	{0x00, 0x08}: EdDSA_SHA512_Ed25519ph,
}

var fileTypes = map[byte]FileType{
	0x00: ZIP,
	0x01: XML,
	0x02: HTML,
	0x03: XML_GZIP,
	0x04: TXT_GZIP,
	0x05: DMG,
	0x06: EXE,
}

var contentTypes = map[byte]ContentType{
	0x00: UNKNOWN,
	0x01: ROUTER_UPDATE,
	0x02: PLUGIN,
	0x03: RESEED,
	0x04: NEWS,
	0x05: BLOCKLIST,
}
