// Package b64crypt implements an encoding similar to RFC4648 Base64, but with
// a slightly different character set. This encoding is used by Unix crypt() to
// encode password hashes.
package b64crypt

import "bytes"

// charset is the character set of the not-quite-base64 encoding
const charset = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
	"abcdefghijklmnopqrstuvwxyz"

// EncodeBytes encodes a given three bytes to a set of four characters.
func EncodeBytes(a, b, c uint8) []byte {
	// calculate the numeric value
	n := (uint(a) << 16) + (uint(b) << 8) + uint(c)
	// encode a character for each 6 bits
	var buf bytes.Buffer
	for i := 0; i < 4; i++ {
		buf.WriteByte(charset[n%64])
		n >>= 6
	}
	return buf.Bytes()
}
