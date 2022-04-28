// Package b64crypt implements an encoding similar to RFC4648 Base64, but with
// a slightly different character set. This encoding is used by Unix crypt() to
// encode password hashes.
package b64crypt

import (
	"bytes"
	"crypto/rand"
	"fmt"
)

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

// GenerateSalt returns a cryptographically secure random string of length n
// encoded by EncodeBytes(). n must be divisible by 4 since this is the number
// of bytes returned by each call to EncodeBytes(). The number of random bytes
// encoded in the return string is only 3/4 of the requested length due to the
// encoding.
func GenerateSalt(n uint) ([]byte, error) {
	if n%4 != 0 {
		return nil, fmt.Errorf("%d is not divisible by 4", n)
	}
	randBytesLen := n * 3 / 4
	rawSalt := make([]byte, randBytesLen)
	_, err := rand.Read(rawSalt)
	if err != nil {
		return nil, fmt.Errorf("couldn't generate random salt: %v", err)
	}
	var salt bytes.Buffer
	for i := uint(0); i < randBytesLen; i += 3 {
		salt.Write(EncodeBytes(rawSalt[i], rawSalt[i+1], rawSalt[i+2]))
	}
	return salt.Bytes(), nil
}
