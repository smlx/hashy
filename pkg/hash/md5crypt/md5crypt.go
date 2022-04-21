package md5crypt

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"regexp"

	"github.com/smlx/hashy/pkg/b64crypt"
	"github.com/smlx/hashy/pkg/hash"
)

const (
	// ID is the identification string for this hash function
	ID = "md5crypt"
	// prefix is the crypt standard identifier
	prefix = "$1$"
	// hashLen is the length of the output hash
	hashLen = 22
	// saltMaxLen is the maximum salt input length
	saltMaxLen = 8
	// keyMaxLen sets an arbitrary 32K limit to avoid DoS in a similar
	// manner to the musl implementation
	keyMaxLen = 1 << 15
	// minParseMatches is the minimum matches expected in successful parsing
	minParseMatches = 3
)

// parseRegex is used to parse the formatted hash into its component parts.
// This regex is taken from the libxcrypt manpage and extended with capture
// groups.
var parseRegex = regexp.MustCompile(
	`^\$1\$([^$:\n]{1,8})\$([./0-9A-Za-z]{22})$`)

// Function implements the hash.Function interface for the md5 function.
type Function struct{}

// Hash returns the hash of the given key. The cost argument is ignored, since
// md5crypt has no such parameter.
//
// Warning: The permutation logic in this function reflects the cryptographic
// era in which it was written.
func (*Function) Hash(key, salt []byte, cost uint) ([]byte, error) {
	// perform some safety checks
	if len(key) > keyMaxLen {
		return nil, fmt.Errorf("key longer than %d bytes: %w", keyMaxLen,
			hash.ErrKeyLen)
	}
	if len(salt) > saltMaxLen {
		return nil, fmt.Errorf("salt longer than %d bytes: %w", saltMaxLen,
			hash.ErrSaltLen)
	}
	// allocate variables
	var buf bytes.Buffer
	var sum [16]byte
	// construct the initial input to the hash function
	buf.Write(key)
	buf.Write(salt)
	buf.Write(key)
	// calculate the first checksum
	sum = md5.Sum(buf.Bytes())
	// construct the next stage of input to the hash function
	buf.Reset()
	buf.Write(key)
	buf.WriteString(prefix)
	buf.Write(salt)
	// add the first checksum to the input in a manner determined by the length
	// of the key
	for i := len(key); i > 0; i -= 16 {
		if i > 15 {
			buf.Write(sum[:])
		} else {
			buf.Write(sum[0:i])
		}
	}
	// add more input determined by the length of the key
	for i := len(key); i > 0; i >>= 1 {
		if i%2 != 0 {
			buf.WriteByte(0)
		} else {
			buf.WriteByte(key[0])
		}
	}
	// calculate the second checksum
	sum = md5.Sum(buf.Bytes())
	// repeatedly calculate the checksum of the function inputs and the most
	// recent checksum calculation itself in a deterministic manner
	for i := 0; i < 1000; i++ {
		// clear the buffer
		buf.Reset()
		// alternate adding the key or most recent intermediate checksum
		if i%2 != 0 {
			buf.Write(key)
		} else {
			buf.Write(sum[:])
		}
		// add the salt unless divisible by three
		if i%3 != 0 {
			buf.Write(salt)
		}
		// add the key unless divisible by seven
		if i%7 != 0 {
			buf.Write(key)
		}
		// alternate adding the key or most recent intermediate checksum, but
		// reverse the logic from the start of the loop
		if i%2 != 0 {
			buf.Write(sum[:])
		} else {
			buf.Write(key)
		}
		// recalculate the checksum
		sum = md5.Sum(buf.Bytes())
	}
	// clear the buffer for the result
	buf.Reset()
	// permute the last checksum again, and encode it in not-quite-base64
	buf.Write(b64crypt.EncodeBytes(sum[0], sum[6], sum[12]))
	buf.Write(b64crypt.EncodeBytes(sum[1], sum[7], sum[13]))
	buf.Write(b64crypt.EncodeBytes(sum[2], sum[8], sum[14]))
	buf.Write(b64crypt.EncodeBytes(sum[3], sum[9], sum[15]))
	buf.Write(b64crypt.EncodeBytes(sum[4], sum[10], sum[5]))
	buf.Write(b64crypt.EncodeBytes(0, 0, sum[11]))
	// return the result
	return buf.Bytes()[:hashLen], nil
}

// Check returns true if the given key matches the given hash, and false
// otherwise.
func (f *Function) Check(key, hash, salt []byte, cost uint) (bool, error) {
	calculatedHash, err := f.Hash(key, salt, cost)
	if err != nil {
		return false, err
	}
	return subtle.ConstantTimeCompare(hash, calculatedHash) == 1, nil
}

// Parse the given hash string in its common encoded form.
func (*Function) Parse(encodedHash string) ([]byte, []byte, uint, error) {
	matches := parseRegex.FindAllSubmatch([]byte(encodedHash), -1)
	if len(matches) < 1 || len(matches[0]) < minParseMatches {
		return nil, nil, 0, fmt.Errorf("couldn't parse %s format: %w", ID,
			hash.ErrParse)
	}
	return matches[0][2], matches[0][1], 0, nil
}

// Format the given parameters into the common "password hash" form.
func (*Function) Format(hash, salt []byte, cost uint) string {
	return fmt.Sprintf("%s%s$%s", prefix, salt, hash)
}

// HashPassword is a convenience method which takes a password string,
// generates a secure salt, and returns the hash of the password and salt in
// common "password hash" form.
//
// The cost parameter is ignored for md5crypt.
func (f *Function) HashPassword(password string, cost uint) (string, error) {
	// Generate salt by converting six bytes of random data into the b64crypt
	// format to produce 8 characters. This salt is not interpreted as encoded in
	// Hash(), but that's just the way md5crypt works.
	rawSalt := make([]byte, 6)
	_, err := rand.Read(rawSalt)
	if err != nil {
		return "", fmt.Errorf("couldn't generate random salt: %v", err)
	}
	var salt bytes.Buffer
	salt.Write(b64crypt.EncodeBytes(rawSalt[0], rawSalt[1], rawSalt[2]))
	salt.Write(b64crypt.EncodeBytes(rawSalt[3], rawSalt[4], rawSalt[5]))
	// convert password
	key := []byte(password)
	// calculate hash
	hash, err := f.Hash(key, salt.Bytes(), cost)
	if err != nil {
		return "", fmt.Errorf("couldn't generate password hash: %w", err)
	}
	// format hash
	return f.Format(hash, salt.Bytes(), cost), nil
}
