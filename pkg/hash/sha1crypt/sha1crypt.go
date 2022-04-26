package sha1crypt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"fmt"
	"io"
	"regexp"
	"strconv"

	"github.com/smlx/hashy/pkg/b64crypt"
	"github.com/smlx/hashy/pkg/hash"
)

const (
	// ID is the identification string for this hash function
	ID = "sha1crypt"
	// prefix is the crypt standard identifier
	prefix = "$sha1$"
	// hashLen is the length of the output hash
	hashLen = 20
	// saltMaxLen is the maximum salt input length
	saltMaxLen = 64
	// keyMaxLen sets an arbitrary 32K limit to avoid DoS in a similar
	// manner to the musl implementation
	keyMaxLen = 1 << 15
	// minParseMatches is the minimum matches expected in successful parsing
	minParseMatches = 4
	// costMax is the maximum number of iterations used by this hash function.
	costMax = (1 << 32) - 1
	// costDefault is the (arbitrary) default number of iterations used by this
	// hash function.
	costDefault = 1 << 18
	// costMax is the minimum number of iterations used by this hash function.
	costMin = 1
)

// parseRegex is used to parse the formatted hash into its component parts.
// This regex is taken from the libxcrypt manpage, fixed (the manpage regex is
// wrong), and extended with capture groups.
var parseRegex = regexp.MustCompile(
	`^\$sha1\$([1-9][0-9]+)\$([./0-9A-Za-z]{1,64})\$([./0-9A-Za-z]{28})$`)

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
	if cost > costMax {
		return nil, fmt.Errorf("cost larger than %d: %w", costMax,
			hash.ErrCost)
	}
	if cost < costMin {
		return nil, fmt.Errorf("cost smaller than %d: %w", costMin,
			hash.ErrCost)
	}
	// prepare the HMAC
	h := hmac.New(sha1.New, key)
	// write the initial input to the hash function
	// h.Write never returns an error
	h.Write(salt)
	io.WriteString(h, prefix)
	io.WriteString(h, strconv.FormatUint(uint64(cost), 10))
	// run cost number of rounds
	sum := h.Sum(nil)
	for i := uint(1); i < cost; i++ {
		h = hmac.New(sha1.New, key)
		h.Write(sum)
		sum = h.Sum(nil)
	}
	var buf bytes.Buffer
	if len(sum) != hashLen {
		return nil, fmt.Errorf("unexpected checksum length: %w", hash.ErrInternal)
	}
	for i := 0; i < hashLen-3; i += 3 {
		buf.Write(b64crypt.EncodeBytes(sum[i], sum[i+1], sum[i+2]))
	}
	buf.Write(b64crypt.EncodeBytes(sum[hashLen-2], sum[hashLen-1], sum[0]))
	return buf.Bytes(), nil
}

// Parse the given hash string in its common encoded form.
func (*Function) Parse(encodedHash string) ([]byte, []byte, uint, error) {
	matches := parseRegex.FindAllSubmatch([]byte(encodedHash), -1)
	if len(matches) < 1 || len(matches[0]) < minParseMatches {
		return nil, nil, 0, fmt.Errorf("couldn't parse %s format: %w", ID,
			hash.ErrParse)
	}
	cost, err := strconv.ParseUint(string(matches[0][1]), 10, 64)
	if err != nil {
		return nil, nil, 0, fmt.Errorf("couldn't parse %s cost: %w", ID,
			hash.ErrParse)
	}
	return matches[0][3], matches[0][2], uint(cost), nil
}

// Format the given parameters into the common "password hash" form.
func (*Function) Format(hash, salt []byte, cost uint) string {
	return fmt.Sprintf("%s%d$%s$%s", prefix, cost, salt, hash)
}

// ID returns the unique identification string of this hash function.
func (*Function) ID() string {
	return ID
}

// DefaultCost returns the maximum cost value for the hash function.
func (*Function) DefaultCost() uint {
	return costDefault
}

// GenerateSalt returns a cryptographically secure salt value which is the
// maximum size for this funciton.
func (*Function) GenerateSalt() ([]byte, error) {
	return b64crypt.GenerateSalt(saltMaxLen)
}