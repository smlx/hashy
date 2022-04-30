package sha256crypt

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"hash"
	"regexp"
	"strconv"

	"github.com/smlx/hashy/pkg/b64crypt"
	"github.com/smlx/hashy/pkg/pwhash"
)

const (
	// ID is the identification string for this hash function
	ID = "sha256crypt"
	// prefix is the crypt standard identifier
	prefix = "$5$"
	// hashLen is the length of the encoded output hash
	hashLen = 43
	// saltMaxLen is the maximum salt input length as per libxcrypt
	saltMaxLen = 16
	// keyMaxLen sets an arbitrary 32K limit to avoid DoS in a similar
	// manner to the musl implementation
	keyMaxLen = 1 << 15
	// costMax is the maximum number of iterations used by this hash function.
	costMax = 999999999
	// costDefault is the default number of iterations used by this hash
	// function, as per libxcrypt
	costDefault = 5000
	// costMax is the minimum number of iterations used by this hash function.
	costMin = 1000
)

// parseRegex is used to parse the formatted hash into its component parts.
// This regex is taken from the libxcrypt manpage, fixed (the manpage regex is
// wrong), and extended with capture groups.
var parseRegex = regexp.MustCompile(
	`^\$5\$(?:rounds=(?P<cost>[1-9][0-9]+)\$)?(?P<salt>[^$:\n]{1,16})\$` +
		`(?P<hash>[./0-9A-Za-z]{43})$`)

// Function implements the hash.Function interface for the md5 function.
type Function struct{}

// recycle repeatedly writes b to h.
func recycle(h hash.Hash, b []byte, keylen int) {
	var n int
	for n = keylen; n >= 32; n -= 32 {
		h.Write(b[:32])
	}
	h.Write(b[:n])
}

// Hash returns the hash of the given key. The cost argument is ignored, since
// md5crypt has no such parameter.
//
// Warning: The permutation logic in this function reflects the cryptographic
// era in which it was written.
func (*Function) Hash(key, salt []byte, cost uint) ([]byte, error) {
	// perform some safety checks
	if len(key) > keyMaxLen {
		return nil, fmt.Errorf("key longer than %d bytes: %w", keyMaxLen,
			pwhash.ErrKeyLen)
	}
	if len(salt) > saltMaxLen {
		return nil, fmt.Errorf("salt longer than %d bytes: %w", saltMaxLen,
			pwhash.ErrSaltLen)
	}
	if cost > costMax {
		return nil, fmt.Errorf("cost larger than %d: %w", uint64(costMax),
			pwhash.ErrCost)
	}
	if cost < costMin {
		return nil, fmt.Errorf("cost smaller than %d: %w", costMin,
			pwhash.ErrCost)
	}
	var h hash.Hash
	var sum []byte
	// init the hash function
	h = sha256.New()
	// write the initial input to the hash function
	// h.Write never returns an error
	h.Write(key)
	h.Write(salt)
	h.Write(key)
	sum = h.Sum(nil)
	// reset for next stage
	h = sha256.New()
	h.Write(key)
	h.Write(salt)
	// repeatedly write the first 32 bytes of the initial sum depending on the
	// length fo the key
	var n int
	for n = len(key); n > 32; n -= 32 {
		h.Write(sum[:32])
	}
	h.Write(sum[:n])
	// alternate writing the initial sum or the key depending on the bit pattern
	// of the length of the key
	for n = len(key); n > 0; n >>= 1 {
		if n%2 != 0 {
			h.Write(sum[:32])
		} else {
			h.Write(key)
		}
	}
	// store intermediate sum again
	sum = h.Sum(sum[:0])
	// re-init the hash function
	h = sha256.New()
	// repeatedly write the key to the hash function depending on the key length
	for n = 0; n < len(key); n++ {
		h.Write(key)
	}
	// store the P bytes
	pbuf := h.Sum(nil)
	// re-init the hash function
	h = sha256.New()
	for n = 0; n < int(16+sum[0]); n++ {
		h.Write(salt)
	}
	// store the S bytes
	sbuf := h.Sum(nil)
	// run the rounds
	for n = 0; n < int(cost); n++ {
		h = sha256.New()
		// alternate writing P bytes or most recent intermediate checksum
		if n%2 != 0 {
			recycle(h, pbuf, len(key))
		} else {
			h.Write(sum[:32])
		}
		// write S bytes unless divisible by 3
		if n%3 != 0 {
			recycle(h, sbuf, len(salt))
		}
		// write P bytes unless divisible by 7
		if n%7 != 0 {
			recycle(h, pbuf, len(key))
		}
		// alternate writing P bytes or most recent intermediate checksum
		if n%2 != 0 {
			h.Write(sum[:32])
		} else {
			recycle(h, pbuf, len(key))
		}
		sum = h.Sum(sum[:0])
	}
	// encode the output
	var buf bytes.Buffer
	buf.Write(b64crypt.EncodeBytes(sum[0], sum[10], sum[20]))
	buf.Write(b64crypt.EncodeBytes(sum[21], sum[1], sum[11]))
	buf.Write(b64crypt.EncodeBytes(sum[12], sum[22], sum[2]))
	buf.Write(b64crypt.EncodeBytes(sum[3], sum[13], sum[23]))
	buf.Write(b64crypt.EncodeBytes(sum[24], sum[4], sum[14]))
	buf.Write(b64crypt.EncodeBytes(sum[15], sum[25], sum[5]))
	buf.Write(b64crypt.EncodeBytes(sum[6], sum[16], sum[26]))
	buf.Write(b64crypt.EncodeBytes(sum[27], sum[7], sum[17]))
	buf.Write(b64crypt.EncodeBytes(sum[18], sum[28], sum[8]))
	buf.Write(b64crypt.EncodeBytes(sum[9], sum[19], sum[29]))
	buf.Write(b64crypt.EncodeBytes(0, sum[31], sum[30]))
	// snip the trailing suffix
	return buf.Bytes()[:hashLen], nil
}

// Parse the given hash string in its common encoded form.
func (*Function) Parse(encodedHash []byte) ([]byte, []byte, uint, error) {
	matches := parseRegex.FindSubmatch(encodedHash)
	if len(matches) < 2 {
		return nil, nil, 0, fmt.Errorf("couldn't parse %s format: %w", ID,
			pwhash.ErrParse)
	}
	salt := matches[parseRegex.SubexpIndex("salt")]
	hash := matches[parseRegex.SubexpIndex("hash")]
	if len(salt) == 0 || len(hash) == 0 {
		return nil, nil, 0, fmt.Errorf("couldn't parse %s format: %w", ID,
			pwhash.ErrParse)
	}
	rawCost := matches[parseRegex.SubexpIndex("cost")]
	cost := uint64(costDefault)
	var err error
	// cost (rounds) is an optional param
	if len(rawCost) > 0 {
		cost, err = strconv.ParseUint(string(rawCost), 10, 64)
		if err != nil {
			return nil, nil, 0, fmt.Errorf("couldn't parse %s cost: %w", ID,
				pwhash.ErrParse)
		}
	}
	return hash, salt, uint(cost), nil
}

// Format the given parameters into the common "password hash" form.
func (*Function) Format(hash, salt []byte, cost uint) string {
	return fmt.Sprintf("%srounds=%d$%s$%s", prefix, cost, salt, hash)
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
