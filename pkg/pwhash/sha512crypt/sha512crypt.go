package sha512crypt

import (
	"bytes"
	"crypto/sha512"
	"fmt"
	"hash"
	"regexp"
	"strconv"

	"github.com/smlx/hashy/pkg/b64crypt"
	"github.com/smlx/hashy/pkg/pwhash"
)

const (
	// ID is the identification string for this hash function
	ID = "sha512crypt"
	// prefix is the crypt standard identifier
	prefix = "$6$"
	// saltMaxLen is the maximum salt input length as per libxcrypt
	saltMaxLen = 16
	// keyMaxLen sets an arbitrary 32K limit to avoid DoS
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
	`^\$6\$(?:rounds=(?P<cost>[1-9][0-9]+)\$)?(?P<salt>[^$:\n]{1,16})\$` +
		`(?P<hash>[./0-9A-Za-z]{86})$`)

// Function implements the hash.Function interface for the md5 function.
type Function struct{}

// recycle repeatedly writes b to h.
func recycle(h hash.Hash, b []byte, keylen int) {
	var n int
	for n = keylen; n >= 64; n -= 64 {
		h.Write(b[:64])
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
	h = sha512.New()
	// write the initial input to the hash function
	// h.Write never returns an error
	h.Write(key)
	h.Write(salt)
	h.Write(key)
	sum = h.Sum(nil)
	// reset for next stage
	h = sha512.New()
	h.Write(key)
	h.Write(salt)
	// repeatedly write the first 64 bytes of the initial sum depending on the
	// length fo the key
	var n int
	for n = len(key); n > 64; n -= 64 {
		h.Write(sum[:64])
	}
	h.Write(sum[:n])
	// alternate writing the initial sum or the key depending on the bit pattern
	// of the length of the key
	for n = len(key); n > 0; n >>= 1 {
		if n%2 != 0 {
			h.Write(sum[:64])
		} else {
			h.Write(key)
		}
	}
	// store intermediate sum again
	sum = h.Sum(sum[:0])
	// re-init the hash function
	h = sha512.New()
	// repeatedly write the key to the hash function depending on the key length
	for n = 0; n < len(key); n++ {
		h.Write(key)
	}
	// store the P bytes
	pbuf := h.Sum(nil)
	// re-init the hash function
	h = sha512.New()
	for n = 0; n < int(16+sum[0]); n++ {
		h.Write(salt)
	}
	// store the S bytes
	sbuf := h.Sum(nil)
	// run the rounds
	for n = 0; n < int(cost); n++ {
		h = sha512.New()
		// alternate writing P bytes or most recent intermediate checksum
		if n%2 != 0 {
			recycle(h, pbuf, len(key))
		} else {
			h.Write(sum[:64])
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
			h.Write(sum[:64])
		} else {
			recycle(h, pbuf, len(key))
		}
		sum = h.Sum(sum[:0])
	}
	// encode the output
	var buf bytes.Buffer
	// limit is number of bytes in checksum minus bytes encoded after the loop,
	// divided by three since we write three bytes inside the loop. Increment by
	// three since we write three times inside the loop.
	for i := 0; i < (sha512.Size-1)/3; i += 3 {
		b64crypt.EncodeBytes(&buf, sum[i], sum[i+21], sum[i+42])
		b64crypt.EncodeBytes(&buf, sum[i+22], sum[i+43], sum[i+1])
		b64crypt.EncodeBytes(&buf, sum[i+44], sum[i+2], sum[i+23])
	}
	b64crypt.EncodeBytes(&buf, 0, 0, sum[63])
	// snip the trailing suffix to ignore the final fully zero 12 bits
	return buf.Bytes()[:sha512.Size*4/3+1], nil
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
