package mariadboldpassword

import (
	"bytes"
	"fmt"
	"regexp"

	"github.com/smlx/hashy/pkg/pwhash"
)

const (
	// ID is the identification string for this hash function
	ID = "mariaDBOldPassword"
	// keyMaxLen sets an arbitrary 32K limit to avoid DoS
	keyMaxLen = 1 << 15
)

// parseRegex is used to parse the formatted hash.
var parseRegex = regexp.MustCompile(`^[0-9a-f]{16}$`)

// Function implements the hash.Function interface for the md5 function.
type Function struct{}

// Hash returns the hash of the given key. The salt and cost arguments are
// ignored, since MariaDB OLD_PASSWORD() has no such parameter.
//
// Implemented with reference to:
// https://github.com/MariaDB/server/blob/10.9/sql/password.c
func (*Function) Hash(key, salt []byte, cost uint) ([]byte, error) {
	// perform some safety checks
	if len(key) > keyMaxLen {
		return nil, fmt.Errorf("key longer than %d bytes: %w", keyMaxLen,
			pwhash.ErrKeyLen)
	}
	// return an empty string for empty input
	if len(key) == 0 {
		return nil, nil
	}
	// set up the magic variables
	var (
		nr  = uint(1345345333)
		add = uint(7)
		nr2 = uint(0x12345671)
	)
	// perform some munging of the input
	for _, c := range key {
		switch c {
		case 0x09, 0x20:
			// skip tabs and spaces
			continue
		default:
			nr ^= (((nr & 63) + add) * uint(c)) + (nr << 8)
			nr2 += (nr2 << 8) ^ nr
			add += uint(c)
		}
	}
	result0 := nr & ((1 << 31) - 1)
	result1 := nr2 & ((1 << 31) - 1)
	// format the result
	var r bytes.Buffer
	if _, err := fmt.Fprintf(&r, "%08x%08x", result0, result1); err != nil {
		return nil, err
	}
	return r.Bytes(), nil
}

// Parse the given hash string in its common encoded form.
func (*Function) Parse(encodedHash []byte) ([]byte, []byte, uint, error) {
	if !parseRegex.Match(encodedHash) {
		return nil, nil, 0, fmt.Errorf("couldn't parse %s format: %w", ID,
			pwhash.ErrParse)
	}
	return encodedHash, nil, 0, nil
}

// Format the given parameters into the common "password hash" form.
// The salt and cost parameters are not used by this hash function.
func (*Function) Format(hash, salt []byte, cost uint) string {
	return fmt.Sprintf("%s", hash)
}

// ID returns the unique identification string of this hash function.
func (*Function) ID() string {
	return ID
}

// DefaultCost always returns zero for this function, as the cost parameter is
// ignored.
func (*Function) DefaultCost() uint {
	return 0
}

// GenerateSalt returns nil for this function, as the function does not use a
// salt.
func (*Function) GenerateSalt() ([]byte, error) {
	return nil, nil
}
