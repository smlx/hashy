package pwhash

import "errors"

var (
	// ErrSaltLen is returned when a salt of invalid length is passed.
	ErrSaltLen = errors.New("invalid salt length")
	// ErrKeyLen is returned when a key of invalid length is passed.
	ErrKeyLen = errors.New("invalid key length")
	// ErrParse is returned when an encoded hash doesn't match the expected format.
	ErrParse = errors.New("invalid encoded format")
	// ErrCost is returned when a cost value is out of range.
	ErrCost = errors.New("invalid cost value")
	// ErrInternal is returned when an internal error occurs.
	ErrInternal = errors.New("invalid internal state")
)

// The Function interface is implemented by each of the hash function
// implementations supported.
type Function interface {
	// Hash returns the hash of the given key.
	Hash(key, salt []byte, cost uint) ([]byte, error)
	// Parse the given hash string in its common encoded form.
	Parse(encodedHash string) (hash, salt []byte, cost uint, err error)
	// Format the given parameters into the common "password hash" form.
	Format(hash, salt []byte, cost uint) string

	// ID returns the unique identification string of this hash function.
	ID() string
	// DefaultCost returns the maximum cost value for the hash function.
	DefaultCost() uint
	// GenerateSalt returns a cryptographically secure salt value which is the
	// maximum size for this funciton.
	GenerateSalt() ([]byte, error)
}
