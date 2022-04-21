package hash

import "errors"

var (
	// ErrSaltLen is returned when a salt of invalid length is passed.
	ErrSaltLen = errors.New("invalid salt length")
	// ErrKeyLen is returned when a key of invalid length is passed.
	ErrKeyLen = errors.New("invalid key length")
	// ErrParse is returned when an encoded hash doesn't match the expected format.
	ErrParse = errors.New("invalid encoded format")
)

// The Function interface is implemented by each of the hash function
// implementations supported.
type Function interface {
	// Hash returns the hash of the given key.
	Hash(key, salt []byte, cost uint) ([]byte, error)
	// Check returns true if the given key matches the given hash, and false
	// otherwise.
	Check(key, hash, salt []byte, cost uint) (bool, error)
	// Parse the given hash string in its common encoded form.
	Parse(encodedHash string) (hash, salt []byte, cost uint, err error)
	// Format the given parameters into the common "password hash" form.
	Format(hash, salt []byte, cost uint) string
	// HashPassword is a convenience method which takes a password string,
	// generates a secure salt, and returns the hash of the password and salt in
	// common "password hash" form.
	HashPassword(password string, cost uint) (string, error)
}
