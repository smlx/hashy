package sha512crypt_test

import (
	"bytes"
	"testing"

	"github.com/smlx/hashy/pkg/pwhash/sha512crypt"
)

type hashTestInput struct {
	password string
	salt     string
	cost     uint
}

func TestHash(t *testing.T) {
	var testCases = map[string]struct {
		input  hashTestInput
		expect string
	}{
		"mkpasswd": {
			input:  hashTestInput{"test", "rTnE1VTfjNYkoY0k", 1000},
			expect: "k1YwHXQXAysWwIPpmQ2EvDjs62.Hqdh2yv8b0qbvR/.myAiOM5olqJdN.wvGk0zkIgGzSwIOIEKuEjX7OBOtX/",
		},
	}
	var c sha512crypt.Function
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			result, err := c.Hash([]byte(tc.input.password), []byte(tc.input.salt),
				tc.input.cost)
			if err != nil {
				tt.Fatal(err)
			}
			if !bytes.Equal(result, []byte(tc.expect)) {
				tt.Fatalf("expected %s, got %s", tc.expect, string(result))
			}
		})
	}
}

type parseOutput struct {
	hash []byte
	salt []byte
	cost uint
	err  error
}

func TestParse(t *testing.T) {
	var testCases = map[string]struct {
		input  string
		expect parseOutput
	}{
		// https://hashcat.net/wiki/doku.php?id=example_hashes
		"hashcat example": {
			input: `$6$52450745$k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/`,
			expect: parseOutput{
				hash: []byte(`k5ka2p8bFuSmoVT1tzOyyuaREkkKBcCNqoDKzYiJL9RaE8yMnPgh2XzzF0NDrUhgrcLwg78xs1w5pJiypEdFX/`),
				salt: []byte(`52450745`),
				cost: 5000,
				err:  nil,
			},
		},
		"mkpasswd": {
			input: `$6$rounds=2000$JW6v18EWXm7n8HKc$m6MAsN0ccu97LdbpnkSnq4AWUrFQv2K87h5WWly6Gy5at78JKmbhkCiOE60a5Ezk4x.KQccr8Q29gSwxPxpG2.`,
			expect: parseOutput{
				hash: []byte(`m6MAsN0ccu97LdbpnkSnq4AWUrFQv2K87h5WWly6Gy5at78JKmbhkCiOE60a5Ezk4x.KQccr8Q29gSwxPxpG2.`),
				salt: []byte(`JW6v18EWXm7n8HKc`),
				cost: 2000,
				err:  nil,
			},
		},
	}
	var c sha512crypt.Function
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			hash, salt, cost, err := c.Parse([]byte(tc.input))
			if tc.expect.err != err {
				tt.Fatalf("expected err %v, got %v", tc.expect.err, err)
			}
			if !bytes.Equal(tc.expect.hash, hash) {
				tt.Fatalf("expected hash %v, got %v", tc.expect.hash, hash)
			}
			if !bytes.Equal(tc.expect.salt, salt) {
				tt.Fatalf("expected salt %v, got %v", tc.expect.salt, salt)
			}
			if tc.expect.cost != cost {
				tt.Fatalf("expected cost %v, got %v", tc.expect.cost, cost)
			}
		})
	}
}
