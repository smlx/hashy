package sha256crypt_test

import (
	"bytes"
	"testing"

	"github.com/smlx/hashy/pkg/pwhash/sha256crypt"
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
		"mkpasswd 1": {
			input:  hashTestInput{"foo", "IDRkfIy1SYTbgI6X", 1000},
			expect: "KNHIuiRy7ZcBnFp0/OzMx0DkFoM6M2AFrdU../DzdU7",
		},
		"mkpasswd 2": {
			input:  hashTestInput{"abiglongpassword", "7zOLT9IhFoUT6hgU", 9999},
			expect: "2Kx5z3lnIZGhjzMd2UKKN9SVxQjLy3wd5x.X00uEoo6",
		},
	}
	var c sha256crypt.Function
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
			input: `$5$rounds=5000$GX7BopJZJxPc/KEK$le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD`,
			expect: parseOutput{
				hash: []byte(`le16UF8I2Anb.rOrn22AUPWvzUETDGefUmAV8AZkGcD`),
				salt: []byte(`GX7BopJZJxPc/KEK`),
				cost: 5000,
				err:  nil,
			},
		},
	}
	var c sha256crypt.Function
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
