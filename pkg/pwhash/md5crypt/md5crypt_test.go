package md5crypt_test

import (
	"bytes"
	"testing"

	"github.com/smlx/hashy/pkg/pwhash/md5crypt"
)

type hashTestInput struct {
	password string
	salt     string
}

func TestHash(t *testing.T) {
	var testCases = map[string]struct {
		input  hashTestInput
		expect string
	}{
		// taken from the go-htpasswd test suite
		"go-htpasswd compat": {
			input:  hashTestInput{"mickey5", "D89ubl/e"},
			expect: "dJ8XW4DfrJHTrnwCdx3Ji1",
		},
		// generated via mkpasswd
		"mkpasswd compat": {
			input:  hashTestInput{"foo", "V0I8Ox6J"},
			expect: "I5JKgWHoC9o7ugE.JLcar/",
		},
		// taken from the musl test function
		"musl compat": {
			input:  hashTestInput{"Xy01@#\x01\x02\x80\x7f\xff\r\n\x81\t !", "abcd0123"},
			expect: "9Qcg8DyviekV3tDGMZynJ1",
		},
	}
	var c md5crypt.Function
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			result, _ := c.Hash([]byte(tc.input.password), []byte(tc.input.salt), 0)
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
			input: `$1$28772684$iEwNOgGugqO9.bIz5sk8k/`,
			expect: parseOutput{
				hash: []byte(`iEwNOgGugqO9.bIz5sk8k/`),
				salt: []byte(`28772684`),
				cost: 0,
				err:  nil,
			},
		},
	}
	var c md5crypt.Function
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
