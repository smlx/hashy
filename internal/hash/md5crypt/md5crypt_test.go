package md5crypt_test

import (
	"bytes"
	"testing"

	"github.com/smlx/hashy/internal/hash/md5crypt"
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
