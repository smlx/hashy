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
