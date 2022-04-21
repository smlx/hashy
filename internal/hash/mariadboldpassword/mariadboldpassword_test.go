package mariadboldpassword_test

import (
	"bytes"
	"testing"

	"github.com/smlx/hashy/internal/hash/mariadboldpassword"
)

func TestHash(t *testing.T) {
	var testCases = map[string]struct {
		input  string
		expect string
	}{
		// test cases taken from
		// https://github.com/MariaDB/server/blob/10.9/mysql-test/main/func_crypt.result
		"MariaDB OLD_PASSWORD() test 0": {
			input:  "idkfa",
			expect: "5c078dc54ca0fcca",
		},
		"MariaDB OLD_PASSWORD() test 1": {
			input:  "abc",
			expect: "7cd2b5942be28759",
		},
		"MariaDB OLD_PASSWORD() test 2": {
			input:  "",
			expect: "",
		},
		"MariaDB OLD_PASSWORD() test 3": {
			input: " i 	 d k f a ",
			expect: "5c078dc54ca0fcca",
		},
		"MariaDB OLD_PASSWORD() test 4": {
			input:  " i \t d k f a ",
			expect: "5c078dc54ca0fcca",
		},
	}
	var f mariadboldpassword.Function
	for name, tc := range testCases {
		t.Run(name, func(tt *testing.T) {
			result, err := f.Hash([]byte(tc.input), nil, 0)
			if err != nil {
				tt.Fatal(err)
			}
			if !bytes.Equal(result, []byte(tc.expect)) {
				tt.Fatalf("expected %s, got %s", tc.expect, result)
			}
		})
	}
}
