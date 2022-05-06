package sha1crypt_test

import (
	"bytes"
	"testing"

	"github.com/smlx/hashy/pkg/pwhash/sha1crypt"
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
		// https://github.com/openwall/john/blob/bleeding-jumbo/src/sha1crypt_common_plug.c
		"john 2": {
			input:  hashTestInput{"password", "wnUR8T1U", 64000},
			expect: "vt1TFQ50tBMFgkflAFAOer2CwdYZ",
		},
		"john 3": {
			input:  hashTestInput{"password", "jtNX3nZ2", 40000},
			expect: "hBNaIXkt4wBI2o5rsi8KejSjNqIq",
		},
		"john 4": {
			input:  hashTestInput{"123456", "wnUR8T1U", 64000},
			expect: "wmwnhQ4lpo/5isi5iewkrHN7DjrT",
		},
		"john 5": {
			input:  hashTestInput{"complexlongpassword@123456", "wnUR8T1U", 64000},
			expect: "azjCegpOIk0FjE61qzGWhdkpuMRL",
		},
		"juniper 1": {
			input:  hashTestInput{"Hashcat1234!", "i3Znp47D", 24659},
			expect: "r7VOjnryOmiGNWRpna0Lk3ooe/jX",
		},
		"juniper 2": {
			input:  hashTestInput{"Hashcat1234!", "SeTzdv2R", 19205},
			expect: "8ZcgMk0PiGRrQdz5xGMncAfymq1C",
		},
		"passlib 1": {
			input:  hashTestInput{"foo", "NSb4QDqW", 2},
			expect: "HBpkSg32map7FLee9lVOGRmy1b.T",
		},
		"juniper 3": {
			input:  hashTestInput{"flipfl0p!", "mROzSQ4a", 19295},
			expect: "SFnJ1fAbP4cHqw/16.xDV4s1LpMA",
		},
		"juniper 4": {
			input:  hashTestInput{"stuff", "/WgTkHoe", 23933},
			expect: "25rdwdZ95cfgY/Tl6li2/LRIbuVT",
		},
	}
	var c sha1crypt.Function
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

// https://github.com/hashcat/hashcat/issues/1204
func TestParse(t *testing.T) {
	var testCases = map[string]struct {
		input  string
		expect parseOutput
	}{
		"parse 0": {
			// Hashcat1234!
			input: `$sha1$19205$SeTzdv2R$8ZcgMk0PiGRrQdz5xGMncAfymq1C`,
			expect: parseOutput{
				hash: []byte(`8ZcgMk0PiGRrQdz5xGMncAfymq1C`),
				salt: []byte(`SeTzdv2R`),
				cost: 19205,
				err:  nil,
			},
		},
		"parse 1": {
			// hashcat
			input: `$sha1$18448$Qnzf/O/0$mE6qrpyPuhsPiLckV8phQ2XnMfYF`,
			expect: parseOutput{
				hash: []byte(`mE6qrpyPuhsPiLckV8phQ2XnMfYF`),
				salt: []byte(`Qnzf/O/0`),
				cost: 18448,
				err:  nil,
			},
		},
		"parse 2": {
			// hashcat
			input: `$sha1$19289$./l/p5Qi$zAMpiG6n/Mh1gVsqpqhShtIsJDrg`,
			expect: parseOutput{
				hash: []byte(`zAMpiG6n/Mh1gVsqpqhShtIsJDrg`),
				salt: []byte(`./l/p5Qi`),
				cost: 19289,
				err:  nil,
			},
		},
		"parse 3": {
			// flipfl0p!
			input: `$sha1$19295$mROzSQ4a$SFnJ1fAbP4cHqw/16.xDV4s1LpMA`,
			expect: parseOutput{
				hash: []byte(`SFnJ1fAbP4cHqw/16.xDV4s1LpMA`),
				salt: []byte(`mROzSQ4a`),
				cost: 19295,
				err:  nil,
			},
		},
		"parse 4": {
			// stuff
			input: `$sha1$23933$/WgTkHoe$25rdwdZ95cfgY/Tl6li2/LRIbuVT`,
			expect: parseOutput{
				hash: []byte(`25rdwdZ95cfgY/Tl6li2/LRIbuVT`),
				salt: []byte(`/WgTkHoe`),
				cost: 23933,
				err:  nil,
			},
		},
	}
	var c sha1crypt.Function
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
