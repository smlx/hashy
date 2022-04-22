package main

import (
	"crypto/subtle"
	"fmt"

	"github.com/smlx/hashy/pkg/hash"
)

// CheckCmd represents the check command.
type CheckCmd struct {
	EncodedHash string `kong:"required,arg,help='Password hash in encoded format'"`
	Password    string `kong:"required,arg,help='Password to test against hash'"`
}

// Run the check command.
func (cmd *CheckCmd) Run(functions map[string]hash.Function) error {
	var fmtMatches []string
	var passMatches []string
	for id, f := range functions {
		queryHash, salt, cost, err := f.Parse(cmd.EncodedHash)
		if err != nil {
			continue
		}
		fmtMatches = append(fmtMatches, id)
		calculatedHash, err := f.Hash([]byte(cmd.Password), salt, cost)
		if err != nil {
			return fmt.Errorf("couldn't hash password using %s: %v", id, err)
		}
		if subtle.ConstantTimeCompare(queryHash, calculatedHash) == 1 {
			passMatches = append(passMatches, id)
		}
	}
	if len(fmtMatches) == 0 {
		return fmt.Errorf("no matching hash format")
	}
	fmt.Println("Matching hash formats:")
	for _, m := range fmtMatches {
		fmt.Printf("* %s\n", m)
	}
	if len(passMatches) == 0 {
		return fmt.Errorf("no valid password found for any matching hash formats")
	}
	fmt.Println("Password matches hash for:")
	for _, m := range passMatches {
		fmt.Printf("* %s\n", m)
	}
	return nil
}
