package main

import (
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
	var matches []string
	for id, f := range functions {
		hash, salt, cost, err := f.Parse(cmd.EncodedHash)
		if err != nil {
			continue
		}
		matches = append(matches, id)
		ok, err := f.Check([]byte(cmd.Password), hash, salt, cost)
		if err != nil {
			return fmt.Errorf("couldn't check %s: %v", id, err)
		}
		if ok {
			fmt.Printf("password matched for hash function %s\n", id)
			return nil
		}
	}
	if len(matches) > 0 {
		fmt.Println("Matching hash formats:")
		for _, m := range matches {
			fmt.Printf("* %s\n", m)
		}
		return fmt.Errorf("incorrect password for all matching hash formats")
	}
	return fmt.Errorf("no matching hash format")
}
