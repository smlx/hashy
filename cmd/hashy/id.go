package main

import (
	"fmt"

	"github.com/smlx/hashy/internal/hash"
)

// IDCmd represents the id command.
type IDCmd struct {
	EncodedHash string `kong:"required,arg,help='Password hash in encoded format'"`
}

// Run the id command.
func (cmd *IDCmd) Run(functions map[string]hash.Function) error {
	var matches []string
	for id, f := range functions {
		_, _, _, err := f.Parse(cmd.EncodedHash)
		if err == nil {
			matches = append(matches, id)
		}
	}
	if len(matches) > 0 {
		fmt.Println("Matching hash formats:")
		for _, m := range matches {
			fmt.Printf("* %s\n", m)
		}
		return nil
	}
	return fmt.Errorf("no matching hash format")
}
