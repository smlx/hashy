package main

import (
	"fmt"

	"github.com/smlx/hashy/internal/hash"
)

// GenerateCmd represents the generate command.
type GenerateCmd struct {
	Function string `kong:"required,enum='md5crypt',help='Cryptographic hash function (AKA method) used to generate the password hash'"`
	Cost     uint   `kong:"help='CPU time cost. This parameter has a different meaning for each cryptographic hash function.'"`
	Password string `kong:"required,arg,help='Password to hash'"`
}

// Run the generate command.
func (cmd *GenerateCmd) Run(functions map[string]hash.Function) error {
	pwHash, err := functions[cmd.Function].HashPassword(cmd.Password, cmd.Cost)
	if err != nil {
		return err
	}
	fmt.Println(pwHash)
	return nil
}
