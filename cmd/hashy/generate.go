package main

import (
	"fmt"

	"github.com/smlx/hashy/pkg/hash"
)

// GenerateCmd represents the generate command.
type GenerateCmd struct {
	Function string `kong:"required,enum='md5crypt,mariaDBOldPassword',help='Cryptographic hash function (AKA method) used to generate the password hash'"`
	Cost     uint   `kong:"help='CPU time cost. This parameter has a different meaning for each cryptographic hash function.'"`
	Password string `kong:"required,arg,help='Password to hash'"`
}

// Run the generate command.
func (cmd *GenerateCmd) Run(functions map[string]hash.Function) error {
	// get the function
	f, ok := functions[cmd.Function]
	if !ok {
		return fmt.Errorf("unknown funciton %s", cmd.Function)
	}
	// get a salt
	salt, err := f.GenerateSalt()
	if err != nil {
		return fmt.Errorf("couldn't generate salt: %v", err)
	}
	// generate a hash
	pwHash, err := f.Hash([]byte(cmd.Password), salt, cmd.Cost)
	if err != nil {
		return fmt.Errorf("couldn't hash password: %v", err)
	}
	// format output
	_, err = fmt.Println(f.Format(pwHash, salt, cmd.Cost))
	return err
}
