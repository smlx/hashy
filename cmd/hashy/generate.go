package main

import (
	"fmt"

	"github.com/smlx/hashy/pkg/pwhash"
)

// GenerateCmd represents the generate command.
type GenerateCmd struct {
	Function string `kong:"required,enum='mariaDBOldPassword,md5crypt,sha1crypt,sha256crypt',help='Cryptographic hash function (AKA method) used to generate the password hash'"`
	Cost     uint   `kong:"help='CPU time cost. This parameter has a different meaning for each cryptographic hash function.'"`
	Password string `kong:"required,arg,help='Password to hash'"`
}

// Run the generate command.
func (cmd *GenerateCmd) Run(functions map[string]pwhash.Function) error {
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
	// use the default cost if none was passed
	cost := cmd.Cost
	if cost == 0 {
		cost = f.DefaultCost()
	}
	// generate a hash
	pwHash, err := f.Hash([]byte(cmd.Password), salt, cost)
	if err != nil {
		return fmt.Errorf("couldn't hash password: %v", err)
	}
	// format output
	_, err = fmt.Println(f.Format(pwHash, salt, cost))
	return err
}
