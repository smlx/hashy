package main

import (
	"github.com/alecthomas/kong"
	"github.com/smlx/hashy/pkg/hash"
	"github.com/smlx/hashy/pkg/hash/mariadboldpassword"
	"github.com/smlx/hashy/pkg/hash/md5crypt"
)

var (
	date        string
	goVersion   string
	shortCommit string
	version     string
)

// CLI represents the command-line interface.
type CLI struct {
	ID       IDCmd       `kong:"cmd,help='Identify a password hash'"`
	Check    CheckCmd    `kong:"cmd,help='Check a password against a hash'"`
	Generate GenerateCmd `kong:"cmd,help='Generate a hash from a password'"`
	Version  VersionCmd  `kong:"cmd,help='Print version information'"`
}

func main() {
	// parse CLI config
	cli := CLI{}
	kctx := kong.Parse(&cli,
		kong.UsageOnError(),
	)
	functions := map[string]hash.Function{
		md5crypt.ID:           &md5crypt.Function{},
		mariadboldpassword.ID: &mariadboldpassword.Function{},
	}
	// execute CLI
	kctx.FatalIfErrorf(kctx.Run(functions))
}
