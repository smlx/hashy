package main

import (
	"github.com/alecthomas/kong"
	"github.com/smlx/hashy/pkg/pwhash"
	"github.com/smlx/hashy/pkg/pwhash/mariadboldpassword"
	"github.com/smlx/hashy/pkg/pwhash/md5crypt"
	"github.com/smlx/hashy/pkg/pwhash/sha1crypt"
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
	functions := map[string]pwhash.Function{
		mariadboldpassword.ID: &mariadboldpassword.Function{},
		md5crypt.ID:           &md5crypt.Function{},
		sha1crypt.ID:          &sha1crypt.Function{},
	}
	// execute CLI
	kctx.FatalIfErrorf(kctx.Run(functions))
}
