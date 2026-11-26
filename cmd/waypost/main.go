package main

import (
	"os"

	"github.com/Farzin312/waypost/internal/cli"
)

func main() {
	os.Exit(cli.Run(os.Args[1:], os.Stdout, os.Stderr))
}
