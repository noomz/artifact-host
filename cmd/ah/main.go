package main

import (
	"os"

	"github.com/noomz/artifact-host/internal/cli"
)

func main() {
	os.Exit(cli.Main(os.Args[1:]))
}
