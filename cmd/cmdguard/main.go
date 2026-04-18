package main

import (
	"os"

	"github.com/tasuku43/cmdguard/internal/cli"
)

func main() {
	cwd, _ := os.Getwd()
	home, _ := os.UserHomeDir()
	env := cli.Env{
		Cwd:           cwd,
		Home:          home,
		XDGConfigHome: os.Getenv("XDG_CONFIG_HOME"),
	}
	code := cli.Run(os.Args[1:], cli.Streams{
		Stdin:  os.Stdin,
		Stdout: os.Stdout,
		Stderr: os.Stderr,
	}, env)
	os.Exit(code)
}
