// xsshunts is an automated multi-vector XSS hunting toolkit written in Go.
// It discovers parameters, analyzes reflection contexts, then attacks GET, POST,
// path, fragment and header injection points — confirming findings by driving
// a real browser and intercepting JavaScript dialogs.
package main

import (
	"os"

	"github.com/zapstiko/xsshunts/internal/config"
	"github.com/zapstiko/xsshunts/internal/scanner"
)

func main() {
	opts := config.Parse(os.Args[1:])
	os.Exit(scanner.Run(opts))
}
