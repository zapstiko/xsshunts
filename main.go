// xsshunts is an automated multi-vector XSS scanner written in Go.
// It discovers parameters, analyzes reflection contexts, then attacks GET, POST,
// path, fragment and header injection points, confirming findings by driving a
// real headless browser and intercepting JavaScript dialogs.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Print("\n\033[1m\033[31m[!]\033[0m Scan interrupted by user.\n")
		os.Exit(130)
	}()

	os.Exit(run())
}
