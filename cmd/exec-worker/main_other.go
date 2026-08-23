//go:build !linux

package main

import (
	"fmt"
	"os"
)

func main() {
	fmt.Fprintln(os.Stderr, "exec-worker: unsupported: Linux is required")
	os.Exit(1)
}
