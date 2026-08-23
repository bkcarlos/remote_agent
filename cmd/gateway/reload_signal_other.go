//go:build !linux

package main

import "os"

func workspaceReloadSignals() (<-chan os.Signal, func()) {
	return nil, func() {}
}
