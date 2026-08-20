//go:build !linux

package sandbox

func ApplyWorkspace(string, bool) error { return nil }
func Supported() error                  { return nil }
