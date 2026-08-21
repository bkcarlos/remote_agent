//go:build !linux

package sandbox

import "errors"

var ErrLandlockUnavailable = errors.New("landlock is unavailable")

func ApplyWorkspace(string, bool) error { return nil }
func Supported() error                  { return nil }
