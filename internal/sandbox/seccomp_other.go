//go:build !linux

package sandbox

func ApplySeccomp() error { return nil }
