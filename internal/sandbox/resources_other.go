//go:build !linux

package sandbox

func ApplyResourceLimits() error { return nil }
