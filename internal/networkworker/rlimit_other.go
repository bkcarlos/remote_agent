//go:build windows || plan9 || js || wasip1

package networkworker

func ApplyResourceLimits() error { return nil }
