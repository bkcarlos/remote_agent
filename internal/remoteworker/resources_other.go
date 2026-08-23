//go:build windows || plan9 || js || wasip1 || solaris || aix

package remoteworker

func ApplyResourceLimits() error { return nil }
