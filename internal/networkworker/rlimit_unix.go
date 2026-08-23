//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package networkworker

import "syscall"

func ApplyResourceLimits() error {
	limits := []struct {
		resource int
		maximum  uint64
	}{
		{resource: syscall.RLIMIT_CORE, maximum: 0},
		{resource: syscall.RLIMIT_NOFILE, maximum: 64},
		{resource: syscall.RLIMIT_CPU, maximum: 65},
	}
	for _, requested := range limits {
		var current syscall.Rlimit
		if err := syscall.Getrlimit(requested.resource, &current); err != nil {
			return err
		}
		if current.Cur > requested.maximum {
			current.Cur = requested.maximum
		}
		if current.Max > requested.maximum {
			current.Max = requested.maximum
		}
		if err := syscall.Setrlimit(requested.resource, &current); err != nil {
			return err
		}
	}
	return nil
}
