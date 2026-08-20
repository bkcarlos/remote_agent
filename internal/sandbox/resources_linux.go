//go:build linux

package sandbox

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func ApplyResourceLimits() error {
	limits := []struct {
		resource int
		value    uint64
	}{
		{unix.RLIMIT_CPU, 10},
		{unix.RLIMIT_NOFILE, 128},
		{unix.RLIMIT_NPROC, 32},
		{unix.RLIMIT_FSIZE, 8 << 20},
		{unix.RLIMIT_CORE, 0},
	}
	for _, item := range limits {
		limit := &unix.Rlimit{Cur: item.value, Max: item.value}
		if err := unix.Setrlimit(item.resource, limit); err != nil {
			return fmt.Errorf("set resource limit %d: %w", item.resource, err)
		}
	}
	return nil
}
