//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package installer

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

type applyLock struct {
	file *os.File
}

func acquireApplyLock(path string) (*applyLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open installer apply lock: %w", err)
	}
	if err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = f.Close()
		if errors.Is(err, unix.EWOULDBLOCK) || errors.Is(err, unix.EAGAIN) {
			return nil, errors.New("another installer apply is in progress for this configuration")
		}
		return nil, fmt.Errorf("lock installer apply: %w", err)
	}
	return &applyLock{file: f}, nil
}

func (l *applyLock) release() {
	_ = unix.Flock(int(l.file.Fd()), unix.LOCK_UN)
	_ = l.file.Close()
	// Keep the marker path: unlinking can split waiters across old and new inodes.
	// The kernel releases the actual lock on close or process exit, so it cannot go stale.
}
