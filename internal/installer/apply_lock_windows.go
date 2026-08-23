package installer

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

type applyLock struct {
	file       *os.File
	overlapped windows.Overlapped
}

func acquireApplyLock(path string) (*applyLock, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open installer apply lock: %w", err)
	}
	lock := &applyLock{file: f}
	err = windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		1,
		0,
		&lock.overlapped,
	)
	if err != nil {
		_ = f.Close()
		if errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return nil, errors.New("another installer apply is in progress for this configuration")
		}
		return nil, fmt.Errorf("lock installer apply: %w", err)
	}
	return lock, nil
}

func (l *applyLock) release() {
	_ = windows.UnlockFileEx(windows.Handle(l.file.Fd()), 0, 1, 0, &l.overlapped)
	_ = l.file.Close()
	// The marker may remain, but the kernel lock is released on close or process exit.
}
