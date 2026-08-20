//go:build !linux

package fileworker

import (
	"errors"
	"syscall"
)

type cgroupHandle struct{}

func prepareCgroup(root, _ string) (*cgroupHandle, error) {
	if root != "" {
		return nil, errors.New("cgroups are only supported on Linux")
	}
	return nil, nil
}
func attachCgroup(*syscall.SysProcAttr, *cgroupHandle) {}
func (*cgroupHandle) close()                           {}
