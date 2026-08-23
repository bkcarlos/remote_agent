//go:build linux

package networkworker

import (
	"errors"
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

func configureWorkerProcess(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
}

func killWorkerProcess(command *exec.Cmd) error {
	if command.Process == nil {
		return os.ErrProcessDone
	}
	if err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL); err == nil {
		return nil
	}
	return command.Process.Kill()
}

// ApplyParentDeathSignal closes the fork/exec race by setting PDEATHSIG again
// inside the worker. No workspace or network namespace is created.
func ApplyParentDeathSignal() error {
	parent := os.Getppid()
	if err := unix.Prctl(unix.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0, 0, 0); err != nil {
		return err
	}
	if os.Getppid() != parent || os.Getppid() == 1 {
		return errors.New("network worker parent exited during startup")
	}
	return nil
}
