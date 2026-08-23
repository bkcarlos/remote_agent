//go:build darwin || freebsd || netbsd || openbsd || dragonfly || solaris || aix

package networkworker

import (
	"os"
	"os/exec"
	"syscall"
)

func configureWorkerProcess(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
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

func ApplyParentDeathSignal() error { return nil }
