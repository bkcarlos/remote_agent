//go:build windows || plan9 || js || wasip1

package networkworker

import (
	"os"
	"os/exec"
)

func configureWorkerProcess(*exec.Cmd) {}

func killWorkerProcess(command *exec.Cmd) error {
	if command.Process == nil {
		return os.ErrProcessDone
	}
	return command.Process.Kill()
}

func ApplyParentDeathSignal() error { return nil }
