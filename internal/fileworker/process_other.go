//go:build windows || plan9 || js || wasip1

package fileworker

import (
	"os"
	"os/exec"
)

func configureWorkerProcess(*exec.Cmd) {}

func killWorkerProcess(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return os.ErrProcessDone
	}
	return cmd.Process.Kill()
}
