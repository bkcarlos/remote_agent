//go:build linux

package fileworker

import (
	"os"
	"os/exec"
	"syscall"
)

func configureWorkerProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER | syscall.CLONE_NEWNS | syscall.CLONE_NEWNET |
			syscall.CLONE_NEWPID | syscall.CLONE_NEWIPC | syscall.CLONE_NEWUTS,
		Unshareflags:               syscall.CLONE_NEWNS,
		UidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getuid(), Size: 1}},
		GidMappings:                []syscall.SysProcIDMap{{ContainerID: 0, HostID: os.Getgid(), Size: 1}},
		GidMappingsEnableSetgroups: false,
		Pdeathsig:                  syscall.SIGKILL,
	}
}
