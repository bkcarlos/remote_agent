//go:build !linux

package fileworker

import "os/exec"

func configureWorkerProcess(*exec.Cmd) {}
