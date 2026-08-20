//go:build linux

package fileworker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

type cgroupHandle struct {
	path string
	file *os.File
}

func prepareCgroup(root, id string) (*cgroupHandle, error) {
	if root == "" {
		return nil, nil
	}
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return nil, errors.New("cgroup-root is not a delegated cgroup v2 directory")
	}
	path := filepath.Join(root, id)
	if err := os.Mkdir(path, 0700); err != nil {
		return nil, fmt.Errorf("create worker cgroup: %w", err)
	}
	cleanup := func() { _ = os.Remove(path) }
	settings := map[string]string{
		"memory.max":      strconv.FormatInt(256<<20, 10),
		"memory.swap.max": "0",
		"pids.max":        "32",
		"cpu.max":         "100000 100000",
	}
	for name, value := range settings {
		if err := os.WriteFile(filepath.Join(path, name), []byte(value), 0600); err != nil {
			cleanup()
			return nil, fmt.Errorf("configure worker cgroup %s: %w", name, err)
		}
	}
	file, err := os.Open(path)
	if err != nil {
		cleanup()
		return nil, err
	}
	return &cgroupHandle{path: path, file: file}, nil
}

func attachCgroup(cmdAttr *syscall.SysProcAttr, handle *cgroupHandle) {
	if handle == nil {
		return
	}
	cmdAttr.UseCgroupFD = true
	cmdAttr.CgroupFD = int(handle.file.Fd())
}

func (h *cgroupHandle) close() {
	if h == nil {
		return
	}
	h.file.Close()
	_ = os.WriteFile(filepath.Join(h.path, "cgroup.kill"), []byte("1"), 0600)
	for attempt := 0; attempt < 20; attempt++ {
		if err := os.Remove(h.path); err == nil || os.IsNotExist(err) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}
