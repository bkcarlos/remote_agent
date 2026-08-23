//go:build linux

package execworker

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type execCgroup struct {
	path string
	file *os.File
}

func validateExecCgroupRoot(root string, required bool) error {
	if root == "" {
		if required {
			return errors.New("production exec isolation requires a delegated cgroup v2 root")
		}
		return nil
	}
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return errors.New("exec cgroup root is not a delegated cgroup v2 directory")
	}
	return nil
}

func prepareRuntimeCgroup(root string, required bool) (string, error) {
	if err := validateExecCgroupRoot(root, required); err != nil {
		return "", err
	}
	if root == "" {
		return "", nil
	}
	runtimeRoot, err := os.MkdirTemp(root, "remote-agent-runtime-")
	if err != nil {
		return "", errors.New("create isolated exec runtime cgroup")
	}
	if err := os.WriteFile(filepath.Join(runtimeRoot, "cgroup.subtree_control"), []byte("+cpu +memory +pids"), 0o600); err != nil {
		_ = os.Remove(runtimeRoot)
		return "", errors.New("delegate exec runtime cgroup controllers")
	}
	return runtimeRoot, nil
}

func prepareExecCgroup(root, id string, limits Limits, required bool) (*execCgroup, error) {
	if err := validateExecCgroupRoot(root, required); err != nil {
		return nil, err
	}
	if root == "" {
		return nil, nil
	}
	path := filepath.Join(root, "exec-"+id)
	if err := os.Mkdir(path, 0o700); err != nil {
		return nil, fmt.Errorf("create exec cgroup: %w", err)
	}
	cleanup := func() { _ = os.Remove(path) }
	period := int64(100000)
	quota := period
	settings := map[string]string{
		"memory.max":      strconv.FormatInt(limits.MemoryBytes, 10),
		"memory.swap.max": "0",
		"pids.max":        strconv.FormatInt(limits.PIDs, 10),
		"cpu.max":         strconv.FormatInt(quota, 10) + " " + strconv.FormatInt(period, 10),
	}
	for name, value := range settings {
		if err := os.WriteFile(filepath.Join(path, name), []byte(value), 0o600); err != nil {
			cleanup()
			return nil, fmt.Errorf("configure exec cgroup %s: %w", name, err)
		}
	}
	file, err := os.Open(path)
	if err != nil {
		cleanup()
		return nil, err
	}
	return &execCgroup{path: path, file: file}, nil
}

func attachExecCgroup(attr *syscall.SysProcAttr, group *execCgroup) {
	if group == nil {
		return
	}
	attr.UseCgroupFD = true
	attr.CgroupFD = int(group.file.Fd())
}

func (g *execCgroup) close() {
	if g == nil {
		return
	}
	_ = g.file.Close()
	_ = os.WriteFile(filepath.Join(g.path, "cgroup.kill"), []byte("1"), 0o600)
	for attempt := 0; attempt < 50; attempt++ {
		if err := os.Remove(g.path); err == nil || os.IsNotExist(err) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func cleanupStaleExecCgroups(root string) error {
	if root == "" {
		return nil
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "exec-proc-") {
			continue
		}
		path := filepath.Join(root, entry.Name())
		if err := os.WriteFile(filepath.Join(path, "cgroup.kill"), []byte("1"), 0o600); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("kill stale exec cgroup: %w", err)
		}
		for attempt := 0; attempt < 50; attempt++ {
			if err := os.Remove(path); err == nil || os.IsNotExist(err) {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	return nil
}
