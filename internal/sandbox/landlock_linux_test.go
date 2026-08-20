//go:build linux

package sandbox

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestLandlockConfinesReadOnlyWorker(t *testing.T) {
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "allowed.txt"), []byte("ok"), 0600)
	cmd := exec.Command(os.Args[0], "-test.run=TestLandlockHelperProcess")
	cmd.Env = append(os.Environ(), "REMOTE_AGENT_LANDLOCK_HELPER=1", "REMOTE_AGENT_LANDLOCK_ROOT="+root)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("landlock helper failed: %v: %s", err, output)
	}
}

func TestLandlockHelperProcess(t *testing.T) {
	if os.Getenv("REMOTE_AGENT_LANDLOCK_HELPER") != "1" {
		return
	}
	root := os.Getenv("REMOTE_AGENT_LANDLOCK_ROOT")
	if err := ApplyWorkspace(root, false); err != nil {
		os.Stderr.WriteString(err.Error())
		os.Exit(2)
	}
	if _, err := os.ReadFile(filepath.Join(root, "allowed.txt")); err != nil {
		os.Exit(3)
	}
	if _, err := os.ReadFile("/etc/passwd"); err == nil {
		os.Exit(4)
	}
	if err := os.WriteFile(filepath.Join(root, "denied.txt"), []byte("x"), 0600); err == nil {
		os.Exit(5)
	}
	os.Exit(0)
}
