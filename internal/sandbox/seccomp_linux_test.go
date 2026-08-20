//go:build linux

package sandbox

import (
	"errors"
	"os"
	"os/exec"
	"testing"

	"golang.org/x/sys/unix"
)

func TestSeccompBlocksNetworkSyscalls(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=TestSeccompHelperProcess")
	cmd.Env = append(os.Environ(), "REMOTE_AGENT_SECCOMP_HELPER=1")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("seccomp helper failed: %v: %s", err, output)
	}
}

func TestSeccompHelperProcess(t *testing.T) {
	if os.Getenv("REMOTE_AGENT_SECCOMP_HELPER") != "1" {
		return
	}
	if err := ApplySeccomp(); err != nil {
		os.Exit(2)
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if fd >= 0 {
		unix.Close(fd)
		os.Exit(3)
	}
	if !errors.Is(err, unix.EPERM) {
		os.Exit(4)
	}
	// Ordinary process operations must remain available to the Go runtime.
	if _, err := os.Getwd(); err != nil {
		os.Exit(5)
	}
	os.Exit(0)
}
