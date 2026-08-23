//go:build linux

package execworker

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

var errProcessIdentity = errors.New("managed process identity mismatch")
var managedProcessStarttime = procStarttime

func procStarttime(pid int) (uint64, error) {
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	closeParen := strings.LastIndexByte(string(raw), ')')
	if closeParen < 0 || closeParen+2 >= len(raw) {
		return 0, errors.New("invalid proc stat")
	}
	fields := strings.Fields(string(raw[closeParen+2:]))
	// fields starts at stat field 3 (state); starttime is field 22.
	if len(fields) <= 19 {
		return 0, errors.New("incomplete proc stat")
	}
	return strconv.ParseUint(fields[19], 10, 64)
}

func procState(pid int, expectedStarttime uint64) (string, error) {
	actual, err := procStarttime(pid)
	if err != nil || actual != expectedStarttime {
		return "", errProcessIdentity
	}
	raw, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if strings.HasPrefix(line, "State:") {
			fields := strings.Fields(strings.TrimPrefix(line, "State:"))
			if len(fields) > 0 {
				switch fields[0] {
				case "T", "t":
					return "stopped", nil
				case "Z", "X", "x":
					return "exited", nil
				default:
					return "running", nil
				}
			}
		}
	}
	return "", errors.New("proc state is unavailable")
}
