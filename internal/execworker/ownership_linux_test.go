//go:build linux

package execworker

import (
	"strings"
	"testing"
)

func TestCrossSessionManagedProcessDenied(t *testing.T) {
	backend := &linuxBackend{items: map[string]*processRecord{
		"proc-owned": {
			id: "proc-owned", principal: "principal-a", sessionID: "session-a",
			workspaceID: "workspace-a", profile: "go-test", state: "running",
		},
	}}
	job := testJob()
	job.ProcessID = "proc-owned"
	job.SessionID = "session-b"
	if _, err := backend.ownedRecord(job); err == nil || !strings.Contains(err.Error(), "not owned") {
		t.Fatalf("cross-session process access error = %v", err)
	}
}

func TestManagedProcessFollowupDoesNotReuseLaunchTaskID(t *testing.T) {
	backend := &linuxBackend{items: map[string]*processRecord{
		"proc-owned": {
			id: "proc-owned", principal: "principal-a", sessionID: "session-a",
			workspaceID: "workspace-a", profile: "go-test", state: "running",
		},
	}}
	job := testJob()
	job.ProcessID = "proc-owned"
	job.TaskID = "different-followup-request"
	if _, err := backend.ownedRecord(job); err != nil {
		t.Fatalf("same-session follow-up with a fresh capability TaskID was denied: %v", err)
	}
}

func TestPIDReuseStarttimeDenied(t *testing.T) {
	original := managedProcessStarttime
	managedProcessStarttime = func(int) (uint64, error) { return 200, nil }
	t.Cleanup(func() { managedProcessStarttime = original })
	record := &processRecord{pid: 1234, starttime: 100}
	if err := verifyProcessIdentity(record); err == nil {
		t.Fatal("reused PID with changed /proc starttime was accepted")
	}
}
