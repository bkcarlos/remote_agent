package execworker

import (
	"sync"
	"testing"
)

type lifecycleBackend struct {
	mu          sync.Mutex
	launchEnter chan struct{}
	launchGo    chan struct{}
	published   bool
	revoked     bool
}

func (backend *lifecycleBackend) execute(job Job, _ TaskProfile, _ string) Response {
	if job.Operation == OperationProcessStart {
		if backend.launchEnter != nil {
			close(backend.launchEnter)
			<-backend.launchGo
		}
		backend.mu.Lock()
		backend.published = true
		backend.mu.Unlock()
	}
	return Response{CapabilityID: job.CapabilityID, ProcessID: "opaque-process"}
}

func (backend *lifecycleBackend) revoke(string, string) {
	backend.mu.Lock()
	backend.revoked = true
	backend.published = false
	backend.mu.Unlock()
}

func (*lifecycleBackend) close() {}

func TestSupervisorTombstoneRejectsNewProcessStart(t *testing.T) {
	backend := &lifecycleBackend{}
	supervisor := &Supervisor{backend: backend, revoked: make(map[sessionOwner]struct{})}
	job := testJob()
	job.Operation = OperationSessionRevoke
	supervisor.executeAuthorized(job, TaskProfile{}, "")
	job.Operation = OperationProcessStart
	job.CapabilityID = "cap-after-revoke"
	response := supervisor.executeAuthorized(job, TaskProfile{}, "")
	if response.Error == "" {
		t.Fatal("process_start was accepted after the session tombstone")
	}
	backend.mu.Lock()
	published := backend.published
	backend.mu.Unlock()
	if published {
		t.Fatal("revoked session published a managed process")
	}
}

func TestSupervisorRevokeLinearizesWithProcessPublication(t *testing.T) {
	backend := &lifecycleBackend{launchEnter: make(chan struct{}), launchGo: make(chan struct{})}
	supervisor := &Supervisor{backend: backend, revoked: make(map[sessionOwner]struct{})}
	start := testJob()
	start.Operation = OperationProcessStart
	startDone := make(chan struct{})
	go func() {
		supervisor.executeAuthorized(start, TaskProfile{}, "")
		close(startDone)
	}()
	<-backend.launchEnter

	revoke := start
	revoke.Operation = OperationSessionRevoke
	revoke.CapabilityID = "cap-revoke"
	revokeDone := make(chan struct{})
	go func() {
		supervisor.executeAuthorized(revoke, TaskProfile{}, "")
		close(revokeDone)
	}()
	close(backend.launchGo)
	<-startDone
	<-revokeDone

	backend.mu.Lock()
	published, revoked := backend.published, backend.revoked
	backend.mu.Unlock()
	if !revoked || published {
		t.Fatalf("revoke did not observe and remove the atomically published process: revoked=%t published=%t", revoked, published)
	}
}
