//go:build linux

package execworker

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"testing"
	"time"
)

func TestExecClientTimeoutHonorsSignedSynchronousTaskLimit(t *testing.T) {
	job := Job{Operation: OperationExecRun, Limits: Limits{TimeoutMillis: 120000}}
	if got, want := execClientTimeout(30*time.Second, job), 125*time.Second; got != want {
		t.Fatalf("exec client timeout = %v, want %v", got, want)
	}
	job.Operation = OperationProcessStart
	if got := execClientTimeout(30*time.Second, job); got != 30*time.Second {
		t.Fatalf("process_start control timeout = %v", got)
	}
}

func TestExecClientCancellationInterruptsConnectedSocket(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "exec.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	requestRead := make(chan struct{})
	release := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer connection.Close()
		var request Request
		if ReadFrame(connection, &request) == nil {
			close(requestRead)
		}
		<-release
	}()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() {
		_, err := (Client{SocketPath: socketPath, Cookie: "cookie", Timeout: time.Minute}).Do(ctx, Job{CapabilityID: "cap"})
		result <- err
	}()
	select {
	case <-requestRead:
	case <-time.After(time.Second):
		t.Fatal("exec client request did not reach the connected supervisor socket")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled exec client error = %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("context cancellation did not interrupt the connected exec socket")
	}
}
