//go:build linux

package execworker

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"time"
)

func platformSupported() error { return nil }

type linuxBackend struct {
	config Config
	mu     sync.Mutex
	items  map[string]*processRecord
	closed bool
}

type processRecord struct {
	id          string
	principal   string
	sessionID   string
	workspaceID string
	profile     string
	pid         int
	starttime   uint64
	startedAt   time.Time
	finishedAt  time.Time
	state       string
	exitCode    int
	signaled    bool
	timedOut    bool
	cmd         *exec.Cmd
	output      *boundedOutput
	group       *execCgroup
	done        chan struct{}
	timer       *time.Timer
}

func newBackend(config Config) (backend, error) {
	info, err := os.Stat(config.WorkerBinary)
	if err != nil || info.IsDir() {
		return nil, errors.New("exec worker binary is unavailable")
	}
	if err := validateExecCgroupRoot(config.CgroupRoot, config.Production); err != nil {
		return nil, err
	}
	if config.Production {
		if err := linuxIsolationSupported(); err != nil {
			return nil, fmt.Errorf("production exec isolation unavailable: %w", err)
		}
	}
	if err := cleanupStaleExecCgroups(config.CgroupRoot); err != nil {
		return nil, fmt.Errorf("clean stale exec processes: %w", err)
	}
	return &linuxBackend{config: config, items: make(map[string]*processRecord)}, nil
}

func (b *linuxBackend) execute(job Job, profile TaskProfile, root string) Response {
	switch job.Operation {
	case OperationExecRun:
		record, err := b.launch(job, profile, root)
		if err != nil {
			return Response{Error: safeProcessError(err)}
		}
		<-record.done
		response := b.responseFor(record, true)
		b.mu.Lock()
		delete(b.items, record.id)
		b.mu.Unlock()
		response.ProcessID = ""
		if response.Status != nil {
			response.Status.ProcessID = ""
		}
		return response
	case OperationProcessStart:
		record, err := b.launch(job, profile, root)
		if err != nil {
			return Response{Error: safeProcessError(err)}
		}
		return b.responseFor(record, false)
	case OperationProcessStatus:
		record, err := b.ownedRecord(job)
		if err != nil {
			return Response{Error: err.Error()}
		}
		return b.responseFor(record, true)
	case OperationProcessStop:
		record, err := b.ownedLiveRecord(job)
		if err != nil {
			return Response{Error: err.Error()}
		}
		b.killRecord(record, syscall.SIGKILL)
		<-record.done
		return b.responseFor(record, true)
	case OperationDebugStatus:
		record, err := b.ownedRecord(job)
		if err != nil {
			return Response{Error: err.Error()}
		}
		response := b.responseFor(record, false)
		if response.Status.State == "running" {
			state, err := procState(record.pid, record.starttime)
			if err != nil {
				return Response{Error: "managed process identity is no longer valid"}
			}
			response.Status.State = state
		}
		return response
	case OperationDebugSignal:
		record, err := b.ownedLiveRecord(job)
		if err != nil {
			return Response{Error: err.Error()}
		}
		signal := map[string]syscall.Signal{"stop": syscall.SIGSTOP, "continue": syscall.SIGCONT, "interrupt": syscall.SIGINT, "terminate": syscall.SIGTERM}[job.Signal]
		if err := b.signalRecord(record, signal); err != nil {
			return Response{Error: "managed process signal failed"}
		}
		return b.responseFor(record, false)
	case OperationMemScan:
		record, err := b.ownedLiveRecord(job)
		if err != nil {
			return Response{Error: err.Error()}
		}
		matches, scanned, err := scanProcessMemory(record.pid, record.starttime, *job.Memory, job.Limits)
		if err != nil {
			return Response{Error: safeMemoryError(err)}
		}
		return Response{ProcessID: record.id, Matches: matches, ScannedBytes: scanned}
	default:
		return Response{Error: "exec operation is not supported"}
	}
}

func (b *linuxBackend) launch(job Job, profile TaskProfile, root string) (*processRecord, error) {
	id, err := randomProcessID()
	if err != nil {
		return nil, err
	}
	group, err := prepareExecCgroup(b.config.CgroupRoot, id, job.Limits, b.config.Production)
	if err != nil {
		return nil, err
	}
	output := newBoundedOutput(job.Limits.OutputBytes)
	spec := childSpec{
		Executable: profile.Executable, Argv: append(append([]string(nil), profile.FixedArgv...), job.Argv...),
		Env: cloneEnv(job.Env), Workspace: root, WorkspaceMode: profile.WorkspaceMode,
		CachePaths: append([]string(nil), profile.CachePaths...), Limits: job.Limits, Production: b.config.Production,
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		group.close()
		return nil, err
	}
	cmd := exec.Command(b.config.WorkerBinary, "--exec-child")
	cmd.Env = []string{}
	cmd.ExtraFiles = []*os.File{reader}
	cmd.Stdout = output.stdoutWriter()
	cmd.Stderr = output.stderrWriter()
	configureExecChild(cmd, group)
	if err := cmd.Start(); err != nil {
		reader.Close()
		writer.Close()
		group.close()
		return nil, err
	}
	reader.Close()
	if err := WriteFrame(writer, spec); err != nil {
		writer.Close()
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
		group.close()
		return nil, err
	}
	writer.Close()
	starttime, err := managedProcessStarttime(cmd.Process.Pid)
	if err != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
		group.close()
		return nil, errors.New("cannot establish managed process identity")
	}
	record := &processRecord{
		id: id, principal: job.Principal, sessionID: job.SessionID, workspaceID: job.WorkspaceID,
		profile: job.Profile, pid: cmd.Process.Pid, starttime: starttime,
		startedAt: time.Now().UTC(), state: "running", exitCode: -1, cmd: cmd, output: output,
		group: group, done: make(chan struct{}),
	}
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Wait()
		group.close()
		return nil, errors.New("exec supervisor is closed")
	}
	b.items[id] = record
	b.mu.Unlock()
	record.timer = time.AfterFunc(time.Duration(job.Limits.TimeoutMillis)*time.Millisecond, func() {
		b.mu.Lock()
		if record.state == "running" {
			record.timedOut = true
		}
		b.mu.Unlock()
		b.killRecord(record, syscall.SIGKILL)
	})
	go b.wait(record)
	return record, nil
}

func (b *linuxBackend) wait(record *processRecord) {
	err := record.cmd.Wait()
	if record.timer != nil {
		record.timer.Stop()
	}
	record.group.close()
	b.mu.Lock()
	record.finishedAt = time.Now().UTC()
	record.state = "exited"
	record.exitCode = 0
	if err != nil {
		record.exitCode = -1
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			if status, ok := exitErr.Sys().(syscall.WaitStatus); ok {
				record.exitCode = status.ExitStatus()
				record.signaled = status.Signaled()
			}
		}
	}
	close(record.done)
	b.mu.Unlock()
}

func (b *linuxBackend) ownedRecord(job Job) (*processRecord, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	record, ok := b.items[job.ProcessID]
	if !ok || record.principal != job.Principal || record.sessionID != job.SessionID || record.workspaceID != job.WorkspaceID || record.profile != job.Profile {
		return nil, errors.New("managed process is not owned by this session")
	}
	return record, nil
}

func (b *linuxBackend) ownedLiveRecord(job Job) (*processRecord, error) {
	record, err := b.ownedRecord(job)
	if err != nil {
		return nil, err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if record.state != "running" || verifyProcessIdentity(record) != nil {
		return nil, errors.New("managed process is not running or its identity changed")
	}
	return record, nil
}

func verifyProcessIdentity(record *processRecord) error {
	actual, err := managedProcessStarttime(record.pid)
	if err != nil || actual != record.starttime {
		return errors.New("process starttime mismatch")
	}
	return nil
}

func (b *linuxBackend) signalRecord(record *processRecord, signal syscall.Signal) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if record.state != "running" || verifyProcessIdentity(record) != nil {
		return errors.New("managed process identity changed")
	}
	return syscall.Kill(-record.pid, signal)
}

func (b *linuxBackend) killRecord(record *processRecord, signal syscall.Signal) {
	_ = b.signalRecord(record, signal)
}

func (b *linuxBackend) responseFor(record *processRecord, includeOutput bool) Response {
	b.mu.Lock()
	status := statusFor(record)
	b.mu.Unlock()
	response := Response{ProcessID: record.id, Status: status}
	if includeOutput {
		response.Stdout, response.Stderr, response.Truncated = record.output.snapshot()
	}
	return response
}

func statusFor(record *processRecord) *ProcessStatus {
	return &ProcessStatus{
		ProcessID: record.id, State: record.state, StartedAt: record.startedAt,
		FinishedAt: record.finishedAt, ExitCode: record.exitCode, Signaled: record.signaled, TimedOut: record.timedOut,
	}
}

func (b *linuxBackend) revoke(principal, session string) {
	b.mu.Lock()
	var records []*processRecord
	for _, record := range b.items {
		if record.principal == principal && record.sessionID == session {
			records = append(records, record)
		}
	}
	b.mu.Unlock()
	for _, record := range records {
		b.killRecord(record, syscall.SIGKILL)
	}
	for _, record := range records {
		if record.done != nil {
			<-record.done
		}
	}
	b.mu.Lock()
	for _, record := range records {
		delete(b.items, record.id)
	}
	b.mu.Unlock()
}

func (b *linuxBackend) close() {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return
	}
	b.closed = true
	var records []*processRecord
	for _, record := range b.items {
		if record.state == "running" {
			records = append(records, record)
		}
	}
	b.mu.Unlock()
	for _, record := range records {
		b.killRecord(record, syscall.SIGKILL)
	}
	for _, record := range records {
		<-record.done
	}
}

func randomProcessID() (string, error) {
	value := make([]byte, 18)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return "proc-" + base64.RawURLEncoding.EncodeToString(value), nil
}

func cloneEnv(value map[string]string) map[string]string {
	out := make(map[string]string, len(value))
	for name, item := range value {
		out[name] = item
	}
	return out
}

func safeProcessError(error) string {
	return "managed task could not be started with required isolation"
}

func safeMemoryError(err error) string {
	if errors.Is(err, errProcessIdentity) {
		return "managed process identity is no longer valid"
	}
	if errors.Is(err, errMemoryPattern) {
		return "memory scan pattern is invalid"
	}
	return "bounded memory scan failed"
}

type boundedOutput struct {
	mu        sync.Mutex
	remaining int64
	stdout    []byte
	stderr    []byte
	truncated bool
}

type outputWriter struct {
	output *boundedOutput
	stderr bool
}

func newBoundedOutput(limit int64) *boundedOutput    { return &boundedOutput{remaining: limit} }
func (b *boundedOutput) stdoutWriter() *outputWriter { return &outputWriter{output: b} }
func (b *boundedOutput) stderrWriter() *outputWriter { return &outputWriter{output: b, stderr: true} }

func (w *outputWriter) Write(value []byte) (int, error) {
	w.output.mu.Lock()
	defer w.output.mu.Unlock()
	accepted := int64(len(value))
	if accepted > w.output.remaining {
		accepted = w.output.remaining
		w.output.truncated = true
	}
	if accepted > 0 {
		if w.stderr {
			w.output.stderr = append(w.output.stderr, value[:accepted]...)
		} else {
			w.output.stdout = append(w.output.stdout, value[:accepted]...)
		}
		w.output.remaining -= accepted
	}
	return len(value), nil
}

func (b *boundedOutput) snapshot() (string, string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(append([]byte(nil), b.stdout...)), string(append([]byte(nil), b.stderr...)), b.truncated
}
