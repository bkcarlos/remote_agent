package fileworker

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os/exec"
	"time"

	"github.com/bkcarlos/remote_agent/internal/capability"
	"github.com/bkcarlos/remote_agent/internal/workspace"
)

type ProcessExecutor struct {
	binary     string
	root       string
	key        []byte
	caps       *capability.Manager
	timeout    time.Duration
	denied     []string
	cgroupRoot string
}

func NewProcessExecutor(binary, root string, key []byte, timeout time.Duration) (*ProcessExecutor, error) {
	return NewProcessExecutorWithDenied(binary, root, key, timeout, nil)
}

func NewProcessExecutorWithDenied(binary, root string, key []byte, timeout time.Duration, deniedNames []string) (*ProcessExecutor, error) {
	return NewSecureProcessExecutor(binary, root, key, timeout, deniedNames, "")
}

func NewSecureProcessExecutor(binary, root string, key []byte, timeout time.Duration, deniedNames []string, cgroupRoot string) (*ProcessExecutor, error) {
	if binary == "" || root == "" {
		return nil, errors.New("worker binary and workspace are required")
	}
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	caps, err := capability.New(key)
	if err != nil {
		return nil, err
	}
	return &ProcessExecutor{binary: binary, root: root, key: append([]byte(nil), key...), caps: caps, timeout: timeout, denied: append([]string(nil), deniedNames...), cgroupRoot: cgroupRoot}, nil
}

func (e *ProcessExecutor) invoke(operation, path string, configure func(*Job)) (Response, error) {
	requestID, tokenID := randomID("worker-request-"), randomID("cap-")
	token, err := e.caps.Sign(Claims(requestID, operation, path, tokenID))
	if err != nil {
		return Response{}, err
	}
	job := Job{Token: token, RequestID: requestID, Operation: operation, Path: path}
	if configure != nil {
		configure(&job)
	}
	input, err := json.Marshal(job)
	if err != nil {
		return Response{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), e.timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, e.binary, "-workspace", e.root)
	configureWorkerProcess(cmd)
	cgroup, err := prepareCgroup(e.cgroupRoot, tokenID)
	if err != nil {
		return Response{}, err
	}
	defer cgroup.close()
	attachCgroup(cmd.SysProcAttr, cgroup)
	deniedJSON, _ := json.Marshal(e.denied)
	cmd.Env = []string{"REMOTE_AGENT_WORKER_KEY=" + base64.RawStdEncoding.EncodeToString(e.key), "REMOTE_AGENT_DENIED_NAMES=" + string(deniedJSON)}
	cmd.Stdin = bytes.NewReader(input)
	stdout := newBoundedBuffer(MaxJobBytes)
	stderr := newBoundedBuffer(16 << 10)
	cmd.Stdout, cmd.Stderr = stdout, stderr
	runErr := cmd.Run()
	if stdout.exceeded || stderr.exceeded {
		return Response{}, errors.New("file worker output exceeded limit")
	}
	if runErr != nil {
		if ctx.Err() != nil {
			return Response{}, errors.New("file worker timed out")
		}
		return Response{}, fmt.Errorf("file worker failed: %w: %s", runErr, truncate(stderr.String(), 512))
	}
	if stdout.Len() > MaxJobBytes {
		return Response{}, errors.New("file worker response exceeded limit")
	}
	var response Response
	dec := json.NewDecoder(stdout)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&response); err != nil {
		return Response{}, errors.New("file worker returned an invalid response")
	}
	if response.Error != "" {
		return Response{}, errors.New(response.Error)
	}
	return response, nil
}

func (e *ProcessExecutor) ReadFile(path string, max int64) ([]byte, error) {
	r, err := e.invoke("read_file", path, func(j *Job) { j.MaxBytes = max })
	if err != nil {
		return nil, err
	}
	b, err := base64.StdEncoding.DecodeString(r.Content)
	if err != nil {
		return nil, errors.New("file worker returned invalid content")
	}
	return b, nil
}
func (e *ProcessExecutor) List(path string, max int) ([]string, error) {
	r, err := e.invoke("list_dir", path, func(j *Job) { j.MaxEntries = max })
	return r.Entries, err
}
func (e *ProcessExecutor) Checksum(path string) (string, error) {
	r, err := e.invoke("checksum", path, nil)
	return r.Checksum, err
}
func (e *ProcessExecutor) Info(path string) (workspace.FileInfo, error) {
	r, err := e.invoke("file_info", path, nil)
	if err != nil {
		return workspace.FileInfo{}, err
	}
	if r.Info == nil {
		return workspace.FileInfo{}, errors.New("file worker returned no file information")
	}
	return *r.Info, nil
}
func (e *ProcessExecutor) Glob(path, pattern string, maxFiles, maxResults int) ([]string, error) {
	r, err := e.invoke("glob", path, func(j *Job) { j.Pattern, j.MaxFiles, j.MaxResults = pattern, maxFiles, maxResults })
	return r.Paths, err
}
func (e *ProcessExecutor) Grep(path, query string, maxFiles, maxResults int, maxBytes int64) ([]workspace.Match, error) {
	r, err := e.invoke("grep", path, func(j *Job) { j.Query, j.MaxFiles, j.MaxResults, j.MaxBytes = query, maxFiles, maxResults, maxBytes })
	return r.Matches, err
}
func (e *ProcessExecutor) WriteFile(path string, data []byte, expected string, max int64) (string, error) {
	r, err := e.invoke("write_file", path, func(j *Job) {
		j.MaxBytes, j.ExpectedHash = max, expected
		j.Data = base64.StdEncoding.EncodeToString(data)
	})
	return r.Checksum, err
}
func randomID(prefix string) string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("%s%d", prefix, time.Now().UnixNano())
	}
	return prefix + hex.EncodeToString(b)
}

type boundedBuffer struct {
	bytes.Buffer
	max      int
	exceeded bool
}

func newBoundedBuffer(max int) *boundedBuffer { return &boundedBuffer{max: max} }
func (b *boundedBuffer) Write(p []byte) (int, error) {
	remaining := b.max - b.Len()
	if len(p) > remaining {
		if remaining > 0 {
			_, _ = b.Buffer.Write(p[:remaining])
		}
		b.exceeded = true
		return len(p), errors.New("output limit exceeded")
	}
	return b.Buffer.Write(p)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max]
}
