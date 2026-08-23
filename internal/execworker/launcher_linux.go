//go:build linux

package execworker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

type LaunchConfig struct {
	Binary        string
	SocketDir     string
	CgroupRoot    string
	Production    bool
	WorkspaceID   string
	WorkspaceRoot string
	Administrator AdministratorConfig
	ReadyTimeout  time.Duration
}

// Runtime owns one long-lived supervisor and one independent capability key for
// exactly one workspace. Closing it terminates managed children and removes all
// runtime credentials, configuration, socket, and logs.
type Runtime struct {
	Client   Client
	Signer   *CapabilitySigner
	Profiles map[string]TaskProfile

	mu        sync.Mutex
	command   *exec.Cmd
	dir       string
	cgroupDir string
	done      chan error
	closed    bool
}

func Launch(config LaunchConfig) (*Runtime, error) {
	if config.Binary == "" || !filepath.IsAbs(config.Binary) || config.SocketDir == "" || !filepath.IsAbs(config.SocketDir) {
		return nil, errors.New("exec worker binary and socket directory must be absolute paths")
	}
	if config.WorkspaceID == "" || config.WorkspaceRoot == "" || !filepath.IsAbs(config.WorkspaceRoot) {
		return nil, errors.New("exec workspace identity and absolute root are required")
	}
	if _, err := ParseAdministratorConfig(mustAdministratorJSON(RuntimeConfig{Version: config.Administrator.Version, Profiles: config.Administrator.Profiles})); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(config.SocketDir, 0o700); err != nil {
		return nil, errors.New("create exec socket directory")
	}
	dir, err := os.MkdirTemp(config.SocketDir, "remote-agent-exec-*")
	if err != nil {
		return nil, errors.New("create exec runtime directory")
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	if err := os.Chmod(dir, 0o700); err != nil {
		cleanup()
		return nil, errors.New("secure exec runtime directory")
	}
	cgroupDir, err := prepareRuntimeCgroup(config.CgroupRoot, config.Production)
	if err != nil {
		cleanup()
		return nil, err
	}
	cleanupRuntime := func() {
		cleanup()
		if cgroupDir != "" {
			_ = os.Remove(cgroupDir)
		}
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		cleanupRuntime()
		return nil, errors.New("generate exec capability key")
	}
	signer, err := NewCapabilitySignerFromSeed(seed)
	for i := range seed {
		seed[i] = 0
	}
	if err != nil {
		cleanupRuntime()
		return nil, err
	}
	cookie, err := GenerateCookie()
	if err != nil {
		cleanupRuntime()
		return nil, errors.New("generate exec supervisor cookie")
	}
	runtimeConfig := struct {
		Profiles   []TaskProfile     `json:"profiles"`
		Workspaces map[string]string `json:"workspaces"`
	}{Profiles: config.Administrator.Profiles, Workspaces: map[string]string{config.WorkspaceID: config.WorkspaceRoot}}
	configRaw, err := json.Marshal(runtimeConfig)
	if err != nil {
		cleanupRuntime()
		return nil, err
	}
	configPath := filepath.Join(dir, "runtime.json")
	cookiePath := filepath.Join(dir, "cookie")
	publicKeyPath := filepath.Join(dir, "public-key")
	socketPath := filepath.Join(dir, "exec.sock")
	for path, value := range map[string][]byte{
		configPath:    configRaw,
		cookiePath:    []byte(cookie),
		publicKeyPath: []byte(base64.RawStdEncoding.EncodeToString(signer.PublicKey())),
	} {
		if err := os.WriteFile(path, value, 0o600); err != nil {
			cleanupRuntime()
			return nil, errors.New("write exec runtime file")
		}
	}
	logFile, err := os.OpenFile(filepath.Join(dir, "worker.log"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		cleanupRuntime()
		return nil, errors.New("open exec worker log")
	}
	arguments := []string{"-socket", socketPath, "-config", configPath, "-cgroup-root", cgroupDir, fmt.Sprintf("-production=%t", config.Production)}
	command := exec.Command(config.Binary, arguments...)
	command.Dir = dir
	command.Env = []string{
		"REMOTE_AGENT_EXEC_COOKIE=" + cookie,
		"REMOTE_AGENT_EXEC_PUBLIC_KEY=" + base64.RawStdEncoding.EncodeToString(signer.PublicKey()),
	}
	command.Stdout = logFile
	command.Stderr = logFile
	command.SysProcAttr = &syscall.SysProcAttr{Pdeathsig: syscall.SIGKILL, Setpgid: true}
	if err := command.Start(); err != nil {
		logFile.Close()
		cleanupRuntime()
		return nil, errors.New("start exec worker")
	}
	done := make(chan error, 1)
	go func() {
		done <- command.Wait()
		_ = logFile.Close()
	}()
	readyTimeout := config.ReadyTimeout
	if readyTimeout <= 0 {
		readyTimeout = 5 * time.Second
	}
	deadline := time.Now().Add(readyTimeout)
	for {
		connection, dialErr := net.DialTimeout("unix", socketPath, 50*time.Millisecond)
		if dialErr == nil {
			_ = connection.Close()
			break
		}
		select {
		case <-done:
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			cleanupRuntime()
			return nil, errors.New("exec worker exited before ready")
		default:
		}
		if time.Now().After(deadline) {
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			<-done
			cleanupRuntime()
			return nil, errors.New("exec worker did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return &Runtime{
		Client: Client{SocketPath: socketPath, Cookie: cookie, Timeout: 30 * time.Second},
		Signer: signer, Profiles: config.Administrator.ProfileMap(), command: command,
		dir: dir, cgroupDir: cgroupDir, done: done,
	}, nil
}

func (runtime *Runtime) Do(ctx context.Context, job Job) (Response, error) {
	if runtime == nil {
		return Response{}, errors.New("exec runtime is not configured")
	}
	return runtime.Client.Do(ctx, job)
}

func (runtime *Runtime) Close() error {
	if runtime == nil {
		return nil
	}
	runtime.mu.Lock()
	if runtime.closed {
		runtime.mu.Unlock()
		return nil
	}
	runtime.closed = true
	command, done, dir, cgroupDir := runtime.command, runtime.done, runtime.dir, runtime.cgroupDir
	runtime.mu.Unlock()
	if command != nil && command.Process != nil {
		_ = syscall.Kill(-command.Process.Pid, syscall.SIGTERM)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			_ = syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
			<-done
		}
	}
	dirErr := os.RemoveAll(dir)
	if cgroupDir != "" {
		if cgroupErr := os.Remove(cgroupDir); dirErr == nil && cgroupErr != nil && !os.IsNotExist(cgroupErr) {
			dirErr = cgroupErr
		}
	}
	return dirErr
}
