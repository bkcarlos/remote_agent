package execworker

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var ErrUnsupported = errors.New("exec worker is supported only on Linux")

type Config struct {
	SocketPath   string
	Cookie       string
	PublicKey    ed25519.PublicKey
	Profiles     map[string]TaskProfile
	Workspaces   map[string]string
	WorkerBinary string
	CgroupRoot   string
	Production   bool
}

type configuredProfile struct {
	profile TaskProfile
	digest  string
}

type backend interface {
	execute(Job, TaskProfile, string) Response
	revoke(principal, session string)
	close()
}

type sessionOwner struct {
	principal string
	sessionID string
}

type Supervisor struct {
	config   Config
	cookie   string
	caps     *CapabilityVerifier
	profiles map[string]configuredProfile
	roots    map[string]string
	backend  backend

	executionMu sync.Mutex
	revoked     map[sessionOwner]struct{}
	mu          sync.Mutex
	listener    net.Listener
	closed      bool
}

func GenerateCookie() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func NewSupervisor(config Config) (*Supervisor, error) {
	if err := platformSupported(); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(config.SocketPath) || config.WorkerBinary == "" || !filepath.IsAbs(config.WorkerBinary) {
		return nil, errors.New("absolute socket path and worker binary are required")
	}
	cookieRaw, err := base64.RawURLEncoding.DecodeString(config.Cookie)
	if err != nil || len(cookieRaw) != 32 || base64.RawURLEncoding.EncodeToString(cookieRaw) != config.Cookie {
		return nil, errors.New("exec supervisor cookie must be canonical base64url encoding of 32 random bytes")
	}
	caps, err := NewCapabilityVerifier(config.PublicKey)
	if err != nil {
		return nil, err
	}
	profiles := make(map[string]configuredProfile, len(config.Profiles))
	for key, profile := range config.Profiles {
		if key == "" || key != profile.Name {
			return nil, errors.New("profile map key must equal profile name")
		}
		digest, err := profile.Digest()
		if err != nil {
			return nil, fmt.Errorf("profile %q: %w", key, err)
		}
		profiles[key] = configuredProfile{profile: profile, digest: digest}
	}
	if len(profiles) == 0 {
		return nil, errors.New("at least one administrator task profile is required")
	}
	roots := make(map[string]string, len(config.Workspaces))
	for id, root := range config.Workspaces {
		if id == "" || strings.IndexByte(id, 0) >= 0 || !filepath.IsAbs(root) {
			return nil, errors.New("workspace IDs and absolute roots are required")
		}
		canonical, err := filepath.EvalSymlinks(root)
		if err != nil {
			return nil, fmt.Errorf("workspace %q is unavailable", id)
		}
		info, err := os.Stat(canonical)
		if err != nil || !info.IsDir() {
			return nil, fmt.Errorf("workspace %q is not a directory", id)
		}
		roots[id] = canonical
	}
	if len(roots) == 0 {
		return nil, errors.New("at least one trusted workspace is required")
	}
	back, err := newBackend(config)
	if err != nil {
		return nil, err
	}
	return &Supervisor{
		config: config, cookie: config.Cookie, caps: caps, profiles: profiles, roots: roots,
		backend: back, revoked: make(map[sessionOwner]struct{}),
	}, nil
}

func (s *Supervisor) ListenAndServe(ctx context.Context) error {
	if err := prepareSocketPath(s.config.SocketPath); err != nil {
		return err
	}
	listener, err := net.Listen("unix", s.config.SocketPath)
	if err != nil {
		return fmt.Errorf("listen on exec supervisor socket: %w", err)
	}
	if err := os.Chmod(s.config.SocketPath, 0o600); err != nil {
		listener.Close()
		_ = os.Remove(s.config.SocketPath)
		return fmt.Errorf("secure exec supervisor socket: %w", err)
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		listener.Close()
		_ = os.Remove(s.config.SocketPath)
		return net.ErrClosed
	}
	s.listener = listener
	s.mu.Unlock()

	go func() {
		<-ctx.Done()
		s.Close()
	}()
	for {
		connection, err := listener.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.serveConnection(connection)
	}
}

func (s *Supervisor) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	listener := s.listener
	s.mu.Unlock()
	if listener != nil {
		_ = listener.Close()
	}
	s.backend.close()
	_ = os.Remove(s.config.SocketPath)
	return nil
}

func (s *Supervisor) serveConnection(connection net.Conn) {
	defer connection.Close()
	for {
		var request Request
		if err := ReadFrame(connection, &request); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				_ = WriteFrame(connection, Response{Error: "invalid exec supervisor frame"})
			}
			return
		}
		response := s.handle(request)
		if err := WriteFrame(connection, response); err != nil {
			return
		}
	}
}

func (s *Supervisor) handle(request Request) Response {
	job := request.Job
	response := Response{CapabilityID: job.CapabilityID}
	if subtle.ConstantTimeCompare([]byte(request.Cookie), []byte(s.cookie)) != 1 {
		response.Error = "exec supervisor authentication rejected"
		return response
	}
	configured, ok := s.profiles[job.Profile]
	if !ok {
		response.Error = "task profile is not configured"
		return response
	}
	root, ok := s.roots[job.WorkspaceID]
	if !ok {
		response.Error = "workspace is not configured"
		return response
	}
	if err := validateJob(job, configured.profile); err != nil {
		response.Error = err.Error()
		return response
	}
	expected, err := ClaimsForJob(job, configured.digest, jobExpiryPlaceholder())
	if err != nil {
		response.Error = "invalid exec capability scope"
		return response
	}
	if _, err := s.caps.Verify(job.Token, expected); err != nil {
		response.Error = "exec capability rejected: " + err.Error()
		return response
	}
	return s.executeAuthorized(job, configured.profile, root)
}

func (s *Supervisor) executeAuthorized(job Job, profile TaskProfile, root string) Response {
	response := Response{CapabilityID: job.CapabilityID}
	owner := sessionOwner{principal: job.Principal, sessionID: job.SessionID}
	if job.Operation == OperationSessionRevoke {
		s.executionMu.Lock()
		if s.revoked == nil {
			s.revoked = make(map[sessionOwner]struct{})
		}
		s.revoked[owner] = struct{}{}
		s.executionMu.Unlock()
		s.backend.revoke(job.Principal, job.SessionID)
		return response
	}
	if job.Operation == OperationProcessStart {
		s.executionMu.Lock()
		if _, revoked := s.revoked[owner]; revoked {
			s.executionMu.Unlock()
			response.Error = "exec session has been revoked"
			return response
		}
		result := s.backend.execute(job, profile, root)
		s.executionMu.Unlock()
		result.CapabilityID = job.CapabilityID
		return result
	}
	s.executionMu.Lock()
	_, revoked := s.revoked[owner]
	s.executionMu.Unlock()
	if revoked {
		response.Error = "exec session has been revoked"
		return response
	}
	result := s.backend.execute(job, profile, root)
	result.CapabilityID = job.CapabilityID
	return result
}

// Verify supplies the actual expiry from the signed token, so only a non-zero
// placeholder is needed while constructing the expected scope.
func jobExpiryPlaceholder() (value time.Time) { return time.Unix(1, 0).UTC() }

func validateJob(job Job, profile TaskProfile) error {
	if job.Token == "" || job.CapabilityID == "" || job.Principal == "" || job.SessionID == "" || job.WorkspaceID == "" || job.TaskID == "" || job.Profile == "" {
		return errors.New("exec job scope is incomplete")
	}
	if job.Profile != profile.Name || !job.Limits.Within(profile.Limits) {
		return errors.New("exec job exceeds task profile")
	}
	if err := job.Limits.Validate(); err != nil {
		return errors.New("exec job limits are invalid")
	}
	for _, arg := range job.Argv {
		if strings.IndexByte(arg, 0) >= 0 {
			return errors.New("exec argv contains NUL")
		}
	}
	if !profile.AllowsArgv(job.Argv) || !profile.AllowsEnv(job.Env) {
		return errors.New("exec argv or environment is not allowed by task profile")
	}
	hasLaunchInput := len(job.Argv) != 0 || len(job.Env) != 0
	switch job.Operation {
	case OperationExecRun, OperationProcessStart:
		if job.ProcessID != "" || job.Signal != "" || job.Memory != nil {
			return errors.New("launch job contains unrelated fields")
		}
	case OperationProcessStatus, OperationProcessStop, OperationDebugStatus:
		if job.ProcessID == "" || hasLaunchInput || job.Signal != "" || job.Memory != nil {
			return errors.New("process job fields are invalid")
		}
	case OperationDebugSignal:
		if job.ProcessID == "" || hasLaunchInput || job.Memory != nil || !allowedDebugSignal(job.Signal) {
			return errors.New("debug signal job is invalid")
		}
	case OperationMemScan:
		if job.ProcessID == "" || hasLaunchInput || job.Signal != "" || job.Memory == nil || (job.Memory.Mode != MemoryHex && job.Memory.Mode != MemoryBase64) {
			return errors.New("memory scan job is invalid")
		}
		if job.Limits.ScanRegions <= 0 || job.Limits.ScanBytes <= 0 || job.Limits.ScanResults <= 0 {
			return errors.New("memory scan requires positive signed scan limits")
		}
	case OperationSessionRevoke:
		if job.ProcessID != "" || hasLaunchInput || job.Signal != "" || job.Memory != nil {
			return errors.New("session revoke job contains unrelated fields")
		}
	default:
		return errors.New("exec operation is not supported")
	}
	return nil
}

func allowedDebugSignal(value string) bool {
	switch value {
	case "stop", "continue", "interrupt", "terminate":
		return true
	default:
		return false
	}
}

func prepareSocketPath(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return errors.New("exec supervisor socket path already exists and is not a socket")
	}
	return os.Remove(path)
}
