package execworker

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	OperationExecRun       = "exec_run"
	OperationProcessStart  = "process_start"
	OperationProcessStatus = "process_status"
	OperationProcessStop   = "process_stop"
	OperationDebugStatus   = "debug_status"
	OperationDebugSignal   = "debug_signal"
	OperationMemScan       = "mem_scan"
	OperationSessionRevoke = "session_revoke"

	WorkspaceNone      WorkspaceMode = "none"
	WorkspaceReadOnly  WorkspaceMode = "read_only"
	WorkspaceReadWrite WorkspaceMode = "read_write"

	MemoryHex    = "hex"
	MemoryBase64 = "base64"
)

var envNamePattern = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

type WorkspaceMode string

// Limits are signed into every capability and are also bounded by the selected
// administrator-owned TaskProfile. Clients cannot increase them.
type Limits struct {
	TimeoutMillis int64 `json:"timeout_ms"`
	CPUSeconds    int64 `json:"cpu_seconds"`
	MemoryBytes   int64 `json:"memory_bytes"`
	PIDs          int64 `json:"pids"`
	OutputBytes   int64 `json:"output_bytes"`
	ScanRegions   int   `json:"scan_regions"`
	ScanBytes     int64 `json:"scan_bytes"`
	ScanResults   int   `json:"scan_results"`
}

func (l Limits) Validate() error {
	if l.TimeoutMillis <= 0 || l.CPUSeconds <= 0 || l.MemoryBytes <= 0 || l.PIDs <= 0 || l.OutputBytes <= 0 {
		return errors.New("execution limits must be positive")
	}
	if l.TimeoutMillis > int64((24*time.Hour)/time.Millisecond) || l.CPUSeconds > 86400 || l.MemoryBytes > 1<<50 || l.PIDs > 1<<20 || l.OutputBytes > 2<<20 {
		return errors.New("execution limits exceed hard safety bounds")
	}
	if l.ScanRegions < 0 || l.ScanBytes < 0 || l.ScanResults < 0 || l.ScanRegions > 4096 || l.ScanBytes > 1<<30 || l.ScanResults > 10000 {
		return errors.New("memory scan limits are invalid")
	}
	return nil
}

func (l Limits) Within(max Limits) bool {
	return l.TimeoutMillis <= max.TimeoutMillis && l.CPUSeconds <= max.CPUSeconds &&
		l.MemoryBytes <= max.MemoryBytes && l.PIDs <= max.PIDs && l.OutputBytes <= max.OutputBytes &&
		l.ScanRegions <= max.ScanRegions && l.ScanBytes <= max.ScanBytes && l.ScanResults <= max.ScanResults
}

// TaskProfile is trusted administrator configuration. Executable is never
// supplied by a protocol client. FixedArgv is always prepended; any requested
// argv must begin with one of AllowedArgvPrefixes. An empty prefix is rejected.
type TaskProfile struct {
	Name                string        `json:"name"`
	Executable          string        `json:"executable"`
	FixedArgv           []string      `json:"fixed_argv,omitempty"`
	AllowedArgvPrefixes [][]string    `json:"allowed_argv_prefixes,omitempty"`
	WorkspaceMode       WorkspaceMode `json:"workspace_mode"`
	EnvAllowlist        []string      `json:"env_allowlist,omitempty"`
	CachePaths          []string      `json:"cache_paths,omitempty"`
	Limits              Limits        `json:"limits"`
}

func (p TaskProfile) Validate() error {
	if p.Name == "" || strings.IndexByte(p.Name, 0) >= 0 {
		return errors.New("profile name is required")
	}
	if p.Executable == "" || !filepath.IsAbs(p.Executable) || strings.IndexByte(p.Executable, 0) >= 0 {
		return errors.New("profile executable must be an absolute path")
	}
	switch p.WorkspaceMode {
	case WorkspaceNone, WorkspaceReadOnly, WorkspaceReadWrite:
	default:
		return errors.New("profile workspace mode is invalid")
	}
	if err := p.Limits.Validate(); err != nil {
		return fmt.Errorf("profile limits: %w", err)
	}
	for _, arg := range p.FixedArgv {
		if strings.IndexByte(arg, 0) >= 0 {
			return errors.New("profile argv contains NUL")
		}
	}
	for _, prefix := range p.AllowedArgvPrefixes {
		if len(prefix) == 0 {
			return errors.New("empty allowed argv prefix would allow arbitrary arguments")
		}
		for _, arg := range prefix {
			if strings.IndexByte(arg, 0) >= 0 {
				return errors.New("allowed argv prefix contains NUL")
			}
		}
	}
	seen := make(map[string]struct{}, len(p.EnvAllowlist))
	for _, name := range p.EnvAllowlist {
		if !envNamePattern.MatchString(name) {
			return fmt.Errorf("invalid environment variable name %q", name)
		}
		if _, exists := seen[name]; exists {
			return fmt.Errorf("duplicate environment variable name %q", name)
		}
		seen[name] = struct{}{}
	}
	if len(p.CachePaths) > 16 {
		return errors.New("profile cache path count exceeds 16")
	}
	seenPaths := make(map[string]struct{}, len(p.CachePaths))
	for _, cachePath := range p.CachePaths {
		if err := validateCachePath(cachePath); err != nil {
			return err
		}
		clean := filepath.Clean(cachePath)
		if _, exists := seenPaths[clean]; exists {
			return errors.New("profile cache paths must be unique")
		}
		seenPaths[clean] = struct{}{}
	}
	return nil
}

func validateCachePath(value string) error {
	if value == "" || strings.IndexByte(value, 0) >= 0 || !filepath.IsAbs(value) || filepath.Clean(value) != value {
		return errors.New("profile cache paths must be clean absolute paths")
	}
	if value == string(filepath.Separator) {
		return errors.New("profile cache path cannot grant filesystem root")
	}
	if filepath.Separator == '/' {
		for _, denied := range []string{"/proc", "/sys", "/dev", "/run", "/var/run"} {
			if value == denied || strings.HasPrefix(value, denied+"/") {
				return errors.New("profile cache path targets a container-sensitive filesystem tree")
			}
		}
	}
	return nil
}

func (p TaskProfile) AllowsArgv(argv []string) bool {
	if len(argv) == 0 {
		return true
	}
	for _, prefix := range p.AllowedArgvPrefixes {
		if hasStringPrefix(argv, prefix) {
			return true
		}
	}
	return false
}

func (p TaskProfile) AllowsEnv(env map[string]string) bool {
	allowed := make(map[string]struct{}, len(p.EnvAllowlist))
	for _, name := range p.EnvAllowlist {
		allowed[name] = struct{}{}
	}
	for name, value := range env {
		if _, ok := allowed[name]; !ok || !envNamePattern.MatchString(name) || strings.IndexByte(value, 0) >= 0 {
			return false
		}
	}
	return true
}

func (p TaskProfile) Digest() (string, error) {
	if err := p.Validate(); err != nil {
		return "", err
	}
	canonical := p
	canonical.FixedArgv = append([]string(nil), p.FixedArgv...)
	canonical.EnvAllowlist = append([]string(nil), p.EnvAllowlist...)
	sort.Strings(canonical.EnvAllowlist)
	canonical.CachePaths = append([]string(nil), p.CachePaths...)
	sort.Strings(canonical.CachePaths)
	canonical.AllowedArgvPrefixes = clonePrefixes(p.AllowedArgvPrefixes)
	sort.Slice(canonical.AllowedArgvPrefixes, func(i, j int) bool {
		left, _ := json.Marshal(canonical.AllowedArgvPrefixes[i])
		right, _ := json.Marshal(canonical.AllowedArgvPrefixes[j])
		return string(left) < string(right)
	})
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func clonePrefixes(in [][]string) [][]string {
	out := make([][]string, len(in))
	for i := range in {
		out[i] = append([]string(nil), in[i]...)
	}
	return out
}

func hasStringPrefix(value, prefix []string) bool {
	if len(value) < len(prefix) {
		return false
	}
	for i := range prefix {
		if value[i] != prefix[i] {
			return false
		}
	}
	return true
}

type MemoryScan struct {
	Pattern        string `json:"pattern"`
	Mode           string `json:"mode"`
	IncludeContext bool   `json:"include_context,omitempty"`
}

// Job never contains an executable, shell command, or host PID. ProcessID is
// an opaque supervisor-issued handle and is resolved only inside the owner
// principal/session namespace.
type Job struct {
	Token        string            `json:"token"`
	CapabilityID string            `json:"capability_id"`
	Principal    string            `json:"principal"`
	SessionID    string            `json:"session_id"`
	WorkspaceID  string            `json:"workspace_id"`
	TaskID       string            `json:"task_id"`
	Profile      string            `json:"profile"`
	Operation    string            `json:"operation"`
	Limits       Limits            `json:"limits"`
	Argv         []string          `json:"argv,omitempty"`
	Env          map[string]string `json:"env,omitempty"`
	ProcessID    string            `json:"process_id,omitempty"`
	Signal       string            `json:"signal,omitempty"`
	Memory       *MemoryScan       `json:"memory,omitempty"`
}

type Request struct {
	Cookie string `json:"cookie"`
	Job    Job    `json:"job"`
}

type ProcessStatus struct {
	ProcessID  string    `json:"process_id"`
	State      string    `json:"state"`
	StartedAt  time.Time `json:"started_at"`
	FinishedAt time.Time `json:"finished_at,omitempty"`
	ExitCode   int       `json:"exit_code,omitempty"`
	Signaled   bool      `json:"signaled,omitempty"`
	TimedOut   bool      `json:"timed_out,omitempty"`
}

type MemoryMatch struct {
	RegionIndex int    `json:"region_index"`
	Offset      int64  `json:"offset"`
	Digest      string `json:"sha256"`
	Context     string `json:"context,omitempty"`
	ContextMode string `json:"context_mode,omitempty"`
	Sensitive   bool   `json:"sensitive,omitempty"`
}

type Response struct {
	CapabilityID string         `json:"capability_id,omitempty"`
	ProcessID    string         `json:"process_id,omitempty"`
	Status       *ProcessStatus `json:"status,omitempty"`
	Stdout       string         `json:"stdout,omitempty"`
	Stderr       string         `json:"stderr,omitempty"`
	Truncated    bool           `json:"truncated,omitempty"`
	Matches      []MemoryMatch  `json:"matches,omitempty"`
	ScannedBytes int64          `json:"scanned_bytes,omitempty"`
	Error        string         `json:"error,omitempty"`
}
