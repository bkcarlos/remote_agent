package policy

import (
	"fmt"
	"path/filepath"
	"strings"
)

type Risk int

const (
	L0 Risk = iota
	L1
	L2
	L3
	L4
)

type Decision struct {
	Allowed  bool   `json:"allowed"`
	Approval bool   `json:"approval_required"`
	PolicyID string `json:"policy_id"`
	Reason   string `json:"reason"`
}

type Config struct {
	MaxReadBytes  int64
	MaxScanBytes  int64
	MaxWriteBytes int64
	DeniedNames   []string
	AllowWrite    bool
	AllowNetwork  bool
	AllowRemote   bool
	AllowExec     bool
	AllowDebug    bool
	AllowMem      bool
}
type Engine struct{ cfg Config }

func New(c Config) *Engine {
	if c.MaxReadBytes <= 0 {
		c.MaxReadBytes = 1 << 20
	}
	if c.MaxScanBytes <= 0 {
		c.MaxScanBytes = 64 << 20
	}
	if c.MaxWriteBytes <= 0 {
		c.MaxWriteBytes = 1 << 20
	}
	defaults := []string{".env", "id_rsa", "id_ed25519", ".aws", ".ssh", ".gnupg"}
	seen := map[string]bool{}
	for _, name := range c.DeniedNames {
		seen[strings.ToLower(name)] = true
	}
	for _, name := range defaults {
		if !seen[name] {
			c.DeniedNames = append(c.DeniedNames, name)
		}
	}
	return &Engine{cfg: c}
}
func (e *Engine) MaxReadBytes() int64   { return e.cfg.MaxReadBytes }
func (e *Engine) MaxScanBytes() int64   { return e.cfg.MaxScanBytes }
func (e *Engine) MaxWriteBytes() int64  { return e.cfg.MaxWriteBytes }
func (e *Engine) DeniedNames() []string { return append([]string(nil), e.cfg.DeniedNames...) }
func (e *Engine) Evaluate(tool, path string) Decision {
	base := strings.ToLower(filepath.Base(path))
	clean := strings.ToLower(filepath.ToSlash(path))
	for _, n := range e.cfg.DeniedNames {
		n = strings.ToLower(n)
		if base == n || strings.Contains("/"+clean+"/", "/"+n+"/") {
			return Decision{false, false, "deny-sensitive-path", fmt.Sprintf("path is denied by policy: %s", n)}
		}
	}
	switch tool {
	case "read_file", "multi_read", "list_dir", "checksum", "file_info", "glob", "grep", "diff":
		return Decision{true, false, "allow-workspace-read", "workspace read allowed"}
	case "write_file", "edit", "multi_edit":
		if !e.cfg.AllowWrite {
			return Decision{false, false, "deny-write-disabled", "workspace writes are disabled"}
		}
		return Decision{true, true, "approve-workspace-write", "write requires approval"}
	case "web_fetch", "upload":
		if !e.cfg.AllowNetwork {
			return Decision{false, false, "deny-network-disabled", "network tools are disabled"}
		}
		return Decision{true, tool == "upload", "allow-network-profile", "network profile access allowed"}
	case "download":
		if !e.cfg.AllowNetwork {
			return Decision{false, false, "deny-network-disabled", "network tools are disabled"}
		}
		if !e.cfg.AllowWrite {
			return Decision{false, false, "deny-write-disabled", "workspace writes are disabled"}
		}
		return Decision{true, true, "approve-network-download", "network download to workspace requires approval"}
	case "ssh_exec", "sftp_list", "sftp_read", "sftp_write", "sftp_mkdir", "sftp_rename":
		if !e.cfg.AllowRemote {
			return Decision{false, false, "deny-remote-disabled", "remote tools are disabled"}
		}
		approval := tool != "sftp_list" && tool != "sftp_read"
		return Decision{true, approval, "allow-remote-profile", "remote profile access allowed"}
	case "exec_run", "process_start", "process_status", "process_stop":
		if !e.cfg.AllowExec {
			return Decision{false, false, "deny-exec-disabled", "execution tools are disabled"}
		}
		return Decision{true, tool == "process_stop", "allow-exec-profile", "administrator task profile allowed"}
	case "debug_status", "debug_signal":
		if !e.cfg.AllowDebug {
			return Decision{false, false, "deny-debug-disabled", "debug tools are disabled"}
		}
		return Decision{true, tool == "debug_signal", "allow-debug-profile", "managed child debugging allowed"}
	case "mem_scan":
		if !e.cfg.AllowMem {
			return Decision{false, false, "deny-mem-disabled", "memory tools are disabled"}
		}
		return Decision{true, true, "allow-mem-profile", "managed child memory scan allowed"}
	default:
		return Decision{false, false, "deny-unknown-tool", "tool is not registered"}
	}
}
