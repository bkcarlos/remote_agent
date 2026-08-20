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
	MaxWriteBytes int64
	DeniedNames   []string
	AllowWrite    bool
}
type Engine struct{ cfg Config }

func New(c Config) *Engine {
	if c.MaxReadBytes <= 0 {
		c.MaxReadBytes = 1 << 20
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
	case "read_file", "list_dir", "checksum", "file_info", "glob", "grep":
		return Decision{true, false, "allow-workspace-read", "workspace read allowed"}
	case "write_file":
		if !e.cfg.AllowWrite {
			return Decision{false, false, "deny-write-disabled", "workspace writes are disabled"}
		}
		return Decision{true, true, "approve-workspace-write", "write requires approval"}
	default:
		return Decision{false, false, "deny-unknown-tool", "tool is not registered"}
	}
}
