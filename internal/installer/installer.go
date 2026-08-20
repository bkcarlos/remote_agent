package installer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const DefaultServerName = "secure-remote-agent"

type Options struct {
	ConfigPath       string
	ServerName       string
	BridgePath       string
	Endpoint         string
	AllowPrivateHTTP bool
	Now              func() time.Time
}

type Plan struct {
	ConfigPath string `json:"config_path"`
	BackupPath string `json:"backup_path,omitempty"`
	Existed    bool   `json:"existed"`
	Before     []byte `json:"-"`
	After      []byte `json:"-"`
}

func ValidateEndpoint(raw string, allowPrivateHTTP bool) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User != nil {
		return errors.New("endpoint must be an absolute HTTP(S) URL without user info")
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("endpoint scheme must be http or https")
	}
	if u.Fragment != "" {
		return errors.New("endpoint must not contain a fragment")
	}
	if u.Scheme == "https" {
		return nil
	}
	if !allowPrivateHTTP {
		return errors.New("HTTP requires explicit --allow-private-http")
	}
	host := u.Hostname()
	if strings.EqualFold(host, "localhost") {
		return nil
	}
	ip := net.ParseIP(host)
	if ip == nil || (!ip.IsPrivate() && !ip.IsLoopback()) {
		return errors.New("HTTP endpoint must use localhost or a private IP address")
	}
	return nil
}

func PlanInstall(o Options) (Plan, error) {
	if o.ConfigPath == "" || o.BridgePath == "" {
		return Plan{}, errors.New("config path and bridge path are required")
	}
	if err := ValidateEndpoint(o.Endpoint, o.AllowPrivateHTTP); err != nil {
		return Plan{}, err
	}
	bridge, err := filepath.Abs(o.BridgePath)
	if err != nil {
		return Plan{}, err
	}
	st, err := os.Stat(bridge)
	if err != nil {
		return Plan{}, fmt.Errorf("stdio bridge: %w", err)
	}
	if st.IsDir() {
		return Plan{}, errors.New("stdio bridge path is a directory")
	}
	name := o.ServerName
	if name == "" {
		name = DefaultServerName
	}
	path, err := filepath.Abs(o.ConfigPath)
	if err != nil {
		return Plan{}, err
	}
	p := Plan{ConfigPath: path}
	root := map[string]json.RawMessage{}
	before, err := os.ReadFile(path)
	if err == nil {
		p.Existed, p.Before = true, before
		if len(bytes.TrimSpace(before)) != 0 && json.Unmarshal(before, &root) != nil {
			return Plan{}, errors.New("existing client configuration is not valid JSON")
		}
	} else if !os.IsNotExist(err) {
		return Plan{}, err
	}
	servers := map[string]json.RawMessage{}
	if raw := root["mcpServers"]; len(raw) != 0 {
		if err := json.Unmarshal(raw, &servers); err != nil {
			return Plan{}, errors.New("mcpServers must be a JSON object")
		}
	}
	entry, _ := json.Marshal(map[string]any{
		"command": bridge,
		"args":    []string{"-endpoint", o.Endpoint},
	})
	servers[name] = entry
	root["mcpServers"], _ = json.Marshal(servers)
	p.After, err = json.MarshalIndent(root, "", "  ")
	p.After = append(p.After, '\n')
	if err != nil {
		return Plan{}, err
	}
	if p.Existed {
		now := time.Now
		if o.Now != nil {
			now = o.Now
		}
		p.BackupPath = path + ".backup-" + now().UTC().Format("20060102T150405Z")
	}
	return p, nil
}

func PlanUninstall(configPath, serverName string, now func() time.Time) (Plan, error) {
	if configPath == "" {
		return Plan{}, errors.New("config path is required")
	}
	if serverName == "" {
		serverName = DefaultServerName
	}
	path, err := filepath.Abs(configPath)
	if err != nil {
		return Plan{}, err
	}
	before, err := os.ReadFile(path)
	if err != nil {
		return Plan{}, err
	}
	root := map[string]json.RawMessage{}
	if json.Unmarshal(before, &root) != nil {
		return Plan{}, errors.New("existing client configuration is not valid JSON")
	}
	servers := map[string]json.RawMessage{}
	if raw := root["mcpServers"]; len(raw) != 0 {
		if json.Unmarshal(raw, &servers) != nil {
			return Plan{}, errors.New("mcpServers must be a JSON object")
		}
	}
	if _, exists := servers[serverName]; !exists {
		return Plan{}, fmt.Errorf("MCP server %q is not installed", serverName)
	}
	delete(servers, serverName)
	root["mcpServers"], _ = json.Marshal(servers)
	after, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return Plan{}, err
	}
	after = append(after, '\n')
	if now == nil {
		now = time.Now
	}
	return Plan{ConfigPath: path, BackupPath: path + ".backup-" + now().UTC().Format("20060102T150405Z"), Existed: true, Before: before, After: after}, nil
}

func Apply(p Plan) error {
	if bytes.Equal(p.Before, p.After) {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(p.ConfigPath), 0700); err != nil {
		return err
	}
	if p.Existed {
		if err := writeExclusive(p.BackupPath, p.Before, 0600); err != nil {
			return fmt.Errorf("create backup: %w", err)
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(p.ConfigPath), ".mcp-config-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err = tmp.Chmod(0600); err == nil {
		_, err = tmp.Write(p.After)
	}
	if err == nil {
		err = tmp.Sync()
	}
	closeErr := tmp.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	return os.Rename(tmpName, p.ConfigPath)
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func DefaultConfigPath(client string) (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch strings.ToLower(client) {
	case "claude":
		switch runtime.GOOS {
		case "darwin":
			return filepath.Join(home, "Library", "Application Support", "Claude", "claude_desktop_config.json"), nil
		case "windows":
			if appData := os.Getenv("APPDATA"); appData != "" {
				return filepath.Join(appData, "Claude", "claude_desktop_config.json"), nil
			}
			return "", errors.New("APPDATA is not set")
		default:
			return filepath.Join(home, ".config", "Claude", "claude_desktop_config.json"), nil
		}
	case "cursor":
		return filepath.Join(home, ".cursor", "mcp.json"), nil
	case "windsurf":
		return filepath.Join(home, ".codeium", "windsurf", "mcp_config.json"), nil
	case "claude-code":
		return filepath.Join(home, ".claude.json"), nil
	default:
		return "", errors.New("unknown client; provide --config explicitly")
	}
}
