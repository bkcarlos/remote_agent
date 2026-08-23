package installer

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

const (
	DefaultServerName = "secure-remote-agent"
	TokenEnvironment  = "REMOTE_AGENT_TOKEN"
)

type Options struct {
	ConfigPath       string
	ServerName       string
	BridgePath       string
	Endpoint         string
	AllowPrivateHTTP bool
	Now              func() time.Time
}

type ConfigDiffSummary struct {
	MCPServerChange           string   `json:"mcp_server_change"`
	MCPServerName             string   `json:"mcp_server_name"`
	MCPServerArguments        []string `json:"mcp_server_arguments,omitempty"`
	PreservedMCPServers       int      `json:"preserved_mcp_servers"`
	PreservedTopLevelSettings int      `json:"preserved_top_level_settings"`
}

type Plan struct {
	ConfigPath string            `json:"config_path"`
	BackupPath string            `json:"backup_path,omitempty"`
	Existed    bool              `json:"existed"`
	Diff       ConfigDiffSummary `json:"config_diff"`
	Before     []byte            `json:"-"`
	After      []byte            `json:"-"`

	testHookAfterTempSync func(string) error
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
	if !st.Mode().IsRegular() {
		return Plan{}, errors.New("stdio bridge must be a regular file")
	}
	if runtime.GOOS != "windows" && st.Mode().Perm()&0111 == 0 {
		return Plan{}, errors.New("stdio bridge must have at least one executable bit set")
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
		root, err = decodeExistingConfig(before)
		if err != nil {
			return Plan{}, err
		}
	} else if !os.IsNotExist(err) {
		return Plan{}, err
	}
	servers := map[string]json.RawMessage{}
	if raw := root["mcpServers"]; len(raw) != 0 {
		servers, err = decodeMCPServers(raw)
		if err != nil {
			return Plan{}, err
		}
	}
	change := "add"
	preservedServers := len(servers)
	if _, exists := servers[name]; exists {
		change = "update"
		preservedServers--
	}
	preservedTopLevel := len(root)
	if _, exists := root["mcpServers"]; exists {
		preservedTopLevel--
	}
	args := bridgeArgs(o.Endpoint, o.AllowPrivateHTTP)
	entry, _ := json.Marshal(map[string]any{
		"command": bridge,
		"args":    args,
	})
	servers[name] = entry
	root["mcpServers"], _ = json.Marshal(servers)
	p.After, err = json.MarshalIndent(root, "", "  ")
	p.After = append(p.After, '\n')
	if err != nil {
		return Plan{}, err
	}
	p.Diff = ConfigDiffSummary{
		MCPServerChange:           change,
		MCPServerName:             name,
		MCPServerArguments:        args,
		PreservedMCPServers:       preservedServers,
		PreservedTopLevelSettings: preservedTopLevel,
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

func bridgeArgs(endpoint string, allowPrivateHTTP bool) []string {
	args := []string{"--endpoint", endpoint}
	u, err := url.Parse(endpoint)
	if err == nil && strings.EqualFold(u.Scheme, "http") && allowPrivateHTTP {
		args = append(args, "--allow-private-http")
	}
	return args
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
	root, err := decodeExistingConfig(before)
	if err != nil {
		return Plan{}, err
	}
	servers := map[string]json.RawMessage{}
	if raw := root["mcpServers"]; len(raw) != 0 {
		servers, err = decodeMCPServers(raw)
		if err != nil {
			return Plan{}, err
		}
	}
	if _, exists := servers[serverName]; !exists {
		return Plan{}, fmt.Errorf("MCP server %q is not installed", serverName)
	}
	preservedTopLevel := len(root)
	if _, exists := root["mcpServers"]; exists {
		preservedTopLevel--
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
	return Plan{
		ConfigPath: path,
		BackupPath: path + ".backup-" + now().UTC().Format("20060102T150405Z"),
		Existed:    true,
		Diff: ConfigDiffSummary{
			MCPServerChange:           "remove",
			MCPServerName:             serverName,
			PreservedMCPServers:       len(servers),
			PreservedTopLevelSettings: preservedTopLevel,
		},
		Before: before,
		After:  after,
	}, nil
}

func Apply(p Plan) error {
	dir := filepath.Dir(p.ConfigPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	lock, err := acquireApplyLock(p.ConfigPath + ".remote-agent-install.lock")
	if err != nil {
		return err
	}
	defer lock.release()

	if _, err := verifyPlanBefore(p); err != nil {
		return err
	}
	if bytes.Equal(p.Before, p.After) {
		return nil
	}
	tmp, err := os.CreateTemp(dir, ".mcp-config-*")
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
	if p.testHookAfterTempSync != nil {
		if err := p.testHookAfterTempSync(tmpName); err != nil {
			return err
		}
	}

	finalBefore, err := verifyPlanBefore(p)
	if err != nil {
		return err
	}
	backupCreated := false
	if p.Existed {
		if err := writeExclusive(p.BackupPath, finalBefore, 0600); err != nil {
			return fmt.Errorf("create backup: %w", err)
		}
		backupCreated = true
		if err := syncDirectory(filepath.Dir(p.BackupPath)); err != nil {
			return fmt.Errorf("sync backup directory: %w", err)
		}
	}
	if _, err := verifyPlanBefore(p); err != nil {
		if backupCreated {
			if removeErr := removeBackup(p.BackupPath); removeErr != nil {
				return fmt.Errorf("%w (also failed to remove unused backup: %v)", err, removeErr)
			}
		}
		return err
	}
	if err := os.Rename(tmpName, p.ConfigPath); err != nil {
		return err
	}
	if err := syncDirectory(dir); err != nil {
		return fmt.Errorf("sync configuration directory: %w", err)
	}
	return nil
}

func verifyPlanBefore(p Plan) ([]byte, error) {
	if !p.Existed {
		if _, err := os.Lstat(p.ConfigPath); err == nil {
			return nil, errors.New("client configuration was created since the plan was created; refusing to apply")
		} else if !os.IsNotExist(err) {
			return nil, fmt.Errorf("verify client configuration before apply: %w", err)
		}
		return nil, nil
	}
	current, err := readRegularFileExactly(p.ConfigPath)
	if err != nil {
		return nil, fmt.Errorf("verify client configuration before apply: %w", err)
	}
	if !bytes.Equal(current, p.Before) {
		return nil, errors.New("client configuration changed since the plan was created; refusing to apply")
	}
	return current, nil
}

func readRegularFileExactly(path string) ([]byte, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !pathInfo.Mode().IsRegular() {
		return nil, errors.New("client configuration is not a regular file")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	openedInfo, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !openedInfo.Mode().IsRegular() || !sameFileObservation(pathInfo, openedInfo) {
		return nil, errors.New("client configuration changed while it was being verified")
	}
	current, err := io.ReadAll(f)
	if err != nil {
		return nil, err
	}
	afterReadInfo, err := f.Stat()
	if err != nil {
		return nil, err
	}
	finalInfo, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if !sameFileObservation(openedInfo, afterReadInfo) || !sameFileObservation(afterReadInfo, finalInfo) {
		return nil, errors.New("client configuration changed while it was being verified")
	}
	return current, nil
}

func sameFileObservation(a, b os.FileInfo) bool {
	return os.SameFile(a, b) &&
		a.Mode() == b.Mode() &&
		a.Size() == b.Size() &&
		a.ModTime().Equal(b.ModTime())
}

func removeBackup(path string) error {
	if err := os.Remove(path); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func writeExclusive(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func syncDirectory(path string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func decodeExistingConfig(data []byte) (map[string]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, errors.New("existing client configuration must be a JSON object")
	}
	if err := validateJSONNoDuplicateKeys(trimmed); err != nil {
		return nil, fmt.Errorf("existing client configuration is not valid JSON: %w", err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &root); err != nil {
		return nil, fmt.Errorf("existing client configuration is not valid JSON: %w", err)
	}
	return root, nil
}

func decodeMCPServers(data []byte) (map[string]json.RawMessage, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return nil, errors.New("mcpServers must be a JSON object")
	}
	var servers map[string]json.RawMessage
	if err := json.Unmarshal(trimmed, &servers); err != nil {
		return nil, errors.New("mcpServers must be a JSON object")
	}
	return servers, nil
}

func validateJSONNoDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := validateJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}

func validateJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delim {
	case '{':
		keys := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("JSON object key must be a string")
			}
			if _, duplicate := keys[key]; duplicate {
				return fmt.Errorf("duplicate JSON object key %q", key)
			}
			keys[key] = struct{}{}
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("invalid JSON object")
		}
	case '[':
		for decoder.More() {
			if err := validateJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("invalid JSON array")
		}
	default:
		return errors.New("unexpected closing JSON delimiter")
	}
	return nil
}

func DefaultConfigPath(client string) (string, error) {
	client = strings.ToLower(client)
	if client == "codex" || client == "codex-json" {
		return "", errors.New("Codex requires an explicit --config path; no default JSON configuration path is assumed")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	switch client {
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
