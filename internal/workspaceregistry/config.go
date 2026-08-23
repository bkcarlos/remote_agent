package workspaceregistry

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	// CurrentVersion is the only configuration schema understood by this package.
	CurrentVersion = "v1"
	maxConfigSize  = 1 << 20
	minIDLength    = 16
	maxIDLength    = 256
)

// Config is a trusted startup configuration. Callers must choose the file path
// from trusted process configuration rather than from an untrusted request.
type Config struct {
	Version    string            `json:"version"`
	Workspaces []WorkspaceConfig `json:"workspaces"`
}

// WorkspaceConfig contains management-only registration data. Root is
// deliberately absent from View, the non-management return type.
type WorkspaceConfig struct {
	ID          string    `json:"id"`
	Root        string    `json:"root"`
	ReadOnly    bool      `json:"read_only"`
	ExpiresAt   time.Time `json:"expires_at"`
	DeniedNames []string  `json:"denied_names"`
}

type configJSON struct {
	Version    *string          `json:"version"`
	Workspaces *[]workspaceJSON `json:"workspaces"`
}

type workspaceJSON struct {
	ID          *string   `json:"id"`
	Root        *string   `json:"root"`
	ReadOnly    *bool     `json:"read_only"`
	ExpiresAt   *string   `json:"expires_at"`
	DeniedNames *[]string `json:"denied_names"`
}

// LoadFile reads a bounded, regular startup file and parses it strictly. The
// supplied time is used to reject configurations that are already expired.
func LoadFile(path string, now time.Time) (Config, error) {
	file, err := os.Open(path)
	if err != nil {
		return Config{}, fmt.Errorf("open workspace registry config: %w", err)
	}
	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return Config{}, fmt.Errorf("stat workspace registry config: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Config{}, errors.New("workspace registry config must be a regular file")
	}
	if info.Size() > maxConfigSize {
		return Config{}, errors.New("workspace registry config is too large")
	}

	data, err := io.ReadAll(io.LimitReader(file, maxConfigSize+1))
	if err != nil {
		return Config{}, fmt.Errorf("read workspace registry config: %w", err)
	}
	if len(data) > maxConfigSize {
		return Config{}, errors.New("workspace registry config is too large")
	}
	return ParseConfig(data, now)
}

// ParseConfig rejects unknown fields, duplicate object names, trailing data,
// missing fields, unsupported versions, duplicate IDs, and invalid workspaces.
func ParseConfig(data []byte, now time.Time) (Config, error) {
	if now.IsZero() {
		return Config{}, errors.New("validation time is required")
	}
	if err := validateJSONShape(data); err != nil {
		return Config{}, fmt.Errorf("invalid workspace registry config: %w", err)
	}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var raw configJSON
	if err := decoder.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("invalid workspace registry config: %w", err)
	}
	if raw.Version == nil || raw.Workspaces == nil {
		return Config{}, errors.New("workspace registry config requires version and workspaces")
	}
	if *raw.Version != CurrentVersion {
		return Config{}, fmt.Errorf("unsupported workspace registry version %q", *raw.Version)
	}
	if len(*raw.Workspaces) == 0 {
		return Config{}, errors.New("workspace registry config requires at least one workspace")
	}

	config := Config{Version: *raw.Version, Workspaces: make([]WorkspaceConfig, 0, len(*raw.Workspaces))}
	seen := make(map[string]struct{}, len(*raw.Workspaces))
	for i, item := range *raw.Workspaces {
		workspace, err := decodeWorkspace(item)
		if err != nil {
			return Config{}, fmt.Errorf("workspace %d: %w", i, err)
		}
		if _, exists := seen[workspace.ID]; exists {
			return Config{}, fmt.Errorf("duplicate workspace ID %q", workspace.ID)
		}
		seen[workspace.ID] = struct{}{}
		if err := validateWorkspace(workspace, now); err != nil {
			return Config{}, fmt.Errorf("workspace %d: %w", i, err)
		}
		config.Workspaces = append(config.Workspaces, workspace)
	}
	return config, nil
}

func decodeWorkspace(raw workspaceJSON) (WorkspaceConfig, error) {
	if raw.ID == nil || raw.Root == nil || raw.ReadOnly == nil || raw.ExpiresAt == nil || raw.DeniedNames == nil {
		return WorkspaceConfig{}, errors.New("id, root, read_only, expires_at, and denied_names are required")
	}
	expiresAt, err := time.Parse(time.RFC3339Nano, *raw.ExpiresAt)
	if err != nil {
		return WorkspaceConfig{}, errors.New("expires_at must be an RFC3339 timestamp")
	}
	return WorkspaceConfig{
		ID:          *raw.ID,
		Root:        *raw.Root,
		ReadOnly:    *raw.ReadOnly,
		ExpiresAt:   expiresAt,
		DeniedNames: append([]string(nil), (*raw.DeniedNames)...),
	}, nil
}

func validateWorkspace(workspace WorkspaceConfig, now time.Time) error {
	if err := ValidateID(workspace.ID); err != nil {
		return err
	}
	if workspace.Root == "" {
		return errors.New("root must not be empty")
	}
	if strings.IndexByte(workspace.Root, 0) >= 0 || !filepath.IsAbs(workspace.Root) {
		return errors.New("root must be an absolute path")
	}
	if filepath.Clean(workspace.Root) != workspace.Root {
		return errors.New("root must be an absolute clean path")
	}
	if workspace.ExpiresAt.IsZero() || !workspace.ExpiresAt.After(now) {
		return errors.New("expires_at must be in the future")
	}

	seenNames := make(map[string]struct{}, len(workspace.DeniedNames))
	for _, name := range workspace.DeniedNames {
		if strings.TrimSpace(name) == "" || name == "." || name == ".." || strings.ContainsAny(name, "\x00/\\") {
			return errors.New("denied_names entries must be non-empty individual path names")
		}
		if _, exists := seenNames[name]; exists {
			return fmt.Errorf("duplicate denied_names entry %q", name)
		}
		seenNames[name] = struct{}{}
	}
	return nil
}

// ValidateID accepts an opaque ASCII token suitable for both an HTTP header
// value and canonical URL path escaping. Percent, slash, query, and fragment
// delimiters are intentionally excluded to prevent ambiguous routing.
func ValidateID(id string) error {
	if len(id) < minIDLength || len(id) > maxIDLength {
		return fmt.Errorf("workspace ID must be between %d and %d characters", minIDLength, maxIDLength)
	}
	for i := 0; i < len(id); i++ {
		if !safeIDByte(id[i]) {
			return errors.New("workspace ID contains an unsafe character")
		}
	}
	return nil
}

func safeIDByte(value byte) bool {
	if value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z' || value >= '0' && value <= '9' {
		return true
	}
	switch value {
	case '!', '$', '&', '\'', '*', '+', '-', '.', '^', '_', '`', '|', '~':
		return true
	default:
		return false
	}
}

func validateJSONShape(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON data")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}

	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key must be a string")
			}
			if _, exists := seen[key]; exists {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return errors.New("malformed JSON object")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return errors.New("malformed JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
