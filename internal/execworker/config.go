package execworker

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/bkcarlos/remote_agent/internal/protocol"
)

const AdminConfigVersion = "v1"

var opaqueTaskProfile = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// AdministratorConfig deliberately has no workspace field. Workspace identity
// and root are injected by the Gateway when it creates a per-workspace runtime.
type AdministratorConfig struct {
	Version  string        `json:"version"`
	Profiles []TaskProfile `json:"profiles"`
}

func LoadAdministratorConfig(path string) (AdministratorConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return AdministratorConfig{}, errors.New("exec administrator configuration is unavailable")
	}
	return ParseAdministratorConfig(raw)
}

func ParseAdministratorConfig(raw []byte) (AdministratorConfig, error) {
	var config AdministratorConfig
	if err := protocol.DecodeStrict(raw, &config); err != nil {
		return AdministratorConfig{}, fmt.Errorf("invalid exec administrator configuration: %w", err)
	}
	if config.Version != AdminConfigVersion {
		return AdministratorConfig{}, errors.New("exec administrator configuration version must be v1")
	}
	if len(config.Profiles) == 0 {
		return AdministratorConfig{}, errors.New("at least one exec task profile is required")
	}
	seen := make(map[string]struct{}, len(config.Profiles))
	for index := range config.Profiles {
		profile := config.Profiles[index]
		if !opaqueTaskProfile.MatchString(profile.Name) {
			return AdministratorConfig{}, fmt.Errorf("exec profile at index %d has an invalid opaque name", index)
		}
		if _, duplicate := seen[profile.Name]; duplicate {
			return AdministratorConfig{}, errors.New("exec task profile names must be unique")
		}
		if err := profile.Validate(); err != nil {
			return AdministratorConfig{}, fmt.Errorf("exec profile %q: %w", profile.Name, err)
		}
		seen[profile.Name] = struct{}{}
	}
	return config, nil
}

func (config AdministratorConfig) ProfileMap() map[string]TaskProfile {
	profiles := make(map[string]TaskProfile, len(config.Profiles))
	for _, profile := range config.Profiles {
		copy := profile
		copy.FixedArgv = append([]string(nil), profile.FixedArgv...)
		copy.AllowedArgvPrefixes = clonePrefixes(profile.AllowedArgvPrefixes)
		copy.EnvAllowlist = append([]string(nil), profile.EnvAllowlist...)
		copy.CachePaths = append([]string(nil), profile.CachePaths...)
		profiles[profile.Name] = copy
	}
	return profiles
}

type RuntimeConfig struct {
	Version     string        `json:"version"`
	Profiles    []TaskProfile `json:"profiles"`
	WorkspaceID string        `json:"workspace_id"`
	Workspace   string        `json:"workspace_root"`
}

func LoadRuntimeConfig(path string) (RuntimeConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return RuntimeConfig{}, errors.New("exec runtime configuration is unavailable")
	}
	var config RuntimeConfig
	if err := protocol.DecodeStrict(raw, &config); err != nil {
		return RuntimeConfig{}, errors.New("exec runtime configuration is invalid")
	}
	if config.Version != AdminConfigVersion || config.WorkspaceID == "" || config.Workspace == "" {
		return RuntimeConfig{}, errors.New("exec runtime configuration is incomplete")
	}
	if _, err := ParseAdministratorConfig(mustAdministratorJSON(config)); err != nil {
		return RuntimeConfig{}, err
	}
	return config, nil
}

func mustAdministratorJSON(config RuntimeConfig) []byte {
	// RuntimeConfig has already been strictly decoded; marshaling this subset
	// guarantees the administrator validator sees no runtime workspace fields.
	raw, _ := json.Marshal(AdministratorConfig{Version: config.Version, Profiles: config.Profiles})
	return raw
}
