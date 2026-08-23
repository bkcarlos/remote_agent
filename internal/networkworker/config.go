package networkworker

import (
	"errors"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/bkcarlos/remote_agent/internal/protocol"
)

const ProfilesVersion = "v1"

var opaqueProfileID = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)

// Profile is administrator-owned network authority. The MCP client can select
// only ID; policy, limits, and expiry always come from this configuration.
type Profile struct {
	ID        string         `json:"id"`
	Policy    Policy         `json:"policy"`
	Limits    ResourceLimits `json:"resource_limits"`
	ExpiresAt time.Time      `json:"expires_at"`
}

type Profiles struct {
	Version  string    `json:"version"`
	Profiles []Profile `json:"profiles"`
}

func LoadProfiles(path string, now time.Time) (map[string]Profile, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, errors.New("network profile configuration is unavailable")
	}
	return ParseProfiles(raw, now)
}

func ParseProfiles(raw []byte, now time.Time) (map[string]Profile, error) {
	var document Profiles
	if err := protocol.DecodeStrict(raw, &document); err != nil {
		return nil, fmt.Errorf("invalid network profile configuration: %w", err)
	}
	if document.Version != ProfilesVersion {
		return nil, errors.New("network profile configuration version must be v1")
	}
	if document.Profiles == nil {
		return nil, errors.New("network profiles must be a JSON array")
	}
	profiles := make(map[string]Profile, len(document.Profiles))
	for index, profile := range document.Profiles {
		if err := ValidateProfile(profile, now); err != nil {
			return nil, fmt.Errorf("network profile at index %d: %w", index, err)
		}
		if _, duplicate := profiles[profile.ID]; duplicate {
			return nil, errors.New("network profile ids must be unique")
		}
		profile.Policy, _ = normalizePolicy(profile.Policy)
		profile.ExpiresAt = profile.ExpiresAt.UTC()
		profiles[profile.ID] = profile
	}
	return profiles, nil
}

func ValidateProfile(profile Profile, now time.Time) error {
	if !opaqueProfileID.MatchString(profile.ID) {
		return errors.New("profile has an invalid opaque id")
	}
	if profile.ExpiresAt.IsZero() || !now.UTC().Before(profile.ExpiresAt.UTC()) {
		return errors.New("profile is expired")
	}
	normalized, err := normalizePolicy(profile.Policy)
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	if len(normalized.AllowedSchemes) == 0 || len(normalized.AllowedPorts) == 0 || (len(normalized.AllowedDomains) == 0 && len(normalized.AllowedCIDRs) == 0) {
		return errors.New("profile must explicitly allow schemes, ports, and targets")
	}
	if err := validateLimits(profile.Limits); err != nil {
		return fmt.Errorf("resource limits: %w", err)
	}
	return nil
}
