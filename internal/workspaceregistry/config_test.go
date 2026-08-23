//go:build !windows

package workspaceregistry

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var configTestNow = time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)

func validConfigJSON() string {
	return `{"version":"v1","workspaces":[{"id":"workspace-0123456789","root":"/srv/workspace-one","read_only":true,"expires_at":"2026-08-23T13:00:00Z","denied_names":[".env","secret.key"]}]}`
}

func TestParseConfigValid(t *testing.T) {
	config, err := ParseConfig([]byte(validConfigJSON()), configTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if config.Version != CurrentVersion || len(config.Workspaces) != 1 {
		t.Fatalf("unexpected config: %+v", config)
	}
	workspace := config.Workspaces[0]
	if workspace.ID != "workspace-0123456789" || workspace.Root != "/srv/workspace-one" || !workspace.ReadOnly {
		t.Fatalf("unexpected workspace: %+v", workspace)
	}
}

func TestParseConfigRejectsNonStrictJSON(t *testing.T) {
	tests := map[string]string{
		"unknown top-level field":   `{"version":"v1","workspaces":[],"extra":true}`,
		"unknown workspace field":   `{"version":"v1","workspaces":[{"id":"workspace-0123456789","root":"/srv/a","read_only":true,"expires_at":"2026-08-23T13:00:00Z","denied_names":[],"extra":true}]}`,
		"duplicate top-level field": `{"version":"v1","version":"v1","workspaces":[]}`,
		"duplicate nested field":    `{"version":"v1","workspaces":[{"id":"workspace-0123456789","id":"workspace-abcdefghij","root":"/srv/a","read_only":true,"expires_at":"2026-08-23T13:00:00Z","denied_names":[]}]}`,
		"trailing token":            validConfigJSON() + ` true`,
		"second document":           validConfigJSON() + validConfigJSON(),
		"trailing comma":            `{"version":"v1","workspaces":[],}`,
	}
	for name, input := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseConfig([]byte(input), configTestNow); err == nil {
				t.Fatal("invalid JSON was accepted")
			}
		})
	}
}

func TestParseConfigRequiresEveryField(t *testing.T) {
	validFields := []string{
		`"id":"workspace-0123456789"`,
		`"root":"/srv/a"`,
		`"read_only":false`,
		`"expires_at":"2026-08-23T13:00:00Z"`,
		`"denied_names":[]`,
	}
	for omitted := range validFields {
		fields := append([]string(nil), validFields[:omitted]...)
		fields = append(fields, validFields[omitted+1:]...)
		input := `{"version":"v1","workspaces":[{` + strings.Join(fields, ",") + `}]}`
		if _, err := ParseConfig([]byte(input), configTestNow); err == nil {
			t.Errorf("accepted workspace with field %d omitted", omitted)
		}
	}
	for _, input := range []string{
		`{"workspaces":[]}`,
		`{"version":"v1"}`,
		`{"version":null,"workspaces":[]}`,
		`{"version":"v1","workspaces":null}`,
	} {
		if _, err := ParseConfig([]byte(input), configTestNow); err == nil {
			t.Errorf("accepted missing or null top-level field: %s", input)
		}
	}
}

func TestParseConfigRejectsInvalidWorkspaceValues(t *testing.T) {
	workspace := func(id, root, expires, denied string) string {
		return `{"version":"v1","workspaces":[{"id":"` + id + `","root":"` + root + `","read_only":false,"expires_at":"` + expires + `","denied_names":` + denied + `}]}`
	}
	tests := []string{
		`{"version":"v2","workspaces":[]}`,
		`{"version":"v1","workspaces":[]}`,
		workspace("short", "/srv/a", "2026-08-23T13:00:00Z", `[]`),
		workspace("workspace/0123456789", "/srv/a", "2026-08-23T13:00:00Z", `[]`),
		workspace("workspace-0123456789", "relative/root", "2026-08-23T13:00:00Z", `[]`),
		workspace("workspace-0123456789", "/srv/../srv/a", "2026-08-23T13:00:00Z", `[]`),
		workspace("workspace-0123456789", "/srv/a", "2026-08-23T12:00:00Z", `[]`),
		workspace("workspace-0123456789", "/srv/a", "not-a-time", `[]`),
		workspace("workspace-0123456789", "/srv/a", "2026-08-23T13:00:00Z", `[""]`),
		workspace("workspace-0123456789", "/srv/a", "2026-08-23T13:00:00Z", `["a/b"]`),
		workspace("workspace-0123456789", "/srv/a", "2026-08-23T13:00:00Z", `["secret","secret"]`),
	}
	for index, input := range tests {
		if _, err := ParseConfig([]byte(input), configTestNow); err == nil {
			t.Errorf("accepted invalid workspace case %d", index)
		}
	}
}

func TestParseConfigRejectsDuplicateIDs(t *testing.T) {
	input := `{"version":"v1","workspaces":[` +
		`{"id":"workspace-0123456789","root":"/srv/a","read_only":false,"expires_at":"2026-08-23T13:00:00Z","denied_names":[]},` +
		`{"id":"workspace-0123456789","root":"/srv/b","read_only":true,"expires_at":"2026-08-23T14:00:00Z","denied_names":[]}` +
		`]}`
	if _, err := ParseConfig([]byte(input), configTestNow); err == nil {
		t.Fatal("duplicate workspace IDs were accepted")
	}
}

func TestLoadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "workspaces.json")
	if err := os.WriteFile(path, []byte(validConfigJSON()), 0600); err != nil {
		t.Fatal(err)
	}
	config, err := LoadFile(path, configTestNow)
	if err != nil {
		t.Fatal(err)
	}
	if len(config.Workspaces) != 1 {
		t.Fatalf("loaded %d workspaces", len(config.Workspaces))
	}

	if _, err := LoadFile(t.TempDir(), configTestNow); err == nil {
		t.Fatal("directory accepted as trusted config file")
	}
	if _, err := ParseConfig([]byte(validConfigJSON()), time.Time{}); err == nil {
		t.Fatal("zero validation time accepted")
	}
	if _, err := LoadFile(filepath.Join(t.TempDir(), "missing.json"), configTestNow); err == nil || errors.Is(err, os.ErrNotExist) == false {
		t.Fatalf("missing file error = %v", err)
	}
}
