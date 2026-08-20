package installer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func bridgeFile(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "stdio-bridge")
	if err := os.WriteFile(p, []byte("binary"), 0700); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestValidateEndpoint(t *testing.T) {
	allowed := []struct {
		url       string
		allowHTTP bool
	}{
		{"https://agent.example.com/mcp", false},
		{"http://127.0.0.1:8080", true},
		{"http://10.0.0.2/mcp", true},
		{"http://[::1]:8080", true},
	}
	for _, tc := range allowed {
		if err := ValidateEndpoint(tc.url, tc.allowHTTP); err != nil {
			t.Errorf("rejected %s: %v", tc.url, err)
		}
	}
	denied := []struct {
		url       string
		allowHTTP bool
	}{
		{"http://10.0.0.2", false},
		{"http://8.8.8.8", true},
		{"http://agent.internal", true},
		{"ftp://10.0.0.2", true},
		{"https://user:pass@example.com", false},
		{"relative", false},
	}
	for _, tc := range denied {
		if err := ValidateEndpoint(tc.url, tc.allowHTTP); err == nil {
			t.Errorf("accepted unsafe endpoint %s", tc.url)
		}
	}
}

func TestPlanPreservesConfigurationAndApplyCreatesBackup(t *testing.T) {
	d := t.TempDir()
	config := filepath.Join(d, "client.json")
	before := []byte(`{"theme":"dark","mcpServers":{"existing":{"command":"other"}}}`)
	if err := os.WriteFile(config, before, 0644); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 3, 10, 12, 0, 0, 0, time.UTC)
	plan, err := PlanInstall(Options{ConfigPath: config, BridgePath: bridgeFile(t), Endpoint: "https://agent.example/mcp", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.Existed || plan.BackupPath != config+".backup-20260310T120000Z" {
		t.Fatalf("bad plan: %+v", plan)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(plan.After, &root); err != nil {
		t.Fatal(err)
	}
	if _, ok := root["theme"]; !ok {
		t.Fatal("unrelated setting was removed")
	}
	var servers map[string]json.RawMessage
	if err := json.Unmarshal(root["mcpServers"], &servers); err != nil {
		t.Fatal(err)
	}
	if _, ok := servers["existing"]; !ok {
		t.Fatal("existing MCP server was removed")
	}
	if _, ok := servers[DefaultServerName]; !ok {
		t.Fatal("remote agent was not added")
	}
	if err := Apply(plan); err != nil {
		t.Fatal(err)
	}
	backup, err := os.ReadFile(plan.BackupPath)
	if err != nil || string(backup) != string(before) {
		t.Fatalf("bad backup: %q %v", backup, err)
	}
	written, err := os.ReadFile(config)
	if err != nil || string(written) != string(plan.After) {
		t.Fatalf("bad config: %v", err)
	}
}

func TestPlanDoesNotWriteAndDoesNotStoreCredential(t *testing.T) {
	config := filepath.Join(t.TempDir(), "new", "client.json")
	plan, err := PlanInstall(Options{ConfigPath: config, BridgePath: bridgeFile(t), Endpoint: "http://127.0.0.1:8080", AllowPrivateHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(config); !os.IsNotExist(err) {
		t.Fatal("planning modified the configuration")
	}
	if json.Valid(plan.After) == false {
		t.Fatal("generated invalid JSON")
	}
	var root map[string]any
	json.Unmarshal(plan.After, &root)
	servers := root["mcpServers"].(map[string]any)
	entry := servers[DefaultServerName].(map[string]any)
	if _, exists := entry["env"]; exists {
		t.Fatal("installer persisted credential configuration")
	}
}

func TestRejectsInvalidExistingConfigurationAndMissingBridge(t *testing.T) {
	d := t.TempDir()
	bad := filepath.Join(d, "bad.json")
	os.WriteFile(bad, []byte("not-json"), 0600)
	if _, err := PlanInstall(Options{ConfigPath: bad, BridgePath: bridgeFile(t), Endpoint: "https://agent.example"}); err == nil {
		t.Fatal("invalid existing JSON accepted")
	}
	if _, err := PlanInstall(Options{ConfigPath: filepath.Join(d, "x"), BridgePath: filepath.Join(d, "missing"), Endpoint: "https://agent.example"}); err == nil {
		t.Fatal("missing bridge accepted")
	}
}

func TestUninstallRemovesOnlyOwnEntry(t *testing.T) {
	d := t.TempDir()
	config := filepath.Join(d, "client.json")
	before := []byte(`{"theme":"dark","mcpServers":{"secure-remote-agent":{"command":"bridge"},"other":{"command":"other"}}}`)
	os.WriteFile(config, before, 0600)
	plan, err := PlanUninstall(config, DefaultServerName, func() time.Time { return time.Unix(10, 0).UTC() })
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]json.RawMessage
	json.Unmarshal(plan.After, &root)
	var servers map[string]json.RawMessage
	json.Unmarshal(root["mcpServers"], &servers)
	if _, exists := servers[DefaultServerName]; exists {
		t.Fatal("own entry was not removed")
	}
	if _, exists := servers["other"]; !exists || root["theme"] == nil {
		t.Fatal("uninstall removed unrelated configuration")
	}
	if err := Apply(plan); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanUninstall(config, DefaultServerName, nil); err == nil {
		t.Fatal("missing entry was not reported")
	}
}

func TestBackupIsExclusive(t *testing.T) {
	d := t.TempDir()
	config := filepath.Join(d, "client.json")
	os.WriteFile(config, []byte(`{}`), 0600)
	now := func() time.Time { return time.Unix(0, 0).UTC() }
	plan, err := PlanInstall(Options{ConfigPath: config, BridgePath: bridgeFile(t), Endpoint: "https://agent.example", Now: now})
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(plan.BackupPath, []byte("do-not-overwrite"), 0600)
	if err := Apply(plan); err == nil {
		t.Fatal("existing backup was overwritten")
	}
	got, _ := os.ReadFile(plan.BackupPath)
	if string(got) != "do-not-overwrite" {
		t.Fatal("backup content changed")
	}
}
