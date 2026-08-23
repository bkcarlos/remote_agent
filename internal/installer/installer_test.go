package installer

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
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
	before := []byte(`{"theme":"dark","future":{"enabled":true,"values":[1,{"nested":"preserve me"}]},"mcpServers":{"existing":{"command":"other"}}}`)
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
	var future map[string]json.RawMessage
	if err := json.Unmarshal(root["future"], &future); err != nil {
		t.Fatalf("arbitrary future setting was not preserved: %v", err)
	}
	if string(future["enabled"]) != "true" || !bytes.Contains(future["values"], []byte(`"preserve me"`)) {
		t.Fatalf("arbitrary future setting changed: %s", root["future"])
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
	wantDiff := ConfigDiffSummary{
		MCPServerChange:           "add",
		MCPServerName:             DefaultServerName,
		MCPServerArguments:        []string{"--endpoint", "https://agent.example/mcp"},
		PreservedMCPServers:       1,
		PreservedTopLevelSettings: 2,
	}
	if !reflect.DeepEqual(plan.Diff, wantDiff) {
		t.Fatalf("unexpected diff summary: %+v", plan.Diff)
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
	secret := "must-not-be-persisted"
	t.Setenv(TokenEnvironment, secret)
	plan, err := PlanInstall(Options{ConfigPath: config, BridgePath: bridgeFile(t), Endpoint: "http://127.0.0.1:8080", AllowPrivateHTTP: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(config); !os.IsNotExist(err) {
		t.Fatal("planning modified the configuration")
	}
	if !json.Valid(plan.After) {
		t.Fatal("generated invalid JSON")
	}
	if bytes.Contains(plan.After, []byte(secret)) {
		t.Fatal("installer persisted the token")
	}
	entry := decodeEntry(t, plan.After)
	if entry.Env != nil {
		t.Fatal("installer persisted credential configuration")
	}
	wantArgs := []string{"--endpoint", "http://127.0.0.1:8080", "--allow-private-http"}
	if !reflect.DeepEqual(entry.Args, wantArgs) {
		t.Fatalf("private HTTP args = %q, want %q", entry.Args, wantArgs)
	}
}

func TestPlanHTTPSNeverAddsAllowPrivateHTTPArgument(t *testing.T) {
	plan, err := PlanInstall(Options{
		ConfigPath:       filepath.Join(t.TempDir(), "client.json"),
		BridgePath:       bridgeFile(t),
		Endpoint:         "https://agent.example/mcp",
		AllowPrivateHTTP: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	entry := decodeEntry(t, plan.After)
	wantArgs := []string{"--endpoint", "https://agent.example/mcp"}
	if !reflect.DeepEqual(entry.Args, wantArgs) {
		t.Fatalf("HTTPS args = %q, want %q", entry.Args, wantArgs)
	}
}

func decodeEntry(t *testing.T, config []byte) struct {
	Args []string          `json:"args"`
	Env  map[string]string `json:"env"`
} {
	t.Helper()
	var root struct {
		MCPServers map[string]json.RawMessage `json:"mcpServers"`
	}
	if err := json.Unmarshal(config, &root); err != nil {
		t.Fatal(err)
	}
	var entry struct {
		Args []string          `json:"args"`
		Env  map[string]string `json:"env"`
	}
	if err := json.Unmarshal(root.MCPServers[DefaultServerName], &entry); err != nil {
		t.Fatal(err)
	}
	return entry
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
	wantDiff := ConfigDiffSummary{
		MCPServerChange:           "remove",
		MCPServerName:             DefaultServerName,
		PreservedMCPServers:       1,
		PreservedTopLevelSettings: 1,
	}
	if !reflect.DeepEqual(plan.Diff, wantDiff) {
		t.Fatalf("unexpected diff summary: %+v", plan.Diff)
	}
	if err := Apply(plan); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanUninstall(config, DefaultServerName, nil); err == nil {
		t.Fatal("missing entry was not reported")
	}
}

func TestDefaultConfigPathRequiresExplicitCodexConfig(t *testing.T) {
	for _, client := range []string{"codex", "codex-json", "CoDeX"} {
		got, err := DefaultConfigPath(client)
		if err == nil || !strings.Contains(err.Error(), "explicit --config") {
			t.Errorf("DefaultConfigPath(%q) = %q, %v; want explicit --config error", client, got, err)
		}
		if got != "" {
			t.Errorf("DefaultConfigPath(%q) returned unverified path %q", client, got)
		}
	}
}

func TestPlanInstallRejectsUnsafeBridgeFiles(t *testing.T) {
	d := t.TempDir()
	config := filepath.Join(d, "client.json")
	if _, err := PlanInstall(Options{ConfigPath: config, BridgePath: d, Endpoint: "https://agent.example"}); err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("directory bridge error = %v, want regular-file rejection", err)
	}

	if runtime.GOOS == "windows" {
		return
	}
	bridge := filepath.Join(d, "non-executable-bridge")
	if err := os.WriteFile(bridge, []byte("binary"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanInstall(Options{ConfigPath: config, BridgePath: bridge, Endpoint: "https://agent.example"}); err == nil || !strings.Contains(err.Error(), "executable bit") {
		t.Fatalf("non-executable bridge error = %v, want executable-bit rejection", err)
	}
}

func TestExistingConfigurationRejectsDuplicateKeysAtAnyDepth(t *testing.T) {
	d := t.TempDir()
	bridge := bridgeFile(t)
	cases := map[string]string{
		"top-level":         `{"theme":"dark","theme":"light"}`,
		"mcp servers":       `{"mcpServers":{"one":{"command":"a"},"one":{"command":"b"}}}`,
		"arbitrary setting": `{"future":{"nested":1,"nested":2}}`,
		"array object":      `{"future":[{"nested":1,"nested":2}]}`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			config := filepath.Join(d, strings.ReplaceAll(name, " ", "-")+".json")
			if err := os.WriteFile(config, []byte(content), 0600); err != nil {
				t.Fatal(err)
			}
			_, err := PlanInstall(Options{ConfigPath: config, BridgePath: bridge, Endpoint: "https://agent.example"})
			if err == nil || !strings.Contains(err.Error(), "duplicate JSON object key") {
				t.Fatalf("duplicate-key configuration error = %v", err)
			}
		})
	}
}

func TestUninstallRejectsDuplicateKeys(t *testing.T) {
	config := filepath.Join(t.TempDir(), "client.json")
	content := []byte(`{"mcpServers":{"secure-remote-agent":{"command":"one"}},"mcpServers":{"secure-remote-agent":{"command":"two"}}}`)
	if err := os.WriteFile(config, content, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := PlanUninstall(config, DefaultServerName, nil); err == nil || !strings.Contains(err.Error(), "duplicate JSON object key") {
		t.Fatalf("duplicate-key uninstall error = %v", err)
	}
}

func TestApplyRejectsChangedExistingConfigWithoutBackup(t *testing.T) {
	d := t.TempDir()
	config := filepath.Join(d, "client.json")
	before := []byte(`{"theme":"dark"}`)
	if err := os.WriteFile(config, before, 0600); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanInstall(Options{
		ConfigPath: config,
		BridgePath: bridgeFile(t),
		Endpoint:   "https://agent.example",
		Now:        func() time.Time { return time.Unix(0, 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	changed := []byte("{\n  \"theme\": \"dark\"\n}\n")
	if err := os.WriteFile(config, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Apply(plan); err == nil || !strings.Contains(err.Error(), "changed since the plan") {
		t.Fatalf("Apply error = %v, want changed-plan rejection", err)
	}
	got, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, changed) {
		t.Fatalf("changed configuration was overwritten: %q", got)
	}
	if _, err := os.Stat(plan.BackupPath); !os.IsNotExist(err) {
		t.Fatalf("misleading backup was created: %v", err)
	}
}

func TestApplyRejectsConfigCreatedAfterNewFilePlan(t *testing.T) {
	d := t.TempDir()
	config := filepath.Join(d, "client.json")
	plan, err := PlanInstall(Options{ConfigPath: config, BridgePath: bridgeFile(t), Endpoint: "https://agent.example"})
	if err != nil {
		t.Fatal(err)
	}
	created := []byte(`{"created":"by another process"}`)
	if err := os.WriteFile(config, created, 0600); err != nil {
		t.Fatal(err)
	}
	if err := Apply(plan); err == nil || !strings.Contains(err.Error(), "was created since the plan") {
		t.Fatalf("Apply error = %v, want newly-created-file rejection", err)
	}
	got, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, created) {
		t.Fatalf("newly created configuration was overwritten: %q", got)
	}
	backups, err := filepath.Glob(config + ".backup-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 0 {
		t.Fatalf("new-file conflict created backups: %v", backups)
	}
}

func TestApplyRejectsDanglingSymlinkCreatedAfterNewFilePlan(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symbolic-link creation is not generally available to unprivileged Windows tests")
	}
	d := t.TempDir()
	config := filepath.Join(d, "client.json")
	plan, err := PlanInstall(Options{ConfigPath: config, BridgePath: bridgeFile(t), Endpoint: "https://agent.example"})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(d, "missing-target"), config); err != nil {
		t.Fatal(err)
	}
	if err := Apply(plan); err == nil || !strings.Contains(err.Error(), "was created since the plan") {
		t.Fatalf("Apply error = %v, want dangling-symlink rejection", err)
	}
	info, err := os.Lstat(config)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("dangling symlink was overwritten")
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

func TestApplyRejectsChangeAfterTempSyncAndPreservesExternalContent(t *testing.T) {
	d := t.TempDir()
	config := filepath.Join(d, "client.json")
	before := []byte(`{"theme":"dark"}`)
	if err := os.WriteFile(config, before, 0600); err != nil {
		t.Fatal(err)
	}
	plan, err := PlanInstall(Options{
		ConfigPath: config,
		BridgePath: bridgeFile(t),
		Endpoint:   "https://agent.example",
		Now:        func() time.Time { return time.Unix(0, 0).UTC() },
	})
	if err != nil {
		t.Fatal(err)
	}
	external := []byte(`{"theme":"changed externally during temp write"}`)
	plan.testHookAfterTempSync = func(string) error {
		return os.WriteFile(config, external, 0600)
	}

	if err := Apply(plan); err == nil || !strings.Contains(err.Error(), "changed since the plan") {
		t.Fatalf("Apply error = %v, want final changed-plan rejection", err)
	}
	got, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, external) {
		t.Fatalf("external configuration was overwritten: %q", got)
	}
	if _, err := os.Stat(plan.BackupPath); !os.IsNotExist(err) {
		t.Fatalf("rejected apply created a backup: %v", err)
	}
	temps, err := filepath.Glob(filepath.Join(d, ".mcp-config-*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(temps) != 0 {
		t.Fatalf("rejected apply left temporary files: %v", temps)
	}
}

func TestUnlockedStaleLockMarkerDoesNotBlockApply(t *testing.T) {
	d := t.TempDir()
	config := filepath.Join(d, "client.json")
	plan, err := PlanInstall(Options{
		ConfigPath: config,
		BridgePath: bridgeFile(t),
		Endpoint:   "https://agent.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	lockPath := config + ".remote-agent-install.lock"
	if err := os.WriteFile(lockPath, []byte("marker left by an exited process"), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Unix(1, 0)
	if err := os.Chtimes(lockPath, old, old); err != nil {
		t.Fatal(err)
	}

	if err := Apply(plan); err != nil {
		t.Fatalf("Apply with stale unlocked marker: %v", err)
	}
	got, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plan.After) {
		t.Fatalf("Apply wrote %q, want %q", got, plan.After)
	}
}

func TestConcurrentApplyOnlyOneSucceeds(t *testing.T) {
	d := t.TempDir()
	config := filepath.Join(d, "client.json")
	plan, err := PlanInstall(Options{
		ConfigPath: config,
		BridgePath: bridgeFile(t),
		Endpoint:   "https://agent.example",
	})
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	plan.testHookAfterTempSync = func(string) error {
		entered <- struct{}{}
		<-release
		return nil
	}
	firstResult := make(chan error, 1)
	go func() {
		firstResult <- Apply(plan)
	}()
	<-entered

	secondErr := Apply(plan)
	if secondErr == nil || !strings.Contains(secondErr.Error(), "another installer apply is in progress") {
		close(release)
		t.Fatalf("concurrent Apply error = %v, want lock rejection", secondErr)
	}
	close(release)
	if err := <-firstResult; err != nil {
		t.Fatalf("locked Apply failed: %v", err)
	}
	got, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plan.After) {
		t.Fatalf("successful Apply wrote %q, want %q", got, plan.After)
	}
}
