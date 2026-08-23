package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bkcarlos/remote_agent/internal/installer"
)

func TestRunPreviewShowsSafeStructuredPlanWithoutWriting(t *testing.T) {
	dir := t.TempDir()
	bridge := filepath.Join(dir, "stdio-bridge")
	if err := os.WriteFile(bridge, []byte("binary"), 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "client.json")
	before := []byte(`{"theme":"dark","mcpServers":{"existing":{"command":"other"}}}`)
	if err := os.WriteFile(config, before, 0600); err != nil {
		t.Fatal(err)
	}
	secret := "preview-must-not-leak-this-token"
	t.Setenv(installer.TokenEnvironment, secret)

	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--config", config,
		"--bridge", bridge,
		"--endpoint", "http://127.0.0.1:8080/mcp",
		"--allow-private-http",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v; stderr: %s", err, stderr.String())
	}
	output := stdout.String()
	for _, want := range []string{
		"remote endpoint: http://127.0.0.1:8080/mcp",
		"authentication: " + installer.TokenEnvironment + " must be injected into the MCP client startup environment",
		`config diff:   {"mcp_server_change":"add","mcp_server_name":"secure-remote-agent","mcp_server_arguments":["--endpoint","http://127.0.0.1:8080/mcp","--allow-private-http"],"preserved_mcp_servers":1,"preserved_top_level_settings":1}`,
		"backup before apply:",
		"Preview only.",
	} {
		if !strings.Contains(output, want) {
			t.Errorf("preview missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, secret) {
		t.Fatal("preview displayed the token")
	}
	got, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, before) {
		t.Fatal("preview modified existing configuration")
	}
	backups, err := filepath.Glob(config + ".backup-*")
	if err != nil {
		t.Fatal(err)
	}
	if len(backups) != 0 {
		t.Fatalf("preview created backups: %v", backups)
	}
}

func TestCodexPresetDescriptionRequiresExplicitConfig(t *testing.T) {
	withoutConfig := presetDescription("codex", false)
	if !strings.Contains(withoutConfig, "requires explicit --config") {
		t.Fatalf("Codex preset description = %q", withoutConfig)
	}
	withConfig := presetDescription("codex", true)
	if !strings.Contains(withConfig, "explicit --config") {
		t.Fatalf("explicit Codex preset description = %q", withConfig)
	}
}

func TestRunRejectsCodexWithoutExplicitConfig(t *testing.T) {
	var stdout, stderr bytes.Buffer
	err := run([]string{"--client", "codex"}, &stdout, &stderr)
	if err == nil || !strings.Contains(err.Error(), "explicit --config") {
		t.Fatalf("run error = %v, want explicit --config requirement", err)
	}
	if strings.Contains(stdout.String(), ".codex") || strings.Contains(err.Error(), ".codex") {
		t.Fatalf("unverified Codex default path was claimed: stdout=%q err=%v", stdout.String(), err)
	}
}

func TestRunAllowsCodexWithExplicitConfig(t *testing.T) {
	dir := t.TempDir()
	bridge := filepath.Join(dir, "stdio-bridge")
	if err := os.WriteFile(bridge, []byte("binary"), 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(dir, "codex-config.json")
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"--client", "codex",
		"--config", config,
		"--bridge", bridge,
		"--endpoint", "https://agent.example/mcp",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run: %v; stderr: %s", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Codex JSON (explicit --config)") {
		t.Fatalf("preview does not identify explicit Codex config:\n%s", stdout.String())
	}
}
