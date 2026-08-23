package policy

import (
	"os"
	"path/filepath"
	"testing"
)

func boolPtr(v bool) *bool  { return &v }
func intPtr(v int64) *int64 { return &v }

func TestParseDocumentStrictValidation(t *testing.T) {
	d, err := ParseDocument([]byte(`{"version":"v1","allow_write":false,"max_read_bytes":100,"denied_names":["secret.txt"]}`))
	if err != nil || d.Version != "v1" || d.MaxReadBytes == nil || *d.MaxReadBytes != 100 {
		t.Fatalf("parse %+v: %v", d, err)
	}
	for _, input := range []string{
		`{}`,
		`{"version":"v1","unknown":true}`,
		`{"version":"v1","max_read_bytes":0}`,
		`{"version":"v1","denied_names":["a/b"]}`,
		`{"version":"v1"} trailing`,
		`{"version":"v1"}{"version":"v2"}`,
	} {
		if _, err := ParseDocument([]byte(input)); err == nil {
			t.Errorf("accepted invalid policy %s", input)
		}
	}
}

func TestRestrictCannotLoosen(t *testing.T) {
	base := Config{AllowWrite: false, MaxReadBytes: 100, MaxWriteBytes: 50, DeniedNames: []string{"base-secret"}}
	looser := Restrict(base, Document{Version: "loose", AllowWrite: boolPtr(true), MaxReadBytes: intPtr(1000), MaxWriteBytes: intPtr(500)})
	if looser.AllowWrite || looser.MaxReadBytes != 100 || looser.MaxWriteBytes != 50 {
		t.Fatalf("policy was loosened: %+v", looser)
	}
	tighter := Restrict(Config{AllowWrite: true, MaxReadBytes: 100, MaxWriteBytes: 50}, Document{Version: "tight", AllowWrite: boolPtr(false), MaxReadBytes: intPtr(10), DeniedNames: []string{"extra-secret", "EXTRA-SECRET"}})
	if tighter.AllowWrite || tighter.MaxReadBytes != 10 || len(tighter.DeniedNames) != 1 {
		t.Fatalf("policy was not tightened: %+v", tighter)
	}
}

func TestDefaultsRemainWhenCustomDeniedNamesExist(t *testing.T) {
	p := New(Config{DeniedNames: []string{"custom.secret"}})
	for _, path := range []string{"custom.secret", ".env", "x/.ssh/config"} {
		if p.Evaluate("read_file", path).Allowed {
			t.Errorf("sensitive default/custom path allowed: %s", path)
		}
	}
}

func TestCapabilityDefaultsAreDisabledAndRestrictionsCannotEnable(t *testing.T) {
	defaults := New(Config{})
	for _, tool := range []string{"web_fetch", "ssh_exec", "exec_run", "debug_status", "mem_scan"} {
		if defaults.Evaluate(tool, "ordinary.txt").Allowed {
			t.Fatalf("default policy exposed %s", tool)
		}
	}
	base := Config{AllowNetwork: false, AllowRemote: false, AllowExec: false, AllowDebug: false, AllowMem: false}
	restricted := Restrict(base, Document{
		Version: "cannot-enable", AllowNetwork: boolPtr(true), AllowRemote: boolPtr(true),
		AllowExec: boolPtr(true), AllowDebug: boolPtr(true), AllowMem: boolPtr(true),
	})
	if restricted.AllowNetwork || restricted.AllowRemote || restricted.AllowExec || restricted.AllowDebug || restricted.AllowMem {
		t.Fatalf("restriction enabled a capability: %+v", restricted)
	}
	enabled := New(Config{AllowNetwork: true, AllowRemote: true, AllowExec: true, AllowDebug: true, AllowMem: true})
	for _, tool := range []string{"web_fetch", "ssh_exec", "exec_run", "debug_status", "mem_scan"} {
		if !enabled.Evaluate(tool, "ordinary.txt").Allowed {
			t.Fatalf("explicit policy did not enable %s", tool)
		}
	}
}

func TestLoadFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	os.WriteFile(path, []byte(`{"version":"2026-01"}`), 0600)
	d, err := LoadFile(path)
	if err != nil || d.Version != "2026-01" {
		t.Fatalf("load %+v: %v", d, err)
	}
}
