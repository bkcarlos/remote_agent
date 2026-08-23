package execworker

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestAdministratorConfigStrictAndCannotSetWorkspace(t *testing.T) {
	executable, err := json.Marshal(testExecutablePath())
	if err != nil {
		t.Fatal(err)
	}
	profile := `{"name":"go-test","executable":` + string(executable) + `,"fixed_argv":["go","test"],"allowed_argv_prefixes":[["./..."]],"workspace_mode":"read_only","env_allowlist":["GOFLAGS"],"limits":{"timeout_ms":30000,"cpu_seconds":30,"memory_bytes":268435456,"pids":64,"output_bytes":1048576,"scan_regions":16,"scan_bytes":1048576,"scan_results":32}}`
	valid := `{"version":"v1","profiles":[` + profile + `]}`
	config, err := ParseAdministratorConfig([]byte(valid))
	if err != nil || len(config.Profiles) != 1 || config.Profiles[0].Name != "go-test" {
		t.Fatalf("parse administrator config: %+v, %v", config, err)
	}
	for _, input := range []string{
		`{"version":"v1","profiles":[],"workspace_id":"injected","workspace_root":"/tmp"}`,
		`{"version":"v1","profiles":[]} trailing`,
		`{"version":"v2","profiles":[]}`,
		`{"version":"v1","profiles":[]}`,
		`{"version":"v1","profiles":[` + profile + `,` + profile + `]}`,
	} {
		if _, err := ParseAdministratorConfig([]byte(input)); err == nil {
			t.Fatalf("accepted invalid exec administrator config: %s", input)
		}
	}
	if _, err := ParseAdministratorConfig([]byte(strings.Replace(valid, `"executable":`+string(executable), `"executable":"env"`, 1))); err == nil {
		t.Fatal("accepted non-absolute administrator executable")
	}
}
