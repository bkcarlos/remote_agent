package networkworker

import (
	"strings"
	"testing"
	"time"
)

func TestParseProfilesStrictAndDenyByDefault(t *testing.T) {
	now := time.Date(2026, 8, 23, 0, 0, 0, 0, time.UTC)
	valid := `{"version":"v1","profiles":[{"id":"public-docs","policy":{"allowed_domains":["example.com"],"allowed_ports":[443],"allowed_schemes":["https"],"allowed_cidrs":[],"allowed_request_headers":["accept"],"allow_private":false},"resource_limits":{"max_request_body_bytes":1024,"max_response_body_bytes":4096,"max_request_header_bytes":1024,"max_response_header_bytes":4096,"max_redirects":2,"timeout_millis":5000},"expires_at":"2027-01-01T00:00:00Z"}]}`
	profiles, err := ParseProfiles([]byte(valid), now)
	if err != nil || profiles["public-docs"].ID != "public-docs" {
		t.Fatalf("parse profiles: %+v, %v", profiles, err)
	}
	for _, input := range []string{
		`{"version":"v2","profiles":[]}`,
		`{"version":"v1","profiles":null}`,
		`{"version":"v1","profiles":[],"unknown":true}`,
		`{"version":"v1","profiles":[]} trailing`,
		`{"version":"v1","profiles":[{"id":"same","policy":{"allowed_domains":["example.com"],"allowed_ports":[443],"allowed_schemes":["https"],"allowed_cidrs":[],"allowed_request_headers":[],"allow_private":false},"resource_limits":{"max_request_body_bytes":1,"max_response_body_bytes":1,"max_request_header_bytes":1,"max_response_header_bytes":1,"max_redirects":0,"timeout_millis":1},"expires_at":"2027-01-01T00:00:00Z"},{"id":"same","policy":{"allowed_domains":["example.com"],"allowed_ports":[443],"allowed_schemes":["https"],"allowed_cidrs":[],"allowed_request_headers":[],"allow_private":false},"resource_limits":{"max_request_body_bytes":1,"max_response_body_bytes":1,"max_request_header_bytes":1,"max_response_header_bytes":1,"max_redirects":0,"timeout_millis":1},"expires_at":"2027-01-01T00:00:00Z"}]}`,
	} {
		if _, err := ParseProfiles([]byte(input), now); err == nil {
			t.Fatalf("accepted invalid network config: %s", input)
		}
	}
	noTargets := strings.Replace(valid, `"allowed_domains":["example.com"]`, `"allowed_domains":[]`, 1)
	if _, err := ParseProfiles([]byte(noTargets), now); err == nil {
		t.Fatal("accepted a profile with no explicit target allowlist")
	}
}
