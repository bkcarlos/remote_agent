package protocol

import "testing"

type strictFixture struct {
	Name   string         `json:"name"`
	Nested map[string]int `json:"nested,omitempty"`
}

func TestDecodeStrict(t *testing.T) {
	var out strictFixture
	if err := DecodeStrict([]byte(`{"name":"ok","nested":{"value":1}}`), &out); err != nil || out.Name != "ok" {
		t.Fatalf("valid value rejected: %+v %v", out, err)
	}
	invalid := []string{
		``,
		`{"name":"a","name":"b"}`,
		`{"name":"a","nested":{"x":1,"x":2}}`,
		`{"name":"a","unknown":1}`,
		`{"name":"a"}{"name":"b"}`,
		`[{"name":"a"},{"name":"b","name":"c"}]`,
	}
	for _, raw := range invalid {
		var value strictFixture
		if err := DecodeStrict([]byte(raw), &value); err == nil {
			t.Errorf("accepted ambiguous JSON: %s", raw)
		}
	}
}
