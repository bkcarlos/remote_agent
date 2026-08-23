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

func TestDecodeStrictInitializeStructures(t *testing.T) {
	valid := `{"protocolVersion":"2025-06-18","capabilities":{"sampling":{}},"clientInfo":{"name":"client","version":"1"}}`
	var params InitializeParams
	if err := DecodeStrict([]byte(valid), &params); err != nil {
		t.Fatalf("valid initialize params rejected: %v", err)
	}
	if params.ProtocolVersion != "2025-06-18" || params.Capabilities == nil || params.ClientInfo.Name != "client" || params.ClientInfo.Version != "1" {
		t.Fatalf("initialize params decoded incorrectly: %+v", params)
	}
	for _, raw := range []string{
		`{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"client","version":"1"},"unknown":true}`,
		`{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"client","version":"1","unknown":true}}`,
		`{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"first","name":"second","version":"1"}}`,
		valid + ` true`,
	} {
		var value InitializeParams
		if err := DecodeStrict([]byte(raw), &value); err == nil {
			t.Errorf("accepted non-strict initialize params: %s", raw)
		}
	}
}
