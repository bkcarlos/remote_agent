package networkworker

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestServeAlwaysEmitsOneStrictJSONResponseForInvalidJob(t *testing.T) {
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	service, err := New(publicKey)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := service.Serve(strings.NewReader(`{"unknown":true}`), &output); err != nil {
		t.Fatal(err)
	}
	var response Response
	decoder := json.NewDecoder(&output)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Error == "" || !response.Untrusted {
		t.Fatalf("unexpected invalid-job response: %#v", response)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		t.Fatalf("worker emitted trailing output: %v", err)
	}
}
