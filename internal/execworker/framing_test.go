package execworker

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"testing"
)

func TestSupervisorCookieIsRandomCanonical256Bit(t *testing.T) {
	left, err := GenerateCookie()
	if err != nil {
		t.Fatal(err)
	}
	right, err := GenerateCookie()
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := base64.RawURLEncoding.DecodeString(left)
	if err != nil || len(decoded) != 32 || base64.RawURLEncoding.EncodeToString(decoded) != left {
		t.Fatalf("cookie is not canonical 256-bit base64url: %q", left)
	}
	if left == right {
		t.Fatal("independent supervisor cookies unexpectedly matched")
	}
}

func TestLengthFramingRoundTrip(t *testing.T) {
	input := Request{Cookie: "cookie", Job: testJob()}
	var wire bytes.Buffer
	if err := WriteFrame(&wire, input); err != nil {
		t.Fatal(err)
	}
	var output Request
	if err := ReadFrame(&wire, &output); err != nil {
		t.Fatal(err)
	}
	if output.Cookie != input.Cookie || output.Job.SessionID != input.Job.SessionID {
		t.Fatalf("framed request changed identity: %+v", output)
	}
}

func TestLengthFramingRejectsOversizeAndUnknownJSON(t *testing.T) {
	var oversized bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], MaxFrameBytes+1)
	oversized.Write(header[:])
	if err := ReadFrame(&oversized, new(Request)); !errors.Is(err, ErrFrameTooLarge) {
		t.Fatalf("oversized frame error = %v", err)
	}

	raw := []byte(`{"cookie":"x","job":{},"unknown":true}`)
	var unknown bytes.Buffer
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	unknown.Write(header[:])
	unknown.Write(raw)
	if err := ReadFrame(&unknown, new(Request)); err == nil {
		t.Fatal("unknown JSON field was accepted")
	}
}

func TestLengthFramingRejectsDuplicateJSONFields(t *testing.T) {
	raw := []byte(`{"cookie":"x","cookie":"y","job":{}}`)
	var wire bytes.Buffer
	var header [4]byte
	binary.BigEndian.PutUint32(header[:], uint32(len(raw)))
	wire.Write(header[:])
	wire.Write(raw)
	if err := ReadFrame(&wire, new(Request)); err == nil {
		t.Fatal("duplicate JSON field was accepted")
	}
}
