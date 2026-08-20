package audit

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestRecordJSONL(t *testing.T) {
	var b bytes.Buffer
	l := New(&b)
	if e := l.Record(Event{RequestID: "r\ninjected", Status: "ok"}); e != nil {
		t.Fatal(e)
	}
	if strings.Count(b.String(), "\n") != 1 {
		t.Fatalf("event was not one JSON line: %q", b.String())
	}
	var e Event
	if json.Unmarshal(b.Bytes(), &e) != nil || e.Time.IsZero() || e.RequestID != "r\ninjected" {
		t.Fatalf("bad event: %+v", e)
	}
}
