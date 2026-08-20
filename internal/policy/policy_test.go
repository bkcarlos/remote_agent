package policy

import "testing"

func TestPolicy(t *testing.T) {
	p := New(Config{})
	for _, path := range []string{".env", "x/.ssh/config", "ID_RSA"} {
		if d := p.Evaluate("read_file", path); d.Allowed {
			t.Errorf("sensitive path allowed: %s", path)
		}
	}
	if d := p.Evaluate("read_file", "src/main.go"); !d.Allowed || d.Approval {
		t.Fatalf("unexpected read decision: %+v", d)
	}
	if d := p.Evaluate("write_file", "a"); d.Allowed {
		t.Fatal("write allowed by default")
	}
	p = New(Config{AllowWrite: true})
	if d := p.Evaluate("write_file", "a"); !d.Allowed || !d.Approval {
		t.Fatalf("unexpected write decision: %+v", d)
	}
	if d := p.Evaluate("shell", "a"); d.Allowed {
		t.Fatal("unknown tool allowed")
	}
}
func TestLimitsDefault(t *testing.T) {
	p := New(Config{})
	if p.MaxReadBytes() <= 0 || p.MaxWriteBytes() <= 0 {
		t.Fatal("invalid defaults")
	}
}
