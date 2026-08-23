package execworker

import (
	"reflect"
	"testing"
)

func testLimits() Limits {
	return Limits{
		TimeoutMillis: 5000, CPUSeconds: 2, MemoryBytes: 64 << 20, PIDs: 8,
		OutputBytes: 1 << 20, ScanRegions: 4, ScanBytes: 4096, ScanResults: 8,
	}
}

func testProfile() TaskProfile {
	return TaskProfile{
		Name: "go-test", Executable: "/usr/bin/go", FixedArgv: []string{"test"},
		AllowedArgvPrefixes: [][]string{{"./..."}, {"-run"}}, WorkspaceMode: WorkspaceReadOnly,
		EnvAllowlist: []string{"GOFLAGS", "GOCACHE"}, Limits: testLimits(),
	}
}

func TestTaskProfileRejectsArbitraryInputs(t *testing.T) {
	profile := testProfile()
	if err := profile.Validate(); err != nil {
		t.Fatal(err)
	}
	if !profile.AllowsArgv([]string{"-run", "TestSafe"}) || profile.AllowsArgv([]string{"-exec", "/tmp/tool"}) {
		t.Fatal("argv prefix policy was not enforced")
	}
	if !profile.AllowsEnv(map[string]string{"GOFLAGS": "-count=1"}) || profile.AllowsEnv(map[string]string{"LD_PRELOAD": "/tmp/inject.so"}) {
		t.Fatal("environment name allowlist was not enforced")
	}
	profile.Executable = "go"
	if err := profile.Validate(); err == nil {
		t.Fatal("relative executable was accepted")
	}
	profile = testProfile()
	profile.AllowedArgvPrefixes = append(profile.AllowedArgvPrefixes, []string{})
	if err := profile.Validate(); err == nil {
		t.Fatal("empty arbitrary argv prefix was accepted")
	}
}

func TestTaskProfileDigestIsCanonical(t *testing.T) {
	left := testProfile()
	right := testProfile()
	right.EnvAllowlist = []string{"GOCACHE", "GOFLAGS"}
	right.AllowedArgvPrefixes = [][]string{{"-run"}, {"./..."}}
	leftDigest, err := left.Digest()
	if err != nil {
		t.Fatal(err)
	}
	rightDigest, err := right.Digest()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(leftDigest, rightDigest) {
		t.Fatalf("canonical profile digests differ: %s != %s", leftDigest, rightDigest)
	}
}
