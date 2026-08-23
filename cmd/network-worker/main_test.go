package main

import (
	"os"
	"strings"
	"testing"
)

func TestWorkerCommandHasNoWorkspaceOrPathFlags(t *testing.T) {
	source, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(source)
	for _, forbidden := range []string{"workspace", "local_path", "-path"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("network worker command contains forbidden local-path concept %q", forbidden)
		}
	}
}
