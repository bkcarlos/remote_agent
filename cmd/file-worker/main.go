package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/bkcarlos/remote_agent/internal/fileworker"
	"github.com/bkcarlos/remote_agent/internal/sandbox"
)

func main() {
	workspace := flag.String("workspace", "", "authorized workspace root")
	flag.Parse()
	if *workspace == "" {
		fatal("-workspace is required")
	}
	encodedPublicKey := os.Getenv("REMOTE_AGENT_WORKER_PUBLIC_KEY")
	publicKey, err := base64.RawStdEncoding.DecodeString(encodedPublicKey)
	if err != nil || len(publicKey) != 32 {
		fatal("valid Ed25519 worker public key is required")
	}
	_ = os.Unsetenv("REMOTE_AGENT_WORKER_PUBLIC_KEY")
	var deniedNames []string
	if raw := os.Getenv("REMOTE_AGENT_DENIED_NAMES"); raw != "" {
		if err := json.Unmarshal([]byte(raw), &deniedNames); err != nil {
			fatal("invalid denied-name policy")
		}
	}
	_ = os.Unsetenv("REMOTE_AGENT_DENIED_NAMES")
	service, err := fileworker.NewWithDenied(*workspace, publicKey, deniedNames)
	if err != nil {
		fatal(err.Error())
	}
	if err := service.ServeWithSandbox(os.Stdin, os.Stdout, func(operation string) error {
		if err := sandbox.ApplyResourceLimits(); err != nil {
			return err
		}
		if err := sandbox.ApplyWorkspace(*workspace, operation == "write_file"); err != nil {
			return err
		}
		return sandbox.ApplySeccomp()
	}); err != nil {
		fatal(err.Error())
	}
}
func fatal(message string) {
	fmt.Fprintln(os.Stderr, "file-worker:", message)
	os.Exit(1)
}
