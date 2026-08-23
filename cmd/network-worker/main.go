package main

import (
	"encoding/base64"
	"fmt"
	"os"

	"github.com/bkcarlos/remote_agent/internal/networkworker"
)

func main() {
	encodedPublicKey := os.Getenv("REMOTE_AGENT_NETWORK_WORKER_PUBLIC_KEY")
	os.Clearenv()
	publicKey, err := base64.RawStdEncoding.DecodeString(encodedPublicKey)
	if err != nil || len(publicKey) != 32 {
		fatal("valid Ed25519 public key is required")
	}
	if err := networkworker.ApplyParentDeathSignal(); err != nil {
		fatal("parent-death protection failed")
	}
	if err := networkworker.ApplyResourceLimits(); err != nil {
		fatal("resource limits failed")
	}
	service, err := networkworker.New(publicKey)
	if err != nil {
		fatal("worker initialization failed")
	}
	if err := service.Serve(os.Stdin, os.Stdout); err != nil {
		fatal("worker protocol failed")
	}
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "network-worker:", message)
	os.Exit(1)
}
