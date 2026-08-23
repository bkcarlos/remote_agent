//go:build linux

package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/bkcarlos/remote_agent/internal/execworker"
	"github.com/bkcarlos/remote_agent/internal/protocol"
)

type administratorConfig struct {
	Profiles   []execworker.TaskProfile `json:"profiles"`
	Workspaces map[string]string        `json:"workspaces"`
}

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--exec-child" {
		if err := execworker.RunExecChild(); err != nil {
			fatal(err.Error())
		}
		return
	}
	socketPath := flag.String("socket", "", "absolute Unix socket path")
	configPath := flag.String("config", "", "administrator-owned task profile JSON")
	cgroupRoot := flag.String("cgroup-root", "", "delegated cgroup v2 directory")
	production := flag.Bool("production", true, "fail closed unless all Linux isolation layers are available")
	flag.Parse()
	if *socketPath == "" || *configPath == "" {
		fatal("-socket and -config are required")
	}
	cookie := os.Getenv("REMOTE_AGENT_EXEC_COOKIE")
	encodedPublicKey := os.Getenv("REMOTE_AGENT_EXEC_PUBLIC_KEY")
	_ = os.Unsetenv("REMOTE_AGENT_EXEC_COOKIE")
	_ = os.Unsetenv("REMOTE_AGENT_EXEC_PUBLIC_KEY")
	publicKey, err := base64.RawStdEncoding.DecodeString(encodedPublicKey)
	if err != nil || len(publicKey) != 32 {
		fatal("valid Ed25519 exec capability public key is required")
	}
	raw, err := os.ReadFile(*configPath)
	if err != nil {
		fatal("administrator config is unavailable")
	}
	var configured administratorConfig
	if err := protocol.DecodeStrict(raw, &configured); err != nil {
		fatal("administrator config is invalid")
	}
	profiles := make(map[string]execworker.TaskProfile, len(configured.Profiles))
	for _, profile := range configured.Profiles {
		if _, exists := profiles[profile.Name]; exists {
			fatal("administrator config contains duplicate profile names")
		}
		profiles[profile.Name] = profile
	}
	binary, err := os.Executable()
	if err != nil {
		fatal("cannot resolve exec worker binary")
	}
	supervisor, err := execworker.NewSupervisor(execworker.Config{
		SocketPath: *socketPath, Cookie: cookie, PublicKey: publicKey,
		Profiles: profiles, Workspaces: configured.Workspaces, WorkerBinary: binary,
		CgroupRoot: *cgroupRoot, Production: *production,
	})
	if err != nil {
		fatal(err.Error())
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := supervisor.ListenAndServe(ctx); err != nil {
		fatal(err.Error())
	}
}

func fatal(message string) {
	fmt.Fprintln(os.Stderr, "exec-worker:", message)
	os.Exit(1)
}
