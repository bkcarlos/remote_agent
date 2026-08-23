package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/bkcarlos/remote_agent/internal/audit"
	"github.com/bkcarlos/remote_agent/internal/execworker"
	"github.com/bkcarlos/remote_agent/internal/fileworker"
	"github.com/bkcarlos/remote_agent/internal/gateway"
	"github.com/bkcarlos/remote_agent/internal/networkworker"
	"github.com/bkcarlos/remote_agent/internal/policy"
	"github.com/bkcarlos/remote_agent/internal/remoteworker"
	"github.com/bkcarlos/remote_agent/internal/workspaceregistry"
)

type workspaceFactory struct {
	workerBinary       string
	workerTimeout      time.Duration
	cgroupRoot         string
	networkBinary      string
	networkProfiles    map[string]networkworker.Profile
	remoteBinary       string
	remoteProfilesPath string
	execBinary         string
	execSocketDir      string
	execCgroupRoot     string
	execProduction     bool
	execAdministrator  execworker.AdministratorConfig
	policy             policy.Config
	gateway            gateway.Config
	audit              *audit.Logger
}

func (factory workspaceFactory) build(workspace workspaceregistry.WorkspaceConfig) (*gateway.Server, error) {
	effectivePolicy := workspacePolicyConfig(factory.policy, workspace)
	policies := policy.New(effectivePolicy)
	seed, err := workerSeed()
	if err != nil {
		return nil, err
	}
	executor, err := fileworker.NewSecureProcessExecutor(
		factory.workerBinary,
		workspace.Root,
		seed,
		factory.workerTimeout,
		policies.DeniedNames(),
		factory.cgroupRoot,
	)
	if err != nil {
		return nil, err
	}
	serverConfig := factory.gateway
	serverConfig.WorkspaceID = workspace.ID
	serverConfig.WorkspaceReadOnly = workspace.ReadOnly
	if factory.networkBinary != "" {
		networkSeed, seedErr := workerSeed()
		if seedErr != nil {
			return nil, seedErr
		}
		serverConfig.NetworkExecutor, err = networkworker.NewProcessExecutor(factory.networkBinary, networkSeed, factory.workerTimeout)
		if err != nil {
			return nil, err
		}
		serverConfig.NetworkProfiles = factory.networkProfiles
	}
	if factory.remoteBinary != "" {
		remoteSeed, seedErr := workerSeed()
		if seedErr != nil {
			return nil, seedErr
		}
		serverConfig.RemoteExecutor, err = remoteworker.NewProcessExecutor(factory.remoteBinary, factory.remoteProfilesPath, remoteSeed)
		if err != nil {
			return nil, err
		}
	}
	var execRuntime *execworker.Runtime
	execAdministrator, execAvailable := execAdministratorForWorkspace(factory.execAdministrator, workspace.ReadOnly)
	if factory.execBinary != "" && execAvailable {
		execRuntime, err = execworker.Launch(execworker.LaunchConfig{
			Binary: factory.execBinary, SocketDir: factory.execSocketDir, CgroupRoot: factory.execCgroupRoot,
			Production: factory.execProduction, WorkspaceID: workspace.ID, WorkspaceRoot: workspace.Root,
			Administrator: execAdministrator,
		})
		if err != nil {
			return nil, err
		}
		serverConfig.ExecExecutor, serverConfig.ExecSigner = execRuntime, execRuntime.Signer
		serverConfig.ExecProfiles, serverConfig.ExecCloser = execRuntime.Profiles, execRuntime
	}
	server, err := gateway.New(serverConfig, executor, policies, factory.audit)
	if err != nil && execRuntime != nil {
		_ = execRuntime.Close()
	}
	return server, err
}

func workerSeed() ([]byte, error) {
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		return nil, errors.New("generate independent workspace worker key")
	}
	return seed, nil
}

func execAdministratorForWorkspace(config execworker.AdministratorConfig, readOnly bool) (execworker.AdministratorConfig, bool) {
	filtered := execworker.AdministratorConfig{Version: config.Version}
	for _, profile := range config.Profiles {
		if readOnly && profile.WorkspaceMode == execworker.WorkspaceReadWrite {
			continue
		}
		filtered.Profiles = append(filtered.Profiles, profile)
	}
	return filtered, len(filtered.Profiles) > 0
}

func workspacePolicyConfig(global policy.Config, workspace workspaceregistry.WorkspaceConfig) policy.Config {
	global.DeniedNames = append([]string(nil), global.DeniedNames...)
	document := policy.Document{
		Version:     "workspace-registry-v1",
		DeniedNames: append([]string(nil), workspace.DeniedNames...),
	}
	if workspace.ReadOnly {
		allowWrite := false
		document.AllowWrite = &allowWrite
	}
	return policy.Restrict(global, document)
}

type workspaceBuilder func(workspaceregistry.WorkspaceConfig) (*gateway.Server, error)

func buildWorkspaceBindings(workspaces []workspaceregistry.WorkspaceConfig, build workspaceBuilder) ([]gateway.WorkspaceBinding, error) {
	if build == nil {
		return nil, errors.New("workspace builder is required")
	}
	bindings := make([]gateway.WorkspaceBinding, 0, len(workspaces))
	for _, workspace := range workspaces {
		handler, err := build(workspace)
		if err != nil {
			closeWorkspaceBindings(bindings)
			return nil, fmt.Errorf("build workspace %q: %w", workspace.ID, err)
		}
		bindings = append(bindings, gateway.WorkspaceBinding{Workspace: workspace, Handler: handler})
	}
	return bindings, nil
}

func closeWorkspaceBindings(bindings []gateway.WorkspaceBinding) {
	for _, binding := range bindings {
		if binding.Handler != nil {
			binding.Handler.Revoke()
		}
	}
}

// reloadWorkspaceConfig leaves the currently routed set untouched unless the
// trusted file loads strictly, every workspace builds, and ReplaceAll succeeds.
func reloadWorkspaceConfig(path string, router *gateway.WorkspaceRouter, build workspaceBuilder, now func() time.Time) ([]gateway.WorkspaceBinding, error) {
	if router == nil || now == nil {
		return nil, errors.New("workspace reload dependencies are required")
	}
	config, err := workspaceregistry.LoadFile(path, now().UTC())
	if err != nil {
		return nil, err
	}
	bindings, err := buildWorkspaceBindings(config.Workspaces, build)
	if err != nil {
		return nil, err
	}
	if err := router.ReplaceAll(bindings); err != nil {
		closeWorkspaceBindings(bindings)
		return nil, err
	}
	return bindings, nil
}
