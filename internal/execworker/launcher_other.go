//go:build !linux

package execworker

import (
	"context"
	"time"
)

type LaunchConfig struct {
	Binary        string
	SocketDir     string
	CgroupRoot    string
	Production    bool
	WorkspaceID   string
	WorkspaceRoot string
	Administrator AdministratorConfig
	ReadyTimeout  time.Duration
}

type Runtime struct {
	Client   Client
	Signer   *CapabilitySigner
	Profiles map[string]TaskProfile
}

func Launch(LaunchConfig) (*Runtime, error) { return nil, ErrUnsupported }

func (runtime *Runtime) Do(context.Context, Job) (Response, error) {
	return Response{}, ErrUnsupported
}

func (runtime *Runtime) Close() error { return nil }
