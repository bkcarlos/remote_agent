# Validation status

Last updated: 2026-08-23

This file distinguishes checks completed on the current macOS development host from checks that remain blocked or require the production Linux environment. A successful cross-build verifies compilation only; it does not prove that Linux kernel isolation is enforced at runtime.

## Local environment

```text
Go:   go1.25.5
OS:   darwin
Arch: arm64
```

The host could not reach `proxy.golang.org` or `golang.org` during validation. The following required modules were not present in the local module cache:

- `golang.org/x/crypto v0.36.0`
- `github.com/pkg/sftp v1.13.7`

Both the default module proxy and one `GOPROXY=direct` attempt timed out. No further download attempts were made.

## Passed locally

### Source checks

```bash
gofmt -l cmd internal
git diff --check HEAD^..HEAD
git diff --check origin/main..HEAD
```

Results:

- No unformatted Go files were reported.
- No whitespace errors were reported.

### Unit tests without the unavailable SSH/SFTP modules

The following package set passed with both the normal test runner and race detector:

```bash
go test -count=1 \
  ./cmd/approve ./cmd/exec-worker ./cmd/file-worker ./cmd/install ./cmd/network-worker \
  ./internal/approval ./internal/approvalview ./internal/audit ./internal/capability \
  ./internal/execworker ./internal/fileworker ./internal/installer ./internal/networkworker \
  ./internal/policy ./internal/protocol ./internal/replay ./internal/requestmeta \
  ./internal/sandbox ./internal/textfile ./internal/transportauth ./internal/workspace \
  ./internal/workspaceregistry

go test -race -count=1 <the same package set>
```

During the first full test attempt, `internal/approvalview` exposed a faulty test mutation: the test uppercased a hash containing only digits, so the value did not change. The test was corrected to use an actually uppercase hexadecimal character, and `internal/approvalview` then passed individually and in both package-set runs.

### Vet and native builds without the unavailable modules

The package set above passed:

```bash
go vet <package set>
go build <package set>
```

The compatibility bridge also built successfully on macOS:

```bash
go build ./cmd/stdio-bridge
```

### Linux cross-builds without the unavailable modules

The package set above and the compatibility bridge compiled successfully for Linux amd64:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build <package set>
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./cmd/stdio-bridge
```

This compiled the Linux build-tagged File, Network, Exec, workspace, sandbox, cgroup, Landlock, seccomp, and openat2 code included in those packages. It did not execute that code.

## Blocked on this host

The following full commands could not complete because the two SSH/SFTP modules could not be downloaded:

```bash
go test -count=1 ./...
go test -race -count=1 ./...
go vet ./...
go build ./...
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build ./...
go mod verify
```

Packages not compiled or tested as part of the complete dependency graph:

- `cmd/gateway`
- `cmd/remote-worker`
- `internal/credentialstore`
- `internal/gateway`
- `internal/remoteworker`
- `cmd/stdio-bridge` tests, because those tests import Gateway code

`cmd/stdio-bridge` production code itself built successfully as noted above.

When the module files are available through a trusted cache or reachable proxy, rerun the full commands exactly as listed above. Do not treat the current dependency timeout as either a pass or a source-code failure for the blocked packages.

## Requires a Linux production host

The following cannot be validated by macOS execution or cross-compilation:

1. Namespace creation and the default no-network boundary for File/Exec children.
2. Seccomp syscall denial behavior.
3. Landlock enforcement and the documented degraded/fail-closed modes.
4. `openat2` workspace confinement and symlink/rename race resistance.
5. cgroup v2 delegation, resource enforcement, `cgroup.kill`, cleanup, and independent per-workspace runtime subtrees.
6. Exec supervisor socket permissions, process ownership, PID start-time checks, session tombstones, cancellation, memory scanning, and process cleanup under real concurrency.
7. Workspace expiry, revoke, and SIGHUP reload while Exec processes are active.
8. Linux credential-file `O_NOFOLLOW`, owner, and permission checks.
9. Remote Worker filesystem lockdown before SSH connection and handshake.
10. Installer permissions and service lifecycle on the target Linux distribution.

## Requires real services or clients

The following need controlled integration environments and are not covered by local unit tests:

1. Claude Code, Codex, and Zed Streamable HTTP connection using the exact deployed client versions.
2. Client-side approval prompts and tool annotations in `client_managed` mode. Standard MCP does not provide a Gateway-verifiable proof of the user's click.
3. Bearer authentication, session initialization, cancellation, DELETE, expiry, and workspace routing over a real LAN HTTP/TLS connection.
4. Network allowlists against controlled HTTPS and private HTTP targets, including DNS rebinding, redirects, timeout, response limits, upload, download, and overwrite conflicts.
5. SSH private-key and `ssh-agent` authentication with real `known_hosts` data.
6. SSH argv allowlists and SFTP list/read/write/mkdir/rename against a dedicated restricted account and server-side jail/chroot.
7. Audit fail-closed behavior during real disk-full, permission, fsync, and process-failure conditions.
8. Abrupt termination and power-loss behavior. Multi-file edits are not crash-atomic across SIGKILL, hard timeout, host failure, or power loss.

## Residual security constraints

- Linux is the only supported production Worker host.
- `client_managed` approval trusts the authenticated MCP client and cannot prove that a user approved the call.
- SFTP `RealPath` validation is not a server-side jail and cannot eliminate a remote concurrent symlink race.
- Numeric PID/start-time validation reduces PID reuse risk but is not equivalent to using pidfds for every signal path.
- Successful Linux cross-compilation is not evidence that the target kernel exposes or enforces every required isolation feature.
