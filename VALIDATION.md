# Validation status

Last updated: 2026-08-23

This file distinguishes checks completed on the current macOS development host from checks that remain blocked or require the production Linux environment. A successful cross-build verifies compilation only; it does not prove that Linux kernel isolation is enforced at runtime.

## Local environment

```text
Go:   go1.25.5
OS:   darwin
Arch: arm64
```

The default Go proxy and direct origin initially timed out. Dependencies were later obtained through a temporary alternate module proxy while normal Go checksum-database verification remained enabled. `go mod tidy` found and corrected an invalid manually recorded `golang.org/x/sync v0.12.0` content hash, completed the transitive module graph, and `GOPROXY=off go mod verify` now passes from the local verified cache.

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

### Complete tests, race detector, vet, and native build

The complete repository dependency graph passed from the verified offline module cache:

```bash
GOPROXY=off go test -count=1 ./...
GOPROXY=off go test -race -count=1 ./...
GOPROXY=off go vet ./...
GOPROXY=off go build ./...
GOPROXY=off go mod verify
```

Validation found and fixed:

- A test mutation that uppercased a digits-only SHA-256 value and therefore did not mutate it.
- A two-dimensional Exec profile clone that replaced configured argv prefixes with empty slices, which prevented normal Exec calls and session revocation.
- Gateway lifecycle tests that used a non-durable audit buffer for an L3 operation.
- A WorkspaceRouter test clock data race.
- An overly short File Worker test startup deadline under heavy concurrent local validation load.

Targeted Gateway/File tests passed five times normally and three times under the race detector before the final full runs.

### Cross-platform compilation

The complete repository compiled with `CGO_ENABLED=0` for every CI build target:

```bash
GOOS=linux GOARCH=amd64 go build ./...
GOOS=linux GOARCH=arm64 go build ./...
GOOS=darwin GOARCH=amd64 go build ./...
GOOS=darwin GOARCH=arm64 go build ./...
GOOS=windows GOARCH=amd64 go build ./...
```

These commands compile build-tagged platform code but do not execute Linux kernel isolation or Windows/macOS production workers.

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
