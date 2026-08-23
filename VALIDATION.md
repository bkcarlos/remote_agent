# Validation status

Last updated: 2026-08-24

This file distinguishes checks completed on the current macOS development host from checks that remain blocked or require the production Linux environment. A successful cross-build verifies compilation only; it does not prove that Linux kernel isolation is enforced at runtime.

## Local environment

```text
Go:   go1.25.5
OS:   darwin
Arch: arm64
```

## Linux integration environment

A production-like black-box validation was completed with binaries built from commit `fdb9f4ad8a0bec31befac5bf9b7fb951649a4da2` and copied over SSH. Transfer integrity was checked by matching SHA-256 hashes before execution.

```text
OS:      Ubuntu 24.04 LTS (Noble)
Kernel:  Linux 6.8.0-55-generic
Arch:    x86_64
systemd: 255
cgroup:  v2 unified hierarchy
```

The target did not have Go installed, so source tests were not rerun there. Validation used temporary loopback and private-interface listeners, root-owned transient systemd units, workspaces, credentials, and a dedicated SSH target account. The Gateway itself therefore ran as root for this disposable test; production must use a dedicated unprivileged service account. All temporary units, processes, listeners, files, keys, tunnels, and the account were removed afterward.

## Passed on the Linux integration host

### Gateway, MCP, File Worker, and sessions

- Streamable HTTP initialization negotiated protocol `2025-03-26`, returned `Mcp-Session-Id`, and accepted `notifications/initialized` with HTTP 202.
- The current Vela Agent acted as an external MCP client through an SSH local forward to the target's `192.168.12.240:18080` private-interface listener. It completed initialize, tool discovery, file read, client-managed write preview/apply, read-back hash verification, Session DELETE, and post-delete rejection.
- Direct access to the cloud NAT address on port 18080 timed out because the perimeter currently exposes SSH only; Gateway startup and the private-interface listener were healthy.
- Bearer authentication rejected a missing token with HTTP 401.
- `client_managed` tool metadata, file read/checksum, write preview, expected-hash apply, durable started/completed audit, and host content/hash verification passed.
- MCP Session DELETE returned 204, revoked the session, and later calls returned the session-not-found 404 response.
- Path traversal was rejected at argument validation, and a workspace symlink to `/etc/passwd` was rejected as an unsafe workspace entry.
- Insecure HTTP on `0.0.0.0` failed closed even with `-allow-insecure-http`; loopback HTTP remained available for controlled testing.

### Linux isolation and cgroup v2

- The kernel configuration enables Landlock, seccomp, and seccomp filters. Workers completed sandbox initialization successfully.
- A live Exec child had separate user, mount, network, PID, IPC, and UTS namespaces, `NSpid` 1, `NoNewPrivs: 1`, and seccomp filter mode 2.
- A delegated systemd cgroup worked with `Delegate=yes`, `DelegateSubgroup=gateway`, and `cpu memory pids` enabled in `cgroup.subtree_control`.
- Observed Exec child limits matched the profile: 128 MiB memory, zero swap, 16 PIDs, and one CPU. Worker/process cgroups were removed after completion or session revocation.
- Supplying a delegated root without enabling the required controllers failed closed rather than silently running without limits.

### Network Worker

- A controlled loopback HTTP service validated `web_fetch`, `download`, and `upload` with a strict profile allowing only `localhost`, port 18081, HTTP, and `127.0.0.0/8`.
- Downloaded bytes and SHA-256 matched the source; upload sent only the selected workspace file and received the expected PUT response.
- Responses were marked untrusted, and audit records contained worker/token identities without exposing target values.

### Remote SSH/SFTP Worker

- A temporary dedicated account, temporary Ed25519 private key, and strict generated `known_hosts` file validated private-key authentication.
- Fixed-argv `ssh_exec` and SFTP list/read/write/mkdir/rename passed. Workspace-to-SFTP bytes and SHA-256 matched.
- A non-allowlisted command and a read outside the configured SFTP root both failed closed.

### Exec, Debug, and Mem

- A fixed `printf` profile passed `exec_run`; a fixed Python profile passed process start/status and debug status.
- `mem_scan` found a known marker within the 16 MiB scan limit and returned only bounded region/offset/hash metadata.
- Session DELETE terminated the managed process, removed its child cgroup, and invalidated later calls.

### Multi-workspace registry

- Opaque per-workspace endpoints worked and the unscoped `/mcp` endpoint returned 404.
- Invalid SIGHUP reload retained the previous configuration atomically.
- Valid SIGHUP reload removed the old route, retained an unchanged route, added the new route, and accepted initialization on it.
- Background workspace expiry removed the route and invalidated its existing session without requiring a request to trigger cleanup.

## Reproducing the Agent-as-client validation

The tested host has a cloud NAT address but only a private `192.168.0.0/16` address on its interface. Replace the placeholders below with the controlled deployment values; do not publish the temporary token.

### 1. Cross-build and copy the minimum binaries

```bash
mkdir -p .client-validation-linux-amd64
GOPROXY=off GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -o .client-validation-linux-amd64/gateway ./cmd/gateway
GOPROXY=off GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -o .client-validation-linux-amd64/file-worker ./cmd/file-worker

ssh root@<ssh-host> \
  'mkdir -p /tmp/remote-agent-client-validation/bin /tmp/remote-agent-client-validation/workspace /tmp/remote-agent-client-validation/state'
scp .client-validation-linux-amd64/gateway \
  .client-validation-linux-amd64/file-worker \
  root@<ssh-host>:/tmp/remote-agent-client-validation/bin/
```

Compare local and remote SHA-256 values before starting the service.

### 2. Start Gateway on the target's private interface

The test used a root-owned transient unit only to validate kernel integration. Production must use the installer and a dedicated unprivileged account. The startup helper must enable the delegated controllers before Gateway creates Worker cgroups:

```sh
#!/bin/sh
set -eu
printf '+cpu +memory +pids' \
  > /sys/fs/cgroup/system.slice/remote-agent-client-validation.service/cgroup.subtree_control
exec /tmp/remote-agent-client-validation/bin/gateway \
  -workspace /tmp/remote-agent-client-validation/workspace \
  -workspace-id client-validation-workspace \
  -file-worker /tmp/remote-agent-client-validation/bin/file-worker \
  -cgroup-root /sys/fs/cgroup/system.slice/remote-agent-client-validation.service \
  -listen <target-private-ip>:18080 \
  -allow-insecure-http \
  -approval-mode client_managed \
  -allow-write \
  -audit-log /tmp/remote-agent-client-validation/audit.jsonl \
  -replay-db /tmp/remote-agent-client-validation/state/replay.db
```

Save the helper as `/tmp/remote-agent-client-validation/start-client-validation.sh`, make it executable, and start it with:

```bash
systemd-run \
  --unit=remote-agent-client-validation \
  --collect \
  --service-type=simple \
  --property=Delegate=yes \
  --property=DelegateSubgroup=gateway \
  --setenv=REMOTE_AGENT_TOKEN='<temporary-random-token-at-least-32-characters>' \
  /tmp/remote-agent-client-validation/start-client-validation.sh
```

Confirm the private listener and an on-host initialize request before testing the external client.

### 3. Probe direct NAT access, then establish the controlled tunnel

A direct request to `http://<cloud-nat-address>:18080/mcp` timed out in the tested environment because its perimeter exposes only SSH. No firewall or security-group rule was changed for validation.

The current Agent then used a bounded SSH local forward:

```bash
ssh -M -S /tmp/remote-agent-mcp-control \
  -f -N -o ExitOnForwardFailure=yes \
  -L 127.0.0.1:18080:<target-private-ip>:18080 \
  root@<ssh-host>
```

The MCP endpoint was therefore available to the client at `http://127.0.0.1:18080/mcp`, while the actual Gateway and Worker remained on the Linux host.

### 4. Run the Streamable HTTP sequence

Every POST used these headers:

```text
Authorization: Bearer <temporary-token>
Content-Type: application/json
Accept: application/json, text/event-stream
MCP-Protocol-Version: 2025-03-26
Mcp-Session-Id: <value returned by initialize, except on initialize itself>
```

The client executed this sequence:

1. `initialize` and capture the `Mcp-Session-Id` response header.
2. `notifications/initialized`, expecting HTTP 202.
3. `tools/list`, confirming the enabled File tools.
4. `tools/call` `read_file` for `hello.txt`, retaining its SHA-256.
5. `tools/call` `write_file` without `apply` to obtain the client-managed preview.
6. `tools/call` `write_file` with `apply=true` and `expected_hash` equal to the read result.
7. `tools/call` `read_file` again, confirming content and SHA-256 match the apply result.
8. HTTP DELETE with the Session ID, expecting 204.
9. A later `tools/list` with the deleted Session ID, expecting the session-not-found 404 response.

Observed status and behavior:

| Step | Result |
| --- | --- |
| Initialize | HTTP 200, protocol `2025-03-26`, Session ID returned |
| Initialized notification | HTTP 202 |
| Tool discovery | 12 File tools |
| Remote read | Content, SHA-256, capability ID, and Worker ID returned |
| Write preview | `client_managed`, before/after/review hashes returned |
| Expected-hash apply | `written=true`; returned SHA-256 matched read-back |
| Session DELETE | HTTP 204 |
| Post-delete call | HTTP 404, session not found or expired |
| Durable audit | All operations successful and `security_degraded=false` |

### 5. Cleanup

```bash
ssh -S /tmp/remote-agent-mcp-control -O exit root@<ssh-host>
ssh root@<ssh-host> \
  'systemctl stop remote-agent-client-validation.service; rm -rf /tmp/remote-agent-client-validation'
rm -rf .client-validation-linux-amd64 /tmp/remote-agent-mcp-control
```

The completed run confirmed that the control socket, local listener, remote unit, remote listener, processes, cgroups, binaries, workspace, state, and temporary audit data were removed.

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

## Remaining Linux production checks

The Linux black-box run covered the main runtime paths, but the following still need focused fault, concurrency, or deployment testing:

1. Explicitly attempt denied syscalls inside File and Exec sandboxes to distinguish seccomp/Landlock enforcement from successful filter setup.
2. Stress `openat2` and SFTP authorization under concurrent rename/symlink races.
3. Exercise cgroup OOM, PID exhaustion, CPU throttling, hard timeout, and `cgroup.kill` while descendants are actively forking.
4. Run concurrent Exec processes through workspace SIGHUP replacement/expiry and verify old supervisor/runtime teardown under load.
5. Test PID start-time mismatch and cancellation races at high concurrency.
6. Add negative credential checks for symlinked, wrong-owner, and group/world-writable profile, key, and `known_hosts` files; test inherited `ssh-agent` authentication.
7. Verify Remote Worker filesystem lockdown with targeted post-Landlock access probes.
8. Validate installer permissions and the dedicated unprivileged Gateway service account, plus persistent service lifecycle, restart, upgrade, and rollback on the intended production distribution.

## Requires additional real services or clients

The loopback Linux run covered direct Streamable HTTP, controlled private HTTP transfers, private-key SSH with strict `known_hosts`, and a dedicated SFTP account. The following still require their intended integration environments:

1. Claude Code, Codex, and Zed Streamable HTTP connection using the exact deployed client versions.
2. Client-side approval prompts and tool annotations in `client_managed` mode. Standard MCP does not provide a Gateway-verifiable proof of the user's click.
3. Direct private-LAN/NAT access without SSH forwarding, cancellation, and, if used, production TLS termination. Bearer authentication, initialize, tools, write flow, DELETE, and post-delete rejection already passed from the development-host Agent through an SSH tunnel.
4. Controlled HTTPS, redirects, DNS rebinding, timeout, response/header limits, download overwrite conflicts, and malformed upstream behavior. Loopback private HTTP fetch/upload/download already passed.
5. Inherited `ssh-agent` authentication and the intended production restricted account/chroot. Private-key authentication, strict `known_hosts`, argv allowlists, and SFTP operations already passed against a temporary dedicated account.
6. Audit fail-closed behavior during real disk-full, permission, fsync, and process-failure conditions.
7. Abrupt termination and power-loss behavior. Multi-file edits are not crash-atomic across SIGKILL, hard timeout, host failure, or power loss.

## Residual security constraints

- Linux is the only supported production Worker host.
- `client_managed` approval trusts the authenticated MCP client and cannot prove that a user approved the call.
- SFTP `RealPath` validation is not a server-side jail and cannot eliminate a remote concurrent symlink race.
- Numeric PID/start-time validation reduces PID reuse risk but is not equivalent to using pidfds for every signal path.
- Successful Linux cross-compilation is not evidence that the target kernel exposes or enforces every required isolation feature.
