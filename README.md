# Secure Remote Agent

Go implementation of the secure remote-agent MVP described in `secure-agent-tool-requirements.zh-CN.md`.

## Run

```bash
mkdir -p bin
go build -o bin/file-worker ./cmd/file-worker
go build -o bin/gateway ./cmd/gateway
export REMOTE_AGENT_TOKEN='replace-with-at-least-32-random-characters'
bin/gateway -workspace ./example -file-worker bin/file-worker \
  -allow-insecure-http -listen 127.0.0.1:8080
```

Public deployments must omit `-allow-insecure-http` and provide `-tls-cert` and `-tls-key`.
Configure an stdio-only MCP client to launch:

```bash
go run ./cmd/stdio-bridge -endpoint http://127.0.0.1:8080
```

The Gateway never opens workspace files directly. Every file operation starts an independent, short-lived `file-worker` process with a sanitized environment and a signed, scoped, 30-second capability. On Linux the child is created in new user, mount, network, PID, IPC, and UTS namespaces with a parent-death signal. After capability verification it applies `no_new_privs`, CPU/open-file/process/file-size/core rlimits and a seccomp-BPF filter. When supported by the kernel, it also applies a Landlock ruleset restricted to the workspace, with no workspace write rights for read jobs. Older kernels, kernels with Landlock disabled, and container seccomp profiles that hide its syscalls continue with an explicit startup warning and rely on the `openat2` workspace boundary plus namespace/seccomp isolation. Other sandbox or resource-limit setup failures remain fail-closed. Worker stdout and stderr use bounded writers so output is rejected before it can grow Gateway memory without limit. No worker receives host network access. The seccomp filter denies networking, mount, namespace mutation, ptrace, BPF, performance-event, kernel-module, keyring, reboot and chroot syscalls.

For production Linux deployments, pass a systemd/container-runtime delegated cgroup v2 directory using `-cgroup-root`. Each Worker is placed into its cgroup at clone time and receives a 256 MiB memory limit, disabled swap, 32-PID limit, and one-CPU quota. If a configured cgroup cannot be created or constrained, the job is denied; omitting `-cgroup-root` emits a startup warning and retains rlimits only. Bridge requests are HMAC-signed with a timestamp and nonce; the Gateway rejects tampering and replay. Consumed HTTP nonces and approval IDs are atomically persisted in the BoltDB file configured by `-replay-db` (default `state/replay.db`), so restart does not restore still-valid credentials. The bridge writes protocol messages only to stdout and diagnostics to stderr.

Writes are disabled by default. To enable them, set a separate approval signing key and pass `-allow-write`:

```bash
export REMOTE_AGENT_APPROVAL_KEY='a-different-random-secret-of-at-least-32-characters'
go build -o bin/approve ./cmd/approve
bin/gateway ... -allow-write
```

A `write_file` call is dry-run unless `apply` is true. Dry-run returns an approval ID, session ID, normalized path, proposed content SHA-256, and current file SHA-256. After reviewing them, a trusted user creates a short-lived, single-use token:

```bash
REMOTE_AGENT_APPROVAL_KEY="$REMOTE_AGENT_APPROVAL_KEY" bin/approve \
  --approval-id '<dry-run approval_id>' \
  --session '<dry-run session_id>' \
  --path 'relative/file.txt' \
  --content-sha256 '<dry-run content_sha256>' \
  --expected-hash '<dry-run before_sha256>' \
  --approve
```

Pass the resulting value as the strict `approval_token` argument with the same write request. The Gateway persists every dry-run challenge before returning it; an approval is accepted only when that exact, unexpired challenge exists, matches all normalized fields, and is atomically consumed. Tokens are bound to session, operation, path, content hash and expected file hash, and cannot be replayed across restart.

## Restrictive policy layers

The Gateway accepts strict JSON policy layers in this order:

```text
administrator > deployment > project > command-line capability
```

Each loaded layer can only disable writes, lower byte limits, or add denied names. It cannot enable a capability or increase a limit disabled by a higher effective layer. Unknown fields, invalid limits, path-shaped denied names, and trailing JSON are rejected at startup.

```bash
bin/gateway ... \
  -admin-policy policies/default/admin.json \
  -deployment-policy /etc/remote-agent/deployment.json \
  -project-policy /trusted/project-policy.json
```

The schema is available at `policies/schema/policy.schema.json`. Repository content must not choose these policy paths; they are trusted launcher/admin arguments.

## Available tools

The Gateway currently exposes policy-filtered tools dynamically:

- `read_file`: bounded regular-file reading
- `list_dir`: bounded directory listing
- `checksum`: SHA-256 calculation
- `file_info`: metadata without host absolute paths
- `glob`: bounded relative-pattern file discovery
- `grep`: bounded text search that skips symlinks, binary content, and policy-denied names
- `write_file`: dry-run and approved atomic writing; hidden when writes are disabled

All tool requests use strict JSON decoding: unknown or duplicate fields, trailing values, malformed SHA-256 values, missing required paths, and oversized security-sensitive parameters are rejected. All file operations execute in the independent file worker and remain relative to the authorized workspace. On Linux, file opens and recursive search use directory file descriptors with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` and `fstatat(AT_SYMLINK_NOFOLLOW)`; search does not use host absolute-path walking. Default and administrator-added sensitive names are passed to the worker and pruned before file content is read. On Unix, files with multiple hard links are denied by default so a workspace hard link cannot expose an inode originating outside the workspace. Atomic writes use parent-directory descriptors, `openat` with exclusive temporary files, a second expected-hash check, `renameat`, and directory `fsync`, reducing path traversal and TOCTOU exposure. Other platforms retain conservative component checks and disable symlinks but do not yet provide the same kernel-enforced boundary.

## Install into an MCP client

Build the commands first:

```bash
go build -o bin/stdio-bridge ./cmd/stdio-bridge
go build -o bin/remote-agent-install ./cmd/install
```

Installation is preview-only unless `--apply` is provided. Existing JSON settings and MCP servers are preserved, and an exclusive timestamped backup is created before modification:

```bash
# Public endpoint: HTTPS is required
bin/remote-agent-install --client cursor --bridge bin/stdio-bridge \
  --endpoint https://agent.example.com/mcp
bin/remote-agent-install --client cursor --bridge bin/stdio-bridge \
  --endpoint https://agent.example.com/mcp --apply

# Controlled private network: HTTP requires explicit acknowledgement
bin/remote-agent-install --client claude --bridge bin/stdio-bridge \
  --endpoint http://10.0.0.20:8080 --allow-private-http --apply
```

Supported JSON client presets are `claude`, `claude-code`, `cursor`, and `windsurf`. Use `--config` for another JSON-based MCP client. The installer never writes authentication or approval tokens into client configuration. The trusted launcher environment must provide `REMOTE_AGENT_TOKEN`.

Uninstall removes only this Agent's MCP entry and preserves all unrelated settings:

```bash
bin/remote-agent-install --client cursor --uninstall          # preview
bin/remote-agent-install --client cursor --uninstall --apply  # apply with backup
```

## CI and releases

Every push and pull request runs tests, `go vet`, the race detector, Linux sandbox integration tests, and cross-platform builds. CI uploads 14-day artifacts for:

- Linux amd64/arm64
- macOS amd64/arm64
- Windows amd64

Pushing a `v*` tag publishes a GitHub Release after every required test and build succeeds:

```bash
git tag -a v0.1.0-alpha.1 -m "v0.1.0-alpha.1"
git push origin v0.1.0-alpha.1
```

Release assets contain platform archives and a top-level `SHA256SUMS`. Tags containing `-alpha`, `-beta`, or `-rc` are automatically marked as pre-releases.

## Test

```bash
go test ./...
go test -race ./...
```
