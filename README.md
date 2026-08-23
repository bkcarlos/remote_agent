# Secure Remote Agent

Linux is the only supported production Worker host for this single-user MCP service on a trusted private network. Claude Code, Codex, Zed, and other MCP clients connect directly through standard MCP Streamable HTTP; `stdio-bridge` remains an optional compatibility adapter for clients that only support stdio. File tools are always isolated, while administrator-configured Network, SSH/SFTP, fixed-task Exec, Debug, and read-only memory-scan tools are optional and hidden by default. Non-Linux builds are for development and compatibility only and must not be used as production Worker hosts. This is not a public SaaS, multi-tenant control plane, GUI automation system, or arbitrary shell/remote-control service.

## Run on a Linux host

```bash
mkdir -p bin
go build -o bin/file-worker ./cmd/file-worker
go build -o bin/gateway ./cmd/gateway
export REMOTE_AGENT_TOKEN='replace-with-at-least-32-random-characters'
bin/gateway -workspace ./example -file-worker bin/file-worker \
  -approval-mode client_managed \
  -allow-insecure-http -listen 127.0.0.1:8080
```

The standard single-workspace MCP endpoint is:

```text
http://127.0.0.1:8080/mcp
```

Configure each MCP client with:

```text
transport: Streamable HTTP
url:       http://127.0.0.1:8080/mcp
header:    Authorization: Bearer <REMOTE_AGENT_TOKEN value>
```

The exact configuration syntax differs between Claude Code, Codex, Zed, and other clients, but no client-specific protocol extension is required. The repository includes a standard-client end-to-end test covering initialization, `Mcp-Session-Id`, notifications, tool listing, tool calls, cancellation, and session termination.

The direct HTTP path uses Bearer authentication and bounded, principal-bound MCP sessions. The Gateway supports the MCP Streamable HTTP `2025-03-26` transport semantics: `POST` requests, `202` notifications, `Mcp-Session-Id`, `MCP-Protocol-Version`, and `DELETE` session termination. Because the current server has no server-initiated messages, `GET` streaming returns `405` as permitted by the transport.

Public deployments must omit `-allow-insecure-http` and provide `-tls-cert` and `-tls-key`. Plain HTTP is accepted only on loopback or an explicit private IP and must never be published through NAT or a public reverse proxy. Bearer tokens have no confidentiality over plaintext HTTP, so use a trusted private network or an encrypted tunnel.

### Optional stdio compatibility bridge

Only clients without Streamable HTTP support need `stdio-bridge`:

```bash
go build -o bin/stdio-bridge ./cmd/stdio-bridge
bin/stdio-bridge \
  --endpoint http://127.0.0.1:8080/mcp \
  --allow-private-http
```

For HTTPS:

```bash
bin/stdio-bridge --endpoint https://agent.example.com/mcp
```

The Bridge speaks the same standard session protocol, supports bounded concurrent requests, backpressure, notifications and cancellation, and writes protocol messages only to stdout. Bearer authentication is always used. Optional Bridge-to-Gateway HMAC can be enabled with `--sign-requests`; the HMAC envelope covers the HTTP method, URI, content type, body digest, standard MCP session/version headers, Bridge identity, timestamp, and nonce. Direct MCP clients do not need to implement this custom HMAC.

The Gateway never opens workspace files directly. Every file operation starts an independent, short-lived `file-worker` process with a sanitized environment and an Ed25519-signed, scoped, 30-second capability. The Gateway keeps the private signing key; Workers receive only the public verification key. Capabilities bind request/session/Bridge identity, Worker type, operation, normalized paths, policy decision, resource limits, argument digest, expected hashes, and approved write targets.

On Linux the child is created in new user, mount, network, PID, IPC, and UTS namespaces with a parent-death signal. After capability verification it applies `no_new_privs`, CPU/open-file/process/file-size/core rlimits and a seccomp-BPF filter. When supported by the kernel, it also applies a Landlock ruleset restricted to the workspace, with no workspace write rights for read jobs. Older kernels, kernels with Landlock disabled, and container seccomp profiles that hide its syscalls continue with an explicit audited security-degradation warning and rely on the `openat2` workspace boundary plus namespace/seccomp isolation. Other sandbox or resource-limit setup failures remain fail-closed. No Linux Worker receives host network access.

For production Linux deployments, pass a systemd/container-runtime delegated cgroup v2 directory using `-cgroup-root`. Each Worker receives a 256 MiB memory limit, disabled swap, 32-PID limit, and one-CPU quota. If a configured cgroup cannot be created or constrained, the job is denied; omitting `-cgroup-root` emits and audits a security-degradation warning. Approval IDs and optional HMAC nonces are atomically persisted in the BoltDB file configured by `-replay-db` (default `state/replay.db`). MCP sessions are bounded, principal-bound, in-memory sessions with an idle TTL.

Writes and every optional Worker family are disabled by default. `-approval-mode` has two values:

- `server_token` is the compatibility default. File writes retain the existing approval CLI and require `REMOTE_AGENT_APPROVAL_KEY` when `-allow-write` is enabled. Because no external server-approval flow exists yet, every non-File tool marked as requiring approval is omitted from `tools/list` and direct calls fail closed in this mode.
- `client_managed` is recommended only for this project's controlled single-user/private-network deployment with trusted Claude Code, Codex, or Zed client policy. It does not require `REMOTE_AGENT_APPROVAL_KEY` and does not inspect `approval_token`. Dry-run/apply, expected-hash checks, administrator policy denial, and durable prewrite audit remain enforced. Audit records `approval_mode=client_managed`, `approval_verified=false`, and `approval_source=mcp_client_policy`.

**Standard MCP does not carry cryptographically verifiable evidence that a user clicked an approval dialog.** In `client_managed` mode the Gateway trusts the MCP client to apply its own high-risk approval policy. Any malicious or compromised client holding the Bearer token can call enabled tools directly. Therefore use this mode only on a trusted private network, protect the Bearer token, and make administrator Network targets, SSH profiles, SFTP roots, and Exec tasks narrow allowlists. This project intentionally provides no GUI.

Recommended controlled-client mode:

```bash
bin/gateway ... -approval-mode client_managed -allow-write
```

Compatibility server-token mode:

```bash
export REMOTE_AGENT_APPROVAL_KEY='a-different-random-secret-of-at-least-32-characters'
export REMOTE_AGENT_APPROVER='trusted-user-or-service-identity'
go build -o bin/approve ./cmd/approve
bin/gateway ... -approval-mode server_token -allow-write
```

`write_file`, `edit`, and `multi_edit` are dry-run unless `apply` is true. A dry-run returns normalized targets, real diffs where applicable, before/after SHA-256 values, the approval mode, and the session ID. In `server_token` mode it also returns a challenge that can be signed into a short-lived, single-use token.

Every new approval must include the exact canonical `approval_review` returned by dry-run. The CLI validates its challenge, session, operation, ordered targets, diff, metadata, expiry, and review digest before signing.

Single target:

```bash
bin/approve \
  --approval-id '<dry-run approval_id>' \
  --session '<dry-run session_id>' \
  --operation write_file \
  --path 'relative/file.txt' \
  --content-sha256 '<dry-run after_sha256>' \
  --expected-hash '<dry-run before_sha256>' \
  --review-json '<dry-run approval_review JSON>' \
  --approve
```

Batch `edit`/`multi_edit` approval uses both dry-run values directly:

```bash
bin/approve \
  --approval-id '<dry-run approval_id>' \
  --session '<dry-run session_id>' \
  --operation multi_edit \
  --targets-json '[{"path":"a.txt","before_sha256":"...","after_sha256":"..."},{"path":"b.txt","before_sha256":"...","after_sha256":"..."}]' \
  --review-json '<dry-run approval_review JSON>' \
  --approve
```

Use `--review-file` instead of `--review-json` when the review is stored in a trusted local file. `--legacy-without-review` exists only for explicitly acknowledged compatibility with old single-target `write_file` challenges.

In `server_token` mode, pass stdout from `approve` as the strict `approval_token` argument with the identical apply request. The Gateway durably prewrites the L2 audit event before consuming the approval. Each token is bound to approver, session, operation, ordered normalized targets, before/after hashes, challenge ID, and expiry, and cannot be replayed across restart. In `client_managed` mode, apply omits the token; the audit log never claims that the Gateway verified a client-side click.

`multi_edit` preflights every file and rolls back completed writes after ordinary errors. Once an approved commit Worker starts, client cancellation no longer kills it mid-commit; it remains bounded by the hard Worker timeout. Like normal filesystems, this is not crash-atomic across a Worker `SIGKILL`, host failure, or power loss.

## Optional Network, Remote, and Exec Workers

Optional tools are registered only when both their Worker/configuration and their independent policy switch are present. Every workspace receives a different random Ed25519 key for File, Network, Remote, and Exec; approval secrets and Worker keys are never reused.

### Network profiles

`-network-policy` is strict JSON: unknown fields, duplicate profile IDs, trailing JSON, expired profiles, invalid limits, and profiles without explicit scheme/port/target allowlists are rejected. A profile ID is opaque to the AI.

```json
{
  "version": "v1",
  "profiles": [
    {
      "id": "docs-readonly",
      "policy": {
        "allowed_domains": ["docs.example.internal"],
        "allowed_ports": [443],
        "allowed_schemes": ["https"],
        "allowed_cidrs": ["10.0.0.0/8"],
        "allowed_request_headers": ["accept"],
        "allow_private": true
      },
      "resource_limits": {
        "max_request_body_bytes": 1048576,
        "max_response_body_bytes": 1048576,
        "max_request_header_bytes": 8192,
        "max_response_header_bytes": 8192,
        "max_redirects": 2,
        "timeout_millis": 10000
      },
      "expires_at": "2030-01-01T00:00:00Z"
    }
  ]
}
```

`download` receives bytes from Network Worker, verifies them in Gateway, then writes through File Worker. Network Worker never receives a workspace path, and downloaded base64 is never emitted into model output. `upload` first uses the internal-only bounded `read_binary` File operation and sends only bytes to Network Worker. Internal File Worker raw binary transfer and every Gateway workspace upload/download are capped at 2 MiB; Gateway signs the minimum of this ceiling, workspace policy, and Network profile limits and rejects a larger transfer. Network Worker itself retains a 16 MiB protocol/profile hard ceiling for non-workspace network use.

### SSH/SFTP profiles

Remote profiles are administrator-owned credential-store configuration. The AI can name only `profile`; it cannot select a host, user, credential path, key, known-hosts file, or workspace path. On Linux, the profile config, private key, and known_hosts source are opened with `O_NOFOLLOW` and validated with `fstat` on that same descriptor; symlinks, non-euid ownership, and group/world-writable files are rejected without returning the path. Existing system private keys or an inherited SSH agent are loaded by the trusted parent and delivered to the short-lived Remote Worker without exposing credential paths in MCP output. The worker caches the envelope-verified fixed signer set before Landlock and never queries agent identities again while building SSH config.

```json
{
  "version": 1,
  "profiles": [
    {
      "name": "staging-read",
      "host": "staging.example.internal",
      "port": 22,
      "user": "deploy",
      "private_key_path": "/home/agent/.ssh/id_ed25519",
      "known_hosts_path": "/home/agent/.ssh/known_hosts",
      "allowed_commands": [["git", "status"]],
      "sftp": {"roots": ["/srv/app"], "read": true, "write": false},
      "expiry": "2030-01-01T00:00:00Z"
    }
  ]
}
```

`sftp_write` reads local bytes through File Worker and gives Remote Worker only bytes plus the remote path. `sftp_read` returns only a bounded small-file base64 result and metadata; it has no implicit local destination. SFTP `RealPath` checks are authorization checks, not a server-side jail. Production profiles must use a dedicated restricted remote account and preferably an SSH chroot; a malicious or concurrently changing remote filesystem can still race a checked path with a symlink before the SFTP operation.

### Fixed-task Exec profiles

Exec is Linux-only. Administrator configuration cannot contain workspace identity or root; Gateway injects the current workspace into a fresh per-workspace supervisor runtime. Runtime configuration, socket, cookie, public key, and log live in a `0700` temporary directory with `0600` files/socket, and each runtime receives a separate random cgroup subtree so staging/reload cleanup cannot target an older runtime. `Revoke`, `Close`, registry replacement, and MCP session `DELETE` revoke managed children and clean the runtime.

```json
{
  "version": "v1",
  "profiles": [
    {
      "name": "git-status",
      "executable": "/usr/bin/git",
      "fixed_argv": ["status", "--short"],
      "allowed_argv_prefixes": [],
      "workspace_mode": "read_only",
      "env_allowlist": [],
      "limits": {
        "timeout_ms": 30000,
        "cpu_seconds": 30,
        "memory_bytes": 268435456,
        "pids": 64,
        "output_bytes": 1048576,
        "scan_regions": 128,
        "scan_bytes": 16777216,
        "scan_results": 256
      }
    }
  ]
}
```

MCP never accepts an executable or shell string. `exec_run`/`process_start` select a fixed profile and optional administrator-constrained argv/env. Every capability remains bound to the current request `TaskID`; after launch, Process/Debug/Mem ownership uses only authenticated principal, MCP session, workspace, profile, opaque `process_id`, and verified PID starttime, so a later request does not need the launch request ID. `mem_scan` accepts only `pattern`, `mode`, and `include_context`; it accepts no address and cannot write memory. Debug/Mem can operate only on Agent children created in the same session. Signals currently verify `/proc` PID starttime but do not use pidfd on every path, so PID signal reuse remains a documented residual risk.

### Combined startup example

```bash
mkdir -p bin

go build -o bin/file-worker ./cmd/file-worker
go build -o bin/network-worker ./cmd/network-worker
go build -o bin/remote-worker ./cmd/remote-worker
go build -o bin/exec-worker ./cmd/exec-worker
go build -o bin/gateway ./cmd/gateway

bin/gateway \
  -workspace /srv/workspaces/project \
  -file-worker "$PWD/bin/file-worker" \
  -approval-mode client_managed \
  -allow-write -allow-network -allow-remote -allow-exec -allow-debug -allow-mem \
  -network-worker "$PWD/bin/network-worker" \
  -network-policy /etc/remote-agent/network.json \
  -remote-worker "$PWD/bin/remote-worker" \
  -remote-profiles /etc/remote-agent/ssh-profiles.json \
  -exec-worker "$PWD/bin/exec-worker" \
  -exec-policy /etc/remote-agent/exec.json \
  -exec-socket-dir /run/user/1000/remote-agent-exec \
  -exec-cgroup-root /sys/fs/cgroup/remote-agent-exec \
  -exec-production \
  -allow-insecure-http -listen 127.0.0.1:8080
```

Omit an optional Worker/config pair to remove that entire tool family from `tools/list`; direct calls are rejected. Policy flags are separate and default false: `-allow-network`, `-allow-remote`, `-allow-exec`, `-allow-debug`, and `-allow-mem`. `-allow-write` additionally controls `download` because it writes the workspace, and a registry workspace marked `read_only` can never download.

## Trusted multi-workspace configuration

Single-workspace mode continues to use `-workspace` and `/mcp`. For multiple independently expiring workspaces, provide a trusted launcher-owned configuration file instead:

```json
{
  "version": "v1",
  "workspaces": [
    {
      "id": "project-a-7f3c91d2",
      "root": "/srv/workspaces/project-a",
      "read_only": false,
      "expires_at": "2030-01-01T00:00:00Z",
      "denied_names": ["secrets", ".production-env"]
    },
    {
      "id": "project-b-4a8e20c1",
      "root": "/srv/workspaces/project-b",
      "read_only": true,
      "expires_at": "2030-01-01T00:00:00Z",
      "denied_names": []
    }
  ]
}
```

```bash
bin/gateway \
  -workspace-config /etc/remote-agent/workspaces.json \
  -file-worker bin/file-worker \
  -listen 10.0.0.20:8080 \
  -allow-insecure-http
```

Endpoints become:

```text
http://10.0.0.20:8080/mcp/project-a-7f3c91d2
http://10.0.0.20:8080/mcp/project-b-4a8e20c1
```

There is no default `/mcp` route in registry mode. Every workspace has an independent Worker key, Gateway session store, policy engine, expiry, audit `workspace_id`, and route. `read_only` cannot be overridden by `-allow-write` and cannot receive a `read_write` Exec profile. On Linux, send `SIGHUP` to reload the trusted configuration atomically; invalid replacement files leave the active registry unchanged. A background scheduler removes workspaces at `expires_at`; removed or expired workspaces revoke sessions, cancel cancellable requests, and reject future calls.

## Restrictive policy layers

The Gateway accepts strict JSON policy layers in this order:

```text
administrator > deployment > project > command-line capability
```

Each loaded layer can only disable `allow_write`, `allow_network`, `allow_remote`, `allow_exec`, `allow_debug`, or `allow_mem`, lower byte limits, or add denied names. It cannot enable a capability or increase a limit disabled by a higher effective layer. All capability switches default false. Unknown fields, invalid limits, path-shaped denied names, and trailing JSON are rejected at startup.

```bash
bin/gateway ... \
  -admin-policy policies/default/admin.json \
  -deployment-policy /etc/remote-agent/deployment.json \
  -project-policy /trusted/project-policy.json
```

Repository content must not choose policy paths; they are trusted launcher/admin arguments. The runtime parser is authoritative and rejects unknown fields and trailing JSON.

## Available tools

The Gateway exposes policy- and configuration-filtered tools dynamically. Every entry preserves custom `risk`, `worker`, `approval_mode`, and compatibility `approval_required` metadata and includes standard MCP `annotations` (`readOnlyHint`, `destructiveHint`, `idempotentHint`, and `openWorldHint`). In `client_managed` mode `approval_required` is not advertised as server verification.

- `read_file`: bounded, encoding-aware text reading with optional 1-based `start_line`/`end_line`, encoding/BOM/newline/confidence metadata, total lines, and truncation status
- `read_image`: bounded PNG/JPEG/GIF/WebP reading returned as a standard MCP image content item with validated MIME type, dimensions, byte count, and SHA-256
- `multi_read`: bounded reading of up to 20 text files
- `list_dir`: bounded directory listing with policy-denied names removed
- `checksum`: SHA-256 calculation
- `file_info`: metadata without host absolute paths
- `glob`: bounded relative-pattern file discovery
- `grep`: bounded text search that skips symlinks, binary content, policy-denied names, and `.gitignore` matches
- `diff`: bounded unified diff against decoded text
- `edit`: exact single-file replacement with preview, approval, encoding/BOM/newline/permission preservation, and optional `adapt_indentation`
- `multi_edit`: preflight and approved editing of up to 20 files
- `write_file`: dry-run and approved/client-managed atomic raw-content writing
- `web_fetch`, `download`, `upload`: allowlisted HTTP fetch and split workspace transfers
- `ssh_exec`: administrator-allowlisted argv execution
- `sftp_list`, `sftp_read`, `sftp_write`, `sftp_mkdir`, `sftp_rename`: root-constrained SFTP operations
- `exec_run`, `process_start`, `process_status`, `process_stop`: fixed-task process lifecycle
- `debug_status`, `debug_signal`: same-session Agent-child debugging
- `mem_scan`: bounded same-session Agent-child memory pattern scan with no address or write API

Write tools are hidden when writes are disabled. Optional Worker tools are hidden when their Worker/configuration is absent or their independent policy switch is false. `adapt_indentation` reads applicable root/nested `.editorconfig` files through the secure workspace interface and supports `indent_style`, `indent_size`, and `tab_width`. Supported text encodings include UTF-8, UTF-8 BOM, UTF-16 LE/BE, EUC-KR, Shift-JIS, and ISO-8859-1 fallback. Mixed existing line endings are preserved.

All tool requests use strict JSON decoding: unknown or duplicate fields, trailing values, malformed SHA-256 values, missing required paths, and oversized security-sensitive parameters are rejected. All file operations execute in the independent file worker and remain relative to the authorized workspace. On Linux, file opens and recursive search use directory file descriptors with `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS)` and `fstatat(AT_SYMLINK_NOFOLLOW)`; search does not use host absolute-path walking. Default and administrator-added sensitive names are passed to the Worker and pruned before names or file content are returned. Files with multiple hard links are denied by default. Atomic writes use parent-directory descriptors, exclusive temporary files, repeated expected-hash and inode checks, `renameat`, and directory `fsync`.

Repository `.gitignore` files affect `glob`/`grep` search convenience only. They are untrusted content and are not an authorization boundary; trusted denied names must come from policy layers.

## Install the stdio fallback

The installer manages the optional stdio Bridge configuration for clients that cannot connect through Streamable HTTP. Clients with native HTTP support should point directly at `/mcp` instead.

Build the compatibility commands first:

```bash
go build -o bin/stdio-bridge ./cmd/stdio-bridge
go build -o bin/remote-agent-install ./cmd/install
```

Installation is preview-only unless `--apply` is provided. Existing JSON settings and MCP servers are preserved, an exclusive timestamped backup is created before modification, and changes observed before apply or in the final check before replacement cause apply to fail instead of being overwritten; an uncooperative external process can still modify the path in the final system-call window:

```bash
# Public endpoint: HTTPS is required
bin/remote-agent-install --client cursor --bridge bin/stdio-bridge \
  --endpoint https://agent.example.com/mcp
bin/remote-agent-install --client cursor --bridge bin/stdio-bridge \
  --endpoint https://agent.example.com/mcp --apply

# Controlled private network: HTTP requires explicit acknowledgement
bin/remote-agent-install --client claude --bridge bin/stdio-bridge \
  --endpoint http://10.0.0.20:8080/mcp --allow-private-http --apply
```

These presets configure the stdio compatibility path only: `claude`, `claude-code`, `cursor`, and `windsurf`. Codex and other JSON-based stdio configurations require an explicit, verified `--config` path. The installer never writes authentication or approval tokens into client configuration. `REMOTE_AGENT_TOKEN` must be injected into the MCP client's actual startup environment; setting it only in an unrelated interactive shell may not be sufficient.

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
git tag -a v0.2.0-alpha.1 -m "v0.2.0-alpha.1"
git push origin v0.2.0-alpha.1
```

Release assets contain platform archives and a top-level `SHA256SUMS`. Tags containing `-alpha`, `-beta`, or `-rc` are automatically marked as pre-releases.

## Test

```bash
go test ./...
go test -race ./...
```
