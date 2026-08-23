# Secure Remote Agent 代码进度

更新时间：2026-08-23

## 当前定位

当前工作区已把 File、Network、Remote、Exec/Debug/Mem 统一接入标准 MCP Streamable HTTP Gateway。部署模型仍是受控私网中的单用户开发机；不提供 GUI、公网 SaaS、任意 shell、任意 SSH/Network 目标或宿主进程调试。

本批按用户要求只执行了 `gofmt` 和编辑器静态诊断，**没有运行测试或 build**。新增测试代码尚待目标 Linux 环境执行。

## 本批完成

### MCP 与 Approval

- [x] `gateway.Config.ApprovalMode`：`server_token` 兼容默认、`client_managed` 可信客户端模式
- [x] `cmd/gateway -approval-mode`
- [x] `client_managed` 不要求 `REMOTE_AGENT_APPROVAL_KEY`，不检查 `approval_token`
- [x] File 写工具保留 dry-run/apply、expected hash、preflight 和 durable audit prewrite
- [x] 审计新增 `approval_mode`、`approval_verified`、`approval_source`
- [x] `tools/list` 增加标准 MCP annotations，并保留 `risk`/`worker`
- [x] `client_managed` 不宣称 Gateway验证了客户端点击

### 动态 Worker 注册

- [x] Gateway接受可选 Network/Remote/Exec Executor
- [x] 未配置 Worker的工具不进入 `tools/list`，直接调用拒绝
- [x] Network严格 `v1` profiles：unknown/duplicate/trailing/expiry/default-deny/limits验证
- [x] Remote CLI flags与credential-store启动验证
- [x] Exec严格管理员 profiles，管理员文件不能写 workspace
- [x] Linux每 workspace独立 Exec supervisor launcher
- [x] Exec runtime临时目录、config/socket/cookie/public-key/log权限与ready等待
- [x] Registry reload可创建每 workspace独立 supervisor；Revoke/Close终止并清理
- [x] 非 Linux配置Exec给出明确错误
- [x] File、Network、Remote、Exec每 workspace分别生成随机 Ed25519 key

### 工具接入

- [x] Network：`web_fetch`、`download`、`upload`
- [x] Remote：`ssh_exec`、`sftp_list`、`sftp_read`、`sftp_write`、`sftp_mkdir`、`sftp_rename`
- [x] Exec：`exec_run`、`process_start`、`process_status`、`process_stop`
- [x] Debug/Mem：`debug_status`、`debug_signal`、`mem_scan`
- [x] Exec只接受管理员profile，不接受 executable/shell/client limits
- [x] Exec capability绑定principal/session/workspace/request/profile/admin limits
- [x] MCP session DELETE和Server Revoke调用Exec `session_revoke`

### 数据边界

- [x] File Worker新增内部-only `read_binary`，未暴露为MCP工具
- [x] `download`：Network bytes → Gateway校验 → File preflight/prewrite/write
- [x] 下载base64不进入模型输出
- [x] `upload`：File `read_binary` → Gateway校验 → Network inline bytes
- [x] `sftp_write`：File `read_binary` → Remote inline bytes
- [x] Network Worker不接收workspace path
- [x] Remote Worker不接收workspace path
- [x] `sftp_read`只有小文件base64/metadata，无隐式local destination
- [x] Debug/Mem只使用opaque process ID；`mem_scan`无地址和写API

### Policy / Audit

- [x] 独立 `AllowNetwork`、`AllowRemote`、`AllowExec`、`AllowDebug`、`AllowMem`
- [x] 所有新开关默认false，policy layer只能收紧
- [x] `download`同时要求Network和workspace write；read-only workspace不可下载
- [x] URL host、header值、env值、memory pattern不进入参数audit
- [x] 错误继续经过敏感值和宿主绝对路径清理

### 测试代码（未执行）

- [x] dynamic tool list与MCP annotations
- [x] client-managed apply与审计语义
- [x] Network upload/download transfer split
- [x] audit不泄漏URL/header/body
- [x] Exec cross-session job scope与session DELETE revoke
- [x] Policy capability defaults/restrict
- [x] Network config strict/default deny
- [x] Exec administrator config strict/workspace字段拒绝

## 仍需验证

1. 在Linux执行目标测试与完整测试套件。
2. 构建 `file-worker`、`network-worker`、`remote-worker`、`exec-worker`、`gateway`。
3. 在目标内核验证namespace、seccomp、Landlock、openat2和cgroup v2。
4. 使用目标版本Claude Code、Codex、Zed回放Streamable HTTP、客户端高风险审批和session DELETE。
5. 使用真实HTTPS/私网HTTP目标验证Network allowlist、redirect、DNS rebinding和下载覆盖冲突。
6. 使用系统已有SSH key/agent和known_hosts验证Remote profile，不向模型/审计泄漏host、credential path或key。
7. 验证Registry SIGHUP期间新旧per-workspace Exec supervisor的原子切换和旧进程清理。

## 重要安全边界

标准MCP没有可由Gateway验证的客户端批准证明。`client_managed` 只适用于受控单用户/可信私网客户端；任何持有Bearer token的恶意客户端都可直接调用已启用工具。管理员必须把Network target、SSH command/SFTP root和Exec task配置为最小白名单。需要服务端可验证批准时，File 写工具可继续使用兼容的 `server_token` + `approve` CLI；external server approval flow 尚未实现，因此 `server_token` 下所有 `Approval=true` 的非 File 工具都会从 `tools/list` 隐藏且直接调用 fail closed。
