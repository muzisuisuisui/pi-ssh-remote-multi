# Changelog

## 0.7.1

- 修复 agent 调用工具时因端点写法不标准而报 `Endpoint not found` 的问题。
  端点选择器现在分层解析：完整 key → 地址（忽略用户名，如 `root@IP`）→ 备注片段
  （`work15`）→ IP 末位（`21`/`.21`）→ 前缀 → 子串；`ssh root@IP -p 22` 与带引号的 key 也能解析。
- 命中多台服务器时仍然拒绝猜测：返回歧义错误并列出候选，
  不再静默落到某台机器上执行。
- 所有端点解析失败的错误信息改为可自我纠正：列出当前全部已配置端点，
  标注 connected/configured、cwd、note，并提示用 `ssh_remote_control action=connect` 连接缺失端点。
- 系统提示中的端点清单从“仅在线端点”改为“全部已配置端点（标注 connected）”，
  并要求优先复制完整 key，避免模型凭记忆重写 IP。
- `ssh_remote_control` 新增 `action=endpoints`：列出全部已配置端点（无论是否已连接）。
- 新增离线回归测试 `test/endpoint-selector.ts`，覆盖完整 key、裸 IP、`host:port`、
  `user@host`、用户名不符、备注、IP 末位、引号/ssh 前缀、歧义与未命中、错误文案。

## 0.7.0

- **移除面向用户的命令穿透通道**：插件现在只提供 Agent 操作服务器的能力
  （`ssh_remote_*` 工具、`/remote` 控制面、内置工具透明路由、文件传输、凭据管理）。
- 删除 `$` 输入拦截及其全部子命令：`$ <cmd>`、`$cd`、`$ctx`、`$server`、`$force`、
  `ssh-passthrough` 会话条目渲染器、底部 `$→` 状态栏。
- 删除容器执行上下文：容器发现、`$ctx docker <name>`、`docker exec` 包装、`containerCwds`。
- 删除 sudo 执行上下文：`$ctx sudo`、sudo 目录缓存、sudo 密码复用，以及 docker.sock
  权限不足时自动 `sudo docker` 的重试。
- 删除仅为穿透服务的交互命令预检（`interactiveHazard`）、`/control_ssh` 命令与
  `passthroughEndpoint` 持久化字段；配置里遗留的这些键会在下次保存时被清除。
- 删除对应的离线测试 `test/passthrough-input.ts`、`test/passthrough-hazard.ts`，
  README / README.zh-CN / skill 同步移除相关章节。
- 保留不变：多端点连接池、自动重连、`/remote` 命令、`ssh_remote_*` 全量工具、
  内置工具远程路由、端口转发、跨平台凭据后端、UI 对话框串行化。

## 0.6.1

- 修复并行首次连接时后续服务器卡死：pi 的交互层同一时刻只能显示一个扩展对话框，
  第二个 `ctx.ui.custom` / `ctx.ui.confirm` 会把前一个组件换下却**不 resolve** 它的 promise，
  于是第一个连接永远等不到密码输入。现在所有连接期的交互（密码、主机密钥确认、
  `/control_ssh`、`$ctx`、`/remote ssh`）都经过同一个串行化队列 `withUiDialog()`，
  一次只弹一个、依次回答，任何连接都不会再被丢弃的对话框挂住。
- 密码提示现在明确标出服务器：`SSH password for root@110.3.241.21:22 (saved password rejected) — Enter submits, Esc skips:`；
  多个连接同时等待时附带 `· N more waiting`，一眼看出这次输的是哪台机器。
- 同一端点被多个并行工具调用请求时复用同一次连接尝试（`pendingConnects`），
  不会再出现两次拨号、两次密码提示、两个 client 抢写 `connections` 的情况。
- 首次并行连接时，谁先连上谁成为当前选中端点；不再由最后启动的那个覆盖选择。
- 底部状态栏在拨号期间列出所有正在连接的端点（`SSH connecting a, b, +1…`），不再是最后一个覆盖前面。
- 会话结束时会清空对话框队列和未完成的连接尝试，避免遗留 promise 把后续连接卡住。
- 新增离线回归测试 `test/password-prompt.ts`：提示文案含端点/重试原因/排队数、对话框严格串行、
  并发请求全部得到回答、某个对话框报错或永远不返回时队列仍可恢复。

## 0.6.0

- **凭据持久化不再只限 Windows**：密码后端改为可插拔的 `SecretCodec` 链，按平台自动选择，
  并在首选后端不可用时自动回退到下一个可用后端。
  - `win32`：Windows DPAPI（行为、密文格式、旧文件全部保持兼容）；
  - `darwin`：macOS Keychain（`security`，可用时优先）；
  - Linux/其它：`secret-tool`（libsecret / Secret Service，可用时优先）；
  - 最后兜底：本地密钥文件加密（AES-256-GCM，密钥 `~/.pi/agent/ssh-remote-secret.key`，0600），
    任何平台都可用，无头服务器、容器里也能持久化密码。
- 凭据文件中的每条密码都带后端标签（`dpapi:` / `keychain:` / `libsecret:` / `file:`）；
  无标签的历史值继续按 DPAPI 解析，升级无需迁移。
- 密钥库类后端（Keychain / libsecret）只在 `ssh-remote-credentials.json` 里留一个标签，
  明文密码存在系统密钥库中；`/remote forget` 与 `--all` 会同步清理密钥库里的副本。
- `ssh_remote_password`、`ssh_remote_control action=password`、`/remote password`
  在 Linux/macOS 上现在也可用；`/remote connections` 会显示每条凭据由哪个后端保存。
- 保存失败时的告警改为通用文案（附带真实失败原因），不再假定 Windows/DPAPI。
- 新增离线回归测试 `test/credentials.ts`：AES-GCM 往返与端点绑定（AAD）、密文篡改拒绝、
  后端标签与回退、旧无标签 DPAPI 值、损坏密文降级为 `undefined`、密钥库副本清理。

## 0.5.1

- `$ctx sudo` 与 Docker socket 权限回退统一复用当前 SSH 端点的已保存密码（内存/Windows DPAPI），不再单独询问 sudo 密码。
- Docker 容器发现或 `docker exec` 遇到 `docker.sock` 权限不足时，自动重试 `sudo docker ...`；无可用 SSH 密码时给出明确错误。

## 0.5.0

- 新增 `$ctx` 执行上下文：可在 `$` 穿透目标上选择宿主机或运行中的 Docker 容器。
- `$ctx docker <name>` 后，`$` 命令通过非交互 `docker exec -w` 在容器内执行；自动探测 `bash`/`sh` 与 `-w` 能力。
- `$cd <path>` 在容器内解析并按容器保存 `containerCwds`；切回 host 不污染内置工具、SFTP 和文件传输使用的宿主机 cwd。
- 新增 `$ctx sudo` root 执行上下文；自动复用该 SSH 端点的已保存密码，用 `sudo -S` 通过 channel stdin 一次性验证/发送，密码只缓存于当前进程，sudo cwd 与普通 host cwd 分离。
- Docker 容器发现和 `docker exec` 遇到 `/var/run/docker.sock` 权限不足时，自动用同一 SSH 密码通过 `sudo docker ...` 重试。
- `/control_ssh` 继续只选择服务器；`$ctx` 改为选择 host/sudo/container 上下文，`$server` 提供目标服务器文本别名，旧 `$ctx <selector>` 保持兼容。
- 对明显的 stdin/TTY 交互命令（`su`、裸 shell、`docker exec -it ... bash`、编辑器、REPL 等）增加预检，避免单向 `$` 通道挂到 600 秒；`$force` 可显式跳过。
- 修正 `$` 输出盒的 Ctrl+C 取消处理，并补交互预检单测与真实 Docker 容器端到端验证。


## 0.4.0

- **BREAKING**: 不再接管 Pi 的 `!` / `!!` 命令。`user_bash` 钩子已移除，用户 `!` 命令一律在
  本机执行；内置 `bash` 工具的远端路由（`/remote on`）不受影响。
- 新增 `$` 穿透通道（`input` 事件，返回 `handled`，**零上下文 token 成本**）：
  - `$ <command>` 在穿透目标服务器上执行，弹出仿 Pi `!` 的实时输出框（流式 tail、
    `Esc` 取消并向远端进程组发 SIGINT、超时/退出码着色）；
  - `$cd <path>` 切换穿透目标当前目录（裸 `$cd` 回家目录），沿用既有的持久 cwd 校验与落盘；
  - `$ctx` 打开目标选择菜单，`$ctx <selector>` 一步设定；`$` 单独输入打印帮助；
  - `$` 后紧跟数字（如 `$100`）以及带附件的消息按普通聊天放行，避免误吞输入。
- 新增 `/control_ssh`（单级菜单）：列出全部已连接端点及其当前目录，`*` 标记当前穿透目标，
  选中即设定 `$` 的落点；支持 `/control_ssh <selector>` 直达，带参数补全。
- 穿透目标与当前目录常驻底部状态栏（新的 `ssh-passthrough` status 段）；目标持久化为
  `ssh-remote-config.json` 的 `passthroughEndpoint`，掉线重连后仍然有效。
- 每条 `$` 命令通过 `appendEntry` + `registerEntryRenderer` 记录成可折叠的会话条目
  （`Ctrl+O` 展开），不进入模型上下文；输出超限仍落临时文件并附路径。
- `execRemote` 拆出 `execRemoteDetailed`，额外返回 `exitCode` / `aborted` / `timedOut`；
  `execRemote` 改为在其之上包装，原有全部拒绝语义（`aborted`、超时文案、非零退出取 stderr/stdout
  尾部作错误文本）逐字保持不变，既有调用方零行为变化。
- 修复 `normalizeRemoteConfig` 会静默丢弃顶层 `defaultTimeout` 的问题；新增的
  `passthroughEndpoint` 只在端点存在时保留。
- `before_agent_start` 注入的 cwd 描述改写：明确 `!` 始终本机、`$` 落在哪台服务器、
  以及 `$` 的输出不在模型上下文里。
- 文档：README / README.zh-CN / SKILL 增补 `$` 与 `/control_ssh` 章节。
- 修复 `ssh_remote_exec` / `ssh_remote_batch` 传 `pty: false` 时必然崩溃的问题
  （`Cannot read properties of undefined (reading 'allowHalfOpen')`）：ssh2 1.17 起
  `exec(cmd, opts, cb)` 只在 `opts` 是函数时归一化成 `{}`，显式传 `undefined` 会直接
  读 `opts.allowHalfOpen`。非 PTY 分支改为传 `{}`（该缺陷自 `pty` 参数引入起就存在，
  与本次改动无关，是在 `$` 无头路径实测中发现）。
- 加固实时输出渲染：`keyHint()` 在宿主未 `initTheme()` 时会抛异常，而异常一旦从
  `onData`/渲染路径冒出就会打断 SSH 通道、静默吞掉远端输出；新增 `safeKeyHint()`
  降级为字面量，并把流式回调包进 try/catch——显示永远不能牺牲数据完整性。
- 新增离线回归测试 `test/passthrough-input.ts`（校验 `!` 不再被接管、`$` 的分流与
  fail-closed 行为）；`npm test` 之前引用了 4 个从未提交的测试文件（必然失败），现改为
  `npm run check && node --import tsx test/passthrough-input.ts`；补 `tsconfig.json`
  使 `npm run check` 真正可运行。

## 0.3.2

- `ssh_remote_exec` / `ssh_remote_batch` stream live output to the TUI while the
  command runs (throttled partial updates like built-in bash), plus a per-job
  last-2-lines preview for `ssh_remote_batch`, so the CLI shows what is executing
  and its progress instead of a black box.
- `ssh_remote_exec` / `ssh_remote_batch`: honor the tool-call `AbortSignal`, so
  pressing Esc cancels the running command (the SSH channel is closed and the
  tool fails with "Command aborted"). Note: closing the channel does not kill
  the remote process; the remote `timeout` wrapper still bounds it.
- `ssh_remote_exec` / `ssh_remote_batch`: add `renderCall` showing the endpoint
  selector and the remote command line in the tool header.
- `execRemote` gains optional hooks (`signal`, `onData`) used by the exec and
  batch tools; other callers are unchanged.
- Raise the default remote exec timeout from 30s to 600s so long-running
  commands (builds, installs, model loads) are not killed by default. Can be
  overridden per call (`timeout` param) or in `ssh-remote-config.json`
  (`defaultTimeout` global, per-endpoint `timeout`).

## 0.3.1

- Add `ssh_remote_password` (plus `ssh_remote_control action=password` and
  `/remote password [endpoint]`): decode the plaintext password for a configured
  endpoint from the in-memory cache or the Windows DPAPI credential store, for
  non-interactive scenarios that truly need it (remote sudo -S, other services,
  jump hosts). Decoding does not require the endpoint to be connected.
- Document that decoded passwords are plaintext and must only be requested when
  required by the current task.

## 0.3.0

- Add three file-transfer tools covering every direction: `ssh_remote_put`
  (local → one or many servers), `ssh_remote_get` (one server → local), and
  `ssh_remote_transfer` (one server → one or many servers, relayed through the
  local process).
- Support point-to-point (single `endpoint`/`target`) and point-to-many
  (fan-out via `targets`, bounded `parallel` concurrency) in one tool each.
- Handle small up to very large files: parallel `fastPut`/`fastGet` SFTP
  channels for local legs, bounded-memory piping (via=stream) or staged
  fastGet/fastPut (via=stage) for server-to-server legs.
- Transfer directories recursively with structure preserved; auto-create remote
  and local destination directories.
- Stream per-file progress through the tool `onUpdate` callback with percentage
  and human-readable byte counts.
- Expose overwrite policies (`always`/`skip`/`newer`), `concurrency`/
  `chunkSize` tuning, endpoint path resolution (`/…`, `~/…`, or relative to the
  endpoint cwd), and structured `details` results.

## 0.2.4

- Replace the PowerShell `SecureString` cmdlet path with an explicitly loaded .NET `System.Security.Cryptography.ProtectedData` DPAPI implementation, avoiding `Microsoft.PowerShell.Security` module autoload failures.
- Include the actual PowerShell/DPAPI error in the warning when persistent password storage fails while still retaining the password in process memory.
- Accept exact host/IP, `host:port`, and `user@host` endpoint selectors, plus unique key, host/IP, and note prefixes.
- Prioritize exact selector matches over prefix matches so an exact `.21` host is not made ambiguous by a `.210` host.
- Add regression coverage for DPAPI script dependencies and endpoint selector exactness, prefixes, notes, and ambiguity.

## 0.2.3

- Persist successfully authenticated passwords on Windows as current-user DPAPI ciphertext in a dedicated credential file; no plaintext password is written to disk or to the ordinary endpoint configuration.
- Reload protected credentials in later Pi processes so known password-authenticated endpoints reconnect without prompting.
- Delete a saved password only after an SSH authentication failure; network, server-availability, and remote-path failures preserve it.
- Expand `/remote forget` and the agent control action to remove persistent credentials for disconnected endpoints or all endpoints.
- Add credential-store regression coverage for encrypted-at-rest persistence, process reload, explicit deletion, Unicode passwords, and decryption failures.

## 0.2.2

- Keep a permanent `error` listener on every `ssh2` client so an intermediate agent error cannot remove the only listener and turn the later terminal authentication error into an uncaught exception.
- Treat `ssh2` agent errors as intermediate authentication events and wait for its final authentication result.
- Probe `SSH_AUTH_SOCK` before connecting and skip stale, unreachable, empty, or malformed Cygwin/OpenSSH agents.
- Broaden authentication-failure detection so failed agent authentication falls back to the interactive password prompt.
- Add an integration regression test with a real local SSH server and an invalid agent socket, verifying no `uncaughtException` or `unhandledRejection` occurs.
- Deliberately avoid process-wide exception handlers, which would hide unrelated Pi and extension failures.

## 0.2.1

- Keep built-in tools local when connecting or selecting endpoints; remote routing now requires `/remote on` or control action `route` with `routing: remote`.
- Force all six `ssh_remote_*` tools active at session start on Pi 0.82.
- Return connection count, endpoint list, selected endpoint, routing state, and the resolved config path through control status/connect results.
- Add `connections` as an agent control action.
- Resolve configuration paths through Pi's `getAgentDir()` so custom and Windows agent directories match Pi itself.

## 0.2.0

- Preserve multiple live SSH connections in one Pi session.
- Keep one active endpoint for transparent built-in `read`, `write`, `edit`, `bash`, and user shell routing.
- Add endpoint-aware `ssh_remote_read`, `ssh_remote_write`, `ssh_remote_edit`, and `ssh_remote_exec` tools.
- Add bounded parallel `ssh_remote_batch` execution with ordered per-endpoint results.
- Make `/remote use` switch endpoints without closing other connections.
- Add `/remote connections`, endpoint-specific disconnect, and `--all` disconnect.
- Make `/remote off` return built-in tools to local execution while retaining the connection pool.
- Use the operating-system home directory fallback on Windows when `HOME` is not exported.
