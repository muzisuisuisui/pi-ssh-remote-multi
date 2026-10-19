<!--
pi-ssh-remote 中文说明文档，重点介绍它面向 Pi Agent 的设计、主要能力、常见使用场景、命令和安全机制。
-->

# pi-ssh-remote-multi

**让 Pi 像操作本地项目一样操作远程服务器。**

[English Docs](README.md) · [社区](https://linux.do/)

`pi-ssh-remote-multi` 基于 `pi-ssh-remote 0.1.4` 扩展，是一个专门面向 Pi Agent 的多服务器 SSH 远程开发插件。

本版本保留透明远程工作区，同时增加多连接池。连接第二台服务器时，第一台不会断开。连接和选择 endpoint 不会自动改变工具路由：内置 `read`、`write`、`edit`、`bash` 默认保持本地，只有显式执行 `/remote on` 后才整体路由到当前选中的服务器。Agent 可以通过 `ssh_remote_read`、`ssh_remote_write`、`ssh_remote_edit`、`ssh_remote_exec` 和 `ssh_remote_batch` 操作任意已连接服务器。

它不只是帮你打开一个远程终端。Agent 可以使用 endpoint-aware 工具直接在服务器上查看文件、分析日志、修改代码和运行任务；需要把整个工作区临时切到远端时，再用 `/remote on` 显式开启透明路由。

例如，你可以直接对 Pi 说：

```text
连接 ssh root@gpu-box -p 2202，进入 /srv/training。
检查最近一次训练为什么失败，修复问题后在后台重新启动，
最后把 PID 和日志路径发给我。
```

Pi 会依次完成连接服务器、切换目录、读取日志、修改文件和启动任务。整个过程中，它使用的仍然是熟悉的 Pi 工具，只是执行位置变成了远程服务器。

除了交给 Agent 的工具路由，插件还提供一条**只给人用的 `$` 穿透通道**：输入框里以 `$` 开头的命令直接跑在你选定的服务器上，结果不进模型上下文（见[$ 穿透执行](#-穿透执行与-control_ssh)）。

## 为什么它更适合 Agent

### 不需要给每一步都套一层 SSH

普通做法通常是让 Agent 不断执行：

```bash
ssh user@host "cd /path && ..."
```

命令一多，目录、引号、环境变量和连接状态都很容易出错。使用本插件后，只需要连接一次，后续文件读写和 Shell 操作都会自动在远端执行。

### Agent 知道自己正在操作哪台服务器

插件会把当前远程目录和服务器信息写入 Pi 的上下文，并显示在底部状态栏：

```text
SSH remote H100 训练机 (root@gpu-box.example.com:2202):/srv/project
```

这样无论是用户还是 Agent，都能随时确认当前操作发生在本地还是远端，减少误操作。

### 服务器配置会保留

每台服务器都可以单独保存：

- SSH 地址；
- 默认工作目录；
- 服务器备注；
- 端口转发配置。

例如可以把几台机器分别备注为 `8xH100 训练机`、`预发布环境`、`线上只读机`。这些配置保存在本地，重启 Pi 后仍然存在。

### 断线后可以自动恢复

当前会话中如果 SSH 连接意外断开，插件会尝试自动重连，不需要 Agent 从头建立工作环境。

### 对 Agent 上下文更友好

远程命令默认 600 秒超时（`ssh-remote-config.json` 的 `defaultTimeout` 可改全局默认，每个 endpoint 可用 `timeout` 单独覆盖；单次调用还可传 `timeout` 参数），避免某个前台任务长期占住 Agent。命令输出过大时，只会把受限内容放入模型上下文，完整输出会另外保存到临时文件，方便后续继续检查。

### 可以远端跑服务、本地改代码

端口转发模式下，可以把远端服务映射到 `localhost`，同时让 Pi 的文件和 Shell 工具继续操作本地项目。

这很适合下面这类场景：

- GPU 服务器运行模型，本地开发 Web UI；
- 远端启动 API，本地调试客户端；
- 远端运行训练监控，本地查看页面；
- 内网服务通过 SSH 隧道提供给本地工具使用。

## 和直接使用 SSH 有什么区别

| 直接执行 SSH | 使用 `pi-ssh-remote` |
|---|---|
| 每条命令都要重新拼接 SSH | 连接一次后，Pi 工具自动在远端执行 |
| 多次调用之间容易丢失目录 | 自动记住远程工作目录 |
| Agent 需要自己判断当前在哪台机器 | 系统上下文和底部状态栏会显示当前服务器 |
| 连接中断后需要手动恢复 | 当前会话内自动重连 |
| 文件修改、命令执行和端口转发各自处理 | 统一通过 `/remote` 和 Agent 工具管理 |
| 大量输出可能直接占满模型上下文 | 内置超时、折叠预览和输出上限 |

## 安装

```bash
pi install ./pi-ssh-remote-multi-0.2.4.tgz
```

安装前请禁用或移除原版 `pi-ssh-remote`，避免两个扩展同时注册内置工具的覆盖逻辑。

插件会先验证 `SSH_AUTH_SOCK` 指向的 agent 是否能返回身份。失效的 Cygwin/OpenSSH agent 会被跳过，随后进入密码提示；认证失败只会结束本次连接，不会注册或依赖全局异常吞噬器。

本地要求 Node.js 20+。远程服务器需要提供 Bash、SFTP 和 GNU `timeout`。

## 快速开始

连接服务器：

```text
/remote ssh root@gpu-box.example.com -p 2202
```

设置远程工作目录和备注：

```text
/remote cd /srv/project
/remote config note H100 训练机
```

查看当前状态：

```text
/remote status
```

连接成功后，跨服务器工具可以立即操作远端，内置文件和 Shell 工具仍保持本地。需要让内置工具整体操作当前选中的远程工作区时执行：

```text
/remote on
```

此时内置工具才会操作远程 `/srv/project`。

需要返回本地时执行：

```text
/remote off
```

## 常见用法

### 1. 让 Pi 直接排查远程服务故障

```text
连接 ubuntu@training.example.com，进入 /opt/app。
先检查部署日志和 Git 状态，找出失败原因。
如果需要修改代码，先说明原因，再做最小修改并运行相关测试，
最后把 diff 和测试结果发给我。
```

连接完成后，Pi 后续的读文件、查日志、改代码和跑测试都会直接在服务器上进行。

### 2. 启动长时间训练任务

```text
在当前远程服务器检查训练命令和配置。
确认无误后用 nohup 在后台启动，并从一开始就重定向 stdout 和 stderr。
把 PID、输出目录和日志路径发给我，再检查一次进程是否仍在运行、日志是否已经开始写入。
```

插件默认限制前台命令的执行时间，但通过 `nohup` 等方式启动的后台任务可以继续在服务器运行。

### 3. 管理多台服务器

先配置训练机：

```text
/remote ssh root@10.0.0.21 -p 22
/remote config note 8xH100 训练机
/remote config cwd /srv/train
```

再配置预发布服务器：

```text
/remote ssh ubuntu@staging.example.com -p 2222
/remote config note 预发布 API
/remote config cwd /opt/service
```

查看并切换服务器：

```text
/remote config
/remote connections
/remote use root@10.0.0.21:22
```

两台服务器会同时保持连接，`/remote use` 只改变默认选中的 endpoint，不会关闭上一台，也不会把本地工具自动切到远程。Agent 工具中的 endpoint 可以使用完整 key、纯 IP/主机名、`user@host`、`host:port`，也可以使用这些值或服务器备注的唯一前缀。精确匹配优先于前缀匹配。

你可以直接让 Agent 并行查看“8xH100 训练机”和“预发布 API”的磁盘、内存和进程状态。此类任务会使用 `ssh_remote_batch`，其中一台失败不会取消其他任务。

### 4. 远端启动模型，本地开发界面

保存并启动端口转发：

```text
/remote config forward 7860:127.0.0.1:7860
/remote forward
```

现在访问本地 `localhost:7860`，实际连接的是远程服务器上的 7860 端口；与此同时，Pi 的文件和 Shell 工具会留在本地，方便继续修改前端或客户端代码。

停止转发：

```text
/remote unforward
```

### 5. 直接用自然语言操作

不想记命令时，可以直接告诉 Pi：

```text
连接已配置的远程服务器，进入 /srv/api，然后检查 Git 状态。
```

```text
把当前服务器备注为“线上只读机”，然后告诉我现在操作的是哪台服务器。
```

```text
把远端 8000 端口转发到本地 8000，但代码工具继续留在本地。
```

Pi 会通过插件提供的 `ssh_remote_control` 工具完成这些操作。

## 命令说明

| 命令 | 作用 |
|---|---|
| `/remote ssh USER@HOST -p PORT` | 保存并连接服务器，不自动改变工具路由 |
| `/remote` | 连接当前选中的服务器，或提示输入 SSH 地址 |
| `/remote config` | 查看已保存的服务器和配置 |
| `/remote connections` | 查看当前保持的全部 SSH 连接 |
| `/remote use USER@HOST:PORT` | 选择默认服务器，不断开其他连接、不自动改变路由 |
| `/remote on` | 把内置 `read/write/edit/bash` 显式路由到当前选中的服务器 |
| `/remote config note TEXT` | 给当前服务器添加或修改备注 |
| `/remote config note --clear` | 清除当前服务器备注 |
| `/remote config cwd PATH` | 设置默认远程工作目录 |
| `/remote cd PATH` | 切换当前远程目录并保存 |
| `/remote config forward MAPPING...` | 保存端口转发配置，例如 `7860:127.0.0.1:7860` |
| `/remote forward [MAPPING...]` | 启动端口转发，并让 Pi 工具留在本地 |
| `/remote unforward` | 停止插件创建的端口转发 |
| `/remote exec COMMAND` | 在当前远程目录执行一次命令 |
| `/remote exec --timeout 60 COMMAND` | 单独设置本次命令的超时时间 |
| `/remote exec --lines 20 COMMAND` | 单独设置本次折叠显示的行数 |
| `/remote config display-lines 10` | 设置默认折叠显示行数 |
| `/remote status` | 查看当前连接和工作目录 |
| `/remote reload` | 重新连接当前服务器 |
| `/remote off` | 让内置工具返回本地，SSH 连接继续保持 |
| `/remote disconnect [ENDPOINT]` | 断开指定服务器；省略时断开活动服务器 |
| `/remote disconnect --all` | 断开全部服务器 |
| `/remote forget [ENDPOINT]` | 必要时断开服务器，并删除对应的持久密码 |
| `/remote forget --all` | 断开全部服务器并删除全部持久密码 |
| `/control_ssh` | 单级菜单选择 `$` 穿透目标服务器（一级菜单，列出在线端点及当前 `$` 上下文） |
| `/control_ssh <selector>` | 直接把 `$` 穿透目标设为指定已连接端点 |

## `$` 穿透执行与 `/control_ssh`

内置工具路由（`/remote on`）解决的是「让 Agent 在远端干活」；`$` 解决的是「我自己想顺手敲一条远端命令」。
两者互不影响：`$` 只看穿透目标和 `$` 自己的执行上下文，不管 `routeRemoteTools` 是开是关。

| 输入 | 作用 |
|---|---|
| `$ <command>` | 在穿透目标的当前上下文执行；弹出实时输出框，Esc/Ctrl+C 向远端进程组发 SIGINT |
| `$cd <path>` | 切换当前上下文目录；host 在宿主机解析，container 在容器内解析，并持久化容器目录 |
| `$ctx` | 打开当前服务器的上下文菜单：宿主机普通用户、sudo root 或运行中的 Docker 容器 |
| `$ctx host` | 切回宿主机普通用户上下文 |
| `$ctx sudo` | 切到宿主机 root 上下文；自动复用该 SSH 端点密码，密码只保存在当前进程内存 |
| `$ctx docker <name>` | 切到指定 Docker 容器；后续 `$` 命令自动用 `docker exec` 执行 |
| `$ctx list` | 列出宿主机目录和运行中的 Docker 容器 |
| `$server [selector]` | 选择 `$` 穿透目标服务器；`/control_ssh` 同义，`$ctx <selector>` 仍兼容旧版目标选择 |
| `$force <command>` | 跳过交互命令预检（仍不提供键盘输入，只有确定命令会自行退出时才使用） |
| `$` | 打印帮助，并显示当前目标与上下文 |

**目标、上下文与可见性**：`/control_ssh` 是一级菜单，只负责列出并选择已连接服务器；`$ctx` 负责在当前服务器上选择 host/sudo/container。
底部状态栏常驻 `$→ <端点> · [docker <name>] <当前目录>`。

**执行上下文规则**：容器和 sudo 上下文只影响 `$` 通道。内置 `read/write/edit/bash`、SFTP 文件读写和文件传输始终在宿主机；这样不会出现 bash 已经在容器里、文件工具却还在宿主机的路径错位。普通容器命令通过非交互的 `docker exec -w <cwd> <container> <shell> -c <command>` 执行；sudo 命令通过 `sudo -S -u root -H bash -lc ...` 执行，密码通过 stdin 一次性发送，不写入命令行或配置文件。

**为什么不进上下文**：`$` 由 `input` 事件接管并返回 `handled`，因此不会产生任何 LLM 请求；命令与输出会以可折叠条目（`ssh-passthrough`）持久留在会话记录里供你回看，`Ctrl+O` 展开。

**与 Pi 原生 `!` 的区别**：

| | `!` / `!!` | `$` |
|---|---|---|
| 执行位置 | 本机（本插件不接管） | 选定服务器的 host/sudo/container 上下文 |
| 上下文 | `!` 进上下文，`!!` 不进 | 都不进 |
| 目录 | 本机 cwd | 当前 host 或 container 目录 |
| 取消 | Pi 原生行为 | Esc/Ctrl+C（远端进程组 SIGINT） |

**限制**：`$` 一次只打一台服务器（要并行用 `ssh_remote_batch`）；带附件的消息不会被当作 `$` 命令；`$` 后紧跟数字按普通聊天处理。
`$` 不提供通用远端 stdin 转发，明显的 `su`、裸 shell、`docker exec -it ... bash`、编辑器和 REPL 会被预检提示，不会默认让你等 600 秒；sudo 密码是插件专门的一次性 stdin 输入，真交互终端仍不属于本版本。

## Agent 多服务器工具

| 工具 | 作用 |
|---|---|
| `ssh_remote_control` | 连接、选择、显式切换路由、断开、重连和查看连接池 |
| `ssh_remote_read` | 从指定 endpoint 读取文件 |
| `ssh_remote_write` | 向指定 endpoint 写入完整文件 |
| `ssh_remote_edit` | 在指定 endpoint 应用精确文本替换 |
| `ssh_remote_exec` | 在指定 endpoint 执行一次命令 |
| `ssh_remote_batch` | 顺序或并行执行最多 32 个跨服务器任务 |
| `ssh_remote_put` | 把本机文件/目录上传到一个或多个服务器 |
| `ssh_remote_get` | 把某个服务器的文件/目录下载到本机 |
| `ssh_remote_transfer` | 在服务器之间拷贝文件/目录(经由本机中继) |
| `ssh_remote_password` | 解码指定服务器的明文密码(Windows DPAPI) |

## 密码解码

密码在 Windows 上以当前用户的 DPAPI 密文存在 `~/.pi/agent/ssh-remote-credentials.json`,
agent 平时在幕后完成认证、看不到明文。当某些无法弹窗提示密码的步骤真的需要密码时
(如远端 `sudo -S`、给其它服务配密码、跳板机),可用 `ssh_remote_password`
(`endpoint=<选择器>`)、`ssh_remote_control action=password` 或 `/remote password [endpoint]`
解码出来。解码结果是明文、会进入模型上下文,仅在确实需要时调用,并避免重复输出。

## 文件传输

三个工具覆盖了你要的各个方向:本机↔服务器、服务器↔服务器、点对点、点对面
(一处发多处 fan-out),从小文件到大文件都能传:

- **大文件**:上传/下载走 ssh2 `fastPut`/`fastGet` 的并行 SFTP 通道;
  服务器↔服务器默认 `via=stream` 在本机进程里流式中继(内存有界、不占本地磁盘),
  也可用 `via=stage` 先落到本地临时文件再上传(两段都更快,但需本地磁盘≈文件大小)。
- **目录**:递归传输并保持目录结构,目标目录自动创建。
- **进度**:通过工具 `onUpdate` 回调实时推送每个文件百分比和人类可读的字节数。
- **覆盖策略**:`always`(默认)、`skip`、`newer`(源比目标新才覆盖);反复同步选 skip/newer。

```text
# 本机 → 一台服务器(点对点)
ssh_remote_put  localPath=D:\model.bin remotePath=/home/u/model.bin endpoint=110.3.241.21

# 本机 → 多台服务器(点对面 fan-out)
ssh_remote_put  localPath=D:\model remotePath=/home/u/model \
                targets=["110.3.241.21","110.3.241.25","110.3.241.15"] \
                overwrite=newer parallel=4

# 服务器 → 本机
ssh_remote_get  endpoint=110.3.241.21 remotePath=/data/logs localPath=D:\downloads

# 服务器 → 服务器(经本机中继,两端无需互通)
ssh_remote_transfer source=110.3.241.21 sourcePath=/data/ckpt.tar \
                    targets=["110.3.241.25"] targetPath=/data/ via=stream
```

路径规则:远端路径可用绝对路径 `/...` 或 `~/...`;相对远端路径相对各端点自己的 cwd;
本机相对路径相对本地进程 cwd。超大文件服务器互传时,`via=stream` 内存有界;
`via=stage` 更快但临时需要本地磁盘≈文件大小。

## 配置保存在哪里

服务器配置保存在本地：

```text
~/.pi/agent/ssh-remote-config.json
```

其中包括：

- 已保存的服务器；
- 当前选中的服务器；
- 服务器备注；
- 默认远程目录；
- 端口转发配置；
- 命令预览设置；
- `$` 穿透目标服务器（`passthroughEndpoint`）；每个容器的 `$` 目录（`containerCwds`）、sudo 目录（`sudoCwd`）和上下文模式。

密码不会写入上述配置文件。在 Windows 上，首次使用密码成功连接后，插件会显式加载 .NET `System.Security`，使用当前 Windows 用户范围的 `ProtectedData`（DPAPI）加密密码，并把密文保存到：

```text
~/.pi/agent/ssh-remote-credentials.json
```

下次启动 Pi 时，插件会在内存中解密并用于连接，通常不再显示密码输入框。凭据只能由保存它的 Windows 用户解密；文件中没有明文密码。密码认证失败时，插件会删除该服务器的旧凭据并提示输入新密码；网络超时、服务器离线、远程目录错误等非认证故障不会删除密码。

`/remote forget [ENDPOINT]` 可以主动删除一台服务器的凭据，`/remote forget --all` 可以删除全部凭据。非 Windows 系统目前仍只使用当前 Pi 进程的内存缓存。

## 安全与输出限制

- 第一次连接新服务器时，需要确认主机密钥；
- 主机密钥发生变化时，会再次要求确认；
- 远程命令默认 600 秒超时；
- 发送给模型的命令输出最多为 2,000 行或 50 KB；
- 超限的完整输出会保存到本地临时文件；
- 折叠显示行数只影响界面，不影响模型输出上限。

## 当前限制

目前只支持 SSH 直连，以及 `-p`、`-l` 参数。暂不读取 `~/.ssh/config`，也不支持 `IdentityFile` 和 ProxyJump。

SSH 的 `exec` 每条命令都是全新的 shell，插件不会实例化常驻远端终端；因此「当前目录」是由插件
按端点维护的字符串，靠 `cd -- <目录> && <命令>` 前缀注入实现无感路由。`$` 穿透与容器执行
共享同一个前缀构造点；容器上下文已支持 `$ctx docker <name>`，使用非交互 `docker exec -w`，但真交互终端仍不属于本版本。

MIT License。
