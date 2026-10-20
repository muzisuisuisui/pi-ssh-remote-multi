# pi-ssh-remote-multi — 多服务器 SSH 远程开发扩展

让 Pi 像操作本地项目一样操作远程服务器。

> **本扩展基于 [`pi-ssh-remote 0.1.4`](https://github.com/petrichor20211/pi-ssh-remote)（原作者 Yutong Bian）二次开发**，
> 保留上游设计同时新增了多连接池、批量执行、文件传输、凭据持久化等能力。
> 上游 LICENSE（MIT）与作者署名已保留，见 [LICENSE](LICENSE) 与 [CHANGELOG](CHANGELOG.md)。

## 与上游 `pi-ssh-remote` 的区别（新增功能）

| 功能 | 说明 |
|---|---|
| **多连接池** | 同一会话内保持多台服务器同时在线，连接第二台不会断开第一台 |
| **`ssh_remote_batch`** | 跨多台服务器并行跑命令，结果按输入顺序返回，单台失败不取消其他 |
| **三向文件传输** | `ssh_remote_put`（本地→一台或多台）、`ssh_remote_get`（服务器→本地）、`ssh_remote_transfer`（服务器→一台或多台，经本地中继） |
| **凭据持久化** | 密码加密保存到本地凭据库（Windows DPAPI / macOS Keychain / libsecret / 本地 AES-256-GCM 密钥文件，按平台自动选择），重开 Pi 自动重连，不落明文 |
| **`ssh_remote_password`** | 从内存缓存或凭据库解码明文密码（用于远程 `sudo -S`、跳板机等非交互场景） |
| **端点选择语义** | 精确匹配优先于前缀匹配，避免 `.21` 被 `.210` 干扰 |
| **路由控制** | 连接/选择端点不自动改路由；内置工具默认本地，只有显式 `/remote on` 才整体路由到所选服务器 |
| **端点状态** | 每个端点记住远程 cwd、note、端口转发配置；note 显示在配置、状态和 footer |
| **并行连接** | 同一轮里连多台服务器时，密码框标出 `user@host:port` 并串行排队（`N more waiting`），不会互相覆盖导致后续连接卡死 |
| **自动重连** | 活动会话掉线自动重建连接；命令默认 600s 超时（可在配置/单次调用覆盖），超出保留到临时文件不怕刷爆上下文 |

## 提供的主要工具

| 工具 | 作用 |
|---|---|
| `ssh_remote_exec` | 在指定远端执行命令（不切换当前工作区） |
| `ssh_remote_read` / `write` / `edit` | 在指定远端读写/编辑文件（不切换工作区） |
| `ssh_remote_batch` | 跨多台服务器并行执行命令 |
| `ssh_remote_put` / `get` / `transfer` | 三向文件传输（支持目录递归、`overwrite` 策略、`concurrency`/`chunkSize` 调优） |
| `ssh_remote_control` | 连接/激活/路由/重连/转发/断开等控制面 |
| `ssh_remote_password` | 解码已保存端点的明文密码（仅必要时调用，注意敏感） |

## `$` 穿透执行（人手工通道，v0.5.1）

内置工具路由（`/remote on`）之外，多了一条**只给你自己**的通道：输入框里以 `$` 开头的内容
直接送到「穿透目标服务器」执行，结果**完全不进模型上下文**（零 token 成本）。

| 输入 | 作用 |
|---|---|
| `$ <command>` | 在穿透目标的当前执行上下文中执行，弹实时输出框，Esc/Ctrl+C 取消 |
| `$cd <path>` | 修改当前执行上下文的目录；host 在宿主机解析，container 在容器内解析 |
| `$ctx` | 选择执行上下文：宿主机普通用户、sudo root 或一个正在运行的 Docker 容器 |
| `$ctx host` | 回到宿主机普通用户上下文 |
| `$ctx sudo` | 切到宿主机 root 上下文；自动复用该 SSH 端点密码，密码只保存在当前进程内存 |
| `$ctx docker <name>` | 选择 Docker 容器；之后的 `$` 命令都用 `docker exec` 在该容器内执行 |
| `$ctx list` | 列出当前服务器目录和运行中的 Docker 容器 |
| `$server [selector]` | 选择 `$` 的目标服务器（等同 `/control_ssh`；`$ctx <selector>` 仍兼容旧版服务器选择） |
| `$force <command>` | 跳过交互命令预检；仅用于明确知道命令会自行退出的场景 |
| `$` | 打印帮助与当前目标/上下文 |

- 服务器目标与执行上下文显示在底部状态栏：`$→ <端点> · [docker <name>] <目录>`。
- `/control_ssh` 保持一级菜单，只负责选择服务器；`$ctx` 负责选择该服务器上的 host/sudo/container 上下文。
- 容器上下文只作用于 `$` 通道；内置工具、SFTP 文件读写和文件传输始终在宿主机，避免路径语义混淆。
- 容器上下文使用非交互的 `docker exec -w <cwd> <container> <shell> -c <command>`；不需要手动输入 `docker exec -it ... bash`。
- sudo 上下文使用 `sudo -S -u root -H bash -lc ...`，密码通过 SSH channel 的 stdin 一次性写入，不进入命令行或配置文件；sudo 目录与普通用户目录分开保存。
- `$` 通道通常不转发远端 stdin。明显的 `su`、裸 `bash`、`docker exec -it ... bash`、`vim`、REPL 等会被提前提示，避免挂到超时；sudo 密码是插件专门的一次性 stdin 输入，不提供通用交互终端。
- 每条 `$` 命令的记录以可折叠条目留在会话里（`Ctrl+O` 展开），但不发给模型。
- 输出超 2000 行 / 50KB 自动截断并落临时文件，附完整输出路径。
- `$` 后紧跟数字（如 `$100`）以及带附件的消息按普通聊天放行。
- **`!`/`!!` 不再被接管**：它们始终在本机执行。

## 用户命令

```
/remote                      查看状态
/remote connect <spec>       连接一台服务器（不改变路由）
/remote use <selector>       切换当前选中的端点（不断开其他连接）
/remote on | off             显式开启/关闭内置工具透明路由
/remote connections          查看全部连接
/remote status               状态总览
/remote forget [--all]       删除保存的凭据
/control_ssh                   选择 $ 穿透目标服务器（单级菜单，列出在线端点及各自目录）
```

## 安装

```bash
# 从源码
pi install ./pi-ssh-remote-multi

# 或 npm 包（发布后）
pi install npm:pi-ssh-remote-multi

# 全局安装位置：~/.pi/agent/npm/pi-ssh-remote-multi/
# 修改代码后：pi 里执行 /reload
```

## 文件说明

```
pi-ssh-remote-multi/
├── index.ts          # 扩展主入口：连接池、工具注册、控制面、文件传输、凭据后端(DPAPI/Keychain/libsecret/本地加密)、$ 穿透
├── package.json      # name=pi-ssh-remote-multi, v0.6.0, MIT
├── LICENSE           # MIT（保留原作者）
├── CHANGELOG.md      # 迭代记录（0.2.0 → 0.6.0）
├── README.md         # 英文文档（Agent-first）
├── README.zh-CN.md   # 中文文档
└── skills/ssh-remote/SKILL.md  # 配套 skill（随插件自动发现）
```

## 上游信息

- 上游仓库：`https://github.com/petrichor20211/pi-ssh-remote`（v0.1.4）
- 原作者：Yutong Bian and contributors
- 本扩展版本：0.6.x，持续基于上游演进
