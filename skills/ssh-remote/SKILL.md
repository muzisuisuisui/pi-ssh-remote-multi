---
name: ssh-remote
description: >
  连接、管理并同时对多台远程 SSH 服务器执行任务。
  适用于:SSH 连接服务器、远程登录、在远程机器上读写文件或执行命令、
  同时连接与操作多台服务器、批量在多个远程主机上并行跑命令、端口转发、
  远程查看日志/进程/磁盘/GPU/NPU 状态等场景。
  当用户要求"连接某台服务器/某台机器/某台主机""连上某台服务器""登录某台服务器"
  "SSH 到/SSH 连接""在多台服务器上并行执行""远程排查故障"
  "对远程主机执行命令/读写文件""查看服务器系统信息/资源状态"等,只要涉及
  "远程服务器"或"SSH"操作,均应加载本 skill 并使用 ssh_remote_* 系列工具。
  注意:用户描述服务器时可能只说片段(如"以21结尾的服务器"),必须按"端点识别"
  章节优先在已配置端点中匹配,不得去全网搜索 IP。
---

# ssh-remote-multi(多服务器远程工作区)

本插件让 Pi 像操作本地一样操作远程服务器,并支持**同时保持多台 SSH 连接**。
核心能力由 `ssh_remote_*` 系列工具提供。

## 连接管理 —— 通过 `ssh_remote_control`

连接一个端点:
```
ssh_remote_control  action=connect
   endpoint/command: "ssh user@host -p 22"
```

查看连接池(会返回 connectionCount / connections / selectedEndpoint /
toolRouting / configPath / credentialsPath):
```
ssh_remote_control  action=status
```

切换"选中端点"(只改默认目标,不改工具路由):
```
ssh_remote_control  action=activate   endpoint=<完整key 或 前缀或 note>
```

开启 / 关闭内置工具(read/write/bash)到选中端点的路由:
```
ssh_remote_control  action=route   routing=remote   # 内置工具切到远程
ssh_remote_control  action=route   routing=local    # 回到本地(连接仍保留)
```

断开(可指定端点,省略断开活动端点；`--all` 断开全部):
```
ssh_remote_control  action=disconnect   endpoint=<key>|all
```

## 端点识别与歧义处理(必须先做)

用户描述服务器时经常只给片段,如"连上以21结尾的服务器""那台 .25"。
**严禁去全网扫描/搜索匹配该片段的 IP**——正确做法是只在本机**已配置的端点**里匹配。

实际操作步骤:

1. **优先读已配置的端点列表**(不用全凭记忆):
   ```
   cat "$HOME/.pi/agent/ssh-remote-config.json"   # endpoints 字段即所有已知可连的服务器
   ```
   也可用 `ssh_remote_control action=status` 查看连接池/已连端点。

2. **把用户片段与这些已知端点匹配**:
   - 片段 "21结尾" 或 ".21" → 对应配置里的 `w00896470@110.3.241.21:22`
   - 片段 ".25" → `w00896470@110.3.241.25:22`
   - 匹配时用 IP 尾号、前缀、note 名称对齐,不回一倒一个 IP 就去扫网络。

3. **匹配唯一 → 直接连**该端点(见下"端点选择器")。
4. **匹配不到 / 有歧义 → 向用户确认**,列出已知端点让用户选,不要猜测。

> 只有确认是"从未配置过的新服务器"时,才需要 `ssh-addhost`(若存在)去新增主机;正常情况下都在已知端点里选择。

## 端点选择器支持这些形式(任选其一)

- 完整 key:`w00896470@110.3.241.21:22`
- 纯 IP:`110.3.241.21`
- host:port:`110.3.241.21:22`
- user@host:`w00896470@110.3.241.21`
- 以上值的唯一前缀,或配置的 note 前缀
- 精确匹配优先;多个账号连同一 IP 时,用纯 IP 会提示歧义(预期行为)
- 端点选择器只识别上述形式;**用户口语化描述必须先经"端点识别"转换成真实 key** 再用

## 跨服务器工具

- `ssh_remote_exec`:在指定 endpoint 执行一条命令
  参数:endpoint + command —— 两者**必填,没有默认服务器**,每次调用都必须显式传入
  endpoint(支持完整 key / 纯 IP / host:port / user@host / 唯一前缀);漏传 endpoint 会
  在校验阶段直接报 `must have required properties endpoint`。可选:cwd / timeout / displayLines / pty
- `ssh_remote_batch`:并行在最多 32 个端点执行命令
  参数:jobs = [{endpoint, command}, ...];一台失败不影响其他,结果按输入顺序返回;执行中
  实时推每 job 状态 + 最后 2 行输出预览;可选 parallel / concurrency / timeout
- `ssh_remote_read`:从指定 endpoint 读文件
- `ssh_remote_write`:向指定 endpoint 写完整文件
- `ssh_remote_edit`:在指定 endpoint 做精确文本替换

## 文件传输(put / get / transfer)

三个传输工具覆盖全部方向,从小文件到大文件都支持(大文件用 SFTP 并行通道/流式传输,
内存有界),目录递归传输并保持结构,自动创建远端/本地目录,进度实时推送:

- `ssh_remote_put`:本机 → 一个或多个服务器(点对点 / 点对面 fan-out)
  endpoint=单目标 或 targets=[...多个端点];localPath 是本机文件/目录,
  remotePath 是远端目标目录(单文件可给精确文件路径)
- `ssh_remote_get`:单个服务器 → 本机
  endpoint + remotePath(源) + localPath(目标目录,单文件可给精确文件路径)
- `ssh_remote_transfer`:服务器 → 一个或多个服务器(经由本机中继,两端不需要互通)
  source + sourcePath + target/targets + targetPath;via=stream(默认,内存有界不占本地盘)
  或 stage(经本地临时文件,更快,但需本地磁盘≈文件大小)
- `ssh_remote_password`:解码指定服务器的明文密码(加密凭据库:Windows DPAPI / macOS Keychain /
  Linux libsecret / 本地 AES-256-GCM 密钥文件,按平台自动选择),
  `endpoint=<选择器>`(无需已连接);或 `ssh_remote_control action=password`。
  仅当远端需要密码且无法交互输入时用(如 sudo -S、给其它服务配密),解出的明文会进入模型上下文。

通用参数:overwrite=always|skip|newer(默认 always;反复同步建议 skip/newer)、
recursive(默认 true);远端路径可用 `/...` 或 `~/...`,相对路径相对各端点 cwd。

典型调用(端点可用 key/IP/前缀匹配):
- 本机→一台服务器: `ssh_remote_put localPath=D:\x.tar remotePath=/data/x.tar endpoint=...21`
- 本机→多台服务器: `ssh_remote_put localPath=D:\model remotePath=/home/u/model targets=[...]`
- 服务器→本机:  `ssh_remote_get endpoint=...21 remotePath=/data/logs localPath=D:\downloads`
- 服务器→服务器: `ssh_remote_transfer source=...21 sourcePath=/data/ckpt.tar targets=[...] targetPath=/data/`

## 典型流程

**场景A:用户说"连上以21结尾的服务器"**
1. 读 `ssh-remote-config.json` 端点列表,匹配到 `w00896470@110.3.241.21:22`(不要扫全网)
2. `ssh_remote_control connect endpoint=w00896470@110.3.241.21:22`
3. `status` 确认已连
4. 若用户同时提到多台(如 21 和 25),分别连接后再用 `ssh_remote_batch` 并行执行

**场景B:连接两台再并行查看**
1. 分别 `ssh_remote_control connect` 连接 .21 与 .25
2. `ssh_remote_batch` 在两台上执行同步命令(hostname / df / nproc / nvidia-smi)
3. 随时 `status` 确认连接池与活动端点

## 注意事项

- **记住用户只给片段时先查已配置端点,禁止全网搜 IP**(见"端点识别"章节)。
- 连接/激活本身**不改变**内置工具的路由;只有 `route routing=remote` 才把
  read/write/bash 切到远程
- 需要密码的端点,密码加密持久化(Windows DPAPI、macOS Keychain、Linux libsecret,无可用密钥环时
  回退到 AES-256-GCM 密钥文件):首次输入后,后续会话自动连接;`ssh_remote_password` 在 Linux/macOS 上同样可用
- 远程命令默认 600 秒超时(`ssh-remote-config.json` 可用 `defaultTimeout` / 每端点 `timeout` 覆盖,
  单次调用也可传 `timeout` 参数);输出超大时会折叠,完整输出保存到临时文件
- exec/batch 默认带 PTY:输出实时流式推给 CLI;执行中按 Esc 会向远端进程组发 SIGINT
  (等价 Ctrl+C,进程树一并清理,关闭的是 exec channel 不影响连接,后续命令可直接再跑);
  若显式传 `pty: false` 则与普通管道一样,按 Esc 只 SIGINT shell 会话、后台子进程可能残留
- 只支持 SSH 直连及 `-p` / `-l` 参数;不读 `~/.ssh/config` 的 IdentityFile/ProxyJump