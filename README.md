# ap

`ap` 是一个只安装在本机的命令行工具。它通过系统 OpenSSH 的反向端口转发，把本机已有的 HTTP、SOCKS5 或 mixed 代理安全地提供给 SSH 可达的远程服务器。

远程服务器不需要互联网、公共 DNS、root 权限或安装 `ap`。它只需运行可登录且允许 remote TCP forwarding 的 `sshd`。`ap` 不修改远程文件；远程用户自行设置代理环境变量。

```text
远端应用
  -> 远端 127.0.0.1:<固定端口>
  -> OpenSSH 反向隧道
  -> 本机 ap 认证网关
  -> 本机已有的无认证代理端口
  -> 目标网络
```

> 当前仓库是 v0.1 开发版本。安全边界和命令行已经按 v1 设计实现，但发布前仍应在目标 Linux/macOS 环境分别完成系统凭据库、用户服务和隔离 sshd 验收。

## 安装

需要 Rust 1.88 或更高版本，以及系统 `ssh`：

```bash
cargo install --path .
ap --help
```

远端不需要安装任何文件。

## 快速开始

先为远端建立专用的 `~/.ssh/config` Host。连接地址、用户、端口、私钥、agent 等都由 OpenSSH 管理；默认的 `ssh-config` 模式也支持 `ProxyJump`/`ProxyCommand`：

```sshconfig
Host dev-server
    HostName 192.0.2.10
    User alice
    IdentityFile ~/.ssh/id_ed25519
```

添加 profile 和代理映射：

```bash
ap server add dev --ssh dev-server

ap proxy add dev web \
  --protocol http \
  --local 127.0.0.1:7890 \
  --remote-port 17890

ap proxy add dev socks \
  --protocol socks5 \
  --local 127.0.0.1:7891 \
  --remote-port 17891

ap doctor dev
ap connect dev
```

`ap doctor` 不检查远端互联网或公共 DNS，也不执行远端命令。它会检查受信任的系统 OpenSSH、专用 Host alias、host key、当前认证方式、本机代理协议握手和一组真实的 `-N -T -R` 回环转发，并对 `GatewayPorts` 造成的非回环暴露做最佳努力探测。

运行中的 profile 默认不能修改映射、轮换代理凭据、切换 SSH 密码模式或删除 server；对应命令必须显式传入 `--restart`，由 `ap` 停止整个 profile、原子保存变更，并在配置仍包含映射时重新连接。

在另一个远端会话中，由远端用户自行获取并设置环境变量：

```bash
ap env dev web
# 把输出复制到远端 shell 执行
```

HTTP 映射输出 `http_proxy` 和 `https_proxy`；SOCKS5 映射输出 `all_proxy=socks5h://...`，目标域名由本机代理侧解析。

## SSH 认证

默认 `ssh-config` 模式完全沿用 OpenSSH 的认证行为，适合私钥、agent、硬件密钥、MFA 以及前台密码提示。

如需让后台服务使用标准 SSH password 认证，可显式保存密码：

```bash
ap auth password set dev [--restart]
ap auth password status dev
ap auth password remove dev [--restart]
```

密码从 `/dev/tty` 无回显读取两次，不接受命令行参数或环境变量。macOS 使用当前用户 Keychain；Linux 使用当前登录会话的 Secret Service（GNOME Keyring、KWallet 等）。不存在系统凭据库时操作直接失败，不回退到普通文件。

`stored-password` 只支持 SSH `password` 方法，不支持 keyboard-interactive、OTP、MFA 或 `publickey,password` 组合认证。为防止 AskPass 密码被本地 SSH hook 误取，该模式还拒绝 `ProxyCommand`、`ProxyJump`、`KnownHostsCommand` 和 `Match exec`；需要这些能力时请使用 `ssh-config` 模式和前台 `ap connect`。

## 后台运行与登录自启动

```bash
ap service install
ap up dev
ap status dev
ap down dev

ap enable dev   # 设置登录自启动并立即连接
ap disable dev  # 取消登录自启动并停止连接
```

macOS 使用 LaunchAgent，Linux 使用 `systemd --user`，均不需要 root。Linux v1 不自动启用 linger，因此默认在用户登录后启动。

daemon 会把网络类故障按带抖动的 `1、2、4、8、15、30、60` 秒退避重连；错误密码、host key 变化、转发策略拒绝和固定端口冲突会进入 `failed` 而不是无限重试。系统凭据库暂时不可访问时，stored-password profile 进入 `waiting-for-secret-store` 并定期重试。本机上游代理中断不会拆掉 SSH 隧道，profile 会标记为 `degraded`。

## 安全模型

- SSH 远端监听固定为 `127.0.0.1`，端口限制在 `1024..=65535`。
- 本机上游端点只能是 `127.0.0.1` 或 `::1`。
- 每个 profile 自动生成独立、可轮换的代理共享凭据。
- 即便远端 sshd 的 `GatewayPorts` 配置意外扩大监听范围，没有代理凭据的连接仍会在本机网关被拒绝。
- HTTP 每个请求都重新校验 Basic 凭据，并在转发前移除认证头；SOCKS5 强制 RFC 1929 username/password。
- 专用 SSH Host alias 中若含额外的 `LocalForward`、`RemoteForward`、`DynamicForward`、`RemoteCommand` 或 `LocalCommand`，`ap` 会拒绝连接；`ProxyJump`/`ProxyCommand` 只允许由 `ssh-config` 模式沿用。
- SSH 密码只在认证发生时从系统凭据库读取，经一次性 AskPass Unix socket 交给经过所有权校验的系统 OpenSSH；密码不进入配置、argv、环境或日志。stored-password 会把已验证的有效 SSH 配置通过匿名管道交给同一次 OpenSSH 进程，不创建可被替换的快照路径，从而关闭配置检查与使用之间的竞态窗口。
- macOS 还使用 Unix socket 的 audit token（包含 pid-version）绑定 watchdog/AskPass 进程：Security.framework 校验 designated code requirement，内核返回已加载进程的 CDHash，并要求它与当前运行 daemon 的 exact CDHash 匹配，而不只比较可被替换的文件路径。这会拒绝运行期间的热替换，也会拒绝同一 Developer ID 签名的旧版本降级。升级或重新链接二进制后必须重启用户服务/daemon；profile UUID、Keychain item 和稳定签名标识 `dev.approxy.ap` 不因此改变。
- 每个 OpenSSH master 都由 `ap` 的内部 watchdog 直接托管。持有连接的 `ap` 进程即使被 `SIGKILL`，内核也会关闭私有存活通道，watchdog 随即终止并回收 OpenSSH（后台模式同时处理其进程组），使远端 `-R` 监听不会作为孤儿继续存在。watchdog 不接收 SSH 密码；密码仍只通过 AskPass 私有通道传递。
- `ap` 在读取任何凭据前把自身及后续 OpenSSH 子进程的 core-dump 上限永久设为零，避免认证期间短暂存在于内存或私有管道中的 SSH 密码进入崩溃文件。
- server 新增/删除和 SSH 密码保存/删除由一个权限为 `0600`、不含任何秘密值的事务日志保护。若进程遭 `SIGKILL` 或机器掉电，下一次 `ap` 启动会在全局事务锁下幂等完成清理或恢复，避免有效 profile 指向已删除的秘密，也避免留下未知的 Keychain/Secret Service 项。
- `ap` 不启用 SSH agent forwarding、X11 forwarding，也不关闭 host-key 校验。
- 状态包含连接/字节/认证失败/上游错误计数；daemon 日志只记录生命周期、错误分类和这些计数。两者都不记录 URL、目标域名、请求正文、认证头或凭据。

同一远程系统上的其他用户通常也能连接远端 loopback 端口，因此不能把 `127.0.0.1` 当作用户隔离。不要在不受信任的远端共享代理凭据。获授权的远端用户会继承本机代理能够访问的互联网、内网与出口身份。

## 明确限制

- 远端 sshd 必须允许 remote TCP forwarding；没有 root 权限时无法绕过管理员策略。
- 远端应用必须自身支持 HTTP/SOCKS 代理；v1 不提供透明全局代理。
- v1 不支持 raw TCP、SOCKS4、SOCKS BIND/UDP、TLS-to-proxy、目标 ACL、限速或插件协议。
- 本机上游代理在 v1 中必须无需认证。
- `stored-password` 只接受不可由普通用户替换的系统 OpenSSH；用户自装且用户可写的 `ssh` 不会被授予 AskPass 凭据。
- SSH 断开后，已有 TCP 连接不能恢复；重连只恢复后续连接。
- 每个 profile 的所有远端用户共用一组代理凭据，不能按远端用户单独撤销或审计。

## 开发与测试

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-targets
```

默认测试覆盖配置、CLI、HTTP/SOCKS5/mixed 协议、10 秒握手期限、无秘密事务恢复、core-dump 禁用、AskPass nonce/进程身份校验，以及 watchdog 的正常关闭和拥有者遭 `SIGKILL` 后的子进程回收。仓库的 Linux CI 另行定义了无默认路由、阻断非回环出站流量的网络 namespace，并以无 root 权限的登录用户运行隔离 sshd；该 job 覆盖正常反向转发、`AllowTcpForwarding no`、`PermitListen`、端口冲突、password-only AskPass 和资源清理。吞吐测试默认记录 32 个并发连接的结果；只有手动工作流启用 `enforce_throughput` 时才以裸 OpenSSH `-R` 的 85% 为门禁。

这些工作流和测试夹具存在于仓库并不等同于已经在每个目标系统执行成功；发布判断应以相应 GitHub Actions run 和目标机验收记录为准。系统凭据库的正向 CRUD 测试会操作当前登录用户的真实 Keychain/Secret Service，因此普通 `cargo test` 不自动启用；在专用测试账户或确认可清理的会话中可显式运行：

```bash
AP_RUN_SECRET_STORE_TEST=1 cargo test --test secret_store_live -- --nocapture
```

真实 SSH Host `server2` 仅用于人工开发验收，不作为持续 CI 的外部依赖、不展开真实连接信息，也不修改远端配置或安装软件。测试中的 SSH 连接只使用 `-N -T`，不要求远端运行 `curl`、`nc` 或任何测试程序；它使用随机高位端口，并通过额外临时 `-L` 从本机回连远端 loopback。完成后必须关闭 ControlMaster 并删除临时本地 profile/代理凭据。

显式运行真实开发验收：

```bash
AP_RUN_SERVER2_TEST=1 cargo test --test server2_dev -- --ignored --nocapture
```

## 发布产物

标签发布会生成两个 Linux musl 和两个 macOS 架构压缩包，以及独立的 `README.md`、`LICENSE`、`CHANGELOG.md`、`SHA256SUMS` 和 CycloneDX SBOM。稳定 macOS 版本必须通过 Developer ID 签名门禁；普通 CI 不接触签名秘密，手动 Release dry-run 则会在三个签名 secret 均已配置时签名，否则明确生成不可稳定分发的未签名产物。具体流程和所需 GitHub Actions secrets 见 [RELEASING.md](RELEASING.md)。

## 配置位置

默认遵循平台用户配置目录。测试时可通过 `AP_CONFIG_DIR` 指向隔离目录。目录权限为 `0700`，普通配置、自动生成的代理秘密文件和不含秘密值的恢复日志均为 `0600`；SSH 密码永远不写入这些文件。macOS 的 OpenSSH ControlMaster socket 属于易失运行状态，默认使用 `/private/tmp` 下当前 UID 专属且权限为 `0700` 的短路径目录，避免 OpenSSH 创建临时 multiplex socket 时超过系统 Unix socket 路径上限。

## License

MIT OR Apache-2.0
