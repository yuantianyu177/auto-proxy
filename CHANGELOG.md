# Changelog

本项目遵循 Semantic Versioning。

## [Unreleased]

### Added

- 全新的 v2 用户配置格式。connection 直接定义 SSH `host`、`user`、`port`、可选 `identity_file` 与任意数量的无名称 HTTP、SOCKS5 或 mixed proxy mappings。
- 扁平 SSH 认证：存在 `identity_file` 时使用密钥，省略时在每次显式启动或重启时从 `/dev/tty` 无回显读取密码。
- 扁平 CLI：通过 `ap <connection>` 连接，并以 `-f`、`-d`、`-r`、`-c`、`-l`、`-v` 和 `-h` 完成全部公开操作。
- 默认后台 supervisor 和显式前台模式；无需安装用户服务。
- 每次显式新建或重启 connection 时自动生成新的远端代理凭据，并在成功后输出远端环境变量。
- macOS 与 Linux 统一采用 `XDG_CONFIG_HOME`、`XDG_STATE_HOME` 和 `XDG_RUNTIME_DIR`，并提供安全的 runtime fallback。
- 独立的 XDG `known_hosts`、OpenSSH ControlMaster、父进程 watchdog，以及密钥 connection 的网络故障自动重连。
- 带认证的 HTTP、SOCKS5 与 mixed 本机网关，以及 Linux musl/macOS 四目标发布、SBOM 和 SHA-256 校验流水线。

### Changed

- SSH 参数完全由 ap v2 配置提供，不读取或复用 `~/.ssh/config`。
- 运行中的 connection 使用不可变配置快照。编辑配置只影响后续显式连接或重启。
- 显式重启会刷新代理凭据；密钥 connection 在同一 lifecycle 内自动断线重连时继续使用原配置快照和原凭据。
- SSH 密码只在首次认证期间短暂驻留受控内存并在认证结束后立即清除。密码 connection 断线后结束且不自动重连，再次显式启动或重启会重新提示。
- 所有终端输出、help、错误和运行日志统一为简洁英文。
- 配置完全由用户手写；程序只读取、验证并解析配置，不修改或打印配置内容。

### Security

- 远端转发固定监听 `127.0.0.1`，本机上游端点仅允许 `127.0.0.1` 或 `::1`。
- 每个 connection lifecycle 使用独立的随机 HTTP Basic/SOCKS5 RFC 1929 凭据；秘密不进入配置、argv、日志或连接列表。
- SSH 密码不能通过 CLI、环境变量、标准输入或配置文件提供，也不进入磁盘、状态、日志、OpenSSH argv 或环境；它通过一次性 AskPass 通道传递给受信任的系统 OpenSSH。
- SSH identity file、XDG 目录、运行 socket、known_hosts 与 ControlMaster 路径均进行所有权和权限校验。
- 用户 SSH 配置中的 alias、forward、local command、`ProxyJump` 和 `ProxyCommand` 无法影响 ap 连接。
- SSH agent forwarding、X11 forwarding 和远端命令被禁用；host-key 校验保持开启。
- HTTP 转发前移除认证与 hop-by-hop headers，SOCKS5 只允许 CONNECT；日志不记录目标、正文或秘密。

### Testing

- 配置解析覆盖 v2 schema、未知字段、密钥与交互密码选择、路径权限、loopback 限制和重复端口。
- CLI 解析覆盖扁平动作、作用域、互斥选项、英文 help/version、无保留字的 connection 名，以及在读取配置前拒绝并隐藏密码参数值。
- 隔离 sshd 测试不依赖远端互联网、公共 DNS、root 登录或远端软件，并覆盖转发策略、端口冲突、断线恢复和资源清理。
- 生命周期测试区分密钥与密码连接：前者自动重连，后者在首次认证后清除密码并于断线时结束。
- 协议测试覆盖 HTTP、CONNECT、SOCKS5、mixed、认证失败、32 路并发、大流量和半关闭传播。
