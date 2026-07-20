# Changelog

本项目遵循 Semantic Versioning。

## [Unreleased]

### Added

- Rust 单二进制 CLI、用户级 daemon IPC 和 macOS/Linux 服务定义。
- OpenSSH 多路反向转发、ControlMaster、AskPass 系统凭据库集成。
- 带认证的 HTTP、SOCKS5 和 mixed 本机代理网关。
- profile、映射、代理凭据、环境变量与 doctor 管理命令。
- Linux musl/macOS 四目标发布流水线、Developer ID 签名门禁、SBOM 与 SHA-256 校验清单。
- OpenSSH 父进程 watchdog；即使持有连接的 `ap` 被 `SIGKILL`，也会终止并回收 SSH 子进程，释放远端监听。
- 无外网/公共 DNS 的隔离 sshd 测试夹具、password-only AskPass 测试、转发策略/端口冲突覆盖、`server2` 人工开发测试和可选吞吐门禁。
- macOS Keychain/Linux Secret Service 的显式真实 CRUD 测试，以及 Linux 无会话 D-Bus 时禁止明文文件回退的自动测试。
- 不含秘密值的跨存储事务日志与启动恢复，覆盖 server 和 SSH 密码的新增/删除崩溃窗口。

### Fixed

- macOS 默认将 OpenSSH ControlMaster socket 放入当前 UID 专属的短路径私有运行目录，避免 `~/Library/Application Support` 加上 OpenSSH 临时后缀后超过 Unix socket 路径上限而产生 `AP_SSH_EXITED`。

### Security

- stored-password 模式仅信任 root-owned 且普通用户不可替换的系统 OpenSSH，并拒绝可继承 AskPass 环境的 SSH 本地 helper。
- macOS 将 watchdog/AskPass 绑定到 socket audit token（含 pid-version）、运行中 daemon 的 designated code requirement 和内核返回的 exact running CDHash，阻止同路径热替换或使用同一签名身份的旧版本降级绕过 Keychain 访问边界。升级后需重启 daemon；profile UUID、Keychain item 与 Developer ID 稳定标识 `dev.approxy.ap` 保持不变。
- 已校验的 OpenSSH effective config 通过匿名 stdin 管道交给实际连接，避免可替换的配置快照路径。
- SSH 密码、自动生成的代理凭据、daemon IPC、运行锁、服务定义和日志采用彼此独立的存储与权限边界。
- 发布脚本使用原子输出、拒绝符号链接输入，并精确校验校验清单和压缩包成员；macOS 打包禁用 AppleDouble 元数据文件。
- 进程在读取凭据前禁用自身及 OpenSSH 子进程的 core dump；HTTP 上游连接和响应头阶段均受握手期限约束，超时会释放连接任务。

### Testing notes

- 真实 Keychain/Secret Service、真实 `systemd --user`/LaunchAgent、Developer ID 签名与四个发布目标仍须以各目标环境或 GitHub Actions 的实际运行结果为发布依据；本条只记录测试入口和发布门禁已经加入仓库。
