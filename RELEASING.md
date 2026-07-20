# 发布 ap

正式版本由 `.github/workflows/release.yml` 在推送 `v<semver>` 标签时构建。标签版本必须与 `Cargo.toml` 完全一致；工作流会构建并打包以下四个目标：

- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

每个压缩包精确包含 `ap`、`README.md`、`RELEASING.md`、`CHANGELOG.md`、`LICENSE`、`LICENSE-MIT` 和 `LICENSE-APACHE`。GitHub Release 还单独附带 `README.md`、`LICENSE`、`CHANGELOG.md`、CycloneDX JSON SBOM，以及覆盖这八项内容（四个压缩包、三份文档和 SBOM）的 `SHA256SUMS`。

## macOS Developer ID 门禁

仓库需要配置下列 GitHub Actions secrets：

- `AP_MACOS_CERTIFICATE_P12_BASE64`：Developer ID Application 证书及私钥的 PKCS#12 文件，经 Base64 编码后的完整内容。
- `AP_MACOS_CERTIFICATE_PASSWORD`：PKCS#12 导出密码。
- `AP_MACOS_SIGNING_IDENTITY`：`Developer ID Application: ...` 身份名称，或对应证书 SHA-1 标识。

所有标签触发的发布都强制要求这三项 secret，并使用 hardened runtime 和可信时间戳签名两个 Mach-O 文件；任意 secret 缺失、身份不匹配或 `codesign --verify` 失败都会阻止发布。CI、pull request 和普通分支构建不会接收或使用签名 secret。

签名脚本固定使用 code-signing identifier `dev.approxy.ap`。不要按版本改变该 identifier：macOS stored-password 先用运行中 daemon 的 designated requirement 校验 watchdog/AskPass，再通过 audit token/pid-version 绑定的内核查询，要求它们已加载进程的 exact CDHash 与该 daemon 一致。稳定 identifier 与 Developer ID team identity 保持 Keychain 访问身份的升级连续性；exact running CDHash 阻止运行期间热替换或降级到同一签名身份的旧版本。

安装任何新二进制（包括开发构建重新链接）后必须重启用户服务/daemon，使新 daemon 与其新 helper 使用同一 CDHash。不要只覆盖磁盘上的 `ap` 就继续运行旧 daemon；旧 daemon 会按设计拒绝新 helper。重启不改变 profile UUID 或凭据引用，稳定签名身份也使原 Keychain item 在新进程中保持可读。

手动运行 Release 工作流只生成供检查的 artifact，永远不会创建 GitHub Release。其 `require_macos_signing` 默认关闭，便于 fork 或首次配置时验证交叉构建：若三个签名 secret 均已配置，手动产物仍会签名；若均未配置，macOS 包会明确标记为未签名 dry-run 产物，不能作为稳定版本分发；只配置一部分始终失败。启用该选项的作用是把“完全未配置签名 secret”也变成失败，从而强制验证完整签名链路。

建议把三个签名值配置为权限受限的仓库或组织 Actions secrets，并为发布标签配置 tag protection。若团队需要额外的人工审批，可再把 macOS 签名 job 关联到受保护的 GitHub Environment。当前 v1 只做 Developer ID 签名，不提交 Apple notarization；若未来分发方式要求公证，应在发布门禁中另增 notarytool 步骤，不应弱化现有签名检查。

## 发布前检查

```bash
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
```

上述命令会运行 watchdog 的正常关闭和拥有者 `SIGKILL` 回收回归测试，但不会自动启用需要真实外部环境的 opt-in 测试。稳定版本还必须在候选提交上确认 `.github/workflows/ci.yml` 的 `isolated-sshd` job 实际成功；该 job 的网络 namespace 没有默认路由并阻断非回环出站流量，使用普通 SSH 用户覆盖反向转发、forwarding policy、端口冲突、password-only AskPass 和清理。普通共享 runner 的吞吐结果只作记录；如需把 85% 比例作为发布门禁，应手动运行 CI workflow 并启用 `enforce_throughput`。

普通测试还验证无秘密事务日志在 server/SSH 密码操作各关键崩溃阶段的幂等恢复，以及子进程继承的零 core-dump 上限。目标系统人工验收应再任选隔离 profile，在事务完成前强制终止测试进程，确认重启后 `transaction.toml` 被清理、profile 与代理凭据保持一致，且日志和恢复文件从未包含测试密码。

目标系统验收不得由“测试文件存在”或“交叉编译成功”代替。至少保存下列实际运行记录：

- 在当前稳定发行支持的 macOS 版本上，用专用测试 Keychain item 运行 `AP_RUN_SECRET_STORE_TEST=1 cargo test --test secret_store_live -- --nocapture`。从前一签名版本升级到候选版本后显式重启用户服务/daemon，确认原 profile UUID 引用的 Keychain item 仍可读，并确认未重启旧 daemon 时会拒绝 CDHash 不同的新 helper。
- 在带真实登录会话 Secret Service 的支持 Linux 桌面上运行同一 CRUD 测试；无 Secret Service 的拒绝和无文件回退由普通 Linux 测试覆盖，但不证明 GNOME Keyring/KWallet 正向路径可用。
- 分别在临时测试账户中实际执行 `ap service install`、登录启动、`ap down`/`enable`/`disable`、daemon 崩溃恢复和 `ap service uninstall`，核对 `systemd --user` 与 LaunchAgent 行为。Linux v1 不修改 linger。
- 在签名 job 中检查两个 macOS 二进制的 Developer ID 验证结果。交叉构建只证明产物可生成，不证明 Keychain、用户服务或真实 SSH 环境已经验收。

真实 `server2` 是开发期人工回归目标，不是发布 CI 门禁。若候选版本需要该记录，只能显式运行 `AP_RUN_SERVER2_TEST=1 cargo test --test server2_dev -- --ignored --nocapture`；不得记录 alias 展开的 IP、用户名、密钥路径或密码，也不得在远端执行命令、安装软件或修改配置。

可用已有本机二进制离线检查打包、SBOM 和校验脚本：

```bash
bash scripts/package-release.sh aarch64-apple-darwin 0.1.0 target/debug/ap dist
bash scripts/generate-sbom.sh 0.1.0 dist/ap-v0.1.0-sbom.cdx.json
```

完整 bundle 校验需要四个目标压缩包都已存在：

```bash
install -m 0644 README.md LICENSE CHANGELOG.md dist/
bash scripts/sha256sums.sh 0.1.0 dist
bash scripts/verify-release-bundle.sh 0.1.0 dist
```

正式发布步骤为：更新版本与 CHANGELOG、完成上述目标环境验收、合并并确认候选提交的完整 CI（包括隔离 sshd）通过、创建并推送匹配的 `v<semver>` 标签。标签发布工作流的 quality job 本身不会重新运行 opt-in 的系统凭据库和真实服务管理器测试，因此不能用它替代发布前记录。不要从未签名的手动 dry-run artifact 创建稳定版本。
