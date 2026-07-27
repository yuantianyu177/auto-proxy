# 发布 ap

正式版本由 [`.github/workflows/release.yml`](.github/workflows/release.yml) 在推送 `v<semver>` 标签时构建。标签版本必须与 `Cargo.toml` 完全一致。工作流生成以下四个目标：

- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

每个 `tar.gz` 必须精确包含八个成员：`ap`、`README.md`、`RELEASING.md`、`CHANGELOG.md`、`config.example.toml`、`LICENSE`、`LICENSE-MIT` 和 `LICENSE-APACHE`。

完整 release bundle 必须精确校验以下九个带哈希的资产：四个目标压缩包、`README.md`、`LICENSE`、`CHANGELOG.md`、`config.example.toml` 和 CycloneDX JSON SBOM。`SHA256SUMS` 本身作为第十个资产发布，但不递归包含自身哈希。`verify-release-bundle.sh` 同时验证哈希条目、SBOM 元数据、每个压缩包的精确成员集合、文件类型与权限，以及二进制架构；Linux 产物还必须是静态链接。

## v2 发布边界

发布候选必须符合当前 v2 行为，不保留旧 CLI 或旧配置兼容层：

- 用户只手写 `${XDG_CONFIG_HOME:-$HOME/.config}/ap/config.toml`，格式为 `version = 2`。
- SSH 的 `host`、`port`、`user` 和可选 `identity_file` 直接写在 ap 配置中；连接不得依赖用户 OpenSSH 配置文件。
- host key 使用 ap 自己的 `$XDG_STATE_HOME/ap/known_hosts`。
- 存在 `identity_file` 时使用显式密钥；省略时，每次显式启动或重启都从 `/dev/tty` 无回显读取 SSH 密码。
- 公开 CLI 是 `ap [OPTIONS] [CONNECTION]`；只提供 `-f/-d/-r/-c/-l/-v/-h` 及其长选项。
- CLI 没有密码选项；SSH 密码不保存，只在首次认证期间短暂驻留受控内存，并在认证结束后立即清除。
- 后台连接由按 connection 隔离的 supervisor 托管；没有登录启动或系统启动管理接口。
- 每次显式 start/restart 读取新的不可变配置快照并生成新的代理凭据；仅密钥 connection 自动重连并复用原快照和凭据，密码 connection 断线后结束。
- macOS 与 Linux 都遵循 XDG config/state/runtime 分离规则。
- 所有终端输出均为简洁英文。

`config.example.toml` 是正式发行接口的一部分。修改配置 schema、默认值或认证字段时，必须在同一候选提交中同步更新该文件、README、测试和 CHANGELOG。

## macOS Developer ID 门禁

仓库需要在名为 `release` 的 GitHub Actions Environment 中配置以下 secrets：

- `AP_MACOS_CERTIFICATE_P12_BASE64`：Developer ID Application 证书及私钥的 PKCS#12 文件，经 Base64 编码后的完整内容。
- `AP_MACOS_CERTIFICATE_PASSWORD`：PKCS#12 导出密码。
- `AP_MACOS_SIGNING_IDENTITY`：`Developer ID Application: ...` 身份名称，或对应证书 SHA-1 标识。

标签发布强制要求三项 secret 全部存在。两个 macOS Mach-O 文件均使用 hardened runtime、可信时间戳和 code-signing identifier `dev.approxy.ap` 签名；secret 缺失、身份不匹配或 `codesign --verify` 失败都会阻止发布。签名在引用 `release` Environment 且不运行 Cargo 构建脚本的全新 runner job 中完成，降低构建进程接触签名 secret 的风险。签名用于确认正式 macOS 产物的来源和完整性，identifier 不应随版本变化。

CI、pull request 和普通分支构建不会接收签名 secret。手动运行 Release workflow 只产生明确标记的未签名 dry-run artifact，不会进入 `release` Environment，也绝不创建 GitHub Release。只有指向默认分支可达提交且版本与 `Cargo.toml` 完全一致的 `v<semver>` 标签才能进入签名和发布步骤。

必须删除同名 repository/organization secrets，只在 `release` Environment 保存签名值；否则旧提交中的 workflow 仍可能读取仓库级 secret。为该 Environment 限制仅允许受保护的 `v*` 标签部署，并建议启用 reviewer。仓库还应使用 tag ruleset 禁止未授权创建、更新或删除 `v*` 标签。workflow 会在创建 draft 前及公开前再次确认标签仍指向本次构建提交，但只有不可移动的标签规则才能消除最后的竞态窗口。当前流程不执行 Apple notarization；如果分发渠道要求公证，应增加独立的 `notarytool` 门禁，不能降低现有签名检查。

安装新版本前，应先用旧版本执行 `ap -c` 关闭活动 supervisor，再替换二进制并重新显式启动所需 connection。已经运行的进程不会因磁盘文件被覆盖而自动切换版本或配置快照。

## 发布前自动检查

在候选提交上运行：

```bash
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo +1.88.0 check --locked --all-targets --all-features
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
```

同时确认 `.github/workflows/ci.yml` 通过。Release workflow 会复用完整 CI（包括 Linux、macOS、MSRV 和隔离 sshd 集成测试），而不是维护另一套较弱的重复检查。吞吐基准默认不在共享 runner 上运行；需要记录或强制性能比例时，从 CI 的手动入口启用 `run_throughput` 或 `enforce_throughput`。

发布测试必须至少覆盖：

- `ap -h` 和 `ap -v` 只展示新扁平 CLI，且输出为英文。
- 隔离 XDG 目录下的配置读取、空连接列表、关闭全部和错误输出。
- v2 配置拒绝未知字段、相对或权限不安全的 identity file，以及不安全 runtime 目录。
- OpenSSH argv 始终使用 `-F /dev/null`，并显式传入 host、user、port、known_hosts 和认证来源。
- HTTP、HTTPS CONNECT、SOCKS5 和 mixed 的认证、转发、半关闭及清理。
- supervisor 的前台/后台启动、list、单连接与全局 restart/close、崩溃清理和并发操作。
- 修改磁盘配置不影响活动连接；显式 restart 使用新快照并轮换代理凭据；密钥 connection 的网络重连不轮换凭据。
- 密钥 connection 断线后自动重连；密码在首次认证结束后立即清除，密码 connection 断线后不重连且退出。
- 日志、状态、argv、环境变量、runtime 元数据和崩溃上下文均不含 SSH 密码或代理 token。

## 目标系统验收

交叉编译成功不能代替实际运行验收。稳定版本至少保存以下记录：

- 在当前支持的 macOS 版本上验证两个架构产物的 Developer ID 签名，并在真实机器上执行 help、XDG 路径、前后台 supervisor 和清理测试。
- 在支持的 Linux 环境上验证 musl 产物可运行，并分别测试设置与未设置 `XDG_RUNTIME_DIR` 的安全路径行为。
- 使用隔离 sshd 或 VM，确保远端无默认路由、无公共 DNS、不安装 ap、只使用普通用户；分别验证显式 identity file 和 `/dev/tty` 交互密码认证，确认显式启动与重启都会重新提示密码，并确认密码连接断线后不会重连。
- 在测试用户目录放置会改变目标、命令或 forward 的 OpenSSH 用户配置，确认 ap 仍只使用 v2 中的直接 SSH 字段。
- 分别验证允许和禁止 remote forwarding、远端端口冲突、host key 首次确认与变更拒绝、网络断开和自动恢复。
- 验证测试结束后 supervisor、OpenSSH、认证网关、本机 socket 和远端监听均被清理。

真实环境记录不得包含主机地址、用户名、密钥路径、密码、代理 token 或完整 OpenSSH stderr。远端验收不得执行破坏性操作，也不得要求远端互联网。

## 离线打包验证

使用已有目标二进制生成一个压缩包：

```bash
bash scripts/package-release.sh \
  aarch64-apple-darwin \
  0.1.0 \
  target/aarch64-apple-darwin/release/ap \
  dist
```

生成 SBOM，并准备 bundle 的独立文档资产：

```bash
bash scripts/generate-sbom.sh 0.1.0 dist/ap-v0.1.0-sbom.cdx.json
install -m 0644 README.md LICENSE CHANGELOG.md config.example.toml dist/
```

完整 bundle 校验要求四个目标压缩包均已存在：

```bash
bash scripts/sha256sums.sh 0.1.0 dist
bash scripts/verify-release-bundle.sh 0.1.0 dist
```

验证脚本会拒绝 bundle 中缺失、额外、符号链接、重复或未被哈希覆盖的资产，并拒绝压缩包中缺少 `config.example.toml`、包含额外成员、目录结构错误、非普通文件、权限错误、架构错误或 Linux 动态链接的情况。

## 正式发布步骤

1. 更新 `Cargo.toml` 版本、CHANGELOG、README 和 `config.example.toml`。
2. 完成自动检查与目标系统验收，保存脱敏结果。
3. 在本机生成完整 bundle，并通过 `verify-release-bundle.sh`。
4. 合并候选提交，确认目标提交的完整 CI 通过。
5. 创建并推送与 Cargo 版本匹配的 `v<semver>` 标签。
6. 确认标签工作流中的完整 CI、四个压缩包、macOS 签名、SBOM、校验和 bundle 验证全部通过。
7. 工作流先创建不可见 draft，核对远端每个资产的 SHA-256 和标签提交后才公开；检查 GitHub Release 包含 `config.example.toml` 和所有预期资产。

不要从未签名的手动 dry-run artifact 创建稳定版本。
