# Releasing ap

Stable releases are built by [`.github/workflows/release.yml`](.github/workflows/release.yml) when a `v<semver>` tag is pushed. The tag version must exactly match `Cargo.toml`. The workflow builds these four targets:

- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`

Each `tar.gz` must contain exactly eight members: `ap`, `README.md`, `RELEASING.md`, `CHANGELOG.md`, `config.example.toml`, `LICENSE`, `LICENSE-MIT`, and `LICENSE-APACHE`.

The complete release bundle must verify exactly nine hashed assets: four target archives, `README.md`, `LICENSE`, `CHANGELOG.md`, `config.example.toml`, and the CycloneDX JSON SBOM. `SHA256SUMS` is published as the tenth asset but does not recursively contain its own hash. `verify-release-bundle.sh` verifies the checksum entries, SBOM metadata, exact archive membership, file types and permissions, and binary architectures. Linux artifacts must also be statically linked.

## v2 release scope

A release candidate must conform to the current v2 behavior and must not retain compatibility layers for the old CLI or configuration:

- Users manually write `${XDG_CONFIG_HOME:-$HOME/.config}/ap/config.toml` with `version = 2`.
- SSH `host`, `port`, `user`, and optional `identity_file` values are defined directly in the ap configuration. Connections must not depend on the user's OpenSSH configuration files.
- Host keys use ap's own `$XDG_STATE_HOME/ap/known_hosts` file.
- When `identity_file` is present, ap uses the specified key. Otherwise, every explicit start or restart reads an SSH password from `/dev/tty` without echoing it.
- The public CLI is `ap [OPTIONS] [CONNECTION]` and provides only `-f/-d/-r/-c/-l/-v/-h` and their long forms.
- The CLI has no password option. SSH passwords are not stored; they remain in controlled memory only during initial authentication and are cleared immediately afterward.
- Background connections are managed by per-connection supervisors. There is no login-startup or system-startup management interface.
- Every explicit start or restart reads a new immutable configuration snapshot and generates new proxy credentials. Only key-authenticated connections reconnect automatically, reusing the original snapshot and credentials. Password-authenticated connections terminate after disconnection.
- Both macOS and Linux follow the XDG separation of configuration, state, and runtime data.
- All terminal output is concise and in English.

`config.example.toml` is part of the stable release interface. Changes to the configuration schema, defaults, or authentication fields must update this file, the README, tests, and CHANGELOG in the same candidate commit.

## macOS Developer ID gate

Configure these secrets in a GitHub Actions Environment named `release`:

- `AP_MACOS_CERTIFICATE_P12_BASE64`: the complete Base64-encoded contents of the PKCS#12 file containing the Developer ID Application certificate and private key.
- `AP_MACOS_CERTIFICATE_PASSWORD`: the PKCS#12 export password.
- `AP_MACOS_SIGNING_IDENTITY`: the `Developer ID Application: ...` identity name or corresponding certificate SHA-1 fingerprint.

All three secrets are mandatory for a tagged release. Both macOS Mach-O files are signed with the hardened runtime, a trusted timestamp, and the code-signing identifier `dev.approxy.ap`. Missing secrets, identity mismatches, or a failed `codesign --verify` block the release. Signing runs in a fresh runner job that references the `release` Environment and does not run Cargo build scripts, reducing the risk that build processes can access signing secrets. The signature establishes the origin and integrity of stable macOS artifacts; the identifier must remain stable across versions.

CI, pull requests, and ordinary branch builds do not receive signing secrets. Manually running the Release workflow produces only an explicitly labeled, unsigned dry-run artifact. It does not enter the `release` Environment and never creates a GitHub Release. Only a `v<semver>` tag that points to a commit reachable from the default branch and exactly matches the version in `Cargo.toml` can enter the signing and publication steps.

Remove same-named repository and organization secrets, and store signing values only in the `release` Environment. Otherwise, workflows from older commits may still read repository-level secrets. Restrict this Environment to deployments from protected `v*` tags only, and consider requiring a reviewer. The repository should also use a tag ruleset to prevent unauthorized creation, modification, or deletion of `v*` tags. The workflow confirms again before creating the draft and before publication that the tag still points to the commit being built, but only immutable tag rules can eliminate the final race window. The current process does not perform Apple notarization. If the distribution channel requires notarization, add a separate `notarytool` gate without weakening the existing signing checks.

Before installing a new version, use the old version to run `ap -c` and stop active supervisors. Then replace the binary and explicitly restart the required connections. Running processes do not automatically switch versions or configuration snapshots when the on-disk binary is replaced.

## Automated pre-release checks

Run these commands on the candidate commit:

```bash
cargo fmt --all --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo +1.88.0 check --locked --all-targets --all-features
go run github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
```

Also confirm that `.github/workflows/ci.yml` passes. The Release workflow reuses the full CI suite, including Linux, macOS, MSRV, and isolated sshd integration tests, instead of maintaining a weaker duplicate set of checks. Throughput benchmarks do not run on shared runners by default. Use the CI workflow's manual entry point with `run_throughput` or `enforce_throughput` when throughput measurements or enforcement are required.

Release testing must cover at least:

- `ap -h` and `ap -v` expose only the new flat CLI and produce English output.
- Configuration loading, an empty connection list, closing all connections, and error output under isolated XDG directories.
- Rejection by v2 configuration parsing of unknown fields, relative or insecurely permissioned identity files, and insecure runtime directories.
- OpenSSH argv always uses `-F /dev/null` and explicitly supplies the host, user, port, `known_hosts`, and authentication source.
- Authentication, forwarding, half-close propagation, and cleanup for HTTP, HTTPS CONNECT, SOCKS5, and mixed mode.
- Foreground/background supervisor startup, listing, per-connection and global restart/close operations, crash cleanup, and concurrent operations.
- Editing the on-disk configuration does not affect active connections. An explicit restart uses a new snapshot and rotates proxy credentials, while network reconnection of a key-authenticated connection does not rotate credentials.
- Key-authenticated connections reconnect automatically after disconnection. Passwords are cleared immediately after initial authentication, and password-authenticated connections terminate without reconnecting after disconnection.
- Logs, status, argv, environment variables, runtime metadata, and crash context contain neither SSH passwords nor proxy tokens.

## Target-system acceptance

Cross-compilation does not replace testing on real target systems. A stable release must preserve records of at least these checks:

- On currently supported macOS versions, verify the Developer ID signatures of both architecture artifacts, and test help, XDG paths, foreground/background supervisors, and cleanup on real machines.
- On supported Linux environments, verify that the musl artifacts run, and test secure path handling both with and without `XDG_RUNTIME_DIR` set.
- Use an isolated sshd or VM where the remote has no default route, no public DNS, no ap installation, and only an unprivileged user. Test both an explicit identity file and interactive `/dev/tty` password authentication. Confirm that explicit starts and restarts prompt again, and that password-authenticated connections do not reconnect after disconnection.
- Place an OpenSSH user configuration in the test user's home directory that would alter the target, commands, or forwards, and confirm that ap still uses only the direct SSH fields from v2 configuration.
- Test remote forwarding when allowed and denied, remote port conflicts, first-use host-key confirmation, rejection of changed host keys, network disconnection, and automatic recovery.
- Confirm that supervisors, OpenSSH processes, authentication gateways, local sockets, and remote listeners are all cleaned up after testing.

Real-environment records must not contain host addresses, usernames, key paths, passwords, proxy tokens, or complete OpenSSH stderr. Remote acceptance testing must not perform destructive operations or require remote internet access.

## Offline package verification

Create one archive from an existing target binary:

```bash
bash scripts/package-release.sh \
  aarch64-apple-darwin \
  0.1.0 \
  target/aarch64-apple-darwin/release/ap \
  dist
```

Generate the SBOM and prepare the standalone documentation assets for the bundle:

```bash
bash scripts/generate-sbom.sh 0.1.0 dist/ap-v0.1.0-sbom.cdx.json
install -m 0644 README.md LICENSE CHANGELOG.md config.example.toml dist/
```

All four target archives must exist before verifying the complete bundle:

```bash
bash scripts/sha256sums.sh 0.1.0 dist
bash scripts/verify-release-bundle.sh 0.1.0 dist
```

The verification script rejects missing, extra, symbolic-link, duplicate, or unhashed assets in the bundle. It also rejects archives that omit `config.example.toml`, contain extra members or an invalid directory layout, include non-regular files or incorrect permissions, use the wrong architecture, or contain dynamically linked Linux binaries.

## Stable release procedure

1. Update the version in `Cargo.toml`, along with CHANGELOG, README, and `config.example.toml`.
2. Complete the automated checks and target-system acceptance testing, and retain redacted results.
3. Generate the complete bundle locally and pass `verify-release-bundle.sh`.
4. Merge the candidate commit and confirm that its full CI run passes.
5. Create and push a `v<semver>` tag matching the Cargo version.
6. Confirm that the tagged workflow passes the full CI suite, creates all four archives, signs the macOS binaries, generates the SBOM and checksums, and verifies the bundle.
7. The workflow first creates a private draft and publishes it only after verifying every remote asset's SHA-256 and the tag commit. Confirm that the GitHub Release contains `config.example.toml` and every expected asset.

Never create a stable release from an unsigned manual dry-run artifact.
