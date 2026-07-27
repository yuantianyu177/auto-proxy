# Changelog

This project follows Semantic Versioning.

## [Unreleased]

### Changed

- GitHub Releases now publish only the four target archives and `SHA256SUMS`, with the version changelog rendered directly in the Release notes.

## [0.1.0] - 2026-07-28

### Added

- A new v2 user configuration format. Each connection directly defines the SSH `host`, `user`, `port`, optional `identity_file`, and any number of unnamed HTTP, SOCKS5, or mixed proxy mappings.
- Flat SSH authentication: an `identity_file` selects key authentication; otherwise, each explicit start or restart reads a password from `/dev/tty` without echoing it.
- A flat CLI: connect with `ap <connection>` and perform all public operations with `-f`, `-d`, `-r`, `-c`, `-l`, `-v`, and `-h`.
- A background supervisor by default and an explicit foreground mode, with no user service installation required.
- Fresh remote proxy credentials for every explicit connection start or restart, followed by remote environment-variable instructions after a successful connection.
- Consistent use of `XDG_CONFIG_HOME`, `XDG_STATE_HOME`, and `XDG_RUNTIME_DIR` on macOS and Linux, with a secure runtime fallback.
- A dedicated XDG `known_hosts` file, OpenSSH ControlMaster, a parent-process watchdog, and automatic reconnection after network failures for key-authenticated connections.
- Authenticated HTTP, SOCKS5, and mixed local gateways, plus a four-target Linux musl/macOS release pipeline with SHA-256 checksums.

### Changed

- SSH parameters now come entirely from the ap v2 configuration. ap no longer reads or reuses `~/.ssh/config`.
- Active connections use immutable configuration snapshots. Editing the configuration affects only later explicit starts or restarts.
- Explicit restarts rotate proxy credentials. Automatic reconnection of a key-authenticated connection within the same lifecycle continues to use the original configuration snapshot and credentials.
- SSH passwords remain in controlled memory only during initial authentication and are cleared immediately afterward. Password-authenticated connections terminate after disconnection and do not reconnect automatically; a later explicit start or restart prompts again.
- All terminal output, help text, errors, and runtime logs are concise and in English.
- Configuration is entirely user-authored. The program only reads, validates, and parses configuration; it never modifies or prints configuration contents.
- Stable releases publish Linux archives and ad-hoc-signed macOS archives without requiring Apple credentials. Release notes explicitly identify the macOS binaries as neither Developer ID signed nor notarized.

### Security

- Remote forwarding always listens on `127.0.0.1`, and local upstream endpoints are restricted to `127.0.0.1` or `::1`.
- Each connection lifecycle uses independent random HTTP Basic/SOCKS5 RFC 1929 credentials. Secrets never enter configuration, argv, logs, or connection listings.
- SSH passwords cannot be supplied through the CLI, environment variables, standard input, or configuration files. They are never written to disk, state, logs, OpenSSH argv, or the environment, and are delivered to trusted system OpenSSH through a single-use AskPass channel.
- SSH identity files, XDG directories, runtime sockets, `known_hosts`, and ControlMaster paths are checked for secure ownership and permissions.
- Aliases, forwards, local commands, `ProxyJump`, and `ProxyCommand` from the user's SSH configuration cannot affect ap connections.
- SSH agent forwarding, X11 forwarding, and remote commands are disabled, while host-key verification remains enabled.
- Authentication and hop-by-hop headers are removed before HTTP forwarding. SOCKS5 permits only CONNECT. Logs never record destinations, request bodies, or secrets.

### Testing

- Configuration parsing covers the v2 schema, unknown fields, key-versus-interactive-password selection, path permissions, loopback restrictions, and duplicate ports.
- CLI parsing covers flat actions, scope, mutually exclusive options, English help/version output, unrestricted connection names, and rejection of password arguments before configuration is read while hiding their values.
- Isolated sshd tests do not require remote internet access, public DNS, root login, or remote software, and cover forwarding policy, port conflicts, reconnection, and resource cleanup.
- Lifecycle tests distinguish key- and password-authenticated connections: key connections reconnect automatically, while password connections clear the password after initial authentication and terminate after disconnection.
- Protocol tests cover HTTP, CONNECT, SOCKS5, mixed mode, authentication failure, 32 concurrent connections, large transfers, and half-close propagation.
