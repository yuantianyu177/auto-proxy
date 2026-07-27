# ap

`ap` shares a local HTTP, SOCKS5, or mixed proxy with an SSH-reachable remote host. It runs only on the local macOS or Linux machine and uses the system OpenSSH client to create reverse port forwards.

The remote host only needs a reachable `sshd` that allows remote TCP forwarding. It does not need `ap`, root access, Internet access, public DNS, or any configuration changes.

```text
remote application
  -> remote 127.0.0.1:<port>
  -> SSH reverse forward
  -> local ap authentication gateway
  -> local proxy
```

## Usage

### Install

Build and install from the repository:

```bash
cargo install --path .
ap -v
```

Rust 1.88 or later and the system OpenSSH client are required.

Prebuilt Linux and macOS archives are available from GitHub Releases. The macOS binaries are not signed with an Apple Developer ID or notarized, so Gatekeeper may block them or require manual approval. Verify downloaded files against the published `SHA256SUMS`.

### Configure

`ap` reads one manually maintained TOML configuration file:

```text
${XDG_CONFIG_HOME:-$HOME/.config}/ap/config.toml
```

Create it from the included example:

```bash
mkdir -p "${XDG_CONFIG_HOME:-$HOME/.config}/ap"
cp config.example.toml "${XDG_CONFIG_HOME:-$HOME/.config}/ap/config.toml"
chmod 600 "${XDG_CONFIG_HOME:-$HOME/.config}/ap/config.toml"
```

A minimal configuration using an SSH key is:

```toml
version = 2

[connections.my-server.ssh]
host = "server.example.com"
port = 22
user = "alice"
identity_file = "/absolute/path/to/id_ed25519"

[[connections.my-server.proxies]]
protocol = "mixed"
local = "127.0.0.1:7890"
remote_port = 17890
```

All supported configuration fields are:

| Field | Required | Description |
| --- | --- | --- |
| `version` | Yes | Configuration format version. It must be `2`. |
| `connections.<name>` | Yes | A connection table. The name is user-defined, must start with an ASCII letter or digit, may contain `.`, `_`, or `-`, and is limited to 64 bytes. |
| `connections.<name>.ssh.host` | Yes | Direct SSH DNS name or unbracketed IP address. SSH config aliases are not supported. |
| `connections.<name>.ssh.port` | Yes | SSH port from `1` to `65535`. |
| `connections.<name>.ssh.user` | Yes | SSH login user. It may contain ASCII letters, digits, `.`, `_`, or `-`, and is limited to 64 bytes. |
| `connections.<name>.ssh.identity_file` | No | Absolute private-key path. When omitted, `ap` prompts for an SSH password without storing it. |
| `connections.<name>.ssh.connect_timeout_seconds` | No | SSH connection timeout from `1` to `300` seconds. The default is `15`. |
| `connections.<name>.proxies` | Yes | One or more proxy mappings, each declared with `[[connections.<name>.proxies]]`. |
| `connections.<name>.proxies[].protocol` | Yes | Local proxy protocol: `http`, `socks5`, or `mixed`. |
| `connections.<name>.proxies[].local` | Yes | Local proxy endpoint. It must use `127.0.0.1` or `::1` and a nonzero port. |
| `connections.<name>.proxies[].remote_port` | Yes | Remote loopback port from `1024` to `65535`; it must be unique within the connection. |

Unknown fields are rejected. TOML paths must be absolute; `~` and environment variables are not expanded. The configuration and identity files must be regular files owned by the current user. The configuration must not be writable by group or other users, and an identity file must not be accessible by them.

See [config.example.toml](config.example.toml) for key and password examples.

### Diagnose

Check the local proxy, host key, SSH authentication, reverse-forwarding policy, and remote port availability:

```bash
ap my-server -d
```

Diagnostics do not test the remote host's Internet or DNS access and do not modify the remote host.

### Connect

Start `my-server` in the background:

```bash
ap my-server
```

Run it in the foreground instead:

```bash
ap my-server -f
```

After the tunnel is ready, `ap` prints proxy environment variables similar to:

```bash
export http_proxy='http://ap:<generated-secret>@127.0.0.1:17890'
export https_proxy='http://ap:<generated-secret>@127.0.0.1:17890'
export all_proxy='socks5h://ap:<generated-secret>@127.0.0.1:17890'
```

Copy the actual output to the remote user's shell. `ap` never changes the remote environment or files itself.

Running `ap my-server` again while `my-server` is active only prints its current status and environment variables. It does not reload the configuration or rotate credentials.

### Manage connections

```bash
ap my-server -r   # Restart my-server with the latest configuration
ap -r       # Restart all active connections
ap my-server -c   # Close my-server
ap -c       # Close all active connections
ap -l       # List active connections
ap -h       # Show help
ap -v       # Show the version
```

Configuration edits affect only later starts or explicit restarts. Every explicit start or restart creates new proxy credentials, so previously printed environment variables become invalid.

Key-authenticated connections reconnect automatically after network loss while keeping the same configuration snapshot and proxy credentials. Password-authenticated connections do not retain the SSH password; after a disconnect, run `ap my-server` again and enter the password again.
