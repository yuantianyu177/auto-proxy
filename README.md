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

### Configure

`ap` reads one manually maintained configuration file:

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

[connections.dev.ssh]
host = "server.example.com"
port = 22
user = "alice"
identity_file = "/absolute/path/to/id_ed25519"

[[connections.dev.proxies]]
protocol = "mixed"
local = "127.0.0.1:7890"
remote_port = 17890
```

- `host`, `port`, and `user` are direct SSH destination values. SSH config aliases are not supported.
- `identity_file` must be an absolute path to a private key that can be used without interaction.
- Omit `identity_file` to use SSH password authentication. `ap` then reads the password without echo from `/dev/tty`; it has no password option and does not store the password.
- `protocol` can be `http`, `socks5`, or `mixed`.
- `local` must use `127.0.0.1` or `::1`.
- `remote_port` must be between 1024 and 65535 and is always bound to remote `127.0.0.1`.
- Add another `[[connections.dev.proxies]]` block to expose another local proxy.
- TOML paths must be absolute. `~` and environment variables are not expanded inside the file.

See [config.example.toml](config.example.toml) for key and password examples.

### Diagnose

Check the local proxy, host key, SSH authentication, reverse-forwarding policy, and remote port availability:

```bash
ap dev -d
```

Diagnostics do not test the remote host's Internet or DNS access and do not modify the remote host.

### Connect

Start `dev` in the background:

```bash
ap dev
```

Run it in the foreground instead:

```bash
ap dev -f
```

After the tunnel is ready, `ap` prints proxy environment variables similar to:

```bash
export http_proxy='http://ap:<generated-secret>@127.0.0.1:17890'
export https_proxy='http://ap:<generated-secret>@127.0.0.1:17890'
export all_proxy='socks5h://ap:<generated-secret>@127.0.0.1:17890'
```

Copy the actual output to the remote user's shell. `ap` never changes the remote environment or files itself.

Running `ap dev` again while `dev` is active only prints its current status and environment variables. It does not reload the configuration or rotate credentials.

### Manage connections

```bash
ap dev -r   # Restart dev with the latest configuration
ap -r       # Restart all active connections
ap dev -c   # Close dev
ap -c       # Close all active connections
ap -l       # List active connections
ap -h       # Show help
ap -v       # Show the version
```

Configuration edits affect only later starts or explicit restarts. Every explicit start or restart creates new proxy credentials, so previously printed environment variables become invalid.

Key-authenticated connections reconnect automatically after network loss while keeping the same configuration snapshot and proxy credentials. Password-authenticated connections do not retain the SSH password; after a disconnect, run `ap dev` again and enter the password again.
