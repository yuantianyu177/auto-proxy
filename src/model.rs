use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{ApError, Result};

pub const CONFIG_VERSION: u32 = 2;
pub const MIN_REMOTE_PORT: u16 = 1024;
pub const DEFAULT_CONNECT_TIMEOUT_SECONDS: u64 = 15;
pub const MAX_CONNECT_TIMEOUT_SECONDS: u64 = 300;

/// The complete, user-authored configuration document.
///
/// This type intentionally has no mutation helpers. Every explicit start or
/// restart reads a new document and turns one entry into an immutable
/// [`ResolvedConnection`] snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub version: u32,
    #[serde(default)]
    pub connections: BTreeMap<String, ConnectionConfig>,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.version != CONFIG_VERSION {
            return Err(ApError::coded(
                "AP_CONFIG_VERSION_UNSUPPORTED",
                format!(
                    "Configuration version {} is not supported; expected version {CONFIG_VERSION}",
                    self.version
                ),
            ));
        }

        for (name, connection) in &self.connections {
            validate_name("connection", name)?;
            connection.validate(name)?;
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectionConfig {
    pub ssh: SshConfig,
    #[serde(default)]
    pub proxies: Vec<ProxyMapping>,
}

impl ConnectionConfig {
    pub fn validate(&self, connection_name: &str) -> Result<()> {
        self.ssh.validate(connection_name)?;
        validate_proxy_mappings(connection_name, &self.proxies)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    #[serde(default = "default_connect_timeout_seconds")]
    pub connect_timeout_seconds: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub identity_file: Option<PathBuf>,
}

impl SshConfig {
    pub fn validate(&self, connection_name: &str) -> Result<()> {
        validate_ssh_host(&self.host)?;
        validate_ssh_user(&self.user)?;
        if self.port == 0 {
            return Err(invalid_config(format!(
                "Connection {connection_name:?} has an invalid SSH port"
            )));
        }
        if !(1..=MAX_CONNECT_TIMEOUT_SECONDS).contains(&self.connect_timeout_seconds) {
            return Err(invalid_config(format!(
                "Connection {connection_name:?} connect_timeout_seconds must be between 1 and {MAX_CONNECT_TIMEOUT_SECONDS}"
            )));
        }
        if let Some(identity_file) = &self.identity_file {
            validate_absolute_path("SSH identity_file", identity_file, true)?;
        }
        Ok(())
    }
}

/// Authentication mode for a resolved connection snapshot. `Password` is a
/// marker only: secret material is supplied by the runtime layer and is never
/// read from configuration.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "method", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ResolvedSshAuth {
    Key { identity_file: PathBuf },
    Password,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolvedSshConfig {
    pub host: String,
    pub port: u16,
    pub user: String,
    pub connect_timeout_seconds: u64,
    pub auth: ResolvedSshAuth,
}

/// A validated, serializable connection snapshot used by the supervisor.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ResolvedConnection {
    pub name: String,
    pub ssh: ResolvedSshConfig,
    pub proxies: Vec<ProxyMapping>,
}

impl ResolvedConnection {
    pub fn validate(&self) -> Result<()> {
        validate_name("connection", &self.name)?;
        validate_ssh_host(&self.ssh.host)?;
        validate_ssh_user(&self.ssh.user)?;
        if self.ssh.port == 0 {
            return Err(invalid_config(format!(
                "Connection {:?} has an invalid SSH port",
                self.name
            )));
        }
        if !(1..=MAX_CONNECT_TIMEOUT_SECONDS).contains(&self.ssh.connect_timeout_seconds) {
            return Err(invalid_config(format!(
                "Connection {:?} connect_timeout_seconds must be between 1 and {MAX_CONNECT_TIMEOUT_SECONDS}",
                self.name
            )));
        }
        match &self.ssh.auth {
            ResolvedSshAuth::Key { identity_file } => {
                validate_absolute_path("SSH identity_file", identity_file, true)?
            }
            ResolvedSshAuth::Password => {}
        }
        validate_proxy_mappings(&self.name, &self.proxies)
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ProxyProtocol {
    Http,
    Socks5,
    Mixed,
}

impl fmt::Display for ProxyProtocol {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Http => "http",
            Self::Socks5 => "socks5",
            Self::Mixed => "mixed",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProxyMapping {
    pub protocol: ProxyProtocol,
    pub local: SocketAddr,
    pub remote_port: u16,
}

impl ProxyMapping {
    pub fn validate(&self) -> Result<()> {
        if !is_supported_loopback(self.local.ip()) {
            return Err(invalid_config(format!(
                "Proxy mapping for remote port {} must use 127.0.0.1 or ::1 as its local endpoint",
                self.remote_port
            )));
        }
        if self.local.port() == 0 {
            return Err(invalid_config(format!(
                "Proxy mapping for remote port {} must not use local port zero",
                self.remote_port
            )));
        }
        if self.remote_port < MIN_REMOTE_PORT {
            return Err(invalid_config(format!(
                "Proxy remote port must be between {MIN_REMOTE_PORT} and 65535"
            )));
        }
        Ok(())
    }
}

fn validate_proxy_mappings(connection_name: &str, proxies: &[ProxyMapping]) -> Result<()> {
    if proxies.is_empty() {
        return Err(invalid_config(format!(
            "Connection {connection_name:?} must define at least one proxy mapping"
        )));
    }

    let mut ports = HashSet::new();
    for mapping in proxies {
        mapping.validate()?;
        if !ports.insert(mapping.remote_port) {
            return Err(invalid_config(format!(
                "Connection {connection_name:?} contains duplicate remote port {}",
                mapping.remote_port
            )));
        }
    }
    Ok(())
}

pub fn is_supported_loopback(address: IpAddr) -> bool {
    matches!(address, IpAddr::V4(ip) if ip == Ipv4Addr::LOCALHOST)
        || matches!(address, IpAddr::V6(ip) if ip == Ipv6Addr::LOCALHOST)
}

pub fn validate_name(kind: &str, value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && b"._-".contains(&byte))
        });
    if !valid {
        return Err(invalid_config(format!(
            "{kind} name must start with an ASCII letter or digit, contain only letters, digits, '.', '_' or '-', and be at most 64 bytes"
        )));
    }
    Ok(())
}

pub fn validate_ssh_host(host: &str) -> Result<()> {
    let valid = host.parse::<IpAddr>().is_ok() || valid_dns_name(host);
    if !valid {
        return Err(invalid_config(
            "SSH host must be a DNS name or unbracketed IP address, contain no user or option syntax, and be at most 255 bytes",
        ));
    }
    Ok(())
}

fn valid_dns_name(host: &str) -> bool {
    if host.is_empty()
        || host.len() > 255
        || host.starts_with('-')
        || host.contains('@')
        || !host.is_ascii()
    {
        return false;
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    !host.is_empty()
        && host.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

pub fn validate_ssh_user(user: &str) -> Result<()> {
    let valid = !user.is_empty()
        && user.len() <= 64
        && !user.starts_with('-')
        && user
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._-".contains(&byte));
    if !valid {
        return Err(invalid_config(
            "SSH user must contain only ASCII letters, digits, '.', '_' or '-' and be at most 64 bytes",
        ));
    }
    Ok(())
}

fn validate_absolute_path(label: &str, path: &std::path::Path, reject_tokens: bool) -> Result<()> {
    if !path.is_absolute() {
        return Err(invalid_config(format!("{label} must be an absolute path")));
    }
    #[cfg(unix)]
    if reject_tokens {
        use std::os::unix::ffi::OsStrExt as _;
        if path.as_os_str().as_bytes().contains(&b'%') {
            return Err(invalid_config(format!(
                "{label} must not contain OpenSSH '%' tokens"
            )));
        }
    }
    Ok(())
}

fn default_connect_timeout_seconds() -> u64 {
    DEFAULT_CONNECT_TIMEOUT_SECONDS
}

fn invalid_config(message: impl Into<String>) -> ApError {
    ApError::coded("AP_INVALID_CONFIG", message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ssh(identity_file: Option<&str>) -> SshConfig {
        SshConfig {
            host: "server.example".into(),
            port: 22,
            user: "alice".into(),
            connect_timeout_seconds: DEFAULT_CONNECT_TIMEOUT_SECONDS,
            identity_file: identity_file.map(PathBuf::from),
        }
    }

    fn mapping(local: &str, remote_port: u16) -> ProxyMapping {
        ProxyMapping {
            protocol: ProxyProtocol::Http,
            local: local.parse().unwrap(),
            remote_port,
        }
    }

    #[test]
    fn parses_key_and_password_authentication_modes() {
        let password: Config = toml::from_str(
            r#"
version = 2
[connections.dev.ssh]
host = "server.example"
port = 22
user = "alice"
[[connections.dev.proxies]]
protocol = "mixed"
local = "127.0.0.1:7890"
remote_port = 17890
"#,
        )
        .unwrap();
        password.validate().unwrap();
        assert_eq!(password.connections["dev"].ssh.identity_file, None);

        let key: Config = toml::from_str(
            r#"
version = 2
[connections.dev.ssh]
host = "server.example"
port = 22
user = "alice"
identity_file = "/keys/id_ed25519"
[[connections.dev.proxies]]
protocol = "mixed"
local = "127.0.0.1:7890"
remote_port = 17890
"#,
        )
        .unwrap();
        key.validate().unwrap();
        assert_eq!(
            key.connections["dev"].ssh.identity_file.as_deref(),
            Some(std::path::Path::new("/keys/id_ed25519"))
        );
    }

    #[test]
    fn rejects_unknown_fields() {
        let input = r#"
version = 2
unexpected = true
"#;
        assert!(toml::from_str::<Config>(input).is_err());
    }

    #[test]
    fn validates_loopback_and_remote_port() {
        assert!(mapping("127.0.0.1:7890", 17890).validate().is_ok());
        assert!(mapping("[::1]:7890", 17890).validate().is_ok());
        assert!(mapping("127.0.0.2:7890", 17890).validate().is_err());
        assert!(mapping("192.0.2.1:7890", 17890).validate().is_err());
        assert!(mapping("127.0.0.1:7890", 1023).validate().is_err());
    }

    #[test]
    fn rejects_duplicate_remote_ports() {
        let connection = ConnectionConfig {
            ssh: ssh(None),
            proxies: vec![
                mapping("127.0.0.1:7890", 17890),
                mapping("127.0.0.1:7891", 17890),
            ],
        };
        assert!(connection.validate("dev").is_err());
    }

    #[test]
    fn rejects_alias_and_option_syntax() {
        for host in ["-oProxyCommand=bad", "host name", "user@host", "[::1]", ""] {
            assert!(validate_ssh_host(host).is_err(), "accepted {host:?}");
        }
        for host in ["server.example", "192.0.2.10", "2001:db8::1"] {
            validate_ssh_host(host).unwrap();
        }
    }

    #[test]
    fn requires_an_absolute_authentication_path() {
        assert!(ssh(Some("id_ed25519")).validate("dev").is_err());
    }

    #[test]
    fn rejects_every_legacy_authentication_and_proxy_field() {
        let prefix = r#"
version = 2
[connections.dev.ssh]
host = "server.example"
port = 22
user = "alice"
"#;
        let suffix = r#"
[[connections.dev.proxies]]
protocol = "mixed"
local = "127.0.0.1:7890"
remote_port = 17890
"#;
        for legacy in [
            "method = \"agent\"\n",
            "password_file = \"/tmp/password\"\n",
            "socket = \"/tmp/agent.sock\"\n",
            "[connections.dev.ssh.auth]\nmethod = \"key\"\nidentity_file = \"/tmp/key\"\n",
        ] {
            let text = format!("{prefix}{legacy}{suffix}");
            assert!(
                toml::from_str::<Config>(&text).is_err(),
                "accepted {legacy:?}"
            );
        }

        let proxy_name = format!("{prefix}{suffix}name = \"mixed\"\n");
        assert!(toml::from_str::<Config>(&proxy_name).is_err());
    }
}
