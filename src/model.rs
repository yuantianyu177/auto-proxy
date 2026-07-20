use std::collections::{BTreeMap, HashSet};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::error::{ApError, Result};

pub const CONFIG_VERSION: u32 = 1;
pub const MIN_REMOTE_PORT: u16 = 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Config {
    #[serde(default = "default_config_version")]
    pub version: u32,
    #[serde(default)]
    pub servers: BTreeMap<String, ServerConfig>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            servers: BTreeMap::new(),
        }
    }
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        if self.version != CONFIG_VERSION {
            return Err(ApError::coded(
                "AP_CONFIG_VERSION_UNSUPPORTED",
                format!(
                    "配置版本 {} 不受支持，当前仅支持版本 {CONFIG_VERSION}",
                    self.version
                ),
            ));
        }

        let mut ids = HashSet::new();
        for (name, server) in &self.servers {
            validate_name("server", name)?;
            server.validate(name)?;
            if !ids.insert(server.id) {
                return Err(invalid_config(format!(
                    "server {name:?} 与另一个 server 使用了相同 UUID"
                )));
            }
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ServerConfig {
    pub id: Uuid,
    pub ssh_host: String,
    #[serde(default)]
    pub auth_mode: AuthMode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ssh_secret_ref: Option<String>,
    #[serde(default)]
    pub autostart: bool,
    #[serde(default)]
    pub proxies: Vec<ProxyMapping>,
}

impl ServerConfig {
    pub fn new(ssh_host: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            ssh_host: ssh_host.into(),
            auth_mode: AuthMode::SshConfig,
            ssh_secret_ref: None,
            autostart: false,
            proxies: Vec::new(),
        }
    }

    pub fn validate(&self, server_name: &str) -> Result<()> {
        validate_ssh_alias(&self.ssh_host)?;
        if self.id.is_nil() {
            return Err(invalid_config(format!(
                "server {server_name:?} 的 UUID 不能为 nil"
            )));
        }

        let expected_ref = ssh_secret_ref(self.id);
        match self.auth_mode {
            AuthMode::SshConfig if self.ssh_secret_ref.is_some() => {
                return Err(invalid_config(format!(
                    "server {server_name:?} 使用 ssh-config 时不能设置 ssh_secret_ref"
                )));
            }
            AuthMode::StoredPassword if self.ssh_secret_ref.as_deref() != Some(&expected_ref) => {
                return Err(invalid_config(format!(
                    "server {server_name:?} 的 ssh_secret_ref 必须为 {expected_ref:?}"
                )));
            }
            _ => {}
        }

        let mut names = HashSet::new();
        let mut ports = HashSet::new();
        for mapping in &self.proxies {
            mapping.validate()?;
            if !names.insert(mapping.name.as_str()) {
                return Err(invalid_config(format!(
                    "server {server_name:?} 中 proxy 名称 {:?} 重复",
                    mapping.name
                )));
            }
            if !ports.insert(mapping.remote_port) {
                return Err(invalid_config(format!(
                    "server {server_name:?} 中远端端口 {} 重复",
                    mapping.remote_port
                )));
            }
        }
        Ok(())
    }

    pub fn use_stored_password(&mut self) {
        self.auth_mode = AuthMode::StoredPassword;
        self.ssh_secret_ref = Some(ssh_secret_ref(self.id));
    }

    pub fn use_ssh_config(&mut self) {
        self.auth_mode = AuthMode::SshConfig;
        self.ssh_secret_ref = None;
    }
}

#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "kebab-case")]
#[value(rename_all = "kebab-case")]
pub enum AuthMode {
    #[default]
    SshConfig,
    StoredPassword,
}

impl fmt::Display for AuthMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::SshConfig => "ssh-config",
            Self::StoredPassword => "stored-password",
        })
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, ValueEnum)]
#[serde(rename_all = "lowercase")]
#[value(rename_all = "lowercase")]
pub enum ProxyProtocol {
    Http,
    Socks5,
    Mixed,
}

impl fmt::Display for ProxyProtocol {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Http => "http",
            Self::Socks5 => "socks5",
            Self::Mixed => "mixed",
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ProxyMapping {
    pub name: String,
    pub protocol: ProxyProtocol,
    pub local: SocketAddr,
    pub remote_port: u16,
}

impl ProxyMapping {
    pub fn validate(&self) -> Result<()> {
        validate_name("proxy", &self.name)?;
        if !matches!(
            self.local.ip(),
            IpAddr::V4(address) if address == Ipv4Addr::LOCALHOST
        ) && !matches!(
            self.local.ip(),
            IpAddr::V6(address) if address == Ipv6Addr::LOCALHOST
        ) {
            return Err(invalid_config(format!(
                "proxy {:?} 的本机端点必须使用 127.0.0.1 或 ::1",
                self.name
            )));
        }
        if self.local.port() == 0 {
            return Err(invalid_config(format!(
                "proxy {:?} 的本机端口不能为 0",
                self.name
            )));
        }
        if self.remote_port < MIN_REMOTE_PORT {
            return Err(invalid_config(format!(
                "proxy {:?} 的远端端口必须处于 {MIN_REMOTE_PORT}–65535",
                self.name
            )));
        }
        Ok(())
    }
}

pub fn validate_name(kind: &str, value: &str) -> Result<()> {
    let valid = !value.is_empty()
        && value.len() <= 64
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && b"._-".contains(&byte))
        });
    if !valid {
        return Err(invalid_config(format!(
            "{kind} 名称必须以 ASCII 字母或数字开头，且仅包含字母、数字、点、下划线或连字符（最长 64 字节）"
        )));
    }
    Ok(())
}

pub fn validate_ssh_alias(alias: &str) -> Result<()> {
    let valid = !alias.is_empty()
        && alias.len() <= 255
        && alias.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric() || (index > 0 && b"._-".contains(&byte))
        });
    if !valid {
        return Err(invalid_config(
            "SSH Host 必须是专用的安全别名：以 ASCII 字母或数字开头，且仅包含字母、数字、点、下划线或连字符",
        ));
    }
    Ok(())
}

pub fn ssh_secret_ref(id: Uuid) -> String {
    format!("ap:ssh-password:{id}")
}

fn default_config_version() -> u32 {
    CONFIG_VERSION
}

fn invalid_config(message: impl Into<String>) -> ApError {
    ApError::coded("AP_INVALID_CONFIG", message)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping(name: &str, local: &str, remote_port: u16) -> ProxyMapping {
        ProxyMapping {
            name: name.into(),
            protocol: ProxyProtocol::Http,
            local: local.parse().unwrap(),
            remote_port,
        }
    }

    #[test]
    fn validates_loopback_and_remote_port() {
        assert!(mapping("web", "127.0.0.1:7890", 17890).validate().is_ok());
        assert!(mapping("web", "[::1]:7890", 17890).validate().is_ok());
        assert!(mapping("web", "127.0.0.2:7890", 17890).validate().is_err());
        assert!(mapping("web", "192.0.2.1:7890", 17890).validate().is_err());
        assert!(mapping("web", "127.0.0.1:7890", 1023).validate().is_err());
    }

    #[test]
    fn rejects_duplicate_mapping_names_and_ports() {
        let mut server = ServerConfig::new("server2");
        server.proxies = vec![
            mapping("web", "127.0.0.1:7890", 17890),
            mapping("web", "127.0.0.1:7891", 17891),
        ];
        assert!(server.validate("dev").is_err());

        server.proxies[1].name = "socks".into();
        server.proxies[1].remote_port = 17890;
        assert!(server.validate("dev").is_err());
    }

    #[test]
    fn stored_password_reference_is_stable() {
        let mut server = ServerConfig::new("server2");
        let id = server.id;
        server.use_stored_password();
        assert_eq!(
            server.ssh_secret_ref.as_deref(),
            Some(ssh_secret_ref(id).as_str())
        );
        assert!(server.validate("dev").is_ok());
        server.use_ssh_config();
        assert!(server.ssh_secret_ref.is_none());
    }

    #[test]
    fn rejects_option_like_or_pattern_aliases() {
        for alias in ["-oProxyCommand=bad", "host name", "host*", ""] {
            assert!(validate_ssh_alias(alias).is_err(), "accepted {alias:?}");
        }
        assert!(validate_ssh_alias("server2").is_ok());
    }
}
