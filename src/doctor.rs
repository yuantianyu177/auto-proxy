//! Diagnostics for one explicit connection snapshot.

use std::path::Path;
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::process::Command;
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;

use crate::config::AppPaths;
use crate::error::{ApError, Result};
use crate::gateway::{RunningGateway, start_mapping_gateway};
use crate::model::{
    ProxyMapping, ProxyProtocol, ResolvedConnection, ResolvedSshAuth, is_supported_loopback,
};
use crate::secrets::{ProxyCredential, SshPassword};
use crate::ssh::{
    HostKeyPolicy, RemoteForward, SshAuth, SshMaster, SshOptions, SshTarget, option_with_path,
    remove_loader_environment, system_ssh_executable,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const HOST_KEY_TIMEOUT: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Passed,
    Failed,
}

#[derive(Clone, Debug, Serialize)]
pub struct DoctorCheck {
    pub name: String,
    pub status: CheckStatus,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct DoctorReport {
    pub checks: Vec<DoctorCheck>,
}

impl DoctorReport {
    pub fn is_healthy(&self) -> bool {
        self.checks
            .iter()
            .all(|check| check.status == CheckStatus::Passed)
    }

    fn pass(&mut self, name: impl Into<String>, message: impl Into<String>) {
        self.checks.push(DoctorCheck {
            name: name.into(),
            status: CheckStatus::Passed,
            message: message.into(),
            code: None,
        });
    }

    fn fail(&mut self, name: impl Into<String>, error: &ApError) {
        self.checks.push(DoctorCheck {
            name: name.into(),
            status: CheckStatus::Failed,
            message: error.to_string(),
            code: Some(error.code().to_owned()),
        });
    }
}

pub async fn diagnose(
    connection: &ResolvedConnection,
    password: Option<SshPassword>,
    paths: &AppPaths,
) -> DoctorReport {
    let mut report = DoctorReport::default();
    let executable = match system_ssh_executable() {
        Ok(executable) => {
            match openssh_version(&executable).await {
                Ok(version) => report.pass("openssh", version),
                Err(error) => report.fail("openssh", &error),
            }
            Some(executable)
        }
        Err(error) => {
            report.fail("openssh", &error);
            None
        }
    };

    if let Some(executable) = executable.as_ref() {
        match ensure_host_key(executable, connection, paths).await {
            Ok(()) => report.pass("host-key", "The host key is trusted by ap"),
            Err(error) => report.fail("host-key", &error),
        }
    }

    for proxy in &connection.proxies {
        let check_name = format!("local-proxy:{}", proxy.remote_port);
        match check_local_proxy(proxy).await {
            Ok(()) => report.pass(
                check_name,
                format!("{} responds as {}", proxy.local, proxy.protocol),
            ),
            Err(error) => report.fail(check_name, &error),
        }
    }

    if executable.is_some() {
        match check_remote_forward(connection, password, paths).await {
            Ok(()) => report.pass(
                "remote-forward",
                "All remote loopback listeners were established",
            ),
            Err(error) => report.fail("remote-forward", &error),
        }
    }

    report
}

async fn openssh_version(executable: &Path) -> Result<String> {
    let mut command = Command::new(executable);
    command
        .arg("-V")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    remove_loader_environment(&mut command);
    let output = command.output().await?;
    let bytes = if output.stderr.is_empty() {
        &output.stdout
    } else {
        &output.stderr
    };
    let version = String::from_utf8_lossy(bytes).trim().to_owned();
    if !output.status.success() || !version.to_ascii_lowercase().contains("openssh") {
        return Err(ApError::coded(
            "AP_OPENSSH_UNAVAILABLE",
            "The system OpenSSH client did not return a valid version",
        ));
    }
    Ok(version)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HostKeyProbe {
    Known,
    Unknown,
}

async fn ensure_host_key(
    executable: &Path,
    connection: &ResolvedConnection,
    paths: &AppPaths,
) -> Result<()> {
    ssh_target(connection, paths).validate()?;
    paths.ensure_known_hosts()?;
    match probe_host_key(executable, connection, paths).await? {
        HostKeyProbe::Known => return Ok(()),
        HostKeyProbe::Unknown => {}
    }
    if unsafe { libc::isatty(libc::STDIN_FILENO) } != 1 {
        return Err(ApError::coded(
            "AP_SSH_HOST_KEY_UNKNOWN",
            "The host key is unknown; run diagnostics from an interactive terminal",
        ));
    }

    let mut command = host_key_command(executable, connection, paths, "ask");
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let mut child = command.spawn()?;
    if timeout(HOST_KEY_TIMEOUT, child.wait()).await.is_err() {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }

    match probe_host_key(executable, connection, paths).await? {
        HostKeyProbe::Known => Ok(()),
        HostKeyProbe::Unknown => Err(ApError::coded(
            "AP_SSH_HOST_KEY_UNKNOWN",
            "The host key was not accepted",
        )),
    }
}

async fn probe_host_key(
    executable: &Path,
    connection: &ResolvedConnection,
    paths: &AppPaths,
) -> Result<HostKeyProbe> {
    let mut command = host_key_command(executable, connection, paths, "yes");
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let output = timeout(HOST_KEY_TIMEOUT, command.output())
        .await
        .map_err(|_| ApError::coded("AP_SSH_HOST_KEY_TIMEOUT", "Host-key check timed out"))??;
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    if stderr.contains("remote host identification has changed") || stderr.contains("offending ") {
        return Err(ApError::coded(
            "AP_SSH_HOST_KEY_CHANGED",
            "The SSH host key changed; verify the server before editing ap's known_hosts file",
        ));
    }
    if stderr.contains("host key verification failed")
        || stderr.contains("no host key is known")
        || stderr.contains("not found in")
    {
        return Ok(HostKeyProbe::Unknown);
    }
    if network_error(&stderr) {
        return Err(ApError::coded(
            "AP_SSH_UNREACHABLE",
            "The SSH server is unreachable",
        ));
    }
    if stderr.contains("permission denied") {
        // Authentication failure proves that host-key verification completed.
        return Ok(HostKeyProbe::Known);
    }
    Err(ApError::coded(
        "AP_SSH_HOST_KEY_CHECK_FAILED",
        "OpenSSH exited before host-key verification could be confirmed",
    ))
}

fn host_key_command(
    executable: &Path,
    connection: &ResolvedConnection,
    paths: &AppPaths,
    strict: &str,
) -> Command {
    let ssh = &connection.ssh;
    let mut command = Command::new(executable);
    command
        .arg("-F")
        .arg("/dev/null")
        .arg("-N")
        .arg("-T")
        .arg("-p")
        .arg(ssh.port.to_string())
        .arg("-l")
        .arg(&ssh.user);
    for option in [
        "ControlMaster=no".to_owned(),
        "ControlPath=none".to_owned(),
        "ClearAllForwardings=yes".to_owned(),
        "PreferredAuthentications=none".to_owned(),
        "PubkeyAuthentication=no".to_owned(),
        "PasswordAuthentication=no".to_owned(),
        "KbdInteractiveAuthentication=no".to_owned(),
        "GSSAPIAuthentication=no".to_owned(),
        "HostbasedAuthentication=no".to_owned(),
        "NumberOfPasswordPrompts=0".to_owned(),
        format!("ConnectTimeout={}", ssh.connect_timeout_seconds),
        "ConnectionAttempts=1".to_owned(),
        "PermitLocalCommand=no".to_owned(),
        "ProxyCommand=none".to_owned(),
        "ProxyJump=none".to_owned(),
        "KnownHostsCommand=none".to_owned(),
        "GlobalKnownHostsFile=/dev/null".to_owned(),
        format!("StrictHostKeyChecking={strict}"),
        "HashKnownHosts=no".to_owned(),
    ] {
        command.arg("-o").arg(option);
    }
    command.arg("-o").arg(option_with_path(
        "UserKnownHostsFile=",
        &paths.known_hosts_file,
    ));
    command
        .arg("--")
        .arg(&ssh.host)
        .env("LC_ALL", "C")
        .env("SSH_ASKPASS_REQUIRE", "never")
        .env_remove("SSH_ASKPASS")
        .env_remove("AP_ASKPASS_MODE")
        .env_remove("AP_ASKPASS_SOCKET")
        .env_remove("AP_ASKPASS_NONCE")
        .kill_on_drop(true);
    remove_loader_environment(&mut command);
    command
}

fn network_error(stderr: &str) -> bool {
    [
        "could not resolve hostname",
        "connection refused",
        "connection timed out",
        "operation timed out",
        "no route to host",
        "network is unreachable",
    ]
    .iter()
    .any(|needle| stderr.contains(needle))
}

pub async fn check_local_proxy(proxy: &ProxyMapping) -> Result<()> {
    if !is_supported_loopback(proxy.local.ip()) {
        return Err(ApError::coded(
            "AP_NON_LOOPBACK_PROXY",
            format!("Local proxy {} is not a loopback endpoint", proxy.local),
        ));
    }
    match proxy.protocol {
        ProxyProtocol::Http => check_http(proxy.local).await,
        ProxyProtocol::Socks5 => check_socks5(proxy.local).await,
        ProxyProtocol::Mixed => {
            check_http(proxy.local).await?;
            check_socks5(proxy.local).await
        }
    }
}

async fn connect_proxy(address: std::net::SocketAddr) -> Result<TcpStream> {
    timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| {
            ApError::coded(
                "AP_PROXY_TIMEOUT",
                format!("Timed out connecting to {address}"),
            )
        })?
        .map_err(ApError::from)
}

async fn check_http(address: std::net::SocketAddr) -> Result<()> {
    let mut stream = connect_proxy(address).await?;
    stream
        .write_all(b"CONNECT 127.0.0.1:1 HTTP/1.1\r\nHost: 127.0.0.1:1\r\n\r\n")
        .await?;
    let response = timeout(HANDSHAKE_TIMEOUT, async {
        let mut line = Vec::with_capacity(64);
        let mut byte = [0_u8; 1];
        while !line.ends_with(b"\r\n") {
            stream.read_exact(&mut byte).await?;
            line.push(byte[0]);
            if line.len() > 1024 {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "HTTP status line is too long",
                ));
            }
        }
        Ok::<_, std::io::Error>(line)
    })
    .await
    .map_err(|_| ApError::coded("AP_PROXY_TIMEOUT", "HTTP proxy did not respond"))??;
    let status_line = std::str::from_utf8(&response).map_err(|_| {
        ApError::coded(
            "AP_PROXY_PROTOCOL",
            "The endpoint returned a non-UTF-8 HTTP status line",
        )
    })?;
    let mut fields = status_line.split_whitespace();
    let version = fields.next().unwrap_or_default();
    let status = fields
        .next()
        .and_then(|value| value.parse::<u16>().ok())
        .ok_or_else(|| {
            ApError::coded(
                "AP_PROXY_PROTOCOL",
                "The endpoint did not return a valid HTTP proxy status",
            )
        })?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(ApError::coded(
            "AP_PROXY_PROTOCOL",
            "The endpoint is not an HTTP proxy",
        ));
    }
    if status == 407 {
        return Err(ApError::coded(
            "AP_PROXY_AUTH_UNSUPPORTED",
            "Authenticated local HTTP proxies are not supported",
        ));
    }
    Ok(())
}

async fn check_socks5(address: std::net::SocketAddr) -> Result<()> {
    let mut stream = connect_proxy(address).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut response = [0_u8; 2];
    timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut response))
        .await
        .map_err(|_| ApError::coded("AP_PROXY_TIMEOUT", "SOCKS5 proxy did not respond"))??;
    if response != [0x05, 0x00] {
        return Err(ApError::coded(
            "AP_PROXY_PROTOCOL",
            "The endpoint is not an unauthenticated SOCKS5 proxy",
        ));
    }
    Ok(())
}

async fn check_remote_forward(
    connection: &ResolvedConnection,
    password: Option<SshPassword>,
    paths: &AppPaths,
) -> Result<()> {
    paths.ensure_runtime()?;
    paths.ensure_known_hosts()?;
    let credential = ProxyCredential::generate()?;
    let cancel = CancellationToken::new();
    let mut gateways = Vec::<RunningGateway>::new();
    for mapping in &connection.proxies {
        match start_mapping_gateway(mapping, &credential, cancel.clone()).await {
            Ok(gateway) => gateways.push(gateway),
            Err(error) => {
                shutdown_gateways(gateways).await;
                return Err(error.into());
            }
        }
    }
    let forwards = connection
        .proxies
        .iter()
        .zip(&gateways)
        .map(|(mapping, gateway)| RemoteForward {
            remote_port: mapping.remote_port,
            local_gateway: gateway.listen_addr,
        })
        .collect::<Vec<_>>();
    let target = ssh_target(connection, paths);
    let auth = ssh_auth(connection, password)?;
    let options = SshOptions::new(target, paths.doctor_control_socket(), forwards, auth)?
        .with_host_key_policy(HostKeyPolicy::Strict);
    let result = match SshMaster::start(options).await {
        Ok(master) => master.shutdown().await,
        Err(error) => Err(error),
    };
    cancel.cancel();
    shutdown_gateways(gateways).await;
    result
}

pub fn ssh_target(connection: &ResolvedConnection, paths: &AppPaths) -> SshTarget {
    SshTarget {
        host: connection.ssh.host.clone(),
        user: connection.ssh.user.clone(),
        port: connection.ssh.port,
        known_hosts: paths.known_hosts_file.clone(),
        connect_timeout: Duration::from_secs(connection.ssh.connect_timeout_seconds),
    }
}

pub fn ssh_auth(connection: &ResolvedConnection, password: Option<SshPassword>) -> Result<SshAuth> {
    match &connection.ssh.auth {
        ResolvedSshAuth::Key { identity_file } => Ok(SshAuth::Key {
            identity_file: identity_file.clone(),
        }),
        ResolvedSshAuth::Password => {
            let password = password.ok_or_else(|| {
                ApError::coded(
                    "AP_PASSWORD_REQUIRED",
                    format!(
                        "SSH password is required for connection {:?}",
                        connection.name
                    ),
                )
            })?;
            Ok(SshAuth::Password {
                provider: Arc::new(move || Ok(password.copy())),
            })
        }
    }
}

async fn shutdown_gateways(gateways: Vec<RunningGateway>) {
    for gateway in gateways {
        gateway.shutdown().await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[tokio::test]
    async fn socks_probe_accepts_an_unauthenticated_server() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0_u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
        });
        check_socks5(address).await.unwrap();
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http_probe_rejects_an_authenticated_upstream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 128];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                .await
                .unwrap();
        });
        assert_eq!(
            check_http(address).await.unwrap_err().code(),
            "AP_PROXY_AUTH_UNSUPPORTED"
        );
        server.await.unwrap();
    }

    #[test]
    fn failed_report_is_unhealthy() {
        let mut report = DoctorReport::default();
        report.fail("example", &ApError::coded("AP_TEST", "expected failure"));
        assert!(!report.is_healthy());
    }
}
