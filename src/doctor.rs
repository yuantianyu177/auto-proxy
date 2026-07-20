//! Non-invasive diagnostics for local proxies and SSH remote forwarding.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::PathBuf;
use std::process::Stdio;
use std::time::Duration;

use serde::Serialize;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, lookup_host};
use tokio::process::Command;
use tokio::time::timeout;

use crate::error::{ApError, Result};
pub use crate::model::ProxyProtocol;
use crate::ssh::{
    RemoteForward, SshAuthentication, SshMaster, SshOptions, inspect_ssh_config,
    remove_loader_environment,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Clone, Debug)]
pub struct LocalProxyCheck {
    pub name: String,
    pub address: SocketAddr,
    pub protocol: ProxyProtocol,
}

#[derive(Clone)]
pub struct RemoteForwardProbe {
    pub authentication: SshAuthentication,
    pub remote_ports: Vec<u16>,
    pub control_socket: PathBuf,
}

pub struct DoctorRequest {
    pub ssh_executable: PathBuf,
    pub ap_executable: PathBuf,
    pub host: String,
    pub local_proxies: Vec<LocalProxyCheck>,
    /// None performs only local/static checks. Some performs a real
    /// "-N -T -R" connection, without executing any remote command.
    pub remote_forward: Option<RemoteForwardProbe>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CheckStatus {
    Passed,
    Warning,
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
        !self
            .checks
            .iter()
            .any(|check| check.status == CheckStatus::Failed)
    }

    fn passed(&mut self, name: impl Into<String>, message: impl Into<String>) {
        self.checks.push(DoctorCheck {
            name: name.into(),
            status: CheckStatus::Passed,
            message: message.into(),
            code: None,
        });
    }

    fn warning(&mut self, name: impl Into<String>, message: impl Into<String>) {
        self.checks.push(DoctorCheck {
            name: name.into(),
            status: CheckStatus::Warning,
            message: message.into(),
            code: None,
        });
    }

    fn failed(&mut self, name: impl Into<String>, error: &ApError) {
        self.checks.push(DoctorCheck {
            name: name.into(),
            status: CheckStatus::Failed,
            message: error.to_string(),
            code: Some(error.code().to_owned()),
        });
    }
}

/// Run all requested checks and retain every result instead of stopping at the
/// first failure. No remote shell command is executed and no Internet/DNS
/// access is required on the remote host.
pub async fn run(request: DoctorRequest) -> DoctorReport {
    let mut report = DoctorReport::default();

    match openssh_version(&request.ssh_executable).await {
        Ok(version) => report.passed("openssh", version),
        Err(error) => report.failed("openssh", &error),
    }

    #[cfg(target_os = "macos")]
    match has_developer_id_signature(&request.ap_executable).await {
        Ok(true) => report.passed(
            "code-signature",
            "ap 使用 Developer ID Application 签名，Keychain 升级身份可稳定验证",
        ),
        Ok(false) => report.warning(
            "code-signature",
            "当前 ap 不是有效的 Developer ID Application 签名（开发构建可忽略；稳定发行版必须修复）",
        ),
        Err(error) => report.failed("code-signature", &error),
    }

    let resolved_hostname = match inspect_ssh_config(&request.ssh_executable, &request.host).await {
        Ok(inspection) => {
            report.passed(
                "ssh-config",
                "Host alias 可由 OpenSSH 解析（连接地址、用户和端口已隐藏）",
            );
            inspection.hostname
        }
        Err(error) => {
            report.failed("ssh-config", &error);
            None
        }
    };

    match ensure_host_key(&request.ssh_executable, &request.host).await {
        Ok(()) => report.passed(
            "host-key",
            "主机密钥已由 OpenSSH known_hosts 验证；此阶段未读取 SSH 密码",
        ),
        Err(error) => report.failed("host-key", &error),
    }

    for proxy in &request.local_proxies {
        let name = format!("local-proxy:{}", proxy.name);
        match check_local_proxy(proxy).await {
            Ok(()) => report.passed(
                name,
                format!("{} responds as {:?}", proxy.address, proxy.protocol),
            ),
            Err(error) => report.failed(name, &error),
        }
    }

    if let Some(probe) = request.remote_forward {
        match check_remote_forward(
            request.ssh_executable,
            request.ap_executable,
            request.host,
            probe,
            resolved_hostname.as_deref(),
        )
        .await
        {
            Ok(gateway_ports) => {
                report.passed(
                    "remote-forward",
                    "all requested remote loopback listeners were established",
                );
                match gateway_ports {
                    GatewayPortsObservation::ExposureObserved => report.warning(
                        "gateway-ports",
                        "检测到远端转发端口可通过 SSH 主机的非回环地址连接；sshd 可能启用了 GatewayPorts yes，代理认证仍然必需",
                    ),
                    GatewayPortsObservation::NoExposureObserved => report.passed(
                        "gateway-ports",
                        "最佳努力探测未发现非回环监听（防火墙或跳板网络可能限制探测，不能作为绝对保证）",
                    ),
                    GatewayPortsObservation::Indeterminate => report.warning(
                        "gateway-ports",
                        "远端监听已请求绑定 127.0.0.1，但当前网络拓扑无法执行非回环暴露探测",
                    ),
                }
            }
            Err(error) => report.failed("remote-forward", &error),
        }
    }

    report
}

async fn openssh_version(executable: &PathBuf) -> Result<String> {
    let mut command = Command::new(executable);
    command
        .arg("-V")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    remove_loader_environment(&mut command);
    let output = command.output().await?;
    // OpenSSH traditionally prints its version on stderr.
    let bytes = if output.stderr.is_empty() {
        &output.stdout
    } else {
        &output.stderr
    };
    let version = String::from_utf8_lossy(bytes).trim().to_owned();
    if !output.status.success() || !version.to_ascii_lowercase().contains("openssh") {
        return Err(ApError::coded(
            "AP_OPENSSH_UNAVAILABLE",
            if version.is_empty() {
                "OpenSSH was not found".to_owned()
            } else {
                version
            },
        ));
    }
    Ok(version)
}

#[cfg(target_os = "macos")]
async fn has_developer_id_signature(executable: &PathBuf) -> Result<bool> {
    let mut verify = Command::new("/usr/bin/codesign");
    verify
        .args(["--verify", "--strict", "--verbose=2"])
        .arg(executable)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    let verified = timeout(Duration::from_secs(10), verify.status())
        .await
        .map_err(|_| ApError::coded("AP_CODE_SIGNATURE_TIMEOUT", "codesign 验证超时"))??;
    if !verified.success() {
        return Ok(false);
    }

    let mut display = Command::new("/usr/bin/codesign");
    display
        .args(["--display", "--verbose=4"])
        .arg(executable)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    let output = timeout(Duration::from_secs(10), display.output())
        .await
        .map_err(|_| ApError::coded("AP_CODE_SIGNATURE_TIMEOUT", "codesign 信息读取超时"))??;
    let details = String::from_utf8_lossy(&output.stderr);
    Ok(output.status.success()
        && details
            .lines()
            .any(|line| line.starts_with("Authority=Developer ID Application:"))
        && details
            .lines()
            .any(|line| line == "Identifier=dev.approxy.ap"))
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HostKeyProbe {
    Known,
    Unknown,
}

async fn ensure_host_key(executable: &PathBuf, host: &str) -> Result<()> {
    match probe_host_key(executable, host).await? {
        HostKeyProbe::Known => return Ok(()),
        HostKeyProbe::Unknown => {}
    }

    // This connection can ask only for host-key confirmation. Every SSH user
    // authentication method is disabled, and no remote command/session is
    // requested. AP_ASKPASS_* is explicitly removed from the child.
    let mut command = host_key_command(executable, host, "ask");
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit());
    let mut child = command.spawn()?;
    if timeout(Duration::from_secs(20), child.wait())
        .await
        .is_err()
    {
        let _ = child.kill().await;
        let _ = child.wait().await;
    }

    match probe_host_key(executable, host).await? {
        HostKeyProbe::Known => Ok(()),
        HostKeyProbe::Unknown => Err(ApError::coded(
            "AP_SSH_HOST_KEY_NOT_CONFIRMED",
            "主机密钥尚未确认；stored-password 不会绕过首次指纹确认",
        )),
    }
}

async fn probe_host_key(executable: &PathBuf, host: &str) -> Result<HostKeyProbe> {
    let mut command = host_key_command(executable, host, "yes");
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::piped());
    let output = match timeout(Duration::from_secs(15), command.output()).await {
        Ok(output) => output?,
        Err(_) => {
            return Err(ApError::coded(
                "AP_SSH_HOST_KEY_TIMEOUT",
                "SSH 主机密钥检查超时",
            ));
        }
    };
    let stderr = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    if stderr.contains("remote host identification has changed") || stderr.contains("offending ") {
        return Err(ApError::coded(
            "AP_SSH_HOST_KEY",
            "SSH 主机密钥发生变化；请人工核验 known_hosts，而不要覆盖或跳过检查",
        ));
    }
    if stderr.contains("host key verification failed")
        || (stderr.contains("host key is known") && stderr.contains("no "))
    {
        return Ok(HostKeyProbe::Unknown);
    }
    if [
        "could not resolve hostname",
        "connection refused",
        "connection timed out",
        "operation timed out",
        "no route to host",
    ]
    .iter()
    .any(|needle| stderr.contains(needle))
    {
        return Err(ApError::coded(
            "AP_SSH_HOST_UNREACHABLE",
            "无法连接 SSH Host alias；主机密钥检查未完成",
        ));
    }
    // Reaching authentication (usually Permission denied because every method
    // is disabled) proves the host key stage completed successfully.
    Ok(HostKeyProbe::Known)
}

fn host_key_command(executable: &PathBuf, host: &str, strict: &str) -> Command {
    let mut command = Command::new(executable);
    command
        .args([
            "-N",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
            "-o",
            "ClearAllForwardings=yes",
            "-o",
            "PreferredAuthentications=none",
            "-o",
            "PubkeyAuthentication=no",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "NumberOfPasswordPrompts=0",
            "-o",
            "ConnectTimeout=10",
            "-o",
            "ConnectionAttempts=1",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            &format!("StrictHostKeyChecking={strict}"),
            "--",
            host,
        ])
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

pub(crate) async fn check_local_proxy(proxy: &LocalProxyCheck) -> Result<()> {
    if !proxy.address.ip().is_loopback() {
        return Err(ApError::coded(
            "AP_NON_LOOPBACK_PROXY",
            format!("local proxy {} is not a loopback endpoint", proxy.address),
        ));
    }
    match proxy.protocol {
        ProxyProtocol::Http => check_http(proxy.address).await,
        ProxyProtocol::Socks5 => check_socks5(proxy.address).await,
        ProxyProtocol::Mixed => {
            check_http(proxy.address).await?;
            check_socks5(proxy.address).await
        }
    }
}

async fn connect(address: SocketAddr) -> Result<TcpStream> {
    timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(address))
        .await
        .map_err(|_| {
            ApError::coded(
                "AP_PROXY_TIMEOUT",
                format!("timed out connecting to {address}"),
            )
        })?
        .map_err(ApError::from)
}

async fn check_http(address: SocketAddr) -> Result<()> {
    let mut stream = connect(address).await?;
    // A normally closed loopback port avoids requiring Internet or DNS while
    // still eliciting an HTTP proxy response.
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
            "endpoint returned a non-UTF-8 HTTP status line",
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
                "endpoint did not return a valid HTTP proxy status",
            )
        })?;
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(ApError::coded(
            "AP_PROXY_PROTOCOL",
            "endpoint did not return an HTTP proxy response",
        ));
    }
    if status == 407 {
        return Err(ApError::coded(
            "AP_PROXY_AUTH_UNSUPPORTED",
            "本机 HTTP 上游要求认证；ap v1 仅支持无认证的本机上游代理",
        ));
    }
    Ok(())
}

async fn check_socks5(address: SocketAddr) -> Result<()> {
    let mut stream = connect(address).await?;
    stream.write_all(&[0x05, 0x01, 0x00]).await?;
    let mut response = [0_u8; 2];
    timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut response))
        .await
        .map_err(|_| ApError::coded("AP_PROXY_TIMEOUT", "SOCKS5 proxy did not respond"))??;
    if response != [0x05, 0x00] {
        return Err(ApError::coded(
            "AP_PROXY_PROTOCOL",
            "endpoint is not an unauthenticated SOCKS5 proxy",
        ));
    }
    Ok(())
}

async fn check_remote_forward(
    ssh_executable: PathBuf,
    ap_executable: PathBuf,
    host: String,
    probe: RemoteForwardProbe,
    resolved_hostname: Option<&str>,
) -> Result<GatewayPortsObservation> {
    if probe.remote_ports.is_empty() {
        return Err(ApError::coded(
            "AP_DOCTOR_REMOTE_PORT",
            "remote forwarding probe has no ports",
        ));
    }
    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    let local_gateway = listener.local_addr()?;
    let accept_task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut discard = [0_u8; 1024];
                while stream.read(&mut discard).await.is_ok_and(|read| read > 0) {}
            });
        }
    });

    let remote_ports = probe.remote_ports;
    let forwards = remote_ports
        .iter()
        .copied()
        .map(|remote_port| RemoteForward {
            remote_port,
            local_gateway,
        })
        .collect();
    let options = SshOptions {
        executable: ssh_executable,
        ap_executable,
        host,
        control_socket: probe.control_socket,
        forwards,
        authentication: probe.authentication,
        startup_timeout: Duration::from_secs(20),
    };
    let result = async {
        let master = SshMaster::start(options).await?;
        let gateway_ports =
            detect_gateway_ports_exposure(resolved_hostname, remote_ports.first().copied()).await;
        master.shutdown().await?;
        Ok(gateway_ports)
    }
    .await;
    accept_task.abort();
    result
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum GatewayPortsObservation {
    ExposureObserved,
    NoExposureObserved,
    Indeterminate,
}

async fn detect_gateway_ports_exposure(
    hostname: Option<&str>,
    remote_port: Option<u16>,
) -> GatewayPortsObservation {
    let (Some(hostname), Some(remote_port)) = (hostname, remote_port) else {
        return GatewayPortsObservation::Indeterminate;
    };
    let addresses =
        match timeout(Duration::from_secs(2), lookup_host((hostname, remote_port))).await {
            Ok(Ok(addresses)) => addresses
                .filter(|address| !address.ip().is_loopback())
                .take(4)
                .collect::<Vec<_>>(),
            _ => return GatewayPortsObservation::Indeterminate,
        };
    if addresses.is_empty() {
        return GatewayPortsObservation::Indeterminate;
    }
    for address in addresses {
        if matches!(
            timeout(Duration::from_millis(500), TcpStream::connect(address)).await,
            Ok(Ok(_))
        ) {
            return GatewayPortsObservation::ExposureObserved;
        }
    }
    GatewayPortsObservation::NoExposureObserved
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn socks_probe_accepts_no_auth_server() {
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
    async fn http_probe_requires_http_status_line() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = [0_u8; 128];
            let _ = stream.read(&mut request).await.unwrap();
            stream
                .write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n")
                .await
                .unwrap();
        });
        check_http(address).await.unwrap();
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
        report.failed("example", &ApError::coded("AP_TEST", "expected failure"));
        assert!(!report.is_healthy());
    }

    #[tokio::test]
    async fn gateway_ports_probe_is_indeterminate_without_a_non_loopback_host() {
        assert_eq!(
            detect_gateway_ports_exposure(None, Some(17890)).await,
            GatewayPortsObservation::Indeterminate
        );
        assert_eq!(
            detect_gateway_ports_exposure(Some("127.0.0.1"), Some(17890)).await,
            GatewayPortsObservation::Indeterminate
        );
    }
}
