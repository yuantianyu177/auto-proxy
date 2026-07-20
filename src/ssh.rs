//! System OpenSSH integration.

use std::ffi::OsString;
use std::fmt;
use std::fs;
use std::io::Write as _;
use std::net::{IpAddr, SocketAddr};
use std::os::fd::{AsRawFd, FromRawFd};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::{ExitStatus, Stdio};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;
use tokio::time::{Instant, sleep, timeout};
use zeroize::Zeroizing;

#[cfg(target_os = "macos")]
use crate::askpass::process_code_matches_current;
use crate::askpass::{AskpassBroker, PasswordProvider};
use crate::config::ensure_control_dir;
use crate::error::{ApError, Result};

const STDERR_LIMIT: usize = 64 * 1024;
const CONFIG_INSPECTION_TIMEOUT: Duration = Duration::from_secs(10);
const CONTROL_COMMAND_TIMEOUT: Duration = Duration::from_secs(5);
// OpenSSH first binds a temporary multiplex socket by appending a suffix to
// ControlPath. Keep enough headroom for that suffix instead of accepting a
// path that the final socket alone could fit. The limits leave 23 bytes on
// macOS and 19 bytes on Linux below each platform's usable sun_path capacity;
// Linux therefore does not inherit macOS's more conservative limit.
#[cfg(target_os = "macos")]
const MAX_CONTROL_PATH_BYTES: usize = 80;
#[cfg(target_os = "linux")]
const MAX_CONTROL_PATH_BYTES: usize = 88;
#[cfg(target_os = "macos")]
const MAX_UNIX_SOCKET_PATH_BYTES: usize = 103;
#[cfg(target_os = "linux")]
const MAX_UNIX_SOCKET_PATH_BYTES: usize = 107;
const MAX_ASKPASS_SOCKET_FILE_BYTES: usize = 44;
const ANONYMOUS_CONFIG_PATH: &str = "/dev/stdin";
const WATCHDOG_MODE_ENV: &str = "AP_SSH_WATCHDOG_MODE";
const WATCHDOG_MODE_VALUE: &str = "ssh-parent-v1";
const WATCHDOG_PROCESS_GROUP_ENV: &str = "AP_SSH_WATCHDOG_PROCESS_GROUP";
const WATCHDOG_LIVENESS_FD: libc::c_int = 198;
const WATCHDOG_REPORT_SIZE: usize = 5;
const WATCHDOG_TERM_GRACE: Duration = Duration::from_secs(3);

/// Resolve the system OpenSSH client to a canonical, root-owned executable in
/// a directory tree that an unprivileged user cannot replace. Stored-password
/// mode must never trust an arbitrary `ssh` found first in `PATH`, because that
/// process is the parent authorized to invoke the one-shot AskPass helper.
pub fn system_ssh_executable() -> Result<PathBuf> {
    let mut candidates = vec![PathBuf::from("/usr/bin/ssh"), PathBuf::from("/bin/ssh")];
    if let Some(path) = std::env::var_os("PATH") {
        candidates.extend(std::env::split_paths(&path).map(|directory| directory.join("ssh")));
    }

    let mut found_untrusted = false;
    let mut checked = std::collections::BTreeSet::new();
    for candidate in candidates {
        if !candidate.is_absolute() || !checked.insert(candidate.clone()) || !candidate.exists() {
            continue;
        }
        match trusted_ssh_path(&candidate) {
            Ok(path) => return Ok(path),
            Err(()) => found_untrusted = true,
        }
    }
    Err(ApError::coded(
        if found_untrusted {
            "AP_OPENSSH_UNTRUSTED"
        } else {
            "AP_OPENSSH_UNAVAILABLE"
        },
        if found_untrusted {
            "找到 ssh，但其文件或父目录可由非 root 用户替换；拒绝将系统凭据交给该进程"
        } else {
            "未找到受信任的系统 OpenSSH 客户端"
        },
    ))
}

fn trusted_ssh_path(path: &Path) -> std::result::Result<PathBuf, ()> {
    let canonical = fs::canonicalize(path).map_err(|_| ())?;
    let metadata = fs::metadata(&canonical).map_err(|_| ())?;
    if !metadata.is_file()
        || metadata.uid() != 0
        || metadata.mode() & 0o022 != 0
        || metadata.mode() & 0o111 == 0
    {
        return Err(());
    }
    for directory in canonical.ancestors().skip(1) {
        let metadata = fs::metadata(directory).map_err(|_| ())?;
        if !metadata.is_dir() || metadata.uid() != 0 || metadata.mode() & 0o022 != 0 {
            return Err(());
        }
    }
    Ok(canonical)
}

fn validate_ssh_executable(path: &Path) -> Result<PathBuf> {
    trusted_ssh_path(path).map_err(|()| {
        ApError::coded(
            "AP_OPENSSH_UNTRUSTED",
            "OpenSSH executable 必须是位于不可由普通用户替换目录中的 root-owned 文件",
        )
    })
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RemoteForward {
    pub remote_port: u16,
    pub local_gateway: SocketAddr,
}

#[derive(Clone)]
pub enum SshAuthentication {
    /// Use the user's SSH config, keys, agent, hardware token, or terminal
    /// prompt. Background callers should set `batch_mode` to avoid hanging.
    SshConfig { batch_mode: bool },
    /// Force the standard SSH password method and obtain its sole password via
    /// the one-shot AskPass bridge.
    StoredPassword { provider: PasswordProvider },
}

impl fmt::Debug for SshAuthentication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SshConfig { batch_mode } => formatter
                .debug_struct("SshConfig")
                .field("batch_mode", batch_mode)
                .finish(),
            Self::StoredPassword { .. } => formatter.write_str("StoredPassword(<redacted>)"),
        }
    }
}

#[derive(Clone, Debug)]
pub struct SshOptions {
    pub executable: PathBuf,
    pub ap_executable: PathBuf,
    pub host: String,
    pub control_socket: PathBuf,
    pub forwards: Vec<RemoteForward>,
    pub authentication: SshAuthentication,
    pub startup_timeout: Duration,
}

impl SshOptions {
    pub fn new(
        host: impl Into<String>,
        control_socket: PathBuf,
        forwards: Vec<RemoteForward>,
        authentication: SshAuthentication,
    ) -> Result<Self> {
        let ap_executable = std::env::current_exe()?;
        Ok(Self {
            executable: system_ssh_executable()?,
            ap_executable,
            host: host.into(),
            control_socket,
            forwards,
            authentication,
            startup_timeout: Duration::from_secs(15),
        })
    }

    pub fn validate(&self) -> Result<()> {
        validate_host_alias(&self.host)?;
        let control_path_bytes = self.control_socket.as_os_str().as_bytes();
        if control_path_bytes.contains(&b'%') {
            return Err(ApError::coded(
                "AP_SSH_CONTROL_PATH_TOKEN",
                "OpenSSH ControlPath 不能包含 `%`，请更换 AP_CONFIG_DIR",
            ));
        }
        if control_path_bytes.len() > MAX_CONTROL_PATH_BYTES {
            return Err(ApError::coded(
                "AP_SSH_CONTROL_PATH_TOO_LONG",
                "OpenSSH ControlPath 过长；请缩短 AP_CONFIG_DIR，或使用平台默认配置目录",
            ));
        }
        if matches!(
            self.authentication,
            SshAuthentication::StoredPassword { .. }
        ) {
            let parent = self.control_socket.parent().ok_or_else(|| {
                ApError::coded(
                    "AP_SSH_CONTROL_PATH",
                    "control socket has no parent directory",
                )
            })?;
            let askpass_path_bytes = parent
                .as_os_str()
                .as_bytes()
                .len()
                .saturating_add(1 + MAX_ASKPASS_SOCKET_FILE_BYTES);
            if askpass_path_bytes > MAX_UNIX_SOCKET_PATH_BYTES {
                return Err(ApError::coded(
                    "AP_ASKPASS_SOCKET_PATH_TOO_LONG",
                    "AskPass Unix socket 路径过长；请缩短 AP_CONFIG_DIR，或使用平台默认配置目录",
                ));
            }
        }
        if self.forwards.is_empty() {
            return Err(ApError::coded(
                "AP_SSH_NO_FORWARD",
                "at least one remote forward is required",
            ));
        }
        let mut ports = std::collections::BTreeSet::new();
        for forward in &self.forwards {
            if forward.remote_port < 1024 {
                return Err(ApError::coded(
                    "AP_INVALID_REMOTE_PORT",
                    format!("remote port {} is below 1024", forward.remote_port),
                ));
            }
            if !forward.local_gateway.ip().is_loopback() {
                return Err(ApError::coded(
                    "AP_NON_LOOPBACK_GATEWAY",
                    "local gateway must use a loopback address",
                ));
            }
            if !ports.insert(forward.remote_port) {
                return Err(ApError::coded(
                    "AP_DUPLICATE_REMOTE_PORT",
                    format!("remote port {} is duplicated", forward.remote_port),
                ));
            }
        }
        Ok(())
    }

    /// Override the executable used for the internal watchdog and AskPass
    /// entry points. Production callers normally keep the current `ap`
    /// executable selected by [`Self::new`]; integration-test harnesses must
    /// point this at the built `ap` binary (or a private mode dispatcher).
    pub fn with_ap_executable(mut self, executable: impl Into<PathBuf>) -> Self {
        self.ap_executable = executable.into();
        self
    }
}

/// Pure command construction, exposed for security regression tests.
pub fn build_master_args(options: &SshOptions) -> Result<Vec<OsString>> {
    options.validate()?;
    let mut args = vec![
        "-M".into(),
        "-S".into(),
        options.control_socket.as_os_str().to_owned(),
        "-N".into(),
        "-T".into(),
        "-o".into(),
        "ControlPersist=no".into(),
        "-o".into(),
        "ClearAllForwardings=no".into(),
        "-o".into(),
        "ForkAfterAuthentication=no".into(),
        "-o".into(),
        "ExitOnForwardFailure=yes".into(),
        "-o".into(),
        "ServerAliveInterval=30".into(),
        "-o".into(),
        "ServerAliveCountMax=3".into(),
        "-o".into(),
        "ForwardAgent=no".into(),
        "-o".into(),
        "ForwardX11=no".into(),
        "-o".into(),
        "PermitLocalCommand=no".into(),
        "-o".into(),
        "Tunnel=no".into(),
    ];
    match &options.authentication {
        SshAuthentication::SshConfig { batch_mode } => {
            args.push("-o".into());
            args.push(format!("BatchMode={}", if *batch_mode { "yes" } else { "no" }).into());
        }
        SshAuthentication::StoredPassword { .. } => {
            for option in [
                "PreferredAuthentications=password",
                "PasswordAuthentication=yes",
                "PubkeyAuthentication=no",
                "PKCS11Provider=none",
                "SecurityKeyProvider=internal",
                "ProxyCommand=none",
                "ProxyJump=none",
                "KnownHostsCommand=none",
                "CanonicalizeHostname=no",
                "KbdInteractiveAuthentication=no",
                "NumberOfPasswordPrompts=1",
                "BatchMode=no",
                "StrictHostKeyChecking=yes",
            ] {
                args.push("-o".into());
                args.push(option.into());
            }
        }
    }
    for forward in &options.forwards {
        args.push("-R".into());
        args.push(format_forward(forward).into());
    }
    args.push("--".into());
    args.push(options.host.clone().into());
    Ok(args)
}

fn format_forward(forward: &RemoteForward) -> String {
    let host = match forward.local_gateway.ip() {
        IpAddr::V4(ip) => ip.to_string(),
        IpAddr::V6(ip) => format!("[{ip}]"),
    };
    format!(
        "127.0.0.1:{}:{host}:{}",
        forward.remote_port,
        forward.local_gateway.port()
    )
}

pub(crate) fn remove_loader_environment(command: &mut Command) {
    for name in [
        "LD_PRELOAD",
        "LD_LIBRARY_PATH",
        "DYLD_INSERT_LIBRARIES",
        "DYLD_LIBRARY_PATH",
        "DYLD_FRAMEWORK_PATH",
        "BASH_ENV",
        "ENV",
        "ZDOTDIR",
    ] {
        command.env_remove(name);
    }
}

/// The SSH watchdog is an internal pre-clap entry point. It is intentionally
/// selected by a fixed environment marker rather than a public subcommand, and
/// it never receives password material in argv or its environment.
pub fn watchdog_mode_requested() -> bool {
    std::env::var_os(WATCHDOG_MODE_ENV).as_deref()
        == Some(std::ffi::OsStr::new(WATCHDOG_MODE_VALUE))
}

/// Run the internal process that is the real OpenSSH child's parent.
///
/// fd [`WATCHDOG_LIVENESS_FD`] is the read side of an anonymous socket pair.
/// The owning `ap` process retains the only peer endpoint. An abnormal parent
/// exit therefore produces EOF even for SIGKILL, at which point this process
/// terminates and reaps OpenSSH before it exits itself.
pub async fn run_ssh_watchdog_from_env() -> Result<u8> {
    if !watchdog_mode_requested() {
        return Err(ApError::coded(
            "AP_SSH_WATCHDOG_MODE",
            "SSH watchdog was invoked without its internal mode marker",
        ));
    }

    let mut arguments = std::env::args_os().skip(1);
    let executable = arguments.next().ok_or_else(|| {
        ApError::coded(
            "AP_SSH_WATCHDOG_PROTOCOL",
            "SSH watchdog did not receive an OpenSSH executable",
        )
    })?;
    let executable = validate_ssh_executable(Path::new(&executable))?;
    let arguments = arguments.collect::<Vec<_>>();
    if arguments.is_empty() {
        return Err(ApError::coded(
            "AP_SSH_WATCHDOG_PROTOCOL",
            "SSH watchdog did not receive OpenSSH arguments",
        ));
    }
    let own_process_group =
        std::env::var_os(WATCHDOG_PROCESS_GROUP_ENV).as_deref() == Some(std::ffi::OsStr::new("1"));
    let liveness = inherited_watchdog_liveness()?;

    let mut command = Command::new(executable);
    command
        .args(arguments)
        .env_remove(WATCHDOG_MODE_ENV)
        .env_remove(WATCHDOG_PROCESS_GROUP_ENV)
        .stdin(Stdio::inherit())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .kill_on_drop(true);
    remove_loader_environment(&mut command);
    configure_ssh_process_group(&mut command, own_process_group);

    let mut child = command.spawn()?;
    let Some(ssh_pid) = child.id() else {
        let _ = child.kill().await;
        let _ = child.wait().await;
        return Err(ApError::coded("AP_SSH_SPAWN", "OpenSSH process has no pid"));
    };
    if let Err(error) = write_watchdog_report(ssh_pid) {
        // The owner may have died in the narrow window between spawning SSH
        // and reading this report. Do not rely on `kill_on_drop`, which only
        // targets the leader and cannot guarantee process-group cleanup.
        let _ = terminate_ssh_child(&mut child, ssh_pid, own_process_group).await;
        return Err(error);
    }
    let status = supervise_ssh_child(child, ssh_pid, own_process_group, liveness).await?;
    Ok(status
        .code()
        .and_then(|code| u8::try_from(code).ok())
        .unwrap_or(255))
}

fn inherited_watchdog_liveness() -> Result<UnixStream> {
    // The descriptor was installed by pre_exec. Mark it close-on-exec now so
    // neither OpenSSH nor AskPass can accidentally retain the watchdog channel.
    let flags = unsafe { libc::fcntl(WATCHDOG_LIVENESS_FD, libc::F_GETFD) };
    if flags < 0 {
        return Err(ApError::coded(
            "AP_SSH_WATCHDOG_PROTOCOL",
            "SSH watchdog liveness descriptor is unavailable",
        ));
    }
    if unsafe {
        libc::fcntl(
            WATCHDOG_LIVENESS_FD,
            libc::F_SETFD,
            flags | libc::FD_CLOEXEC,
        )
    } < 0
    {
        return Err(std::io::Error::last_os_error().into());
    }
    let stream = unsafe { StdUnixStream::from_raw_fd(WATCHDOG_LIVENESS_FD) };
    stream.set_nonblocking(true)?;
    Ok(UnixStream::from_std(stream)?)
}

fn configure_ssh_process_group(command: &mut Command, own_process_group: bool) {
    if !own_process_group {
        return;
    }
    unsafe {
        command.as_std_mut().pre_exec(|| {
            if libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

fn write_watchdog_report(ssh_pid: u32) -> Result<()> {
    let mut report = [0_u8; WATCHDOG_REPORT_SIZE];
    report[0] = 1;
    report[1..].copy_from_slice(&ssh_pid.to_be_bytes());
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();
    stdout.write_all(&report)?;
    stdout.flush()?;
    Ok(())
}

async fn supervise_ssh_child(
    mut child: Child,
    ssh_pid: u32,
    own_process_group: bool,
    mut liveness: UnixStream,
) -> Result<ExitStatus> {
    tokio::select! {
        status = child.wait() => Ok(status?),
        _ = wait_for_parent_eof(&mut liveness) => {
            terminate_ssh_child(&mut child, ssh_pid, own_process_group).await
        }
    }
}

async fn wait_for_parent_eof(liveness: &mut UnixStream) {
    let mut byte = [0_u8; 1];
    loop {
        match liveness.read(&mut byte).await {
            Ok(0) | Err(_) => return,
            Ok(_) => {}
        }
    }
}

fn signal_ssh(ssh_pid: u32, own_process_group: bool, signal: nix::sys::signal::Signal) {
    let Ok(pid) = i32::try_from(ssh_pid) else {
        return;
    };
    let target = if own_process_group { -pid } else { pid };
    let _ = nix::sys::signal::kill(nix::unistd::Pid::from_raw(target), signal);
}

async fn terminate_ssh_child(
    child: &mut Child,
    ssh_pid: u32,
    own_process_group: bool,
) -> Result<ExitStatus> {
    signal_ssh(
        ssh_pid,
        own_process_group,
        nix::sys::signal::Signal::SIGTERM,
    );
    if let Ok(status) = timeout(WATCHDOG_TERM_GRACE, child.wait()).await {
        return Ok(status?);
    }

    signal_ssh(
        ssh_pid,
        own_process_group,
        nix::sys::signal::Signal::SIGKILL,
    );
    match timeout(WATCHDOG_TERM_GRACE, child.wait()).await {
        Ok(status) => Ok(status?),
        Err(_) => {
            child.kill().await?;
            Ok(child.wait().await?)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfigDirective {
    pub name: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SshConfigInspection {
    pub hostname: Option<String>,
    pub user: Option<String>,
    pub port: Option<u16>,
    pub disallowed: Vec<ConfigDirective>,
    pub credential_helpers: Vec<ConfigDirective>,
}

/// Resolve an alias with OpenSSH itself and reject settings which could add
/// unaccounted tunnels or execute local/remote commands.
pub async fn inspect_ssh_config(executable: &Path, host: &str) -> Result<SshConfigInspection> {
    let (inspection, _effective_config) = load_effective_ssh_config(executable, host).await?;
    Ok(inspection)
}

async fn load_effective_ssh_config(
    executable: &Path,
    host: &str,
) -> Result<(SshConfigInspection, Zeroizing<Vec<u8>>)> {
    validate_host_alias(host)?;
    let mut command = Command::new(executable);
    command
        .arg("-G")
        .arg("--")
        .arg(host)
        .env("LC_ALL", "C")
        .env_remove("SSH_ASKPASS")
        .env_remove("AP_ASKPASS_MODE")
        .env_remove("AP_ASKPASS_SOCKET")
        .env_remove("AP_ASKPASS_NONCE")
        .stdin(Stdio::null())
        .kill_on_drop(true);
    remove_loader_environment(&mut command);
    let output = timeout(CONFIG_INSPECTION_TIMEOUT, command.output())
        .await
        .map_err(|_| {
            ApError::coded(
                "AP_SSH_CONFIG_TIMEOUT",
                "检查 SSH Host alias 超时（请检查 Include 或 Match exec）",
            )
        })??;
    if !output.status.success() {
        return Err(ApError::coded(
            "AP_SSH_CONFIG",
            // `ssh -G` diagnostics can contain resolved host/user values,
            // Include paths, key paths, or output from config helpers. Keep
            // daemon/status surfaces bounded and direct the user to an
            // explicit local diagnostic command instead of reflecting it.
            "OpenSSH 无法解析专用 Host alias；请在本机运行 `ssh -G -- <alias>` 检查 SSH config",
        ));
    }

    let effective_config = Zeroizing::new(output.stdout);
    let text = String::from_utf8_lossy(effective_config.as_slice());
    let inspection = parse_ssh_config(&text)?;
    Ok((inspection, effective_config))
}

async fn reject_match_exec(executable: &Path, host: &str) -> Result<()> {
    // `ssh -G` evaluates Include and Match blocks but does not expose the
    // Match-exec command in its normal output. Debug output does, and this
    // preflight runs before AP_ASKPASS_* is added to the real SSH child.
    let mut command = Command::new(executable);
    command
        .args(["-vvv", "-G", "--"])
        .arg(host)
        .env("LC_ALL", "C")
        .env_remove("SSH_ASKPASS")
        .env_remove("AP_ASKPASS_MODE")
        .env_remove("AP_ASKPASS_SOCKET")
        .env_remove("AP_ASKPASS_NONCE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .kill_on_drop(true);
    remove_loader_environment(&mut command);
    let output = timeout(CONFIG_INSPECTION_TIMEOUT, command.output())
        .await
        .map_err(|_| {
            ApError::coded(
                "AP_SSH_CONFIG_TIMEOUT",
                "检查 SSH Host alias 的 Match exec 超时",
            )
        })??;
    if !output.status.success() {
        return Err(ApError::coded(
            "AP_SSH_CONFIG",
            "无法安全检查 SSH Host alias 中的 Match exec",
        ));
    }
    let debug = String::from_utf8_lossy(&output.stderr).to_ascii_lowercase();
    let has_match_exec = debug.lines().any(|line| {
        line.contains("executing command:")
            || (line.contains("checking match for '")
                && (line.contains("'exec ") || line.contains(" exec ")))
    });
    if has_match_exec {
        return Err(ApError::coded(
            "AP_SSH_STORED_PASSWORD_UNSAFE_ALIAS",
            "stored-password 不允许 SSH config 使用 Match exec；请建立不执行本地命令的专用 Host alias",
        ));
    }
    Ok(())
}

fn parse_ssh_config(text: &str) -> Result<SshConfigInspection> {
    let mut inspection = SshConfigInspection {
        hostname: None,
        user: None,
        port: None,
        disallowed: Vec::new(),
        credential_helpers: Vec::new(),
    };
    for line in text.lines() {
        let Some((name, value)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let name = name.to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "hostname" => inspection.hostname = Some(value.to_owned()),
            "user" => inspection.user = Some(value.to_owned()),
            "port" => inspection.port = value.parse().ok(),
            "localforward" | "remoteforward" | "dynamicforward" | "remotecommand"
            | "localcommand"
                if !value.eq_ignore_ascii_case("none") =>
            {
                inspection.disallowed.push(ConfigDirective {
                    name,
                    value: "<configured>".to_owned(),
                });
            }
            "proxycommand" | "proxyjump" | "knownhostscommand"
                if !value.eq_ignore_ascii_case("none") =>
            {
                inspection.credential_helpers.push(ConfigDirective {
                    name,
                    value: "<configured>".to_owned(),
                });
            }
            _ => {}
        }
    }
    if !inspection.disallowed.is_empty() {
        let names = inspection
            .disallowed
            .iter()
            .map(|directive| directive.name.as_str())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(ApError::coded(
            "AP_SSH_UNSAFE_ALIAS",
            format!(
                "SSH alias contains disallowed directives ({names}); create a dedicated Host alias"
            ),
        ));
    }
    Ok(inspection)
}

/// Send an already validated effective configuration through the anonymous,
/// read-only side of the child's stdin pipe. OpenSSH reparses that exact byte
/// stream via `-F /dev/stdin`; there is no user-writable pathname to replace
/// between validation and use. Closing the writer is required so OpenSSH sees
/// EOF and can finish parsing.
async fn write_anonymous_config(child: &mut Child, contents: &[u8]) -> Result<()> {
    let mut stdin = child
        .stdin
        .take()
        .ok_or_else(|| ApError::coded("AP_SSH_CONFIG_PIPE", "OpenSSH 的匿名配置输入不可用"))?;
    timeout(CONFIG_INSPECTION_TIMEOUT, async {
        stdin.write_all(contents).await?;
        stdin.shutdown().await
    })
    .await
    .map_err(|_| ApError::coded("AP_SSH_CONFIG_TIMEOUT", "向 OpenSSH 传递已验证配置超时"))?
    .map_err(|_| ApError::coded("AP_SSH_CONFIG_PIPE", "无法向 OpenSSH 传递已验证配置"))?;
    drop(stdin);
    Ok(())
}

fn configure_watchdog_spawn(
    command: &mut Command,
    child_liveness_fd: libc::c_int,
    parent_liveness_fd: libc::c_int,
    own_process_group: bool,
) {
    unsafe {
        command.as_std_mut().pre_exec(move || {
            if own_process_group && libc::setpgid(0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if child_liveness_fd != WATCHDOG_LIVENESS_FD
                && libc::dup2(child_liveness_fd, WATCHDOG_LIVENESS_FD) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            let flags = libc::fcntl(WATCHDOG_LIVENESS_FD, libc::F_GETFD);
            if flags < 0
                || libc::fcntl(
                    WATCHDOG_LIVENESS_FD,
                    libc::F_SETFD,
                    flags & !libc::FD_CLOEXEC,
                ) < 0
            {
                return Err(std::io::Error::last_os_error());
            }
            if parent_liveness_fd != WATCHDOG_LIVENESS_FD {
                libc::close(parent_liveness_fd);
            }
            if child_liveness_fd != WATCHDOG_LIVENESS_FD {
                libc::close(child_liveness_fd);
            }
            Ok(())
        });
    }
}

async fn read_watchdog_report(child: &mut Child, startup_timeout: Duration) -> Result<u32> {
    let mut stdout = child.stdout.take().ok_or_else(|| {
        ApError::coded(
            "AP_SSH_WATCHDOG_PROTOCOL",
            "SSH watchdog did not expose its report channel",
        )
    })?;
    let mut report = [0_u8; WATCHDOG_REPORT_SIZE];
    timeout(startup_timeout, stdout.read_exact(&mut report))
        .await
        .map_err(|_| {
            ApError::coded(
                "AP_SSH_WATCHDOG_TIMEOUT",
                "timed out waiting for the SSH watchdog",
            )
        })?
        .map_err(|_| {
            ApError::coded(
                "AP_SSH_WATCHDOG_PROTOCOL",
                "SSH watchdog exited before reporting the OpenSSH pid",
            )
        })?;
    if report[0] != 1 {
        return Err(ApError::coded(
            "AP_SSH_WATCHDOG_PROTOCOL",
            "SSH watchdog returned an invalid report",
        ));
    }
    let pid = u32::from_be_bytes(report[1..].try_into().expect("fixed report size"));
    if pid == 0 || i32::try_from(pid).is_err() {
        return Err(ApError::coded(
            "AP_SSH_WATCHDOG_PROTOCOL",
            "SSH watchdog returned an invalid OpenSSH pid",
        ));
    }
    Ok(pid)
}

async fn stop_watchdog_after_start_failure(
    child: &mut Child,
    liveness: &mut Option<StdUnixStream>,
    ssh_target: Option<(u32, bool)>,
) {
    // EOF asks the watchdog to terminate and reap OpenSSH. Only kill the
    // watchdog itself after both its TERM and KILL grace windows have elapsed.
    drop(liveness.take());
    if timeout(WATCHDOG_TERM_GRACE * 3, child.wait())
        .await
        .is_err()
    {
        if let Some((ssh_pid, own_process_group)) = ssh_target {
            signal_ssh(
                ssh_pid,
                own_process_group,
                nix::sys::signal::Signal::SIGKILL,
            );
            let _ = timeout(WATCHDOG_TERM_GRACE, child.wait()).await;
        }
        let _ = child.kill().await;
        let _ = child.wait().await;
    }
}

pub struct SshMaster {
    /// The direct child is the internal watchdog; `ssh_pid` is the actual
    /// OpenSSH process reported by that watchdog.
    child: Child,
    ssh_pid: u32,
    ssh_own_process_group: bool,
    watchdog_liveness: Option<StdUnixStream>,
    options: SshOptions,
    stderr: Arc<Mutex<BoundedStderr>>,
    stderr_task: JoinHandle<()>,
    askpass: Option<AskpassBroker>,
}

impl SshMaster {
    /// Start OpenSSH and wait until its multiplex control socket answers. With
    /// `ExitOnForwardFailure=yes`, this means all requested `-R` listeners have
    /// been established.
    pub async fn start(mut options: SshOptions) -> Result<Self> {
        options.executable = validate_ssh_executable(&options.executable)?;
        options.validate()?;
        prepare_control_parent(&options.control_socket)?;
        if options.control_socket.exists() {
            if control_check(&options).await {
                return Err(ApError::coded(
                    "AP_SSH_CONTROL_EXISTS",
                    format!(
                        "SSH control socket is already active: {}",
                        options.control_socket.display()
                    ),
                ));
            }
            remove_stale_control_socket(&options.control_socket)?;
        }

        let stored_password = matches!(
            options.authentication,
            SshAuthentication::StoredPassword { .. }
        );
        let (inspection, effective_config) = if stored_password {
            // This diagnostic preflight runs with no AP_ASKPASS_* values. The
            // effective config is then captured and supplied to the real SSH
            // process through an anonymous stdin pipe, closing the check/use
            // race on mutable Include files and Match blocks.
            reject_match_exec(&options.executable, &options.host).await?;
            let (inspection, bytes) =
                load_effective_ssh_config(&options.executable, &options.host).await?;
            (inspection, Some(bytes))
        } else {
            (
                inspect_ssh_config(&options.executable, &options.host).await?,
                None,
            )
        };
        if stored_password && !inspection.credential_helpers.is_empty() {
            let names = inspection
                .credential_helpers
                .iter()
                .map(|directive| directive.name.as_str())
                .collect::<Vec<_>>()
                .join(", ");
            return Err(ApError::coded(
                "AP_SSH_STORED_PASSWORD_UNSAFE_ALIAS",
                format!(
                    "stored-password 不允许会继承 AskPass 环境的 SSH 配置项（{names}）；请使用不含本地命令的专用 Host alias"
                ),
            ));
        }

        let mut askpass = match &options.authentication {
            SshAuthentication::StoredPassword { provider } => {
                let socket = askpass_socket_path(&options.control_socket)?;
                Some(
                    AskpassBroker::bind(
                        socket,
                        options.startup_timeout,
                        Arc::clone(provider),
                        options.executable.clone(),
                    )
                    .await?,
                )
            }
            SshAuthentication::SshConfig { .. } => None,
        };

        let mut args = build_master_args(&options)?;
        if effective_config.is_some() {
            args.insert(0, ANONYMOUS_CONFIG_PATH.into());
            args.insert(0, "-F".into());
        }
        let ssh_own_process_group = match &options.authentication {
            SshAuthentication::StoredPassword { .. } => true,
            // A background connection has no terminal to preserve. Foreground
            // ssh-config keeps the caller's process group so OpenSSH can still
            // read hardware-token and password prompts from the controlling TTY.
            SshAuthentication::SshConfig { batch_mode } => *batch_mode,
        };
        let (parent_liveness, child_liveness) = StdUnixStream::pair()?;
        let mut watchdog_liveness = Some(parent_liveness);
        #[cfg(target_os = "macos")]
        let verify_watchdog_code_identity = {
            // Compare the immutable path values, not two filesystem
            // resolutions: an attacker controlling the containing directory
            // must not be able to toggle a symlink between canonicalize calls
            // and turn this security check off. Production constructs this
            // value directly from current_exe().
            let current = std::env::current_exe()?;
            let is_self = options.ap_executable == current;
            if stored_password && !is_self {
                if let Some(broker) = askpass.take() {
                    broker.abort();
                }
                return Err(ApError::coded(
                    "AP_EXECUTABLE_IDENTITY_CHANGED",
                    "macOS stored-password 只允许由当前 ap 二进制直接托管 watchdog/AskPass",
                ));
            }
            is_self
        };
        let mut command = Command::new(&options.ap_executable);
        command
            .arg(&options.executable)
            .args(args)
            .env(WATCHDOG_MODE_ENV, WATCHDOG_MODE_VALUE)
            .env(
                WATCHDOG_PROCESS_GROUP_ENV,
                if ssh_own_process_group { "1" } else { "0" },
            )
            .env("LC_ALL", "C")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // Dropping the parent handle must leave the watchdog alive long
            // enough to observe EOF and reap its OpenSSH child.
            .kill_on_drop(false);
        remove_loader_environment(&mut command);
        match &options.authentication {
            SshAuthentication::SshConfig { batch_mode } if !batch_mode => {
                command.stdin(Stdio::inherit());
            }
            SshAuthentication::SshConfig { .. } => {
                command.stdin(Stdio::null());
            }
            SshAuthentication::StoredPassword { .. } => {
                // The pipe's read end becomes fd 0 in the child. `/dev/stdin`
                // is a root-owned fd indirection on both Linux and macOS, and
                // the inherited descriptor cannot be replaced through the
                // filesystem by another process running as this user.
                command.stdin(Stdio::piped());
                // ProxyJump internally launches another `ssh` by name. A
                // fixed system PATH prevents a user-controlled wrapper from
                // replacing that direct child of the trusted OpenSSH process.
                command.env("PATH", "/usr/bin:/bin:/usr/sbin:/sbin");
                let environment = askpass.as_ref().expect("created above").environment();
                for (name, value) in environment.variables(&options.ap_executable) {
                    command.env(name, value);
                }
            }
        }
        configure_watchdog_spawn(
            &mut command,
            child_liveness.as_raw_fd(),
            watchdog_liveness
                .as_ref()
                .expect("created above")
                .as_raw_fd(),
            ssh_own_process_group,
        );

        let mut child = command.spawn()?;
        drop(child_liveness);
        #[cfg(target_os = "macos")]
        if verify_watchdog_code_identity && !child.id().is_some_and(process_code_matches_current) {
            stop_watchdog_after_start_failure(&mut child, &mut watchdog_liveness, None).await;
            if let Some(broker) = askpass.take() {
                broker.abort();
            }
            return Err(ApError::coded(
                "AP_EXECUTABLE_IDENTITY_CHANGED",
                "ap 可执行文件的 macOS 代码签名身份在 daemon 运行期间发生变化；已拒绝启动 SSH，请重启受信任的 ap 服务",
            ));
        }
        let stderr = Arc::new(Mutex::new(BoundedStderr::default()));
        let mut stderr_pipe = child
            .stderr
            .take()
            .ok_or_else(|| ApError::coded("AP_SSH_STDERR", "failed to capture SSH stderr"))?;
        let stderr_for_task = Arc::clone(&stderr);
        let stderr_task = tokio::spawn(async move {
            let mut buffer = [0_u8; 4096];
            loop {
                match stderr_pipe.read(&mut buffer).await {
                    Ok(0) | Err(_) => break,
                    Ok(read) => stderr_for_task
                        .lock()
                        .expect("stderr buffer poisoned")
                        .push(&buffer[..read]),
                }
            }
        });

        let ssh_pid = match read_watchdog_report(&mut child, options.startup_timeout).await {
            Ok(pid) => pid,
            Err(error) => {
                stop_watchdog_after_start_failure(&mut child, &mut watchdog_liveness, None).await;
                if let Some(broker) = askpass.take() {
                    broker.abort();
                }
                stderr_task.abort();
                return Err(error);
            }
        };
        if let Some(broker) = &askpass {
            // AskPass authenticates the real trusted OpenSSH pid, never the
            // intermediate watchdog process.
            broker.set_ssh_pid(ssh_pid);
        }

        if let Some(contents) = effective_config {
            if let Err(error) = write_anonymous_config(&mut child, contents.as_slice()).await {
                stop_watchdog_after_start_failure(
                    &mut child,
                    &mut watchdog_liveness,
                    Some((ssh_pid, ssh_own_process_group)),
                )
                .await;
                if let Some(broker) = askpass.take() {
                    broker.abort();
                }
                stderr_task.abort();
                return Err(error);
            }
            // `Zeroizing` clears the parent copy here. Any unread bytes now
            // exist only in the kernel pipe buffer owned by the SSH child.
            drop(contents);
        }

        let deadline = Instant::now() + options.startup_timeout;
        loop {
            if askpass.as_ref().is_some_and(AskpassBroker::is_finished) {
                let broker = askpass.take().expect("checked above");
                if let Err(error) = broker.wait().await {
                    stop_watchdog_after_start_failure(
                        &mut child,
                        &mut watchdog_liveness,
                        Some((ssh_pid, ssh_own_process_group)),
                    )
                    .await;
                    stderr_task.abort();
                    return Err(error);
                }
            }
            if let Some(status) = child.try_wait()? {
                sleep(Duration::from_millis(20)).await;
                if askpass.as_ref().is_some_and(AskpassBroker::is_finished) {
                    let broker = askpass.take().expect("checked above");
                    // Secret-store and broker authorization failures are more
                    // precise than the generic SSH exit they trigger.
                    broker.wait().await?;
                }
                let stderr = stderr.lock().expect("stderr buffer poisoned");
                let raw = stderr.raw_text();
                return Err(ssh_exit_error(status.code(), &raw));
            }
            if control_check(&options).await {
                return Ok(Self {
                    child,
                    ssh_pid,
                    ssh_own_process_group,
                    watchdog_liveness,
                    options,
                    stderr,
                    stderr_task,
                    askpass,
                });
            }
            if Instant::now() >= deadline {
                stop_watchdog_after_start_failure(
                    &mut child,
                    &mut watchdog_liveness,
                    Some((ssh_pid, ssh_own_process_group)),
                )
                .await;
                if let Some(broker) = askpass.take() {
                    broker.abort();
                }
                stderr_task.abort();
                return Err(ApError::coded(
                    "AP_SSH_START_TIMEOUT",
                    "timed out waiting for OpenSSH ControlMaster",
                ));
            }
            sleep(Duration::from_millis(100)).await;
        }
    }

    pub fn pid(&self) -> Option<u32> {
        self.child.id().map(|_| self.ssh_pid)
    }

    pub async fn try_wait(&mut self) -> Result<Option<std::process::ExitStatus>> {
        Ok(self.child.try_wait()?)
    }

    pub async fn wait(&mut self) -> Result<std::process::ExitStatus> {
        Ok(self.child.wait().await?)
    }

    pub fn exit_error(&self, status: std::process::ExitStatus) -> ApError {
        let stderr = self.stderr.lock().expect("stderr buffer poisoned");
        let raw = stderr.raw_text();
        ssh_exit_error(status.code(), &raw)
    }

    /// Ask the master to exit, then escalate to SIGTERM and finally kill.
    pub async fn shutdown(mut self) -> Result<()> {
        let _ = control_exit(&self.options).await;
        if timeout(WATCHDOG_TERM_GRACE, self.child.wait())
            .await
            .is_err()
        {
            signal_ssh(
                self.ssh_pid,
                self.ssh_own_process_group,
                nix::sys::signal::Signal::SIGTERM,
            );
            if timeout(WATCHDOG_TERM_GRACE, self.child.wait())
                .await
                .is_err()
            {
                signal_ssh(
                    self.ssh_pid,
                    self.ssh_own_process_group,
                    nix::sys::signal::Signal::SIGKILL,
                );
                if timeout(WATCHDOG_TERM_GRACE, self.child.wait())
                    .await
                    .is_err()
                {
                    drop(self.watchdog_liveness.take());
                    self.child.kill().await?;
                    let _ = self.child.wait().await;
                }
            }
        }
        drop(self.watchdog_liveness.take());
        if let Some(broker) = self.askpass.take() {
            broker.abort();
        }
        self.stderr_task.abort();
        let _ = fs::remove_file(&self.options.control_socket);
        Ok(())
    }
}

impl Drop for SshMaster {
    fn drop(&mut self) {
        // Closing the peer endpoint is crash-safe: the independently running
        // watchdog observes EOF and terminates/reaps OpenSSH. If the watchdog
        // itself was killed by a signal, make a final best-effort group kill.
        if self
            .child
            .try_wait()
            .ok()
            .flatten()
            .is_some_and(|status| status.code().is_none())
        {
            signal_ssh(
                self.ssh_pid,
                self.ssh_own_process_group,
                nix::sys::signal::Signal::SIGKILL,
            );
        }
        drop(self.watchdog_liveness.take());
        if let Some(broker) = &self.askpass {
            broker.abort();
        }
        self.stderr_task.abort();
        let _ = fs::remove_file(&self.options.control_socket);
    }
}

async fn control_check(options: &SshOptions) -> bool {
    if !options.control_socket.exists() {
        return false;
    }
    let mut command = control_command(options, "check");
    timeout(CONTROL_COMMAND_TIMEOUT, command.status())
        .await
        .is_ok_and(|status| status.is_ok_and(|status| status.success()))
}

async fn control_exit(options: &SshOptions) -> bool {
    let mut command = control_command(options, "exit");
    timeout(CONTROL_COMMAND_TIMEOUT, command.status())
        .await
        .is_ok_and(|status| status.is_ok_and(|status| status.success()))
}

fn control_command(options: &SshOptions, operation: &str) -> Command {
    let mut command = Command::new(&options.executable);
    command
        .arg("-F")
        .arg("/dev/null")
        .arg("-S")
        .arg(&options.control_socket)
        .arg("-O")
        .arg(operation)
        .arg("--")
        .arg(&options.host)
        .env("LC_ALL", "C")
        .env_remove("SSH_ASKPASS")
        .env_remove("AP_ASKPASS_MODE")
        .env_remove("AP_ASKPASS_SOCKET")
        .env_remove("AP_ASKPASS_NONCE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    remove_loader_environment(&mut command);
    command
}

fn validate_host_alias(host: &str) -> Result<()> {
    if host.is_empty()
        || host.starts_with('-')
        || host.chars().any(|character| character.is_whitespace())
    {
        return Err(ApError::coded(
            "AP_INVALID_SSH_HOST",
            "SSH Host alias must be non-empty, contain no whitespace, and not start with '-'",
        ));
    }
    Ok(())
}

fn prepare_control_parent(control_socket: &Path) -> Result<()> {
    let parent = control_socket.parent().ok_or_else(|| {
        ApError::coded(
            "AP_SSH_CONTROL_PATH",
            "control socket has no parent directory",
        )
    })?;
    ensure_control_dir(parent)
}

fn remove_stale_control_socket(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.file_type().is_socket() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(ApError::coded(
            "AP_SSH_CONTROL_UNSAFE",
            "refusing to replace a control path that is not a user-owned Unix socket",
        ));
    }
    fs::remove_file(path)?;
    Ok(())
}

/// Reclaim a ControlMaster left behind when a previous daemon was killed.
/// Callers must hold the profile lease before invoking this function.
pub async fn stop_existing_master(
    executable: &Path,
    control_socket: &Path,
    host: &str,
) -> Result<bool> {
    validate_host_alias(host)?;
    let executable = validate_ssh_executable(executable)?;
    if !control_socket.exists() {
        return Ok(false);
    }
    let metadata = fs::symlink_metadata(control_socket)?;
    if !metadata.file_type().is_socket() || metadata.uid() != unsafe { libc::geteuid() } {
        return Err(ApError::coded(
            "AP_SSH_CONTROL_UNSAFE",
            "拒绝接管非当前用户拥有的 ControlMaster socket",
        ));
    }

    let mut check_command = Command::new(&executable);
    check_command
        .arg("-F")
        .arg("/dev/null")
        .arg("-S")
        .arg(control_socket)
        .arg("-O")
        .arg("check")
        .arg("--")
        .arg(host)
        .env("LC_ALL", "C")
        .env_remove("SSH_ASKPASS")
        .env_remove("AP_ASKPASS_MODE")
        .env_remove("AP_ASKPASS_SOCKET")
        .env_remove("AP_ASKPASS_NONCE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    remove_loader_environment(&mut check_command);
    let check = timeout(CONTROL_COMMAND_TIMEOUT, check_command.status())
        .await
        .map_err(|_| {
            ApError::coded(
                "AP_SSH_CONTROL_RECLAIM_FAILED",
                "检查遗留 OpenSSH ControlMaster 超时",
            )
        })??;
    if !check.success() {
        remove_stale_control_socket(control_socket)?;
        return Ok(false);
    }

    let mut exit_command = Command::new(&executable);
    exit_command
        .arg("-F")
        .arg("/dev/null")
        .arg("-S")
        .arg(control_socket)
        .arg("-O")
        .arg("exit")
        .arg("--")
        .arg(host)
        .env("LC_ALL", "C")
        .env_remove("SSH_ASKPASS")
        .env_remove("AP_ASKPASS_MODE")
        .env_remove("AP_ASKPASS_SOCKET")
        .env_remove("AP_ASKPASS_NONCE")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    remove_loader_environment(&mut exit_command);
    let exit = timeout(CONTROL_COMMAND_TIMEOUT, exit_command.status())
        .await
        .map_err(|_| {
            ApError::coded(
                "AP_SSH_CONTROL_RECLAIM_FAILED",
                "停止遗留 OpenSSH ControlMaster 超时",
            )
        })??;
    if !exit.success() {
        return Err(ApError::coded(
            "AP_SSH_CONTROL_RECLAIM_FAILED",
            "无法停止上一次 daemon 遗留的 OpenSSH ControlMaster",
        ));
    }
    let deadline = Instant::now() + Duration::from_secs(3);
    while control_socket.exists() && Instant::now() < deadline {
        sleep(Duration::from_millis(50)).await;
    }
    if control_socket.exists() {
        return Err(ApError::coded(
            "AP_SSH_CONTROL_RECLAIM_FAILED",
            "遗留的 OpenSSH ControlMaster 未在超时内退出",
        ));
    }
    Ok(true)
}

fn askpass_socket_path(control_socket: &Path) -> Result<PathBuf> {
    let parent = control_socket.parent().ok_or_else(|| {
        ApError::coded(
            "AP_SSH_CONTROL_PATH",
            "control socket has no parent directory",
        )
    })?;
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|error| ApError::coded("AP_RANDOM", error.to_string()))?;
    Ok(parent.join(format!(
        "askpass-{}-{}.sock",
        std::process::id(),
        u64::from_ne_bytes(random)
    )))
}

#[derive(Default)]
struct BoundedStderr {
    bytes: Vec<u8>,
}

impl BoundedStderr {
    fn push(&mut self, bytes: &[u8]) {
        if bytes.len() >= STDERR_LIMIT {
            self.bytes.clear();
            self.bytes
                .extend_from_slice(&bytes[bytes.len() - STDERR_LIMIT..]);
            return;
        }
        let excess = self
            .bytes
            .len()
            .saturating_add(bytes.len())
            .saturating_sub(STDERR_LIMIT);
        if excess > 0 {
            self.bytes.drain(..excess);
        }
        self.bytes.extend_from_slice(bytes);
    }

    #[cfg(test)]
    fn text(&self) -> String {
        sanitize_text(&self.raw_text())
    }

    fn raw_text(&self) -> String {
        String::from_utf8_lossy(&self.bytes).into_owned()
    }
}

#[cfg(test)]
fn sanitize_text(text: &str) -> String {
    text.lines()
        .map(|line| {
            let lowercase = line.to_ascii_lowercase();
            if lowercase.contains("proxy-authorization")
                || lowercase.contains("authorization: basic")
            {
                "<redacted authentication header>".to_owned()
            } else if lowercase.contains("password:") {
                "<password prompt>".to_owned()
            } else {
                line.to_owned()
            }
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn ssh_exit_error(code: Option<i32>, raw_stderr: &str) -> ApError {
    let lowercase = raw_stderr.to_ascii_lowercase();
    let error_code = if lowercase.contains("permission denied") {
        "AP_SSH_AUTH_FAILED"
    } else if lowercase.contains("controlpath too long")
        || lowercase.contains("unix_listener") && lowercase.contains("too long")
    {
        "AP_SSH_CONTROL_PATH_TOO_LONG"
    } else if lowercase.contains("remote port forwarding failed")
        || lowercase.contains("cannot listen to port")
    {
        "AP_SSH_FORWARD_FAILED"
    } else if lowercase.contains("host key verification failed")
        || lowercase.contains("remote host identification has changed")
    {
        "AP_SSH_HOST_KEY"
    } else if lowercase.contains("administratively prohibited") {
        "AP_SSH_FORWARDING_DISABLED"
    } else {
        "AP_SSH_EXITED"
    };
    // Status and daemon logs intentionally use a bounded classification
    // instead of echoing arbitrary OpenSSH diagnostics, which can contain the
    // resolved host, user name, key paths, ProxyCommand output, or credentials.
    let details = match error_code {
        "AP_SSH_AUTH_FAILED" => "SSH password authentication failed".to_owned(),
        "AP_SSH_CONTROL_PATH_TOO_LONG" => {
            "OpenSSH ControlPath exceeded the platform Unix-socket limit".to_owned()
        }
        "AP_SSH_FORWARD_FAILED" => {
            "OpenSSH could not establish every requested remote forwarding port".to_owned()
        }
        "AP_SSH_FORWARDING_DISABLED" => {
            "the SSH server administratively prohibited remote forwarding".to_owned()
        }
        "AP_SSH_HOST_KEY" => {
            "SSH host-key verification failed; run `ap doctor` and verify known_hosts manually"
                .to_owned()
        }
        _ => format!("OpenSSH exited with status {}", code.unwrap_or(-1)),
    };
    ApError::coded(error_code, details)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    const WATCHDOG_TEST_CHILD_ENV: &str = "AP_WATCHDOG_TEST_CHILD";
    const WATCHDOG_TEST_HELPER_ENV: &str = "AP_WATCHDOG_TEST_HELPER";
    const WATCHDOG_TEST_PARENT_ENV: &str = "AP_WATCHDOG_TEST_PARENT";
    const WATCHDOG_TEST_REPORT_ENV: &str = "AP_WATCHDOG_TEST_REPORT";
    const WATCHDOG_TEST_CHILD_NAME: &str = "ssh::tests::watchdog_test_child_process";
    const WATCHDOG_TEST_HELPER_NAME: &str = "ssh::tests::watchdog_test_helper_process";
    const WATCHDOG_TEST_PARENT_NAME: &str = "ssh::tests::watchdog_test_parent_process";

    fn options(authentication: SshAuthentication) -> SshOptions {
        SshOptions {
            executable: "ssh".into(),
            ap_executable: "/usr/local/bin/ap".into(),
            host: "server2".to_owned(),
            control_socket: "/tmp/ap-test/master.sock".into(),
            forwards: vec![RemoteForward {
                remote_port: 17890,
                local_gateway: "127.0.0.1:43123".parse().unwrap(),
            }],
            authentication,
            startup_timeout: Duration::from_secs(1),
        }
    }

    #[test]
    fn stored_password_arguments_are_locked_down_and_secret_free() {
        let args = build_master_args(&options(SshAuthentication::StoredPassword {
            provider: Arc::new(|| Ok(Zeroizing::new("top-secret".to_owned()))),
        }))
        .unwrap();
        let rendered = args
            .iter()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(rendered.contains("PreferredAuthentications=password"));
        assert!(rendered.contains("PasswordAuthentication=yes"));
        assert!(rendered.contains("PubkeyAuthentication=no"));
        assert!(rendered.contains("KbdInteractiveAuthentication=no"));
        assert!(rendered.contains("NumberOfPasswordPrompts=1"));
        assert!(rendered.contains("StrictHostKeyChecking=yes"));
        assert!(rendered.contains("ClearAllForwardings=no"));
        assert!(rendered.contains("ForkAfterAuthentication=no"));
        assert!(rendered.contains("Tunnel=no"));
        assert!(rendered.contains("ProxyCommand=none"));
        assert!(rendered.contains("ProxyJump=none"));
        assert!(rendered.contains("KnownHostsCommand=none"));
        assert!(!rendered.contains("top-secret"));
    }

    #[test]
    fn forward_is_bound_to_remote_loopback() {
        let args =
            build_master_args(&options(SshAuthentication::SshConfig { batch_mode: true })).unwrap();
        assert!(
            args.iter()
                .any(|arg| { arg.to_string_lossy() == "127.0.0.1:17890:127.0.0.1:43123" })
        );
    }

    #[test]
    fn invalid_alias_cannot_be_interpreted_as_an_option() {
        let mut options = options(SshAuthentication::SshConfig { batch_mode: true });
        options.host = "-oProxyCommand=bad".to_owned();
        assert!(build_master_args(&options).is_err());
    }

    #[test]
    fn rejects_control_paths_without_openssh_temporary_headroom() {
        let mut options = options(SshAuthentication::SshConfig { batch_mode: true });
        options.control_socket = PathBuf::from(format!("/{}", "x".repeat(MAX_CONTROL_PATH_BYTES)));
        assert_eq!(
            build_master_args(&options).unwrap_err().code(),
            "AP_SSH_CONTROL_PATH_TOO_LONG"
        );
    }

    #[test]
    fn control_path_limit_accepts_boundary_and_rejects_next_byte() {
        let mut options = options(SshAuthentication::SshConfig { batch_mode: true });
        options.control_socket =
            PathBuf::from(format!("/{}", "x".repeat(MAX_CONTROL_PATH_BYTES - 1)));
        assert_eq!(
            options.control_socket.as_os_str().as_bytes().len(),
            MAX_CONTROL_PATH_BYTES
        );
        assert!(build_master_args(&options).is_ok());

        options.control_socket = PathBuf::from(format!("/{}", "x".repeat(MAX_CONTROL_PATH_BYTES)));
        assert_eq!(
            options.control_socket.as_os_str().as_bytes().len(),
            MAX_CONTROL_PATH_BYTES + 1
        );
        assert_eq!(
            build_master_args(&options).unwrap_err().code(),
            "AP_SSH_CONTROL_PATH_TOO_LONG"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_accepts_a_control_path_longer_than_the_macos_limit() {
        let mut options = options(SshAuthentication::SshConfig { batch_mode: true });
        options.control_socket = PathBuf::from(format!("/{}", "x".repeat(84)));
        assert_eq!(options.control_socket.as_os_str().as_bytes().len(), 85);
        assert!(build_master_args(&options).is_ok());
    }

    #[test]
    fn rejects_openssh_tokens_in_control_path() {
        let mut options = options(SshAuthentication::SshConfig { batch_mode: true });
        options.control_socket = PathBuf::from("/tmp/ap-%h/control.sock");
        assert_eq!(
            build_master_args(&options).unwrap_err().code(),
            "AP_SSH_CONTROL_PATH_TOKEN"
        );
    }

    #[test]
    fn stored_password_reserves_space_for_askpass_socket() {
        let mut options = options(SshAuthentication::StoredPassword {
            provider: Arc::new(|| Ok(Zeroizing::new("top-secret".to_owned()))),
        });
        options.control_socket = PathBuf::from(format!("/{}/s", "x".repeat(70)));
        assert!(options.control_socket.as_os_str().as_bytes().len() <= MAX_CONTROL_PATH_BYTES);
        assert_eq!(
            build_master_args(&options).unwrap_err().code(),
            "AP_ASKPASS_SOCKET_PATH_TOO_LONG"
        );
    }

    #[test]
    fn classifies_openssh_control_path_failures() {
        let error = ssh_exit_error(
            Some(255),
            "unix_listener: path too long for Unix domain socket",
        );
        assert_eq!(error.code(), "AP_SSH_CONTROL_PATH_TOO_LONG");
        assert!(!error.to_string().contains("/Users/"));
    }

    #[test]
    fn stderr_is_bounded_and_redacted() {
        let mut buffer = BoundedStderr::default();
        buffer.push(b"Proxy-Authorization: Basic c2VjcmV0\n");
        assert!(!buffer.text().contains("c2VjcmV0"));
        buffer.push(&vec![b'x'; STDERR_LIMIT + 10]);
        assert_eq!(buffer.bytes.len(), STDERR_LIMIT);
    }

    #[test]
    fn config_with_extra_forward_is_rejected_without_echoing_it() {
        let error = parse_ssh_config(
            "hostname example.invalid\nport 22\nremotecommand none\nremoteforward 19000 10.0.0.1:1234\n",
        )
        .unwrap_err();
        assert_eq!(error.code(), "AP_SSH_UNSAFE_ALIAS");
        assert!(!error.to_string().contains("10.0.0.1"));
    }

    #[test]
    fn config_reports_local_helpers_without_echoing_commands() {
        let inspection = parse_ssh_config(
            "hostname example.invalid\nproxycommand /tmp/steal-secrets --flag\nproxyjump jump-host\nknownhostscommand none\n",
        )
        .unwrap();
        assert_eq!(inspection.credential_helpers.len(), 2);
        assert_eq!(inspection.credential_helpers[0].name, "proxycommand");
        assert_eq!(inspection.credential_helpers[1].name, "proxyjump");
        assert!(!format!("{inspection:?}").contains("steal-secrets"));
        assert!(!format!("{inspection:?}").contains("jump-host"));
    }

    #[test]
    fn resolves_a_trusted_absolute_system_ssh() {
        let executable = system_ssh_executable().unwrap();
        assert!(executable.is_absolute());
        assert_eq!(fs::metadata(&executable).unwrap().uid(), 0);
    }

    #[test]
    fn anonymous_config_path_is_not_user_replaceable() {
        let metadata = fs::symlink_metadata(ANONYMOUS_CONFIG_PATH).unwrap();
        assert_eq!(metadata.uid(), 0);
        assert_eq!(ANONYMOUS_CONFIG_PATH, "/dev/stdin");
    }

    #[tokio::test]
    async fn openssh_can_reparse_effective_config_from_anonymous_stdin() {
        let executable = system_ssh_executable().unwrap();
        let (_inspection, effective) = load_effective_ssh_config(&executable, "localhost")
            .await
            .unwrap();
        let mut child = Command::new(executable)
            .arg("-G")
            .arg("-F")
            .arg(ANONYMOUS_CONFIG_PATH)
            .arg("--")
            .arg("localhost")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        write_anonymous_config(&mut child, effective.as_slice())
            .await
            .unwrap();
        drop(effective);
        let status = child.wait().await.unwrap();
        assert!(status.success());
    }

    /// A deliberately long-lived stand-in for OpenSSH. This test is also an
    /// internal process entry point selected with `--exact` by the lifecycle
    /// tests below.
    #[test]
    fn watchdog_test_child_process() {
        if std::env::var_os(WATCHDOG_TEST_CHILD_ENV).as_deref() != Some(std::ffi::OsStr::new("1")) {
            return;
        }
        std::thread::sleep(Duration::from_secs(60));
    }

    /// A test-only watchdog process using the same liveness descriptor,
    /// process-group setup, termination escalation, and child-reaping path as
    /// the production watchdog. No shell is involved in this process tree.
    #[test]
    fn watchdog_test_helper_process() {
        if std::env::var_os(WATCHDOG_TEST_HELPER_ENV).as_deref() != Some(std::ffi::OsStr::new("1"))
        {
            return;
        }
        let report = PathBuf::from(
            std::env::var_os(WATCHDOG_TEST_REPORT_ENV).expect("watchdog test report path"),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build watchdog test runtime");
        runtime.block_on(async move {
            let liveness = inherited_watchdog_liveness().expect("inherit watchdog liveness fd");
            let mut command = Command::new(std::env::current_exe().expect("test executable"));
            command
                .arg("--exact")
                .arg(WATCHDOG_TEST_CHILD_NAME)
                .arg("--nocapture")
                .env(WATCHDOG_TEST_CHILD_ENV, "1")
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true);
            configure_ssh_process_group(&mut command, true);
            let child = command.spawn().expect("spawn watchdog test child");
            let child_pid = child.id().expect("watchdog test child pid");
            fs::write(&report, format!("{} {child_pid}\n", std::process::id()))
                .expect("write watchdog test report");
            supervise_ssh_child(child, child_pid, true, liveness)
                .await
                .expect("supervise watchdog test child");
        });
    }

    /// A disposable owning process. The outer regression test sends SIGKILL
    /// here, proving the private liveness socket works even when Rust Drop and
    /// signal handlers cannot run.
    #[test]
    fn watchdog_test_parent_process() {
        if std::env::var_os(WATCHDOG_TEST_PARENT_ENV).as_deref() != Some(std::ffi::OsStr::new("1"))
        {
            return;
        }
        let report = PathBuf::from(
            std::env::var_os(WATCHDOG_TEST_REPORT_ENV).expect("watchdog test report path"),
        );
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build watchdog owner test runtime");
        let (watchdog, liveness) = runtime.block_on(async {
            spawn_watchdog_test_helper(&report).expect("spawn watchdog test helper")
        });
        std::thread::sleep(Duration::from_secs(60));
        // Keep both RAII handles live through the sleep. The outer test kills
        // this process before these black-box uses; the socket must therefore
        // be closed by the kernel, not by an early normal Drop.
        std::hint::black_box(&watchdog);
        std::hint::black_box(&liveness);
        std::hint::black_box(&runtime);
    }

    #[tokio::test]
    async fn normal_parent_shutdown_reaps_watchdog_and_ssh_child() {
        let temporary = tempfile::tempdir().expect("create watchdog test directory");
        let report = temporary.path().join("normal.report");
        let (mut watchdog, liveness) =
            spawn_watchdog_test_helper(&report).expect("spawn watchdog test helper");
        let watchdog_pid = watchdog.id().expect("watchdog helper pid");
        let (reported_watchdog_pid, child_pid) = wait_for_watchdog_report(&report).await;
        assert_eq!(reported_watchdog_pid, watchdog_pid);
        assert!(process_exists(child_pid));

        drop(liveness);
        let status = match timeout(Duration::from_secs(10), watchdog.wait()).await {
            Ok(result) => result.expect("wait for watchdog test helper"),
            Err(_) => {
                cleanup_watchdog_test_processes(watchdog_pid, child_pid);
                let _ = watchdog.kill().await;
                let _ = watchdog.wait().await;
                panic!("watchdog did not finish normal EOF shutdown")
            }
        };
        assert!(
            status.success(),
            "watchdog helper failed after normal shutdown: {status}"
        );
        assert!(
            wait_for_process_exit(child_pid, Duration::from_secs(2)).await,
            "watchdog left its SSH child alive after normal shutdown"
        );
        assert!(!process_exists(watchdog_pid), "watchdog was not reaped");
    }

    #[test]
    fn sigkill_parent_still_terminates_and_reaps_ssh_child() {
        let temporary = tempfile::tempdir().expect("create watchdog test directory");
        let report = temporary.path().join("sigkill.report");
        let mut parent = std::process::Command::new(
            std::env::current_exe().expect("resolve watchdog test executable"),
        )
        .arg("--exact")
        .arg(WATCHDOG_TEST_PARENT_NAME)
        .arg("--nocapture")
        .env(WATCHDOG_TEST_PARENT_ENV, "1")
        .env(WATCHDOG_TEST_REPORT_ENV, &report)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn disposable watchdog owner");
        let parent_pid = parent.id();
        let (watchdog_pid, child_pid) = wait_for_watchdog_report_sync(&report);
        let watchdog_started = process_exists(watchdog_pid);
        let child_started = process_exists(child_pid);
        let processes_started = watchdog_started && child_started;
        if !processes_started {
            let _ = parent.kill();
            let _ = parent.wait();
            cleanup_watchdog_test_processes(watchdog_pid, child_pid);
        }
        assert!(
            processes_started,
            "watchdog process tree exited before SIGKILL (watchdog pid {watchdog_pid}: {watchdog_started}, child pid {child_pid}: {child_started})"
        );

        nix::sys::signal::kill(
            nix::unistd::Pid::from_raw(i32::try_from(parent_pid).expect("parent pid range")),
            nix::sys::signal::Signal::SIGKILL,
        )
        .expect("SIGKILL disposable watchdog owner");
        parent.wait().expect("reap disposable watchdog owner");

        let child_exited = wait_for_process_exit_sync(child_pid, Duration::from_secs(10));
        let watchdog_exited = wait_for_process_exit_sync(watchdog_pid, Duration::from_secs(10));
        if !child_exited || !watchdog_exited {
            cleanup_watchdog_test_processes(watchdog_pid, child_pid);
        }
        assert!(
            child_exited,
            "SSH stand-in survived SIGKILL of its owning ap process"
        );
        assert!(
            watchdog_exited,
            "orphan watchdog did not exit after cleanup"
        );
    }

    fn spawn_watchdog_test_helper(report: &Path) -> std::io::Result<(Child, StdUnixStream)> {
        let (parent_liveness, child_liveness) = StdUnixStream::pair()?;
        let mut command = Command::new(std::env::current_exe()?);
        command
            .arg("--exact")
            .arg(WATCHDOG_TEST_HELPER_NAME)
            .arg("--nocapture")
            .env(WATCHDOG_TEST_HELPER_ENV, "1")
            .env(WATCHDOG_TEST_REPORT_ENV, report)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(false);
        configure_watchdog_spawn(
            &mut command,
            child_liveness.as_raw_fd(),
            parent_liveness.as_raw_fd(),
            true,
        );
        let child = command.spawn()?;
        drop(child_liveness);
        Ok((child, parent_liveness))
    }

    async fn wait_for_watchdog_report(path: &Path) -> (u32, u32) {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(report) = read_watchdog_test_report(path) {
                return report;
            }
            assert!(
                Instant::now() < deadline,
                "watchdog test helper did not publish its process ids"
            );
            sleep(Duration::from_millis(20)).await;
        }
    }

    fn wait_for_watchdog_report_sync(path: &Path) -> (u32, u32) {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if let Some(report) = read_watchdog_test_report(path) {
                return report;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "watchdog test helper did not publish its process ids"
            );
            std::thread::sleep(Duration::from_millis(20));
        }
    }

    fn read_watchdog_test_report(path: &Path) -> Option<(u32, u32)> {
        let contents = fs::read_to_string(path).ok()?;
        let mut fields = contents.split_whitespace();
        let watchdog_pid = fields.next()?.parse().ok()?;
        let child_pid = fields.next()?.parse().ok()?;
        (fields.next().is_none() && watchdog_pid != 0 && child_pid != 0)
            .then_some((watchdog_pid, child_pid))
    }

    fn process_exists(pid: u32) -> bool {
        let Ok(pid) = i32::try_from(pid) else {
            return false;
        };
        if unsafe { libc::kill(pid, 0) } == 0 {
            return true;
        }
        std::io::Error::last_os_error().raw_os_error() != Some(libc::ESRCH)
    }

    async fn wait_for_process_exit(pid: u32, duration: Duration) -> bool {
        let deadline = Instant::now() + duration;
        while process_exists(pid) && Instant::now() < deadline {
            sleep(Duration::from_millis(20)).await;
        }
        !process_exists(pid)
    }

    fn wait_for_process_exit_sync(pid: u32, duration: Duration) -> bool {
        let deadline = std::time::Instant::now() + duration;
        while process_exists(pid) && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        !process_exists(pid)
    }

    fn cleanup_watchdog_test_processes(watchdog_pid: u32, child_pid: u32) {
        signal_ssh(child_pid, true, nix::sys::signal::Signal::SIGKILL);
        signal_ssh(watchdog_pid, true, nix::sys::signal::Signal::SIGKILL);
    }
}
