use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fs2::FileExt;
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::{Mutex, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{Instant, MissedTickBehavior, interval, sleep, timeout};
use tokio_util::sync::CancellationToken;
use zeroize::Zeroizing;

use crate::config::{AppPaths, ConfigStore, open_lock_file};
use crate::doctor::{LocalProxyCheck, check_local_proxy};
use crate::error::{ApError, Result};
use crate::gateway::{RunningGateway, start_mapping_gateway};
use crate::model::{AuthMode, ServerConfig};
use crate::secrets::{ProxyCredential, ProxySecretStore, SshPasswordStore};
use crate::ssh::{
    RemoteForward, SshAuthentication, SshMaster, SshOptions, stop_existing_master,
    system_ssh_executable,
};
use crate::transaction::{self, PendingProfile, RecoveryFailure, RecoveryOutcome};
use uuid::Uuid;

pub const IPC_VERSION: u16 = 2;
const MAX_FRAME_SIZE: usize = 1024 * 1024;
const MAX_PROFILE_LOG_BYTES: u64 = 1024 * 1024;
const IPC_IO_TIMEOUT: Duration = Duration::from_secs(10);
// A normal profile stop may spend up to five seconds asking ControlMaster to
// exit and then three three-second escalation windows in the watchdog. Leave
// room for a request queued behind one other serialized profile operation.
const IPC_PROFILE_OPERATION_TIMEOUT: Duration = Duration::from_secs(60);
const IPC_RELOAD_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const MAX_IPC_CONNECTIONS: usize = 64;
#[cfg(not(test))]
const TRANSACTION_RECOVERY_INTERVAL: Duration = Duration::from_secs(5);
#[cfg(test)]
const TRANSACTION_RECOVERY_INTERVAL: Duration = Duration::from_millis(50);

struct ProfileLease {
    _file: File,
}

pub struct ProfileMutationGuard {
    _lease: ProfileLease,
}

impl ProfileLease {
    fn acquire(paths: &AppPaths, server_id: Uuid) -> Result<Self> {
        paths.ensure()?;
        let file = open_lock_file(&profile_lock_path(paths, server_id))?;
        file.try_lock_exclusive().map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                ApError::coded(
                    "AP_PROFILE_RUNNING",
                    "此 profile 已由另一个 ap 前台连接或 daemon 管理",
                )
            } else {
                ApError::coded(
                    "AP_PROFILE_LOCK_FAILED",
                    format!("无法取得 profile 运行锁：{error}"),
                )
            }
        })?;
        Ok(Self { _file: file })
    }
}

fn profile_lock_path(paths: &AppPaths, server_id: Uuid) -> PathBuf {
    paths.runtime_dir.join(format!("profile-{server_id}.lock"))
}

/// Check the process-independent advisory lease used by foreground and daemon
/// connections. A stale lock file is harmless: the kernel releases its lock
/// when the owning process exits.
pub fn profile_is_running(paths: &AppPaths, server_id: Uuid) -> Result<bool> {
    paths.ensure()?;
    let file = open_lock_file(&profile_lock_path(paths, server_id))?;
    match file.try_lock_exclusive() {
        Ok(()) => {
            FileExt::unlock(&file)?;
            Ok(false)
        }
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(true),
        Err(error) => Err(ApError::coded(
            "AP_PROFILE_LOCK_FAILED",
            format!("无法检查 profile 运行锁：{error}"),
        )),
    }
}

pub fn lock_profile_for_mutation(
    paths: &AppPaths,
    server_id: Uuid,
) -> Result<ProfileMutationGuard> {
    Ok(ProfileMutationGuard {
        _lease: ProfileLease::acquire(paths, server_id)?,
    })
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DaemonRequest {
    pub version: u16,
    pub command: DaemonCommand,
}

impl DaemonRequest {
    pub fn new(command: DaemonCommand) -> Self {
        Self {
            version: IPC_VERSION,
            command,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "command", rename_all = "kebab-case")]
pub enum DaemonCommand {
    Up {
        server: String,
        expected_server_id: Uuid,
    },
    Down {
        server: String,
        expected_server_id: Uuid,
    },
    Restart {
        server: String,
        expected_server_id: Uuid,
    },
    Status {
        server: Option<String>,
    },
    Reload,
    Shutdown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonReply {
    pub version: u16,
    pub ok: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub statuses: Vec<ProfileStatus>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

impl DaemonReply {
    pub fn success(statuses: Vec<ProfileStatus>) -> Self {
        Self {
            version: IPC_VERSION,
            ok: true,
            statuses,
            code: None,
            message: None,
        }
    }

    pub fn error(code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            version: IPC_VERSION,
            ok: false,
            statuses: Vec::new(),
            code: Some(code.into()),
            message: Some(message.into()),
        }
    }

    pub fn into_result(self) -> Result<Self> {
        if self.ok {
            return Ok(self);
        }
        let code = match self.code.as_deref() {
            Some("AP_PROFILE_FOREGROUND_RUNNING") => "AP_PROFILE_FOREGROUND_RUNNING",
            Some("AP_PROFILE_IDENTITY_CHANGED") => "AP_PROFILE_IDENTITY_CHANGED",
            _ => "AP_DAEMON_ERROR",
        };
        Err(ApError::coded(
            code,
            format!(
                "{}: {}",
                self.code.as_deref().unwrap_or("AP_DAEMON_ERROR"),
                self.message.as_deref().unwrap_or("daemon 请求失败")
            ),
        ))
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ProfilePhase {
    Stopped,
    Connecting,
    Connected,
    Degraded,
    WaitingForSecretStore,
    Reconnecting,
    Failed,
}

impl std::fmt::Display for ProfilePhase {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let value = match self {
            Self::Stopped => "stopped",
            Self::Connecting => "connecting",
            Self::Connected => "connected",
            Self::Degraded => "degraded",
            Self::WaitingForSecretStore => "waiting-for-secret-store",
            Self::Reconnecting => "reconnecting",
            Self::Failed => "failed",
        };
        formatter.write_str(value)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileStatus {
    pub server: String,
    pub phase: ProfilePhase,
    pub autostart: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_pid: Option<u32>,
    pub retry_count: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(default)]
    pub mappings: Vec<MappingStatus>,
}

impl ProfileStatus {
    pub fn stopped(server: impl Into<String>, autostart: bool) -> Self {
        Self {
            server: server.into(),
            phase: ProfilePhase::Stopped,
            autostart,
            ssh_pid: None,
            retry_count: 0,
            last_error: None,
            mappings: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MappingStatus {
    pub name: String,
    pub active_connections: u64,
    pub bytes_from_remote: u64,
    pub bytes_to_remote: u64,
    pub auth_failures: u64,
    pub upstream_errors: u64,
}

pub struct IpcServer {
    listener: UnixListener,
    path: PathBuf,
    owner_uid: u32,
    _daemon_lease: File,
}

impl IpcServer {
    pub fn bind(path: impl Into<PathBuf>) -> Result<Self> {
        let path = path.into();
        let parent = path
            .parent()
            .ok_or_else(|| ApError::coded("AP_INVALID_PATH", "daemon socket 路径无父目录"))?;
        fs::create_dir_all(parent)?;
        #[cfg(unix)]
        fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;

        let lease_path = parent.join("daemon.lock");
        let daemon_lease = open_lock_file(&lease_path)?;
        daemon_lease.try_lock_exclusive().map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                ApError::coded("AP_DAEMON_ALREADY_RUNNING", "另一个 ap daemon 已持有运行锁")
            } else {
                ApError::coded(
                    "AP_DAEMON_LOCK_FAILED",
                    format!("无法取得 daemon 运行锁：{error}"),
                )
            }
        })?;

        if path.exists() {
            match std::os::unix::net::UnixStream::connect(&path) {
                Ok(_) => {
                    return Err(ApError::coded(
                        "AP_DAEMON_ALREADY_RUNNING",
                        format!("daemon 已在 {} 监听", path.display()),
                    ));
                }
                Err(_) => fs::remove_file(&path)?,
            }
        }
        let listener = UnixListener::bind(&path)?;
        #[cfg(unix)]
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600))?;
        let owner_uid = unsafe { libc::geteuid() };
        Ok(Self {
            listener,
            path,
            owner_uid,
            _daemon_lease: daemon_lease,
        })
    }

    pub async fn accept(&self) -> Result<UnixStream> {
        let (stream, _) = self.listener.accept().await?;
        let credential = stream.peer_cred()?;
        if credential.uid() != self.owner_uid {
            return Err(ApError::coded(
                "AP_DAEMON_PEER_REJECTED",
                "拒绝来自其他 UID 的 daemon 请求",
            ));
        }
        Ok(stream)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for IpcServer {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

pub async fn request(socket: &Path, request: &DaemonRequest) -> Result<DaemonReply> {
    let mut stream = timeout(IPC_IO_TIMEOUT, UnixStream::connect(socket))
        .await
        .map_err(|_| {
            ApError::coded(
                "AP_DAEMON_UNAVAILABLE",
                "连接 daemon 超时（请确认用户级服务正在运行）",
            )
        })?
        .map_err(|error| {
            ApError::coded(
                "AP_DAEMON_UNAVAILABLE",
                format!("无法连接 daemon（请先执行 `ap service install`）: {error}"),
            )
        })?;
    timeout(IPC_IO_TIMEOUT, write_frame(&mut stream, request))
        .await
        .map_err(|_| ApError::coded("AP_IPC_TIMEOUT", "向 daemon 写入请求超时"))??;
    let response: DaemonReply = timeout(
        ipc_response_timeout(&request.command),
        read_frame(&mut stream),
    )
    .await
    .map_err(|_| ApError::coded("AP_IPC_TIMEOUT", "等待 daemon 响应超时"))??;
    if response.version != IPC_VERSION {
        return Err(ApError::coded(
            "AP_IPC_VERSION_MISMATCH",
            format!(
                "daemon IPC 版本为 {}，CLI 需要 {IPC_VERSION}",
                response.version
            ),
        ));
    }
    response.into_result()
}

fn ipc_response_timeout(command: &DaemonCommand) -> Duration {
    match command {
        DaemonCommand::Up { .. }
        | DaemonCommand::Down { .. }
        | DaemonCommand::Restart { .. }
        | DaemonCommand::Shutdown => IPC_PROFILE_OPERATION_TIMEOUT,
        DaemonCommand::Reload => IPC_RELOAD_TIMEOUT,
        DaemonCommand::Status { .. } => IPC_IO_TIMEOUT,
    }
}

pub async fn read_request(stream: &mut UnixStream) -> Result<DaemonRequest> {
    let request: DaemonRequest = read_frame(stream).await?;
    if request.version != IPC_VERSION {
        return Err(ApError::coded(
            "AP_IPC_VERSION_MISMATCH",
            format!(
                "请求 IPC 版本为 {}，daemon 需要 {IPC_VERSION}",
                request.version
            ),
        ));
    }
    Ok(request)
}

pub async fn write_reply(stream: &mut UnixStream, reply: &DaemonReply) -> Result<()> {
    write_frame(stream, reply).await
}

async fn write_frame<T: Serialize>(stream: &mut UnixStream, value: &T) -> Result<()> {
    let payload = serde_json::to_vec(value)
        .map_err(|error| ApError::coded("AP_IPC_ENCODE_ERROR", error.to_string()))?;
    if payload.len() > MAX_FRAME_SIZE {
        return Err(ApError::coded(
            "AP_IPC_FRAME_TOO_LARGE",
            format!("IPC 帧超过 {MAX_FRAME_SIZE} 字节"),
        ));
    }
    stream.write_u32(payload.len() as u32).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_frame<T: for<'de> Deserialize<'de>>(stream: &mut UnixStream) -> Result<T> {
    let length = stream.read_u32().await? as usize;
    if length > MAX_FRAME_SIZE {
        return Err(ApError::coded(
            "AP_IPC_FRAME_TOO_LARGE",
            format!("IPC 帧超过 {MAX_FRAME_SIZE} 字节"),
        ));
    }
    let mut payload = vec![0; length];
    stream.read_exact(&mut payload).await?;
    serde_json::from_slice(&payload)
        .map_err(|error| ApError::coded("AP_IPC_DECODE_ERROR", error.to_string()))
}

trait CredentialSource: Send + Sync {
    fn proxy_credential(&self, server: &ServerConfig) -> Result<ProxyCredential>;
    fn ssh_password(&self, server: &ServerConfig) -> Result<Zeroizing<String>>;
}

struct SystemCredentialSource {
    proxy: ProxySecretStore,
    ssh: SshPasswordStore,
}

impl CredentialSource for SystemCredentialSource {
    fn proxy_credential(&self, server: &ServerConfig) -> Result<ProxyCredential> {
        self.proxy.get(server.id)
    }

    fn ssh_password(&self, server: &ServerConfig) -> Result<Zeroizing<String>> {
        let secret = self.ssh.get(server.id)?;
        Ok(Zeroizing::new(secret.expose_secret().to_owned()))
    }
}

struct ManagedProfile {
    server_id: Uuid,
    cancel: CancellationToken,
    task: JoinHandle<()>,
    status: Arc<Mutex<ProfileStatus>>,
}

struct PreparedProfile {
    server: ServerConfig,
    proxy_credential: ProxyCredential,
    lease: ProfileLease,
}

/// Owns all background profile supervisors in one user daemon.
pub struct ProfileManager {
    store: ConfigStore,
    credentials: Arc<dyn CredentialSource>,
    interactive_ssh: bool,
    operations: Mutex<()>,
    profiles: Mutex<HashMap<String, ManagedProfile>>,
}

impl ProfileManager {
    pub fn new(paths: AppPaths) -> Self {
        Self::with_interactive_ssh(paths, false)
    }

    fn with_interactive_ssh(paths: AppPaths, interactive_ssh: bool) -> Self {
        Self {
            store: ConfigStore::new(paths.clone()),
            credentials: Arc::new(SystemCredentialSource {
                proxy: ProxySecretStore::new(paths),
                ssh: SshPasswordStore::new(),
            }),
            interactive_ssh,
            operations: Mutex::new(()),
            profiles: Mutex::new(HashMap::new()),
        }
    }

    async fn start_autostart(&self) -> Result<()> {
        self.start_autostart_except(None).await
    }

    async fn start_autostart_except(&self, blocked_server_id: Option<Uuid>) -> Result<()> {
        let config = self.store.load()?;
        for (name, server) in config.servers {
            if server.autostart
                && blocked_server_id != Some(server.id)
                && let Err(error) = self.up_expected(&name, server.id).await
            {
                // Never attach an error from an obsolete name/UUID snapshot to
                // a newly-created profile with the same display name.
                if self.configured_profile_id(&name).ok() == Some(server.id) {
                    self.record_failed(&name, server.id, true, error).await;
                }
            }
        }
        Ok(())
    }

    async fn record_recovery_waiting(&self, pending: &PendingProfile, error: &ApError) {
        let _operation = self.operations.lock().await;
        let Ok(server) = self.store.get_server(&pending.server_name) else {
            return;
        };
        if server.id != pending.server_id {
            return;
        }

        let obsolete = {
            let mut profiles = self.profiles.lock().await;
            match profiles.get(&pending.server_name) {
                Some(profile)
                    if profile.server_id != pending.server_id || !profile.task.is_finished() =>
                {
                    return;
                }
                Some(_) => profiles.remove(&pending.server_name),
                None => None,
            }
        };
        if let Some(profile) = obsolete {
            profile.cancel.cancel();
            let _ = profile.task.await;
        }

        let mut waiting = ProfileStatus::stopped(&pending.server_name, server.autostart);
        waiting.phase = ProfilePhase::WaitingForSecretStore;
        waiting.last_error = Some(error.to_string());
        waiting.mappings = server
            .proxies
            .iter()
            .map(|mapping| MappingStatus {
                name: mapping.name.clone(),
                ..MappingStatus::default()
            })
            .collect();
        self.profiles.lock().await.insert(
            pending.server_name.clone(),
            ManagedProfile {
                server_id: pending.server_id,
                cancel: CancellationToken::new(),
                task: tokio::spawn(async {}),
                status: Arc::new(Mutex::new(waiting)),
            },
        );
    }

    async fn clear_recovery_waiting(&self, pending: &PendingProfile) {
        let _operation = self.operations.lock().await;
        let candidate = {
            let profiles = self.profiles.lock().await;
            profiles.get(&pending.server_name).and_then(|profile| {
                (profile.server_id == pending.server_id).then(|| Arc::clone(&profile.status))
            })
        };
        let Some(status) = candidate else {
            return;
        };
        if status.lock().await.phase != ProfilePhase::WaitingForSecretStore {
            return;
        }
        let removed = self.profiles.lock().await.remove(&pending.server_name);
        if let Some(profile) = removed {
            profile.cancel.cancel();
            let _ = profile.task.await;
        }
    }

    async fn record_failed(&self, name: &str, server_id: Uuid, autostart: bool, error: ApError) {
        let mut failed = ProfileStatus::stopped(name, autostart);
        failed.phase = ProfilePhase::Failed;
        failed.last_error = Some(error.to_string());
        self.profiles.lock().await.insert(
            name.to_owned(),
            ManagedProfile {
                server_id,
                cancel: CancellationToken::new(),
                task: tokio::spawn(async {}),
                status: Arc::new(Mutex::new(failed)),
            },
        );
    }

    pub async fn up(&self, name: &str) -> Result<()> {
        let expected_server_id = self.configured_profile_id(name)?;
        self.up_expected(name, expected_server_id).await
    }

    pub async fn up_expected(&self, name: &str, expected_server_id: Uuid) -> Result<()> {
        let _operation = self.operations.lock().await;
        self.up_locked(name, expected_server_id).await
    }

    async fn up_locked(&self, name: &str, expected_server_id: Uuid) -> Result<()> {
        self.ensure_profile_identity(name, expected_server_id)?;
        if self
            .keep_current_profile_or_reap(name, expected_server_id)
            .await
        {
            return Ok(());
        }

        let prepared = self.prepare_profile_start(name, expected_server_id)?;
        let server = prepared.server;
        let server_id = server.id;
        let ap_executable = std::env::current_exe()?;
        let control_socket = self.store.paths().profile_control_socket(server_id);

        let status = Arc::new(Mutex::new(ProfileStatus {
            server: name.to_owned(),
            phase: ProfilePhase::Connecting,
            autostart: server.autostart,
            ssh_pid: None,
            retry_count: 0,
            last_error: None,
            mappings: server
                .proxies
                .iter()
                .map(|mapping| MappingStatus {
                    name: mapping.name.clone(),
                    ..MappingStatus::default()
                })
                .collect(),
        }));
        let cancel = CancellationToken::new();
        let log_path = self.store.paths().logs_dir.join(format!("{name}.log"));
        let task = tokio::spawn(profile_supervisor(ProfileRuntime {
            server,
            proxy_credential: prepared.proxy_credential,
            credentials: Arc::clone(&self.credentials),
            control_socket,
            ap_executable,
            interactive_ssh: self.interactive_ssh,
            cancel: cancel.clone(),
            status: Arc::clone(&status),
            log_path,
            _lease: prepared.lease,
        }));
        self.profiles.lock().await.insert(
            name.to_owned(),
            ManagedProfile {
                server_id,
                cancel,
                task,
                status,
            },
        );
        Ok(())
    }

    fn configured_profile_id(&self, name: &str) -> Result<Uuid> {
        Ok(self.store.get_server(name)?.id)
    }

    fn ensure_profile_identity(&self, name: &str, expected_server_id: Uuid) -> Result<()> {
        let actual_server_id = match self.configured_profile_id(name) {
            Ok(actual_server_id) => actual_server_id,
            Err(error) if error.code() == "AP_SERVER_NOT_FOUND" => {
                return Err(profile_identity_missing(name, expected_server_id));
            }
            Err(error) => return Err(error),
        };
        if actual_server_id != expected_server_id {
            return Err(profile_identity_changed(
                name,
                expected_server_id,
                actual_server_id,
            ));
        }
        Ok(())
    }

    /// Keep an active supervisor only when it belongs to the UUID currently
    /// associated with this name. A completed task, or a live task left from a
    /// delete-and-recreate of the same name, is removed and joined before a new
    /// lease is acquired. Joining is what makes release of the old runtime's
    /// lease deterministic.
    async fn keep_current_profile_or_reap(&self, name: &str, configured_id: Uuid) -> bool {
        let obsolete = {
            let mut profiles = self.profiles.lock().await;
            match profiles.get(name) {
                Some(profile)
                    if profile.server_id == configured_id && !profile.task.is_finished() =>
                {
                    return true;
                }
                Some(_) => profiles.remove(name),
                None => None,
            }
        };
        if let Some(profile) = obsolete {
            profile.cancel.cancel();
            let _ = profile.task.await;
        }
        false
    }

    fn prepare_profile_start(
        &self,
        name: &str,
        expected_server_id: Uuid,
    ) -> Result<PreparedProfile> {
        self.prepare_profile_start_with(name, expected_server_id, |_| {})
    }

    fn prepare_profile_start_with(
        &self,
        name: &str,
        expected_server_id: Uuid,
        mut before_lease: impl FnMut(Uuid),
    ) -> Result<PreparedProfile> {
        self.ensure_profile_identity(name, expected_server_id)?;
        before_lease(expected_server_id);
        let lease = ProfileLease::acquire(self.store.paths(), expected_server_id)?;

        // The UUID is checked again only after its process-independent lease is
        // held. If the name was deleted and recreated, this request belongs to
        // the old identity and must not silently start the replacement.
        let server = match self.store.get_server(name) {
            Ok(server) => server,
            Err(error) if error.code() == "AP_SERVER_NOT_FOUND" => {
                return Err(profile_identity_missing(name, expected_server_id));
            }
            Err(error) => return Err(error),
        };
        if server.id != expected_server_id {
            return Err(profile_identity_changed(
                name,
                expected_server_id,
                server.id,
            ));
        }
        if server.proxies.is_empty() {
            return Err(ApError::coded(
                "AP_NO_PROXY_MAPPING",
                format!("server {name:?} 没有 proxy mapping"),
            ));
        }

        // Credential rotation uses the same profile lease. Reading it only now
        // guarantees it corresponds to the stable server snapshot.
        let proxy_credential = self.credentials.proxy_credential(&server)?;
        Ok(PreparedProfile {
            server,
            proxy_credential,
            lease,
        })
    }

    pub async fn down(&self, name: &str) -> Result<()> {
        let expected_server_id = self.configured_profile_id(name)?;
        self.down_expected(name, expected_server_id).await
    }

    pub async fn down_expected(&self, name: &str, expected_server_id: Uuid) -> Result<()> {
        let _operation = self.operations.lock().await;
        self.down_locked(name, expected_server_id).await
    }

    async fn down_locked(&self, name: &str, expected_server_id: Uuid) -> Result<()> {
        self.ensure_profile_identity(name, expected_server_id)?;
        let removed = {
            let mut profiles = self.profiles.lock().await;
            if let Some(profile) = profiles.get(name)
                && profile.server_id != expected_server_id
            {
                return Err(profile_identity_changed(
                    name,
                    expected_server_id,
                    profile.server_id,
                ));
            }
            profiles.remove(name)
        };
        if let Some(profile) = removed {
            profile.cancel.cancel();
            let _ = profile.task.await;
        }

        // Once this daemon's own supervisor has released the UUID lease, any
        // remaining owner is a foreground/external ap process. Hold the lease
        // while rechecking the name so `down` cannot falsely report stopped.
        let lease = match ProfileLease::acquire(self.store.paths(), expected_server_id) {
            Ok(lease) => lease,
            Err(error) if error.code() == "AP_PROFILE_RUNNING" => {
                return Err(ApError::coded(
                    "AP_PROFILE_FOREGROUND_RUNNING",
                    format!(
                        "{name} 正由 `ap connect` 前台或另一个外部 ap 进程运行，daemon 无权停止该连接"
                    ),
                ));
            }
            Err(error) => return Err(error),
        };
        let server = match self.store.get_server(name) {
            Ok(server) => server,
            Err(error) if error.code() == "AP_SERVER_NOT_FOUND" => {
                return Err(profile_identity_missing(name, expected_server_id));
            }
            Err(error) => return Err(error),
        };
        if server.id != expected_server_id {
            return Err(profile_identity_changed(
                name,
                expected_server_id,
                server.id,
            ));
        }
        let mut profiles = self.profiles.lock().await;
        let status = Arc::new(Mutex::new(ProfileStatus::stopped(name, server.autostart)));
        profiles.insert(
            name.to_owned(),
            ManagedProfile {
                server_id: server.id,
                cancel: CancellationToken::new(),
                task: tokio::spawn(async {}),
                status,
            },
        );
        drop(profiles);
        drop(lease);
        Ok(())
    }

    pub async fn restart(&self, name: &str) -> Result<()> {
        let expected_server_id = self.configured_profile_id(name)?;
        self.restart_expected(name, expected_server_id).await
    }

    pub async fn restart_expected(&self, name: &str, expected_server_id: Uuid) -> Result<()> {
        let _operation = self.operations.lock().await;
        self.down_locked(name, expected_server_id).await?;
        self.up_locked(name, expected_server_id).await
    }

    pub async fn status(&self, filter: Option<&str>) -> Result<Vec<ProfileStatus>> {
        let config = self.store.load()?;
        if let Some(name) = filter
            && !config.servers.contains_key(name)
        {
            return Err(ApError::coded(
                "AP_SERVER_NOT_FOUND",
                format!("server {name:?} 不存在"),
            ));
        }
        let names = match filter {
            Some(name) => BTreeSet::from([name.to_owned()]),
            None => config.servers.keys().cloned().collect(),
        };
        let mut statuses = Vec::with_capacity(names.len());
        for name in names {
            let Some(server) = config.servers.get(&name) else {
                continue;
            };
            let managed = {
                let profiles = self.profiles.lock().await;
                profiles.get(&name).map(|profile| {
                    (
                        profile.server_id,
                        profile.task.is_finished(),
                        Arc::clone(&profile.status),
                    )
                })
            };
            match managed {
                Some((managed_id, finished, managed_status)) => {
                    if managed_id != server.id {
                        let mut status = ProfileStatus::stopped(&name, server.autostart);
                        status.phase = ProfilePhase::Failed;
                        status.last_error = Some(
                            profile_identity_changed(&name, server.id, managed_id).to_string(),
                        );
                        statuses.push(status);
                    } else if !finished {
                        statuses.push(managed_status.lock().await.clone());
                    } else if profile_is_running(self.store.paths(), server.id)? {
                        statuses.push(external_profile_status(&name, server.autostart));
                    } else {
                        statuses.push(managed_status.lock().await.clone());
                    }
                }
                None if profile_is_running(self.store.paths(), server.id)? => {
                    statuses.push(external_profile_status(&name, server.autostart));
                }
                None => statuses.push(ProfileStatus::stopped(&name, server.autostart)),
            }
        }
        Ok(statuses)
    }

    pub async fn reload(&self) -> Result<()> {
        let _operation = self.operations.lock().await;
        let config = self.store.load()?;
        let known: BTreeSet<String> = config.servers.keys().cloned().collect();
        let active: Vec<String> = self.profiles.lock().await.keys().cloned().collect();
        let mut obsolete = Vec::new();
        for name in active {
            if !known.contains(&name)
                && let Some(profile) = self.profiles.lock().await.remove(&name)
            {
                obsolete.push(profile);
            }
        }
        for profile in &obsolete {
            profile.cancel.cancel();
        }
        for profile in obsolete {
            let _ = profile.task.await;
        }
        for (name, server) in config.servers {
            if server.autostart {
                self.up_locked(&name, server.id).await?;
            }
        }
        Ok(())
    }

    pub async fn shutdown(&self) {
        let _operation = self.operations.lock().await;
        let profiles = std::mem::take(&mut *self.profiles.lock().await);
        for profile in profiles.values() {
            profile.cancel.cancel();
        }
        for (_, profile) in profiles {
            let _ = profile.task.await;
        }
    }
}

fn profile_identity_changed(name: &str, expected: Uuid, actual: Uuid) -> ApError {
    ApError::coded(
        "AP_PROFILE_IDENTITY_CHANGED",
        format!(
            "server {name:?} 的身份在操作期间发生变化（期望 UUID {expected}，实际 UUID {actual}）；已中止操作"
        ),
    )
}

fn profile_identity_missing(name: &str, expected: Uuid) -> ApError {
    ApError::coded(
        "AP_PROFILE_IDENTITY_CHANGED",
        format!("server {name:?}（期望 UUID {expected}）在操作期间被删除；已中止操作"),
    )
}

fn external_profile_status(name: &str, autostart: bool) -> ProfileStatus {
    ProfileStatus {
        server: name.to_owned(),
        phase: ProfilePhase::Connected,
        autostart,
        ssh_pid: None,
        retry_count: 0,
        last_error: None,
        mappings: Vec::new(),
    }
}

/// User service entry point.
pub async fn run(paths: AppPaths) -> Result<()> {
    paths.ensure()?;
    let socket_path = paths.daemon_socket.clone();
    let server = IpcServer::bind(socket_path)?;
    // Bind the socket and hold daemon.lock before touching any autostart
    // profile. A losing daemon instance must have no profile side effects.
    let manager = Arc::new(ProfileManager::new(paths.clone()));
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let requested_shutdown = CancellationToken::new();
    let permits = Arc::new(Semaphore::new(MAX_IPC_CONNECTIONS));
    let mut connections = JoinSet::new();
    let mut recoveries = JoinSet::new();
    spawn_transaction_recovery(&mut recoveries, paths.clone());
    let mut recovery_needed = true;
    let mut autostart_initialized = false;
    let mut recovery_tick = interval(TRANSACTION_RECOVERY_INTERVAL);
    recovery_tick.set_missed_tick_behavior(MissedTickBehavior::Delay);
    recovery_tick.tick().await;
    let mut fatal_error = None;

    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = requested_shutdown.cancelled() => break,
            accepted = server.accept() => {
                let Ok(stream) = accepted else { continue };
                let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                let manager = Arc::clone(&manager);
                let requested_shutdown = requested_shutdown.clone();
                connections.spawn(async move {
                    let _permit = permit;
                    handle_ipc_connection(stream, manager, requested_shutdown).await;
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => {}
            Some(joined) = recoveries.join_next(), if !recoveries.is_empty() => {
                match joined {
                    Ok(Ok(RecoveryOutcome::Busy)) => {
                        recovery_needed = true;
                    }
                    Ok(Ok(RecoveryOutcome::NoPending)) => {
                        recovery_needed = false;
                        if !autostart_initialized {
                            if let Err(error) = manager.start_autostart().await {
                                fatal_error = Some(error);
                                break;
                            }
                            autostart_initialized = true;
                        }
                    }
                    Ok(Ok(RecoveryOutcome::Recovered(pending))) => {
                        recovery_needed = false;
                        manager.clear_recovery_waiting(&pending).await;
                        let result = if autostart_initialized {
                            // Only a genuinely recovered journal triggers a
                            // reload. An active CLI that committed before our
                            // try-lock returns NoPending above and cannot cause
                            // a spurious restart/reload.
                            manager.reload().await
                        } else {
                            manager.start_autostart().await
                        };
                        if let Err(error) = result {
                            fatal_error = Some(error);
                            break;
                        }
                        autostart_initialized = true;
                    }
                    Ok(Err(failure)) if is_secret_store_error(failure.error.code()) => {
                        recovery_needed = true;
                        let blocked_server_id = failure
                            .profile
                            .as_ref()
                            .map(|profile| profile.server_id);
                        if let Some(profile) = failure.profile.as_ref() {
                            manager
                                .record_recovery_waiting(profile, &failure.error)
                                .await;
                        }
                        if !autostart_initialized {
                            if let Err(error) = manager
                                .start_autostart_except(blocked_server_id)
                                .await
                            {
                                fatal_error = Some(error);
                                break;
                            }
                            autostart_initialized = true;
                        }
                    }
                    Ok(Err(failure)) => {
                        fatal_error = Some(failure.error);
                        break;
                    }
                    Err(error) => {
                        fatal_error = Some(ApError::coded(
                            "AP_TRANSACTION_RECOVERY_TASK_FAILED",
                            format!("跨存储事务恢复任务异常退出：{error}"),
                        ));
                        break;
                    }
                }
            }
            _ = recovery_tick.tick() => {
                if recoveries.is_empty()
                    && (recovery_needed || transaction_journal_may_exist(&paths))
                {
                    spawn_transaction_recovery(&mut recoveries, paths.clone());
                }
            }
        }
    }
    requested_shutdown.cancel();
    connections.abort_all();
    while connections.join_next().await.is_some() {}
    recoveries.abort_all();
    while recoveries.join_next().await.is_some() {}
    manager.shutdown().await;
    match fatal_error {
        Some(error) => Err(error),
        None => Ok(()),
    }
}

fn spawn_transaction_recovery(
    recoveries: &mut JoinSet<std::result::Result<RecoveryOutcome, RecoveryFailure>>,
    paths: AppPaths,
) {
    recoveries.spawn_blocking(move || transaction::try_recover_pending(&paths));
}

fn transaction_journal_may_exist(paths: &AppPaths) -> bool {
    match fs::symlink_metadata(&paths.transaction_journal) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        // Let the recovery path produce the precise permission/type error.
        Err(_) => true,
    }
}

async fn handle_ipc_connection(
    mut stream: UnixStream,
    manager: Arc<ProfileManager>,
    requested_shutdown: CancellationToken,
) {
    let request = match timeout(IPC_IO_TIMEOUT, read_request(&mut stream)).await {
        Ok(Ok(request)) => request,
        Ok(Err(error)) => {
            let reply = DaemonReply::error(error.code(), error.to_string());
            let _ = timeout(IPC_IO_TIMEOUT, write_reply(&mut stream, &reply)).await;
            return;
        }
        Err(_) => {
            let reply = DaemonReply::error("AP_IPC_TIMEOUT", "daemon IPC 请求读取超时");
            let _ = timeout(IPC_IO_TIMEOUT, write_reply(&mut stream, &reply)).await;
            return;
        }
    };
    let should_shutdown = matches!(request.command, DaemonCommand::Shutdown);
    let reply = handle_request(&manager, request.command).await;
    let _ = timeout(IPC_IO_TIMEOUT, write_reply(&mut stream, &reply)).await;
    if should_shutdown {
        requested_shutdown.cancel();
    }
}

/// Foreground connect entry point. It uses the same supervisor and cleanup path
/// as the daemon but does not create an IPC socket.
pub async fn run_foreground(paths: AppPaths, server: &str) -> Result<()> {
    let manager = Arc::new(ProfileManager::with_interactive_ssh(paths, true));
    manager.up(server).await?;
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let mut poll = tokio::time::interval(Duration::from_millis(250));
    loop {
        tokio::select! {
            _ = &mut shutdown => break,
            _ = poll.tick() => {
                let status = manager.status(Some(server)).await?
                    .into_iter().next().expect("requested profile exists");
                if status.phase == ProfilePhase::Failed {
                    manager.shutdown().await;
                    return Err(ApError::coded(
                        "AP_PROFILE_FAILED",
                        status.last_error.unwrap_or_else(|| "SSH profile failed".to_owned()),
                    ));
                }
            }
        }
    }
    manager.shutdown().await;
    Ok(())
}

async fn handle_request(manager: &ProfileManager, command: DaemonCommand) -> DaemonReply {
    let result: Result<Vec<ProfileStatus>> = async {
        match command {
            DaemonCommand::Up {
                server,
                expected_server_id,
            } => {
                manager.up_expected(&server, expected_server_id).await?;
                manager.status(Some(&server)).await
            }
            DaemonCommand::Down {
                server,
                expected_server_id,
            } => {
                manager.down_expected(&server, expected_server_id).await?;
                manager.status(Some(&server)).await
            }
            DaemonCommand::Restart {
                server,
                expected_server_id,
            } => {
                manager
                    .restart_expected(&server, expected_server_id)
                    .await?;
                manager.status(Some(&server)).await
            }
            DaemonCommand::Status { server } => manager.status(server.as_deref()).await,
            DaemonCommand::Reload => {
                manager.reload().await?;
                manager.status(None).await
            }
            DaemonCommand::Shutdown => Ok(Vec::new()),
        }
    }
    .await;
    match result {
        Ok(statuses) => DaemonReply::success(statuses),
        Err(error) => DaemonReply::error(error.code(), error.to_string()),
    }
}

struct ProfileRuntime {
    server: ServerConfig,
    proxy_credential: ProxyCredential,
    credentials: Arc<dyn CredentialSource>,
    control_socket: PathBuf,
    ap_executable: PathBuf,
    interactive_ssh: bool,
    cancel: CancellationToken,
    status: Arc<Mutex<ProfileStatus>>,
    log_path: PathBuf,
    _lease: ProfileLease,
}

async fn profile_supervisor(runtime: ProfileRuntime) {
    let mut retry = 0_u32;
    loop {
        if runtime.cancel.is_cancelled() {
            set_stopped(&runtime.status).await;
            append_profile_log(&runtime.log_path, "phase=stopped");
            return;
        }
        {
            let mut current = runtime.status.lock().await;
            current.phase = if retry == 0 {
                ProfilePhase::Connecting
            } else {
                ProfilePhase::Reconnecting
            };
            current.retry_count = retry;
            current.ssh_pid = None;
        }
        append_profile_log(
            &runtime.log_path,
            if retry == 0 {
                "phase=connecting"
            } else {
                "phase=reconnecting"
            },
        );

        let attempt_started = Instant::now();
        let outcome = run_profile_attempt(&runtime).await;
        if runtime.cancel.is_cancelled() {
            set_stopped(&runtime.status).await;
            append_profile_log(&runtime.log_path, "phase=stopped");
            return;
        }
        let error = match outcome {
            Ok(()) => ApError::coded("AP_SSH_EXITED", "OpenSSH exited unexpectedly"),
            Err(error) => error,
        };
        let code = error.code();
        append_profile_log(
            &runtime.log_path,
            &format!("phase=disconnected code={code} error={error}"),
        );
        {
            let mut current = runtime.status.lock().await;
            current.last_error = Some(error.to_string());
            current.ssh_pid = None;
        }
        if is_secret_store_error(code) {
            runtime.status.lock().await.phase = ProfilePhase::WaitingForSecretStore;
            append_profile_log(&runtime.log_path, "phase=waiting-for-secret-store");
            if wait_or_cancel(&runtime.cancel, Duration::from_secs(5)).await {
                set_stopped(&runtime.status).await;
                append_profile_log(&runtime.log_path, "phase=stopped");
                return;
            }
            continue;
        }
        if is_permanent_error(code) {
            runtime.status.lock().await.phase = ProfilePhase::Failed;
            append_profile_log(&runtime.log_path, "phase=failed");
            return;
        }

        if attempt_started.elapsed() >= Duration::from_secs(60) {
            retry = 0;
        }
        retry = retry.saturating_add(1);
        {
            let mut current = runtime.status.lock().await;
            current.phase = ProfilePhase::Reconnecting;
            current.retry_count = retry;
        }
        if wait_or_cancel(&runtime.cancel, retry_delay(retry)).await {
            set_stopped(&runtime.status).await;
            append_profile_log(&runtime.log_path, "phase=stopped");
            return;
        }
    }
}

async fn run_profile_attempt(runtime: &ProfileRuntime) -> Result<()> {
    let ssh_executable = system_ssh_executable()?;
    stop_existing_master(
        &ssh_executable,
        &runtime.control_socket,
        &runtime.server.ssh_host,
    )
    .await?;
    let mut proxy_checks = JoinSet::new();
    for mapping in &runtime.server.proxies {
        let mapping_name = mapping.name.clone();
        let check = LocalProxyCheck {
            name: mapping_name.clone(),
            address: mapping.local,
            protocol: mapping.protocol,
        };
        proxy_checks.spawn(async move { (mapping_name, check_local_proxy(&check).await) });
    }
    while !proxy_checks.is_empty() {
        let checked = tokio::select! {
            _ = runtime.cancel.cancelled() => {
                proxy_checks.shutdown().await;
                return Ok(());
            }
            checked = proxy_checks.join_next() => checked,
        };
        match checked {
            Some(Ok((_name, Ok(())))) => {}
            Some(Ok((name, Err(error)))) => {
                proxy_checks.shutdown().await;
                return Err(ApError::coded(
                    "AP_LOCAL_PROXY_UNAVAILABLE",
                    format!(
                        "本机 proxy {name:?} 尚未通过协议握手（{}）；连接将在退避后重试",
                        error.code()
                    ),
                ));
            }
            Some(Err(_)) => {
                proxy_checks.shutdown().await;
                return Err(ApError::coded(
                    "AP_LOCAL_PROXY_CHECK_FAILED",
                    "本机代理协议检查任务异常结束；连接将在退避后重试",
                ));
            }
            None => break,
        }
    }
    let gateway_cancel = runtime.cancel.child_token();
    let mut gateways = Vec::with_capacity(runtime.server.proxies.len());
    for mapping in &runtime.server.proxies {
        match start_mapping_gateway(mapping, &runtime.proxy_credential, gateway_cancel.clone())
            .await
        {
            Ok(gateway) => gateways.push(gateway),
            Err(error) => {
                gateway_cancel.cancel();
                shutdown_gateways(gateways).await;
                return Err(ApError::coded(
                    "AP_GATEWAY_START_FAILED",
                    format!("无法启动 proxy {:?} 的本机认证网关：{error}", mapping.name),
                ));
            }
        }
    }
    let forwards = runtime
        .server
        .proxies
        .iter()
        .zip(&gateways)
        .map(|(mapping, gateway)| RemoteForward {
            remote_port: mapping.remote_port,
            local_gateway: gateway.listen_addr,
        })
        .collect();
    let authentication = match runtime.server.auth_mode {
        AuthMode::SshConfig => SshAuthentication::SshConfig {
            batch_mode: !runtime.interactive_ssh,
        },
        AuthMode::StoredPassword => {
            let server = runtime.server.clone();
            let credentials = Arc::clone(&runtime.credentials);
            SshAuthentication::StoredPassword {
                provider: Arc::new(move || credentials.ssh_password(&server)),
            }
        }
    };
    let options = SshOptions {
        executable: ssh_executable,
        ap_executable: runtime.ap_executable.clone(),
        host: runtime.server.ssh_host.clone(),
        control_socket: runtime.control_socket.clone(),
        forwards,
        authentication,
        startup_timeout: Duration::from_secs(20),
    };
    let start = SshMaster::start(options);
    tokio::pin!(start);
    let started = tokio::select! {
        _ = runtime.cancel.cancelled() => {
            gateway_cancel.cancel();
            shutdown_gateways(gateways).await;
            return Ok(());
        }
        started = &mut start => started,
    };
    let mut master = match started {
        Ok(master) => master,
        Err(error) => {
            gateway_cancel.cancel();
            shutdown_gateways(gateways).await;
            return Err(error);
        }
    };
    {
        let mut current = runtime.status.lock().await;
        current.ssh_pid = master.pid();
        current.last_error = None;
    }
    append_profile_log(&runtime.log_path, "phase=connected");

    let mut health = tokio::time::interval(Duration::from_secs(5));
    let outcome = loop {
        tokio::select! {
            _ = runtime.cancel.cancelled() => break Ok(()),
            exited = master.wait() => {
                break match exited {
                    Ok(exit) if exit.success() => Ok(()),
                    Ok(exit) => Err(master.exit_error(exit)),
                    Err(error) => Err(error),
                };
            }
            _ = health.tick() => {
                refresh_status(
                    &runtime.server,
                    &gateways,
                    &runtime.status,
                    &runtime.log_path,
                ).await;
            }
        }
    };
    gateway_cancel.cancel();
    if runtime.cancel.is_cancelled() {
        let _ = master.shutdown().await;
    }
    shutdown_gateways(gateways).await;
    outcome
}

async fn refresh_status(
    server: &ServerConfig,
    gateways: &[RunningGateway],
    status: &Arc<Mutex<ProfileStatus>>,
    log_path: &Path,
) {
    let mut degraded = false;
    for mapping in &server.proxies {
        if !matches!(
            timeout(
                Duration::from_millis(750),
                tokio::net::TcpStream::connect(mapping.local),
            )
            .await,
            Ok(Ok(_))
        ) {
            degraded = true;
        }
    }
    let mut current = status.lock().await;
    let previous = current.phase;
    let next = if degraded {
        ProfilePhase::Degraded
    } else {
        ProfilePhase::Connected
    };
    current.phase = next;
    current.mappings = gateways
        .iter()
        .map(|gateway| {
            let snapshot = gateway.stats.snapshot();
            MappingStatus {
                name: gateway.name.clone(),
                active_connections: snapshot.active_connections as u64,
                bytes_from_remote: snapshot.bytes_to_upstream,
                bytes_to_remote: snapshot.bytes_to_client,
                auth_failures: snapshot.authentication_failures,
                upstream_errors: snapshot.upstream_errors,
            }
        })
        .collect();
    drop(current);
    if previous != next {
        append_profile_log(log_path, &format!("phase={next}"));
    }
}

async fn shutdown_gateways(gateways: Vec<RunningGateway>) {
    for gateway in gateways {
        gateway.shutdown().await;
    }
}

async fn set_stopped(status: &Arc<Mutex<ProfileStatus>>) {
    let mut status = status.lock().await;
    status.phase = ProfilePhase::Stopped;
    status.ssh_pid = None;
}

fn is_secret_store_error(code: &str) -> bool {
    matches!(
        code,
        "AP_SECRET_STORE_LOCKED"
            | "AP_SECRET_STORE_UNAVAILABLE"
            | "AP_SECRET_STORE_ERROR"
            | "AP_SSH_PASSWORD_NOT_FOUND"
    )
}

fn is_permanent_error(code: &str) -> bool {
    matches!(
        code,
        "AP_OPENSSH_UNAVAILABLE"
            | "AP_OPENSSH_UNTRUSTED"
            | "AP_EXECUTABLE_IDENTITY_CHANGED"
            | "AP_SSH_AUTH_FAILED"
            | "AP_SSH_FORWARD_FAILED"
            | "AP_SSH_FORWARDING_DISABLED"
            | "AP_SSH_HOST_KEY"
            | "AP_SSH_UNSAFE_ALIAS"
            | "AP_SSH_CONFIG"
            | "AP_SSH_CONFIG_TIMEOUT"
            | "AP_SSH_STORED_PASSWORD_UNSAFE_ALIAS"
            | "AP_INVALID_SSH_HOST"
            | "AP_INVALID_REMOTE_PORT"
            | "AP_DUPLICATE_REMOTE_PORT"
            | "AP_GATEWAY_START_FAILED"
            | "AP_PROXY_SECRET_NOT_FOUND"
            | "AP_SECRET_STORE_AMBIGUOUS"
            | "AP_SECRET_STORE_CORRUPT"
            | "AP_ASKPASS_UNEXPECTED_PROMPT"
            | "AP_ASKPASS_REJECTED"
            | "AP_ASKPASS_PASSWORD_SIZE"
            | "AP_ASKPASS_PEER"
            | "AP_SSH_CONTROL_UNSAFE"
            | "AP_SSH_CONTROL_PATH_TOKEN"
            | "AP_SSH_CONTROL_PATH_TOO_LONG"
            | "AP_ASKPASS_SOCKET_PATH_TOO_LONG"
            | "AP_SSH_CONTROL_RECLAIM_FAILED"
    )
}

fn retry_delay(retry: u32) -> Duration {
    const STEPS: [u64; 7] = [1, 2, 4, 8, 15, 30, 60];
    let base = STEPS[(retry.saturating_sub(1) as usize).min(STEPS.len() - 1)];
    let mut random = [0_u8; 2];
    let jitter = if getrandom::fill(&mut random).is_ok() {
        // 0.85 through 1.15, inclusive.
        0.85 + (u16::from_ne_bytes(random) as f64 / u16::MAX as f64) * 0.30
    } else {
        1.0
    };
    Duration::from_millis((base as f64 * 1000.0 * jitter) as u64)
}

async fn wait_or_cancel(cancel: &CancellationToken, duration: Duration) -> bool {
    tokio::select! {
        _ = cancel.cancelled() => true,
        _ = sleep(duration) => false,
    }
}

fn append_profile_log(path: &Path, message: &str) {
    let Some(parent) = path.parent() else {
        return;
    };
    if fs::create_dir_all(parent).is_err() {
        return;
    }
    #[cfg(unix)]
    if fs::set_permissions(parent, fs::Permissions::from_mode(0o700)).is_err() {
        return;
    }

    if fs::metadata(path).is_ok_and(|metadata| metadata.len() >= MAX_PROFILE_LOG_BYTES) {
        let rotated = path.with_extension("log.1");
        let _ = fs::remove_file(&rotated);
        let _ = fs::rename(path, rotated);
    }

    let mut options = OpenOptions::new();
    options.create(true).append(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let Ok(mut file) = options.open(path) else {
        return;
    };
    #[cfg(unix)]
    {
        let Ok(metadata) = file.metadata() else {
            return;
        };
        if !metadata.is_file() || metadata.uid() != unsafe { libc::geteuid() } {
            return;
        }
        let _ = file.set_permissions(fs::Permissions::from_mode(0o600));
    }

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let safe = sanitize_log_message(message);
    let _ = writeln!(file, "ts={timestamp} {safe}");
}

fn sanitize_log_message(message: &str) -> String {
    let lower = message.to_ascii_lowercase();
    if lower.contains("proxy-authorization") || lower.contains("authorization: basic") {
        return "event=<redacted-authentication-data>".to_owned();
    }
    message
        .chars()
        .map(|character| {
            if character.is_control() {
                ' '
            } else {
                character
            }
        })
        .take(4096)
        .collect()
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {}
            _ = terminate.recv() => {}
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;
    use crate::model::{ProxyMapping, ProxyProtocol};
    use crate::transaction::CrossStoreTransaction;

    fn test_mapping(name: &str, remote_port: u16) -> ProxyMapping {
        ProxyMapping {
            name: name.to_owned(),
            protocol: ProxyProtocol::Http,
            local: "127.0.0.1:7890".parse().unwrap(),
            remote_port,
        }
    }

    #[tokio::test]
    async fn framed_request_round_trip() {
        let directory = tempdir().unwrap();
        let socket = directory.path().join("daemon.sock");
        let server = IpcServer::bind(&socket).unwrap();
        let client_socket = socket.clone();

        let client = tokio::spawn(async move {
            request(
                &client_socket,
                &DaemonRequest::new(DaemonCommand::Status { server: None }),
            )
            .await
            .unwrap()
        });

        let mut stream = server.accept().await.unwrap();
        let incoming = read_request(&mut stream).await.unwrap();
        assert_eq!(incoming.command, DaemonCommand::Status { server: None });
        write_reply(&mut stream, &DaemonReply::success(Vec::new()))
            .await
            .unwrap();
        assert!(client.await.unwrap().ok);
    }

    #[tokio::test]
    async fn daemon_lease_prevents_a_second_listener() {
        let directory = tempdir().unwrap();
        let socket = directory.path().join("daemon.sock");
        let first = IpcServer::bind(&socket).unwrap();
        let error = match IpcServer::bind(&socket) {
            Ok(_) => panic!("second daemon unexpectedly acquired the lease"),
            Err(error) => error,
        };
        assert_eq!(error.code(), "AP_DAEMON_ALREADY_RUNNING");
        drop(first);
        IpcServer::bind(&socket).unwrap();
    }

    #[tokio::test]
    async fn rejects_oversized_frames_before_allocating() {
        let (mut left, mut right) = UnixStream::pair().unwrap();
        tokio::spawn(async move {
            right.write_u32((MAX_FRAME_SIZE + 1) as u32).await.unwrap();
        });
        let result: Result<DaemonRequest> = read_frame(&mut left).await;
        assert!(matches!(
            result,
            Err(ApError::Coded {
                code: "AP_IPC_FRAME_TOO_LARGE",
                ..
            })
        ));
    }

    #[tokio::test]
    async fn half_frame_does_not_block_other_daemon_clients() {
        let directory = tempdir().unwrap();
        let paths = AppPaths::from_root(directory.path().join("ap"));
        let socket = paths.daemon_socket.clone();
        let daemon = tokio::spawn(run(paths));
        for _ in 0..50 {
            if socket.exists() {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }

        let mut slow = UnixStream::connect(&socket).await.unwrap();
        slow.write_u32(100).await.unwrap();
        sleep(Duration::from_millis(25)).await;

        let reply = timeout(
            Duration::from_secs(1),
            request(
                &socket,
                &DaemonRequest::new(DaemonCommand::Status { server: None }),
            ),
        )
        .await
        .expect("half-frame client blocked daemon")
        .unwrap();
        assert!(reply.ok);
        drop(slow);

        request(&socket, &DaemonRequest::new(DaemonCommand::Shutdown))
            .await
            .unwrap();
        timeout(Duration::from_secs(2), daemon)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn transaction_lock_contention_keeps_ipc_responsive_and_recovers_later() {
        let directory = tempdir().unwrap();
        let paths = AppPaths::from_root(directory.path().join("ap"));
        let store = ConfigStore::new(paths.clone());
        let mut server = ServerConfig::new("dev-alias");
        server.autostart = true;
        let transaction =
            CrossStoreTransaction::begin_server_add(&paths, "dev", server.id).unwrap();
        store.insert_server("dev", server).unwrap();

        let socket = paths.daemon_socket.clone();
        let daemon = tokio::spawn(run(paths.clone()));
        for _ in 0..50 {
            if socket.exists() {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }

        let reply = timeout(
            Duration::from_secs(1),
            request(
                &socket,
                &DaemonRequest::new(DaemonCommand::Status {
                    server: Some("dev".to_owned()),
                }),
            ),
        )
        .await
        .expect("transaction lock contention blocked daemon IPC")
        .unwrap();
        assert!(reply.ok);
        assert_eq!(reply.statuses[0].phase, ProfilePhase::Stopped);

        drop(transaction); // leave the journal as if the CLI crashed
        timeout(Duration::from_secs(2), async {
            loop {
                let reply = request(
                    &socket,
                    &DaemonRequest::new(DaemonCommand::Status {
                        server: Some("dev".to_owned()),
                    }),
                )
                .await
                .unwrap();
                if !paths.transaction_journal.exists()
                    && reply.statuses[0].phase == ProfilePhase::Failed
                {
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("daemon did not recover the abandoned journal and resume autostart");

        request(&socket, &DaemonRequest::new(DaemonCommand::Shutdown))
            .await
            .unwrap();
        timeout(Duration::from_secs(2), daemon)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn credential_recovery_failure_is_visible_as_waiting() {
        let directory = tempdir().unwrap();
        let paths = AppPaths::from_root(directory.path().join("ap"));
        let manager = ProfileManager::new(paths);
        let mut server = ServerConfig::new("dev-alias");
        server.autostart = true;
        let id = server.id;
        manager.store.insert_server("dev", server).unwrap();
        let pending = PendingProfile {
            server_name: "dev".to_owned(),
            server_id: id,
        };
        let error = ApError::coded("AP_SECRET_STORE_LOCKED", "系统凭据库当前已锁定");
        let error_text = error.to_string();

        manager.record_recovery_waiting(&pending, &error).await;
        let status = manager.status(Some("dev")).await.unwrap().remove(0);
        assert_eq!(status.phase, ProfilePhase::WaitingForSecretStore);
        assert_eq!(status.last_error.as_deref(), Some(error_text.as_str()));

        manager.clear_recovery_waiting(&pending).await;
        assert_eq!(
            manager.status(Some("dev")).await.unwrap()[0].phase,
            ProfilePhase::Stopped
        );
    }

    #[test]
    fn retry_schedule_is_bounded_and_capped() {
        for (retry, base) in [(1, 1.0), (2, 2.0), (3, 4.0), (7, 60.0), (99, 60.0)] {
            let seconds = retry_delay(retry).as_secs_f64();
            assert!(seconds >= base * 0.84, "retry {retry}: {seconds}");
            assert!(seconds <= base * 1.16, "retry {retry}: {seconds}");
        }
    }

    #[test]
    fn failure_classes_match_supervisor_policy() {
        assert!(is_secret_store_error("AP_SECRET_STORE_LOCKED"));
        assert!(is_permanent_error("AP_SSH_AUTH_FAILED"));
        assert!(is_permanent_error("AP_SSH_HOST_KEY"));
        assert!(is_permanent_error("AP_EXECUTABLE_IDENTITY_CHANGED"));
        assert!(!is_permanent_error("AP_SSH_EXITED"));
    }

    #[test]
    fn profile_operations_receive_a_shutdown_sized_ipc_timeout() {
        let server_id = Uuid::new_v4();
        assert!(
            ipc_response_timeout(&DaemonCommand::Down {
                server: "dev".to_owned(),
                expected_server_id: server_id,
            }) >= Duration::from_secs(30)
        );
        assert!(
            ipc_response_timeout(&DaemonCommand::Restart {
                server: "dev".to_owned(),
                expected_server_id: server_id,
            }) >= Duration::from_secs(30)
        );
        assert_eq!(
            ipc_response_timeout(&DaemonCommand::Status { server: None }),
            IPC_IO_TIMEOUT
        );
    }

    #[test]
    fn daemon_reply_preserves_actionable_profile_error_codes() {
        for code in [
            "AP_PROFILE_FOREGROUND_RUNNING",
            "AP_PROFILE_IDENTITY_CHANGED",
        ] {
            let error = DaemonReply::error(code, "test").into_result().unwrap_err();
            assert_eq!(error.code(), code);
        }
    }

    #[test]
    fn profile_log_is_private_and_redacts_authentication_headers() {
        let directory = tempdir().unwrap();
        let log = directory.path().join("logs/dev.log");
        append_profile_log(&log, "Proxy-Authorization: Basic must-not-appear");
        let text = fs::read_to_string(&log).unwrap();
        assert!(!text.contains("must-not-appear"));
        assert!(text.contains("redacted-authentication-data"));
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(log).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn profile_start_aborts_when_same_name_is_recreated_during_lease_acquisition() {
        let directory = tempdir().unwrap();
        let paths = AppPaths::from_root(directory.path().join("ap"));
        let manager = ProfileManager::new(paths.clone());
        let proxy_store = ProxySecretStore::new(paths.clone());

        let old = manager.store.add_server("dev", "old-alias").unwrap();
        manager
            .store
            .add_proxy("dev", test_mapping("old", 17890))
            .unwrap();
        proxy_store.get_or_create(old.id).unwrap();

        let replacement = std::cell::Cell::new(None);
        let result = manager.prepare_profile_start_with("dev", old.id, |observed_id| {
            assert_eq!(observed_id, old.id);
            manager.store.remove_server("dev").unwrap();
            proxy_store.delete(old.id).unwrap();

            let new = manager.store.add_server("dev", "new-alias").unwrap();
            manager
                .store
                .add_proxy("dev", test_mapping("new", 27890))
                .unwrap();
            proxy_store.get_or_create(new.id).unwrap();
            replacement.set(Some(new.id));
        });
        let error = match result {
            Ok(_) => panic!("obsolete profile identity was unexpectedly started"),
            Err(error) => error,
        };

        let new_id = replacement.get().unwrap();
        assert_eq!(error.code(), "AP_PROFILE_IDENTITY_CHANGED");
        assert!(!profile_is_running(&paths, old.id).unwrap());
        assert!(!profile_is_running(&paths, new_id).unwrap());
    }

    #[test]
    fn profile_start_reads_config_and_credential_after_acquiring_lease() {
        let directory = tempdir().unwrap();
        let paths = AppPaths::from_root(directory.path().join("ap"));
        let manager = ProfileManager::new(paths.clone());
        let proxy_store = ProxySecretStore::new(paths);

        let server = manager.store.add_server("dev", "dev-alias").unwrap();
        manager
            .store
            .add_proxy("dev", test_mapping("old", 17890))
            .unwrap();
        let old_password = proxy_store
            .get_or_create(server.id)
            .unwrap()
            .password()
            .to_owned();

        let mut changed = false;
        let prepared = manager
            .prepare_profile_start_with("dev", server.id, |observed_id| {
                assert_eq!(observed_id, server.id);
                if changed {
                    return;
                }
                manager
                    .store
                    .update_proxy("dev", "old", test_mapping("fresh", 27890))
                    .unwrap();
                proxy_store.rotate(server.id).unwrap();
                changed = true;
            })
            .unwrap();

        assert_eq!(prepared.server.id, server.id);
        assert_eq!(prepared.server.proxies[0].name, "fresh");
        assert_eq!(prepared.server.proxies[0].remote_port, 27890);
        assert_ne!(prepared.proxy_credential.password(), old_password);
        assert_eq!(
            prepared.proxy_credential.password(),
            proxy_store.get(server.id).unwrap().password()
        );
    }

    #[tokio::test]
    async fn completed_profile_is_joined_before_its_uuid_is_reused() {
        let directory = tempdir().unwrap();
        let paths = AppPaths::from_root(directory.path().join("ap"));
        let manager = ProfileManager::new(paths.clone());
        let id = Uuid::new_v4();
        let lease = ProfileLease::acquire(&paths, id).unwrap();
        let (finish, finished) = tokio::sync::oneshot::channel::<()>();
        let task = tokio::spawn(async move {
            let _ = finished.await;
            drop(lease);
        });
        manager.profiles.lock().await.insert(
            "dev".to_owned(),
            ManagedProfile {
                server_id: id,
                cancel: CancellationToken::new(),
                task,
                status: Arc::new(Mutex::new(ProfileStatus::stopped("dev", false))),
            },
        );

        finish.send(()).unwrap();
        loop {
            let is_finished = manager
                .profiles
                .lock()
                .await
                .get("dev")
                .is_some_and(|profile| profile.task.is_finished());
            if is_finished {
                break;
            }
            tokio::task::yield_now().await;
        }

        assert!(!manager.keep_current_profile_or_reap("dev", id).await);
        assert!(!manager.profiles.lock().await.contains_key("dev"));
        let reacquired = ProfileLease::acquire(&paths, id).unwrap();
        assert!(profile_is_running(&paths, id).unwrap());
        drop(reacquired);
    }

    #[test]
    fn profile_lease_detects_foreground_or_other_process() {
        let directory = tempdir().unwrap();
        let paths = AppPaths::from_root(directory.path().join("ap"));
        let id = Uuid::new_v4();
        let lease = ProfileLease::acquire(&paths, id).unwrap();
        assert!(profile_is_running(&paths, id).unwrap());
        drop(lease);
        assert!(!profile_is_running(&paths, id).unwrap());
    }

    #[tokio::test]
    async fn status_detects_external_profile_lease_and_down_refuses_it() {
        let directory = tempdir().unwrap();
        let paths = AppPaths::from_root(directory.path().join("ap"));
        let manager = ProfileManager::new(paths.clone());
        let server = manager.store.add_server("dev", "dev-alias").unwrap();
        let lease = ProfileLease::acquire(&paths, server.id).unwrap();

        let status = manager.status(Some("dev")).await.unwrap().remove(0);
        assert_eq!(status.phase, ProfilePhase::Connected);
        assert_eq!(status.ssh_pid, None);

        let error = manager.down_expected("dev", server.id).await.unwrap_err();
        assert_eq!(error.code(), "AP_PROFILE_FOREGROUND_RUNNING");

        drop(lease);
        manager.down_expected("dev", server.id).await.unwrap();
        assert_eq!(
            manager.status(Some("dev")).await.unwrap()[0].phase,
            ProfilePhase::Stopped
        );
    }

    #[tokio::test]
    async fn up_and_restart_ipc_abort_for_a_recreated_name() {
        let directory = tempdir().unwrap();
        let paths = AppPaths::from_root(directory.path().join("ap"));
        let manager = ProfileManager::new(paths);
        let old = manager.store.add_server("dev", "old-alias").unwrap();
        manager.store.remove_server("dev").unwrap();
        let replacement = manager.store.add_server("dev", "new-alias").unwrap();
        assert_ne!(old.id, replacement.id);

        for command in [
            DaemonCommand::Up {
                server: "dev".to_owned(),
                expected_server_id: old.id,
            },
            DaemonCommand::Restart {
                server: "dev".to_owned(),
                expected_server_id: old.id,
            },
        ] {
            let reply = handle_request(&manager, command).await;
            assert!(!reply.ok);
            assert_eq!(reply.code.as_deref(), Some("AP_PROFILE_IDENTITY_CHANGED"));
        }
        assert!(!profile_is_running(manager.store.paths(), replacement.id).unwrap());
    }

    #[tokio::test]
    async fn losing_daemon_lease_does_not_start_autostart_profiles() {
        let directory = tempdir().unwrap();
        let paths = AppPaths::from_root(directory.path().join("ap"));
        let store = ConfigStore::new(paths.clone());
        let server = store.add_server("dev", "dev-alias").unwrap();
        store.add_proxy("dev", test_mapping("web", 17890)).unwrap();
        store
            .update_server("dev", |profile| {
                profile.autostart = true;
                Ok(())
            })
            .unwrap();
        ProxySecretStore::new(paths.clone())
            .get_or_create(server.id)
            .unwrap();

        let existing = IpcServer::bind(paths.daemon_socket.clone()).unwrap();
        let error = run(paths.clone()).await.unwrap_err();
        assert_eq!(error.code(), "AP_DAEMON_ALREADY_RUNNING");
        assert!(!profile_is_running(&paths, server.id).unwrap());
        drop(existing);
    }
}
