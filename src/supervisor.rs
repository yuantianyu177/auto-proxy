//! Per-connection foreground and detached supervisors.
//!
//! A supervisor owns one immutable configuration snapshot, one in-memory
//! proxy credential, all local authentication gateways, and one OpenSSH
//! ControlMaster at a time. Network reconnection never reloads configuration
//! and never rotates the proxy credential.

use std::fs::{self, File, OpenOptions};
use std::io::ErrorKind;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::process::CommandExt as _;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::Duration;

use fs2::FileExt;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::process::Command;
use tokio::sync::{RwLock, oneshot};
use tokio::time::{sleep, timeout};
use tokio_util::sync::CancellationToken;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::config::{AppPaths, validate_resolved_auth};
use crate::error::{ApError, Result};
use crate::gateway::{GatewayStats, RunningGateway, start_mapping_gateway};
use crate::model::{ResolvedConnection, ResolvedSshAuth};
use crate::presentation::{EnvironmentBlock, environment_blocks, print_environment};
use crate::secrets::{ProxyCredential, SshPassword};
use crate::ssh::{
    RemoteForward, SshAuth, SshMaster, SshOptions, SshTarget, remove_loader_environment,
};

const REQUEST_LIMIT: usize = 8 * 1024;
const RESPONSE_LIMIT: usize = 4 * 1024 * 1024;
const IPC_TIMEOUT: Duration = Duration::from_secs(3);
const CLOSE_TIMEOUT: Duration = Duration::from_secs(20);
const RETRY_DELAYS: &[u64] = &[1, 2, 4, 8, 15, 30, 60];
const CONNECTION_CANCELLED_CODE: &str = "AP_CONNECTION_CANCELLED";

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum ConnectionPhase {
    Connecting,
    Connected,
    Reconnecting,
    Failed,
    Closing,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ProxyDescription {
    pub remote_port: u16,
    pub active_connections: usize,
    pub total_connections: u64,
    pub bytes_to_upstream: u64,
    pub bytes_to_client: u64,
    pub authentication_failures: u64,
    pub upstream_errors: u64,
}

/// Secret-free status returned by `ap -l` and scoped status requests.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ConnectionDescription {
    pub name: String,
    pub instance_id: Uuid,
    pub phase: ConnectionPhase,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ssh_pid: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,
    pub proxies: Vec<ProxyDescription>,
}

/// Successful connection data. This type deliberately does not implement
/// `Debug`, because its environment blocks contain the proxy password.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StartResult {
    pub description: ConnectionDescription,
    pub environment: Vec<EnvironmentBlock>,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "command", rename_all = "kebab-case", deny_unknown_fields)]
enum SupervisorRequest {
    Describe {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_name: Option<String>,
    },
    Environment {
        expected_name: String,
    },
    Close {
        expected_name: String,
        expected_instance_id: Uuid,
    },
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "result", rename_all = "kebab-case", deny_unknown_fields)]
enum SupervisorReply {
    Description {
        description: ConnectionDescription,
    },
    Environment {
        description: ConnectionDescription,
        environment: Vec<EnvironmentBlock>,
    },
    Closing {
        name: String,
        instance_id: Uuid,
    },
    Error {
        error: WireError,
    },
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct WireError {
    code: String,
    message: String,
}

impl WireError {
    fn from_error(error: &ApError) -> Self {
        let message = match error {
            ApError::Coded { message, .. } => message.clone(),
            ApError::Io(_) => error.to_string(),
        };
        Self {
            code: error.code().to_owned(),
            message,
        }
    }

    fn into_error(self) -> ApError {
        ApError::coded(self.code, self.message)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "kebab-case", deny_unknown_fields)]
enum Readiness {
    Ready { connection: StartResult },
    Error { error: WireError },
}

/// One-shot startup payload for a detached supervisor. The SSH password is
/// carried only by the private stdin pipe; it is not placed in argv, the
/// environment, the configuration snapshot, or any status response.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct StartEnvelope {
    snapshot: ResolvedConnection,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    ssh_password: Option<WirePassword>,
}

/// Serializable only for the parent-to-child startup pipe. This type has no
/// `Debug` implementation and zeroizes its allocation when either process is
/// done with it.
struct WirePassword(Zeroizing<String>);

impl WirePassword {
    fn from_runtime(password: SshPassword) -> Self {
        Self(password.copy())
    }

    fn into_runtime(self) -> Result<SshPassword> {
        SshPassword::new(self.0.as_str().to_owned())
    }
}

impl Serialize for WirePassword {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(self.0.as_str())
    }
}

impl<'de> Deserialize<'de> for WirePassword {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(|password| Self(Zeroizing::new(password)))
    }
}

struct RuntimeProxy {
    remote_port: u16,
    stats: GatewayStats,
}

struct RuntimeState {
    phase: ConnectionPhase,
    ssh_pid: Option<u32>,
    error_code: Option<String>,
}

struct SharedSupervisor {
    name: String,
    instance_id: Uuid,
    state: RwLock<RuntimeState>,
    proxies: Vec<RuntimeProxy>,
    environment: Vec<EnvironmentBlock>,
    cancel: CancellationToken,
}

impl SharedSupervisor {
    async fn describe(&self) -> ConnectionDescription {
        let state = self.state.read().await;
        ConnectionDescription {
            name: self.name.clone(),
            instance_id: self.instance_id,
            phase: state.phase,
            ssh_pid: state.ssh_pid,
            error_code: state.error_code.clone(),
            proxies: self
                .proxies
                .iter()
                .map(|proxy| {
                    let stats = proxy.stats.snapshot();
                    ProxyDescription {
                        remote_port: proxy.remote_port,
                        active_connections: stats.active_connections,
                        total_connections: stats.total_connections,
                        bytes_to_upstream: stats.bytes_to_upstream,
                        bytes_to_client: stats.bytes_to_client,
                        authentication_failures: stats.authentication_failures,
                        upstream_errors: stats.upstream_errors,
                    }
                })
                .collect(),
        }
    }

    async fn set_connected(&self, pid: Option<u32>) -> bool {
        let mut state = self.state.write().await;
        if state.phase == ConnectionPhase::Closing || self.cancel.is_cancelled() {
            return false;
        }
        state.phase = ConnectionPhase::Connected;
        state.ssh_pid = pid;
        state.error_code = None;
        true
    }

    async fn set_reconnecting(&self, error: &ApError) {
        let mut state = self.state.write().await;
        if state.phase == ConnectionPhase::Closing {
            return;
        }
        state.phase = ConnectionPhase::Reconnecting;
        state.ssh_pid = None;
        state.error_code = Some(error.code().to_owned());
    }

    async fn set_failed(&self, error: &ApError) -> bool {
        let mut state = self.state.write().await;
        if state.phase == ConnectionPhase::Closing || self.cancel.is_cancelled() {
            return false;
        }
        state.phase = ConnectionPhase::Failed;
        state.ssh_pid = None;
        state.error_code = Some(error.code().to_owned());
        true
    }

    async fn set_closing(&self) {
        let mut state = self.state.write().await;
        state.phase = ConnectionPhase::Closing;
        state.ssh_pid = None;
    }
}

struct SupervisorBinding {
    socket_path: PathBuf,
    listener: Option<UnixListener>,
    lease: File,
}

impl SupervisorBinding {
    fn take_listener(&mut self) -> UnixListener {
        self.listener
            .take()
            .expect("supervisor listener is present")
    }
}

impl Drop for SupervisorBinding {
    fn drop(&mut self) {
        self.listener.take();
        remove_owned_socket(&self.socket_path);
        let _ = FileExt::unlock(&self.lease);
    }
}

struct InitialRuntime {
    binding: SupervisorBinding,
    gateways: Vec<RunningGateway>,
    shared: Arc<SharedSupervisor>,
    control_socket: PathBuf,
}

/// Start a detached per-connection supervisor, or retrieve the current
/// environment from an already active supervisor.
pub async fn start_background(
    snapshot: ResolvedConnection,
    ssh_password: Option<SshPassword>,
    paths: &AppPaths,
) -> Result<StartResult> {
    if let Some(existing) = environment_one(&snapshot.name, paths).await? {
        return Ok(existing);
    }

    paths.ensure_runtime()?;
    paths.ensure_known_hosts()?;

    let readiness_timeout = Duration::from_secs(
        snapshot
            .ssh
            .connect_timeout_seconds
            .saturating_add(20)
            .clamp(30, 330),
    );
    let executable = std::env::current_exe()?;
    let mut command = Command::new(executable);
    command
        .arg(&snapshot.name)
        .arg("--internal-supervisor")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(false);
    remove_loader_environment(&mut command);
    unsafe {
        command.as_std_mut().pre_exec(|| {
            if libc::setsid() < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }

    let mut child = command.spawn()?;
    let mut stdin = child.stdin.take().ok_or_else(|| {
        ApError::coded(
            "AP_SUPERVISOR_PROTOCOL",
            "Detached supervisor stdin is unavailable",
        )
    })?;
    let mut stdout = child.stdout.take().ok_or_else(|| {
        ApError::coded(
            "AP_SUPERVISOR_PROTOCOL",
            "Detached supervisor stdout is unavailable",
        )
    })?;
    let envelope = StartEnvelope {
        snapshot,
        ssh_password: ssh_password.map(WirePassword::from_runtime),
    };
    let connection_name = envelope.snapshot.name.clone();
    let mut encoded = Zeroizing::new(
        serde_json::to_vec(&envelope)
            .map_err(|error| ApError::coded("AP_SUPERVISOR_PROTOCOL", error.to_string()))?,
    );
    encoded.push(b'\n');
    stdin.write_all(&encoded).await?;
    stdin.shutdown().await?;
    drop(stdin);
    drop(encoded);
    drop(envelope);

    let readiness = match timeout(
        readiness_timeout,
        read_json_frame::<_, Readiness>(&mut stdout, RESPONSE_LIMIT),
    )
    .await
    {
        Ok(result) => result?,
        Err(_) => {
            let _ = child.kill().await;
            let _ = child.wait().await;
            return Err(ApError::coded(
                "AP_SUPERVISOR_START_TIMEOUT",
                "Timed out waiting for the detached supervisor",
            ));
        }
    };

    match readiness {
        Readiness::Ready { connection } => Ok(connection),
        Readiness::Error { error } if error.code == "AP_CONNECTION_ACTIVE" => {
            // A concurrent start won the per-connection lease. Its socket may
            // still be between bind and readiness, so retry the private IPC.
            for _ in 0..100 {
                if let Some(existing) = environment_one(&connection_name, paths).await? {
                    return Ok(existing);
                }
                sleep(Duration::from_millis(50)).await;
            }
            Err(error.into_error())
        }
        Readiness::Error { error } => Err(error.into_error()),
    }
}

/// Run one connection attached to the current terminal. The environment is
/// printed after the SSH forward is ready; Ctrl-C or an IPC close request
/// performs an orderly shutdown.
pub async fn start_foreground(
    snapshot: ResolvedConnection,
    ssh_password: Option<SshPassword>,
    paths: &AppPaths,
) -> Result<()> {
    if describe_one(&snapshot.name, paths).await?.is_some() {
        return Err(ApError::coded(
            "AP_CONNECTION_ACTIVE",
            format!("Connection {:?} is already active", snapshot.name),
        ));
    }

    let cancel = CancellationToken::new();
    let signal_cancel = cancel.clone();
    let signal_task = tokio::spawn(async move {
        if tokio::signal::ctrl_c().await.is_ok() {
            signal_cancel.cancel();
        }
    });
    let (ready_tx, ready_rx) = oneshot::channel();
    let task = tokio::spawn(supervise(
        snapshot,
        ssh_password,
        paths.clone(),
        cancel,
        ready_tx,
    ));
    match ready_rx.await {
        Ok(Ok(ready)) => {
            println!("Connected: {}", ready.description.name);
            print_environment(&ready.environment);
        }
        Ok(Err(error)) => {
            signal_task.abort();
            let cancelled = error.code == CONNECTION_CANCELLED_CODE;
            let result = task
                .await
                .map_err(|error| ApError::coded("AP_SUPERVISOR_TASK", error.to_string()))?;
            if cancelled {
                return result;
            }
            return Err(error.into_error());
        }
        Err(_) => {
            signal_task.abort();
            return task
                .await
                .map_err(|error| ApError::coded("AP_SUPERVISOR_TASK", error.to_string()))?;
        }
    }
    let result = task
        .await
        .map_err(|error| ApError::coded("AP_SUPERVISOR_TASK", error.to_string()))?;
    signal_task.abort();
    result
}

/// Entry point for the hidden detached process. The caller must invoke this
/// only after the internal CLI flag has been recognized.
pub async fn run_internal_supervisor(expected_name: &str, paths: AppPaths) -> Result<()> {
    let envelope: StartEnvelope = read_json_frame(&mut tokio::io::stdin(), RESPONSE_LIMIT).await?;
    let snapshot = envelope.snapshot;
    if snapshot.name != expected_name {
        let error = ApError::coded(
            "AP_SUPERVISOR_SNAPSHOT_MISMATCH",
            "Internal supervisor name does not match the supplied snapshot",
        );
        let readiness = Readiness::Error {
            error: WireError::from_error(&error),
        };
        write_json_frame(&mut tokio::io::stdout(), &readiness).await?;
        return Err(error);
    }
    let ssh_password = envelope
        .ssh_password
        .map(WirePassword::into_runtime)
        .transpose()?;
    let cancel = CancellationToken::new();
    let (ready_tx, ready_rx) = oneshot::channel();
    let task = tokio::spawn(supervise(
        snapshot,
        ssh_password,
        paths,
        cancel.clone(),
        ready_tx,
    ));
    let readiness = match ready_rx.await {
        Ok(Ok(connection)) => Readiness::Ready { connection },
        Ok(Err(error)) => Readiness::Error { error },
        Err(_) => Readiness::Error {
            error: WireError {
                code: "AP_SUPERVISOR_TASK".into(),
                message: "Supervisor exited before reporting readiness".into(),
            },
        },
    };
    if let Err(error) = write_json_frame(&mut tokio::io::stdout(), &readiness).await {
        cancel.cancel();
        let _ = task.await;
        return Err(error);
    }
    task.await
        .map_err(|error| ApError::coded("AP_SUPERVISOR_TASK", error.to_string()))?
}

pub async fn describe_one(name: &str, paths: &AppPaths) -> Result<Option<ConnectionDescription>> {
    match send_request(
        name,
        paths,
        SupervisorRequest::Describe {
            expected_name: Some(name.to_owned()),
        },
    )
    .await?
    {
        None => Ok(None),
        Some(SupervisorReply::Description { description }) if description.name == name => {
            Ok(Some(description))
        }
        Some(SupervisorReply::Description { .. }) => Err(connection_identity_mismatch()),
        Some(SupervisorReply::Error { error }) => Err(error.into_error()),
        Some(_) => Err(ApError::coded(
            "AP_SUPERVISOR_PROTOCOL",
            "Supervisor returned an unexpected response",
        )),
    }
}

pub async fn list_active(paths: &AppPaths) -> Result<Vec<ConnectionDescription>> {
    paths.ensure_runtime()?;
    let mut descriptions = Vec::new();
    for entry in fs::read_dir(&paths.runtime_dir)? {
        let entry = entry?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        if !name.starts_with("s-") || !name.ends_with(".sock") {
            continue;
        }
        let path = entry.path();
        match is_owned_socket(&path) {
            Ok(true) => {}
            Ok(false) => continue,
            Err(ApError::Io(error)) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        }
        match send_request_to_path(
            &path,
            SupervisorRequest::Describe {
                expected_name: None,
            },
        )
        .await?
        {
            None => {}
            Some(SupervisorReply::Description { description }) => {
                descriptions.push(description);
            }
            Some(SupervisorReply::Error { error }) => return Err(error.into_error()),
            Some(_) => {
                return Err(ApError::coded(
                    "AP_SUPERVISOR_PROTOCOL",
                    format!(
                        "Supervisor socket returned an unexpected response: {}",
                        path.display()
                    ),
                ));
            }
        }
    }
    descriptions.sort_by(|left, right| left.name.cmp(&right.name));
    descriptions.dedup_by(|left, right| left.name == right.name);
    Ok(descriptions)
}

pub async fn close_one(name: &str, paths: &AppPaths) -> Result<bool> {
    let Some(description) = describe_one(name, paths).await? else {
        return Ok(false);
    };
    close_instance(&description, paths).await
}

/// Close exactly the supervisor generation represented by `description`.
/// A replacement with the same connection name is never closed accidentally.
pub async fn close_instance(description: &ConnectionDescription, paths: &AppPaths) -> Result<bool> {
    let name = &description.name;
    let instance_id = description.instance_id;
    let socket = supervisor_socket_path(paths, name);
    let reply = send_request_to_path(
        &socket,
        SupervisorRequest::Close {
            expected_name: name.to_owned(),
            expected_instance_id: instance_id,
        },
    )
    .await?;
    match reply {
        None => Ok(false),
        Some(SupervisorReply::Closing {
            name: closed_name,
            instance_id: closed_instance_id,
        }) if closed_name == *name && closed_instance_id == instance_id => {
            wait_until_inactive(description, paths).await?;
            Ok(true)
        }
        Some(SupervisorReply::Closing { .. }) => Err(connection_identity_mismatch()),
        Some(SupervisorReply::Error { error }) => Err(error.into_error()),
        Some(_) => Err(ApError::coded(
            "AP_SUPERVISOR_PROTOCOL",
            "Supervisor returned an unexpected response",
        )),
    }
}

/// Wait until this exact supervisor generation has released its runtime
/// socket. A replacement generation satisfies the wait without being stopped.
pub async fn wait_until_inactive(
    description: &ConnectionDescription,
    paths: &AppPaths,
) -> Result<()> {
    let name = &description.name;
    let instance_id = description.instance_id;
    let socket = supervisor_socket_path(paths, name);
    timeout(CLOSE_TIMEOUT, async {
        loop {
            match describe_one(name, paths).await {
                Ok(Some(current)) if current.instance_id == instance_id => {
                    sleep(Duration::from_millis(50)).await;
                }
                Ok(Some(_)) => break Ok::<(), ApError>(()),
                Ok(None) if socket.exists() => {
                    // The IPC listener can disappear just before the binding
                    // removes its socket and releases the connection lease.
                    sleep(Duration::from_millis(50)).await;
                }
                Ok(None) => break Ok::<(), ApError>(()),
                Err(error) if error.code() == "AP_SUPERVISOR_IPC_TIMEOUT" && socket.exists() => {
                    sleep(Duration::from_millis(50)).await;
                }
                Err(error) => break Err(error),
            }
        }
    })
    .await
    .map_err(|_| {
        ApError::coded(
            "AP_CONNECTION_CLOSE_TIMEOUT",
            format!("Timed out closing connection {name:?}"),
        )
    })??;
    Ok(())
}

pub async fn close_all(paths: &AppPaths) -> Result<usize> {
    let active = list_active(paths).await?;
    let mut closed = 0;
    let mut failures = Vec::new();
    for connection in active {
        match close_instance(&connection, paths).await {
            Ok(true) => closed += 1,
            Ok(false) => {}
            Err(error) => failures.push(format!("{}: {}", connection.name, error.code())),
        }
    }
    if failures.is_empty() {
        Ok(closed)
    } else {
        Err(ApError::coded(
            "AP_CLOSE_FAILED",
            format!("Failed to close {}", failures.join(", ")),
        ))
    }
}

/// Retrieve the current environment without reading the configuration file.
/// This remains available even if an active connection was removed from, or
/// outlived a malformed, user configuration.
pub async fn environment_one(name: &str, paths: &AppPaths) -> Result<Option<StartResult>> {
    match send_request(
        name,
        paths,
        SupervisorRequest::Environment {
            expected_name: name.to_owned(),
        },
    )
    .await?
    {
        None => Ok(None),
        Some(SupervisorReply::Environment {
            description,
            environment,
        }) if description.name == name => Ok(Some(StartResult {
            description,
            environment,
        })),
        Some(SupervisorReply::Environment { .. }) => Err(connection_identity_mismatch()),
        Some(SupervisorReply::Error { error }) => Err(error.into_error()),
        Some(_) => Err(ApError::coded(
            "AP_SUPERVISOR_PROTOCOL",
            "Supervisor returned an unexpected response",
        )),
    }
}

async fn supervise(
    snapshot: ResolvedConnection,
    mut ssh_password: Option<SshPassword>,
    paths: AppPaths,
    cancel: CancellationToken,
    ready: oneshot::Sender<std::result::Result<StartResult, WireError>>,
) -> Result<()> {
    let mut ready = Some(ready);
    if let Err(error) = snapshot.validate() {
        if let Some(sender) = ready.take() {
            let _ = sender.send(Err(WireError::from_error(&error)));
        }
        return Err(error);
    }
    if let Err(error) = validate_runtime_password(&snapshot, ssh_password.as_ref()) {
        if let Some(sender) = ready.take() {
            let _ = sender.send(Err(WireError::from_error(&error)));
        }
        return Err(error);
    }
    let initial = match prepare_initial(&snapshot, &paths, cancel.clone()).await {
        Ok(initial) => initial,
        Err(error) => {
            if let Some(sender) = ready.take() {
                let _ = sender.send(Err(WireError::from_error(&error)));
            }
            return if error.code() == CONNECTION_CANCELLED_CODE {
                Ok(())
            } else {
                Err(error)
            };
        }
    };

    let InitialRuntime {
        mut binding,
        gateways,
        shared,
        control_socket,
    } = initial;
    let listener = binding.take_listener();
    let ipc_shared = Arc::clone(&shared);
    let ipc_task = tokio::spawn(async move { serve_ipc(listener, ipc_shared).await });

    // Publish the supervisor socket and the Connecting state before waiting on
    // OpenSSH. This keeps list/close/restart responsive throughout bootstrap.
    let automatic_reconnect = supports_automatic_reconnect(&snapshot.ssh.auth);
    let initial_master = tokio::select! {
        biased;
        _ = shared.cancel.cancelled() => None,
        result = start_ssh(
            &snapshot,
            ssh_password.take(),
            &paths,
            &gateways,
            &control_socket,
        ) => Some(result),
    };
    let master = match initial_master {
        Some(Ok(master)) if shared.set_connected(master.pid()).await => master,
        Some(Ok(master)) => {
            let _ = master.shutdown().await;
            shared.set_closing().await;
            let error = connection_cancelled_error();
            if let Some(sender) = ready.take() {
                let _ = sender.send(Err(WireError::from_error(&error)));
            }
            shutdown_supervisor(ipc_task, gateways).await;
            drop(binding);
            return Ok(());
        }
        Some(Err(error)) => {
            if !shared.set_failed(&error).await {
                shared.set_closing().await;
                let cancelled = connection_cancelled_error();
                if let Some(sender) = ready.take() {
                    let _ = sender.send(Err(WireError::from_error(&cancelled)));
                }
                shutdown_supervisor(ipc_task, gateways).await;
                drop(binding);
                return Ok(());
            }
            if let Some(sender) = ready.take() {
                let _ = sender.send(Err(WireError::from_error(&error)));
            }
            shared.cancel.cancel();
            shutdown_supervisor(ipc_task, gateways).await;
            drop(binding);
            return Err(error);
        }
        None => {
            shared.set_closing().await;
            let error = connection_cancelled_error();
            if let Some(sender) = ready.take() {
                let _ = sender.send(Err(WireError::from_error(&error)));
            }
            shutdown_supervisor(ipc_task, gateways).await;
            drop(binding);
            return Ok(());
        }
    };

    let start_result = StartResult {
        description: shared.describe().await,
        environment: shared.environment.clone(),
    };
    if ready
        .take()
        .is_some_and(|sender| sender.send(Ok(start_result)).is_err())
    {
        shared.cancel.cancel();
    }

    let mut master = Some(master);
    let mut retry_index = 0_usize;
    loop {
        let active = master.as_mut().expect("SSH master is active");
        let event = tokio::select! {
            _ = shared.cancel.cancelled() => {
                None
            }
            status = active.wait() => {
                Some(match status {
                    Ok(status) => active.exit_error(status),
                    Err(error) => error,
                })
            }
        };
        let Some(error) = event else {
            shared.set_closing().await;
            if let Some(master) = master.take() {
                let _ = master.shutdown().await;
            }
            break;
        };
        drop(master.take());
        if !automatic_reconnect {
            // Passwords are intentionally one-shot. They are discarded after
            // the initial authentication, so a disconnected password-based
            // connection ends and a later `ap <name>` prompts again.
            shared.set_closing().await;
            break;
        }
        if is_permanent_ssh_error(&error) {
            let _ = shared.set_failed(&error).await;
            shared.cancel.cancelled().await;
            break;
        }
        shared.set_reconnecting(&error).await;

        let delay = RETRY_DELAYS[retry_index.min(RETRY_DELAYS.len() - 1)];
        retry_index = retry_index.saturating_add(1);
        tokio::select! {
            _ = shared.cancel.cancelled() => break,
            _ = sleep(Duration::from_secs(delay)) => {}
        }

        loop {
            if shared.cancel.is_cancelled() {
                break;
            }
            let attempt = tokio::select! {
                biased;
                _ = shared.cancel.cancelled() => None,
                result = start_ssh(
                    &snapshot,
                    None,
                    &paths,
                    &gateways,
                    &control_socket,
                ) => Some(result),
            };
            let Some(attempt) = attempt else {
                break;
            };
            match attempt {
                Ok(new_master) => {
                    if shared.set_connected(new_master.pid()).await {
                        master = Some(new_master);
                        retry_index = 0;
                    } else {
                        let _ = new_master.shutdown().await;
                    }
                    break;
                }
                Err(error) if is_permanent_ssh_error(&error) => {
                    let _ = shared.set_failed(&error).await;
                    shared.cancel.cancelled().await;
                    break;
                }
                Err(error) => {
                    shared.set_reconnecting(&error).await;
                    let delay = RETRY_DELAYS[retry_index.min(RETRY_DELAYS.len() - 1)];
                    retry_index = retry_index.saturating_add(1);
                    tokio::select! {
                        _ = shared.cancel.cancelled() => break,
                        _ = sleep(Duration::from_secs(delay)) => {}
                    }
                }
            }
        }
        if shared.cancel.is_cancelled()
            || shared.state.read().await.phase == ConnectionPhase::Failed
        {
            break;
        }
    }

    shared.cancel.cancel();
    shutdown_supervisor(ipc_task, gateways).await;
    drop(binding);
    Ok(())
}

async fn prepare_initial(
    snapshot: &ResolvedConnection,
    paths: &AppPaths,
    cancel: CancellationToken,
) -> Result<InitialRuntime> {
    paths.ensure_runtime()?;
    paths.ensure_known_hosts()?;
    let binding = bind_supervisor(paths, &snapshot.name)?;
    if cancel.is_cancelled() {
        return Err(connection_cancelled_error());
    }
    let credential = ProxyCredential::generate()?;
    let environment = environment_blocks(snapshot, &credential);

    let mut gateways = Vec::with_capacity(snapshot.proxies.len());
    for mapping in &snapshot.proxies {
        if cancel.is_cancelled() {
            shutdown_gateways(gateways).await;
            return Err(connection_cancelled_error());
        }
        match start_mapping_gateway(mapping, &credential, cancel.clone()).await {
            Ok(gateway) => gateways.push(gateway),
            Err(error) => {
                shutdown_gateways(gateways).await;
                return Err(ApError::coded(
                    "AP_GATEWAY_START_FAILED",
                    format!(
                        "Unable to start proxy on remote port {}: {error}",
                        mapping.remote_port
                    ),
                ));
            }
        }
    }

    let instance_id = Uuid::new_v4();
    let control_socket = paths.control_socket(instance_id);
    let proxies = snapshot
        .proxies
        .iter()
        .zip(&gateways)
        .map(|(mapping, gateway)| RuntimeProxy {
            remote_port: mapping.remote_port,
            stats: gateway.stats.clone(),
        })
        .collect();
    let shared = Arc::new(SharedSupervisor {
        name: snapshot.name.clone(),
        instance_id,
        state: RwLock::new(RuntimeState {
            phase: ConnectionPhase::Connecting,
            ssh_pid: None,
            error_code: None,
        }),
        proxies,
        environment,
        cancel,
    });
    Ok(InitialRuntime {
        binding,
        gateways,
        shared,
        control_socket,
    })
}

fn connection_cancelled_error() -> ApError {
    ApError::coded(
        CONNECTION_CANCELLED_CODE,
        "Connection startup was cancelled",
    )
}

async fn shutdown_supervisor(
    ipc_task: tokio::task::JoinHandle<Result<()>>,
    gateways: Vec<RunningGateway>,
) {
    shutdown_gateways(gateways).await;
    ipc_task.abort();
    let _ = ipc_task.await;
}

async fn shutdown_gateways(gateways: Vec<RunningGateway>) {
    for gateway in gateways {
        gateway.shutdown().await;
    }
}

async fn start_ssh(
    snapshot: &ResolvedConnection,
    ssh_password: Option<SshPassword>,
    paths: &AppPaths,
    gateways: &[RunningGateway],
    control_socket: &Path,
) -> Result<SshMaster> {
    validate_resolved_auth(&snapshot.ssh.auth)?;
    let target = SshTarget {
        host: snapshot.ssh.host.clone(),
        user: snapshot.ssh.user.clone(),
        port: snapshot.ssh.port,
        known_hosts: paths.known_hosts_file.clone(),
        connect_timeout: Duration::from_secs(snapshot.ssh.connect_timeout_seconds),
    };
    let auth = match &snapshot.ssh.auth {
        ResolvedSshAuth::Key { identity_file } => SshAuth::Key {
            identity_file: identity_file.clone(),
        },
        ResolvedSshAuth::Password => {
            let password = ssh_password.ok_or_else(|| {
                ApError::coded(
                    "AP_SSH_PASSWORD_REQUIRED",
                    format!(
                        "SSH password is required for connection {:?}",
                        snapshot.name
                    ),
                )
            })?;
            SshAuth::Password {
                provider: Arc::new(move || Ok(password.copy())),
            }
        }
    };
    let forwards = snapshot
        .proxies
        .iter()
        .zip(gateways)
        .map(|(mapping, gateway)| RemoteForward {
            remote_port: mapping.remote_port,
            local_gateway: gateway.listen_addr,
        })
        .collect();
    let mut options = SshOptions::new(target, control_socket.to_owned(), forwards, auth)?;
    options.startup_timeout = Duration::from_secs(
        snapshot
            .ssh
            .connect_timeout_seconds
            .saturating_add(10)
            .clamp(15, 310),
    );
    SshMaster::start(options).await
}

fn validate_runtime_password(
    snapshot: &ResolvedConnection,
    ssh_password: Option<&SshPassword>,
) -> Result<()> {
    validate_resolved_auth(&snapshot.ssh.auth)?;
    match (&snapshot.ssh.auth, ssh_password) {
        (ResolvedSshAuth::Key { .. }, None) | (ResolvedSshAuth::Password, Some(_)) => Ok(()),
        (ResolvedSshAuth::Password, None) => Err(ApError::coded(
            "AP_SSH_PASSWORD_REQUIRED",
            format!(
                "SSH password is required for connection {:?}",
                snapshot.name
            ),
        )),
        (ResolvedSshAuth::Key { .. }, Some(_)) => Err(ApError::coded(
            "AP_SUPERVISOR_PROTOCOL",
            "An SSH password was supplied for a key-authenticated connection",
        )),
    }
}

fn is_permanent_ssh_error(error: &ApError) -> bool {
    !matches!(
        error.code(),
        "AP_SSH_EXITED" | "AP_SSH_START_TIMEOUT" | "AP_IO_ERROR"
    )
}

fn supports_automatic_reconnect(auth: &ResolvedSshAuth) -> bool {
    matches!(auth, ResolvedSshAuth::Key { .. })
}

async fn serve_ipc(listener: UnixListener, shared: Arc<SharedSupervisor>) -> Result<()> {
    loop {
        tokio::select! {
            _ = shared.cancel.cancelled() => return Ok(()),
            accepted = listener.accept() => {
                let (stream, _) = accepted?;
                let shared = Arc::clone(&shared);
                tokio::spawn(async move {
                    let _ = handle_client(stream, shared).await;
                });
            }
        }
    }
}

async fn handle_client(mut stream: UnixStream, shared: Arc<SharedSupervisor>) -> Result<()> {
    if peer_uid(&stream)? != effective_uid() {
        return Err(ApError::coded(
            "AP_SUPERVISOR_PEER_REJECTED",
            "Supervisor IPC peer UID does not match",
        ));
    }
    let request: SupervisorRequest = read_json_frame(&mut stream, REQUEST_LIMIT).await?;
    let reply = match request {
        SupervisorRequest::Describe { expected_name } => {
            if expected_name
                .as_deref()
                .is_some_and(|name| name != shared.name)
            {
                identity_mismatch_reply()
            } else {
                SupervisorReply::Description {
                    description: shared.describe().await,
                }
            }
        }
        SupervisorRequest::Environment { expected_name } => {
            if expected_name != shared.name {
                identity_mismatch_reply()
            } else {
                SupervisorReply::Environment {
                    description: shared.describe().await,
                    environment: shared.environment.clone(),
                }
            }
        }
        SupervisorRequest::Close {
            expected_name,
            expected_instance_id,
        } if expected_name != shared.name || expected_instance_id != shared.instance_id => {
            identity_mismatch_reply()
        }
        SupervisorRequest::Close { .. } => {
            shared.set_closing().await;
            shared.cancel.cancel();
            SupervisorReply::Closing {
                name: shared.name.clone(),
                instance_id: shared.instance_id,
            }
        }
    };
    write_json_frame(&mut stream, &reply).await
}

fn identity_mismatch_reply() -> SupervisorReply {
    SupervisorReply::Error {
        error: WireError {
            code: "AP_CONNECTION_IDENTITY_MISMATCH".into(),
            message: "Supervisor connection identity does not match the request".into(),
        },
    }
}

fn connection_identity_mismatch() -> ApError {
    ApError::coded(
        "AP_CONNECTION_IDENTITY_MISMATCH",
        "Supervisor connection identity does not match the request",
    )
}

async fn send_request(
    name: &str,
    paths: &AppPaths,
    request: SupervisorRequest,
) -> Result<Option<SupervisorReply>> {
    send_request_to_path(&supervisor_socket_path(paths, name), request).await
}

async fn send_request_to_path(
    path: &Path,
    request: SupervisorRequest,
) -> Result<Option<SupervisorReply>> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(metadata)
            if metadata.file_type().is_symlink()
                || !metadata.file_type().is_socket()
                || metadata.uid() != effective_uid() =>
        {
            return Err(ApError::coded(
                "AP_SUPERVISOR_SOCKET_UNSAFE",
                format!(
                    "Supervisor socket is not a user-owned Unix socket: {}",
                    path.display()
                ),
            ));
        }
        Ok(_) => {}
    }

    let mut stream = match timeout(IPC_TIMEOUT, UnixStream::connect(path)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(error))
            if matches!(
                error.kind(),
                ErrorKind::NotFound | ErrorKind::ConnectionRefused
            ) =>
        {
            return Ok(None);
        }
        Ok(Err(error)) => return Err(error.into()),
        Err(_) => {
            return Err(ApError::coded(
                "AP_SUPERVISOR_IPC_TIMEOUT",
                format!(
                    "Timed out connecting to supervisor socket {}",
                    path.display()
                ),
            ));
        }
    };
    timeout(IPC_TIMEOUT, write_json_frame(&mut stream, &request))
        .await
        .map_err(|_| ApError::coded("AP_SUPERVISOR_IPC_TIMEOUT", "Supervisor write timed out"))??;
    let reply = timeout(
        IPC_TIMEOUT,
        read_json_frame::<_, SupervisorReply>(&mut stream, RESPONSE_LIMIT),
    )
    .await
    .map_err(|_| ApError::coded("AP_SUPERVISOR_IPC_TIMEOUT", "Supervisor response timed out"))??;
    Ok(Some(reply))
}

fn bind_supervisor(paths: &AppPaths, name: &str) -> Result<SupervisorBinding> {
    let socket_path = supervisor_socket_path(paths, name);
    let lock_path = supervisor_lock_path(paths, name);
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let lease = options.open(&lock_path).map_err(|error| {
        ApError::coded(
            "AP_SUPERVISOR_LEASE_FAILED",
            format!(
                "Unable to open supervisor lease {}: {error}",
                lock_path.display()
            ),
        )
    })?;
    let metadata = lease.metadata()?;
    if !metadata.is_file() || metadata.uid() != effective_uid() {
        return Err(ApError::coded(
            "AP_SUPERVISOR_LEASE_UNSAFE",
            "Supervisor lease must be a regular file owned by the current user",
        ));
    }
    lease.set_permissions(fs::Permissions::from_mode(0o600))?;
    if let Err(error) = FileExt::try_lock_exclusive(&lease) {
        if error.kind() == ErrorKind::WouldBlock {
            return Err(ApError::coded(
                "AP_CONNECTION_ACTIVE",
                format!("Connection {name:?} is already active"),
            ));
        }
        return Err(ApError::coded(
            "AP_SUPERVISOR_LEASE_FAILED",
            format!("Unable to lock supervisor lease: {error}"),
        ));
    }

    if socket_path.exists() {
        if !is_owned_socket(&socket_path)? {
            return Err(ApError::coded(
                "AP_SUPERVISOR_SOCKET_UNSAFE",
                format!(
                    "Refusing to replace an unsafe supervisor socket: {}",
                    socket_path.display()
                ),
            ));
        }
        fs::remove_file(&socket_path)?;
    }
    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;
    Ok(SupervisorBinding {
        socket_path,
        listener: Some(listener),
        lease,
    })
}

fn is_owned_socket(path: &Path) -> Result<bool> {
    let metadata = fs::symlink_metadata(path)?;
    Ok(!metadata.file_type().is_symlink()
        && metadata.file_type().is_socket()
        && metadata.uid() == effective_uid())
}

fn remove_owned_socket(path: &Path) {
    if is_owned_socket(path).unwrap_or(false) {
        let _ = fs::remove_file(path);
    }
}

fn supervisor_socket_path(paths: &AppPaths, name: &str) -> PathBuf {
    paths
        .runtime_dir
        .join(format!("s-{}.sock", connection_key(name)))
}

fn supervisor_lock_path(paths: &AppPaths, name: &str) -> PathBuf {
    paths
        .runtime_dir
        .join(format!("s-{}.lock", connection_key(name)))
}

fn connection_key(name: &str) -> String {
    fn hash(bytes: &[u8], seed: u64) -> u64 {
        let mut value = seed;
        for byte in bytes {
            value ^= u64::from(*byte);
            value = value.wrapping_mul(0x0000_0100_0000_01b3);
        }
        value
    }
    format!(
        "{:016x}{:016x}",
        hash(name.as_bytes(), 0xcbf2_9ce4_8422_2325),
        hash(name.as_bytes(), 0x8422_2325_cbf2_9ce4)
    )
}

async fn write_json_frame<W: AsyncWriteExt + Unpin, T: Serialize>(
    writer: &mut W,
    value: &T,
) -> Result<()> {
    let mut encoded = Zeroizing::new(
        serde_json::to_vec(value)
            .map_err(|error| ApError::coded("AP_SUPERVISOR_PROTOCOL", error.to_string()))?,
    );
    if encoded.len() > RESPONSE_LIMIT {
        return Err(ApError::coded(
            "AP_SUPERVISOR_PROTOCOL",
            "Supervisor JSON frame is too large",
        ));
    }
    encoded.push(b'\n');
    writer.write_all(&encoded).await?;
    writer.flush().await?;
    Ok(())
}

async fn read_json_frame<R: AsyncReadExt + Unpin, T: DeserializeOwned>(
    reader: &mut R,
    limit: usize,
) -> Result<T> {
    let mut bytes = Zeroizing::new(Vec::with_capacity(1024));
    let mut byte = [0_u8; 1];
    loop {
        let read = reader.read(&mut byte).await?;
        if read == 0 {
            return Err(ApError::coded(
                "AP_SUPERVISOR_PROTOCOL",
                "Supervisor JSON frame ended before a newline",
            ));
        }
        if byte[0] == b'\n' {
            break;
        }
        if bytes.len() >= limit {
            return Err(ApError::coded(
                "AP_SUPERVISOR_PROTOCOL",
                "Supervisor JSON frame is too large",
            ));
        }
        bytes.push(byte[0]);
    }
    serde_json::from_slice(&bytes)
        .map_err(|error| ApError::coded("AP_SUPERVISOR_PROTOCOL", error.to_string()))
}

#[cfg(target_os = "linux")]
fn peer_uid(stream: &UnixStream) -> Result<libc::uid_t> {
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credentials).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(credentials.uid)
}

#[cfg(target_os = "macos")]
fn peer_uid(stream: &UnixStream) -> Result<libc::uid_t> {
    let mut uid = 0;
    let mut gid = 0;
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(uid)
}

fn effective_uid() -> libc::uid_t {
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gateway::GatewayStats;
    use crate::model::{ProxyMapping, ProxyProtocol, ResolvedSshConfig};
    use crate::secrets::ProxyCredential;
    use tempfile::TempDir;

    fn paths(temp: &TempDir) -> AppPaths {
        let runtime = temp.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        fs::set_permissions(&runtime, fs::Permissions::from_mode(0o700)).unwrap();
        AppPaths::from_xdg_dirs(
            temp.path().join("config"),
            temp.path().join("state"),
            runtime,
        )
        .unwrap()
    }

    fn short_temp() -> TempDir {
        // macOS test sandboxes may deny Unix-domain sockets in the system
        // temporary directory even when ordinary files are allowed there.
        // The repository path is short enough to retain sockaddr_un headroom.
        tempfile::tempdir_in(std::env::current_dir().unwrap()).unwrap()
    }

    fn snapshot() -> ResolvedConnection {
        ResolvedConnection {
            name: "dev".into(),
            ssh: ResolvedSshConfig {
                host: "server.example".into(),
                port: 22,
                user: "alice".into(),
                connect_timeout_seconds: 15,
                auth: ResolvedSshAuth::Password,
            },
            proxies: vec![ProxyMapping {
                protocol: ProxyProtocol::Mixed,
                local: "127.0.0.1:7890".parse().unwrap(),
                remote_port: 17890,
            }],
        }
    }

    fn shared(secret: &str) -> Arc<SharedSupervisor> {
        shared_named("dev", secret)
    }

    fn shared_named(name: &str, secret: &str) -> Arc<SharedSupervisor> {
        let snapshot = snapshot();
        let credential = ProxyCredential::from_parts("ap", secret);
        Arc::new(SharedSupervisor {
            name: name.into(),
            instance_id: Uuid::new_v4(),
            state: RwLock::new(RuntimeState {
                phase: ConnectionPhase::Connected,
                ssh_pid: Some(123),
                error_code: None,
            }),
            proxies: vec![RuntimeProxy {
                remote_port: 17890,
                stats: GatewayStats::default(),
            }],
            environment: environment_blocks(&snapshot, &credential),
            cancel: CancellationToken::new(),
        })
    }

    #[test]
    fn connection_socket_key_is_stable_and_name_free() {
        let first = connection_key("dev");
        assert_eq!(first, connection_key("dev"));
        assert_ne!(first, connection_key("prod"));
        assert!(!first.contains("dev"));
        assert_eq!(first.len(), 32);
    }

    #[test]
    fn password_auth_requires_runtime_secret() {
        let snapshot = snapshot();
        let error = validate_runtime_password(&snapshot, None).unwrap_err();
        assert_eq!(error.code(), "AP_SSH_PASSWORD_REQUIRED");

        let password = SshPassword::new("top-secret".to_owned()).unwrap();
        validate_runtime_password(&snapshot, Some(&password)).unwrap();
    }

    #[test]
    fn only_key_authentication_can_reconnect_without_user_input() {
        assert!(!supports_automatic_reconnect(&ResolvedSshAuth::Password));
        assert!(supports_automatic_reconnect(&ResolvedSshAuth::Key {
            identity_file: PathBuf::from("/keys/id_ed25519"),
        }));
    }

    #[test]
    fn wire_password_round_trips_through_startup_encoding() {
        let password = SshPassword::new("top-secret".to_owned()).unwrap();
        let wire = WirePassword::from_runtime(password);
        let encoded = Zeroizing::new(serde_json::to_vec(&wire).unwrap());
        let decoded: WirePassword = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(
            decoded.into_runtime().unwrap().copy().as_str(),
            "top-secret"
        );
    }

    #[tokio::test]
    async fn description_is_secret_free() {
        let description = shared("top-secret").describe().await;
        let encoded = serde_json::to_string(&description).unwrap();
        assert!(!encoded.contains("top-secret"));
        assert!(!encoded.contains("http_proxy"));
        assert_eq!(description.phase, ConnectionPhase::Connected);
    }

    #[tokio::test]
    async fn private_ipc_reuses_the_same_environment() {
        let temp = short_temp();
        let paths = paths(&temp);
        paths.ensure_runtime().unwrap();
        let socket = supervisor_socket_path(&paths, "dev");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let shared = shared("stable-secret");
        let server = tokio::spawn(serve_ipc(listener, Arc::clone(&shared)));

        let first = environment_one("dev", &paths).await.unwrap().unwrap();
        let second = environment_one("dev", &paths).await.unwrap().unwrap();
        assert_eq!(
            first.environment[0].variables[0].value,
            second.environment[0].variables[0].value
        );
        assert!(
            first.environment[0].variables[0]
                .value
                .contains("stable-secret")
        );

        shared.cancel.cancel();
        server.await.unwrap().unwrap();
        let _ = fs::remove_file(socket);
    }

    #[tokio::test]
    async fn close_request_cancels_the_supervisor() {
        let temp = short_temp();
        let paths = paths(&temp);
        paths.ensure_runtime().unwrap();
        let socket = supervisor_socket_path(&paths, "dev");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let shared = shared("secret");
        let server = tokio::spawn(serve_ipc(listener, Arc::clone(&shared)));
        let reply = send_request_to_path(
            &socket,
            SupervisorRequest::Close {
                expected_name: "dev".into(),
                expected_instance_id: shared.instance_id,
            },
        )
        .await
        .unwrap();
        assert!(matches!(
            reply,
            Some(SupervisorReply::Closing { name, instance_id })
                if name == "dev" && instance_id == shared.instance_id
        ));
        timeout(Duration::from_secs(1), shared.cancel.cancelled())
            .await
            .unwrap();
        server.await.unwrap().unwrap();
        let _ = fs::remove_file(socket);
    }

    #[tokio::test]
    async fn binding_reclaims_only_an_owned_stale_socket() {
        let temp = short_temp();
        let paths = paths(&temp);
        paths.ensure_runtime().unwrap();
        let socket = supervisor_socket_path(&paths, "dev");
        let stale = UnixListener::bind(&socket).unwrap();
        drop(stale);
        let binding = bind_supervisor(&paths, "dev").unwrap();
        assert!(socket.exists());
        drop(binding);
        assert!(!socket.exists());
    }

    #[tokio::test]
    async fn expected_name_blocks_collision_reads_and_closes() {
        let temp = short_temp();
        let paths = paths(&temp);
        paths.ensure_runtime().unwrap();
        let socket = supervisor_socket_path(&paths, "dev");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let shared = shared_named("other", "must-not-leak");
        let server = tokio::spawn(serve_ipc(listener, Arc::clone(&shared)));

        let environment = send_request_to_path(
            &socket,
            SupervisorRequest::Environment {
                expected_name: "dev".into(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(environment, Some(SupervisorReply::Error { .. })));

        let close = send_request_to_path(
            &socket,
            SupervisorRequest::Close {
                expected_name: "dev".into(),
                expected_instance_id: shared.instance_id,
            },
        )
        .await
        .unwrap();
        assert!(matches!(close, Some(SupervisorReply::Error { .. })));
        assert!(!shared.cancel.is_cancelled());

        shared.cancel.cancel();
        server.await.unwrap().unwrap();
        let _ = fs::remove_file(socket);
    }

    #[tokio::test]
    async fn expected_instance_blocks_replacement_close() {
        let temp = short_temp();
        let paths = paths(&temp);
        paths.ensure_runtime().unwrap();
        let socket = supervisor_socket_path(&paths, "dev");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let shared = shared("must-stay-active");
        let server = tokio::spawn(serve_ipc(listener, Arc::clone(&shared)));

        let close = send_request_to_path(
            &socket,
            SupervisorRequest::Close {
                expected_name: "dev".into(),
                expected_instance_id: Uuid::new_v4(),
            },
        )
        .await
        .unwrap();
        assert!(matches!(close, Some(SupervisorReply::Error { .. })));
        assert!(!shared.cancel.is_cancelled());

        shared.cancel.cancel();
        server.await.unwrap().unwrap();
        let _ = fs::remove_file(socket);
    }

    #[tokio::test]
    async fn connecting_supervisor_is_listed_and_closeable() {
        let temp = short_temp();
        let paths = paths(&temp);
        paths.ensure_runtime().unwrap();
        let mut binding = bind_supervisor(&paths, "dev").unwrap();
        let listener = binding.take_listener();
        let shared = shared("bootstrap-secret");
        shared.state.write().await.phase = ConnectionPhase::Connecting;
        let server = tokio::spawn(serve_ipc(listener, Arc::clone(&shared)));
        let cleanup = tokio::spawn(async move {
            server.await.unwrap().unwrap();
            drop(binding);
        });

        let active = list_active(&paths).await.unwrap();
        assert_eq!(active.len(), 1);
        assert_eq!(active[0].instance_id, shared.instance_id);
        assert_eq!(active[0].phase, ConnectionPhase::Connecting);
        assert!(close_instance(&active[0], &paths).await.unwrap());
        assert!(shared.cancel.is_cancelled());

        cleanup.await.unwrap();
    }

    #[tokio::test]
    async fn list_propagates_a_supervisor_protocol_error() {
        let temp = short_temp();
        let paths = paths(&temp);
        paths.ensure_runtime().unwrap();
        let socket = supervisor_socket_path(&paths, "dev");
        let listener = UnixListener::bind(&socket).unwrap();
        fs::set_permissions(&socket, fs::Permissions::from_mode(0o600)).unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let _: SupervisorRequest = read_json_frame(&mut stream, REQUEST_LIMIT).await.unwrap();
            stream.write_all(b"{}\n").await.unwrap();
        });

        let error = list_active(&paths).await.unwrap_err();
        assert_eq!(error.code(), "AP_SUPERVISOR_PROTOCOL");

        server.await.unwrap();
        let _ = fs::remove_file(socket);
    }
}
