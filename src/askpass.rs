//! One-shot OpenSSH AskPass bridge.
//!
//! The SSH password is deliberately not placed in argv or the environment.  A
//! short-lived nonce in the environment authorizes exactly one request over a
//! private Unix socket; the password is fetched only after that request has
//! been validated.

use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::JoinHandle;
use tokio::time::timeout;
use zeroize::{Zeroize, Zeroizing};

#[cfg(target_os = "macos")]
use core_foundation::{
    base::TCFType,
    data::CFData,
    dictionary::{CFDictionary, CFDictionaryGetValue, CFDictionaryRef},
    string::CFStringRef,
};
#[cfg(target_os = "macos")]
use security_framework::os::macos::code_signing::{
    Flags as CodeFlags, GuestAttributes, SecCode, SecRequirement,
};

use crate::error::{ApError, Result};

pub const SOCKET_ENV: &str = "AP_ASKPASS_SOCKET";
pub const NONCE_ENV: &str = "AP_ASKPASS_NONCE";
pub const MODE_ENV: &str = "AP_ASKPASS_MODE";
const MODE_VALUE: &str = "ssh-password-v1";
const MAX_REQUEST: usize = 4096;
const MAX_PASSWORD: usize = 64 * 1024;

pub type PasswordProvider = Arc<dyn Fn() -> Result<Zeroizing<String>> + Send + Sync>;

#[derive(Debug, Serialize, Deserialize)]
struct Request {
    nonce: String,
    pid: u32,
    parent_pid: u32,
}

/// Environment additions required by OpenSSH for a stored-password attempt.
#[derive(Clone, Debug)]
pub struct AskpassEnvironment {
    pub socket: PathBuf,
    pub nonce: String,
}

impl AskpassEnvironment {
    pub fn variables(&self, executable: &Path) -> [(OsString, OsString); 5] {
        [
            (
                OsString::from("SSH_ASKPASS"),
                executable.as_os_str().to_owned(),
            ),
            (
                OsString::from("SSH_ASKPASS_REQUIRE"),
                OsString::from("force"),
            ),
            (OsString::from(MODE_ENV), OsString::from(MODE_VALUE)),
            (
                OsString::from(SOCKET_ENV),
                self.socket.as_os_str().to_owned(),
            ),
            (OsString::from(NONCE_ENV), OsString::from(&self.nonce)),
        ]
    }
}

/// A one-use AskPass server associated with one SSH process.
pub struct AskpassBroker {
    environment: AskpassEnvironment,
    expected_ssh_pid: Arc<AtomicU32>,
    task: Option<JoinHandle<Result<()>>>,
}

impl AskpassBroker {
    /// Bind a one-shot broker. `socket_path` must be inside a user-private
    /// runtime directory. The caller sets the SSH pid immediately after spawn.
    pub async fn bind(
        socket_path: PathBuf,
        lifetime: Duration,
        password_provider: PasswordProvider,
        expected_parent_executable: PathBuf,
    ) -> Result<Self> {
        prepare_socket_parent(&socket_path)?;
        if socket_path.exists() {
            return Err(ApError::coded(
                "AP_ASKPASS_SOCKET_EXISTS",
                format!("AskPass socket already exists: {}", socket_path.display()),
            ));
        }

        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;

        let nonce = random_nonce()?;
        let expected_ssh_pid = Arc::new(AtomicU32::new(0));
        let task_pid = Arc::clone(&expected_ssh_pid);
        let task_nonce = nonce.clone();
        let task_socket = socket_path.clone();
        let task = tokio::spawn(async move {
            let result = timeout(
                lifetime,
                serve_once(
                    listener,
                    &task_nonce,
                    task_pid,
                    password_provider,
                    expected_parent_executable,
                ),
            )
            .await
            .map_err(|_| ApError::coded("AP_ASKPASS_EXPIRED", "AskPass request expired"))?;
            let _ = fs::remove_file(&task_socket);
            result
        });

        Ok(Self {
            environment: AskpassEnvironment {
                socket: socket_path,
                nonce,
            },
            expected_ssh_pid,
            task: Some(task),
        })
    }

    pub fn environment(&self) -> &AskpassEnvironment {
        &self.environment
    }

    pub fn set_ssh_pid(&self, pid: u32) {
        self.expected_ssh_pid.store(pid, Ordering::Release);
    }

    pub fn is_finished(&self) -> bool {
        self.task.as_ref().is_none_or(JoinHandle::is_finished)
    }

    pub async fn wait(mut self) -> Result<()> {
        self.task
            .take()
            .expect("AskPass task is present")
            .await
            .map_err(|error| ApError::coded("AP_ASKPASS_TASK", error.to_string()))?
    }

    pub fn abort(&self) {
        if let Some(task) = &self.task {
            task.abort();
        }
        let _ = fs::remove_file(&self.environment.socket);
    }
}

impl Drop for AskpassBroker {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
        let _ = fs::remove_file(&self.environment.socket);
    }
}

/// Run the internal helper when the process was invoked by OpenSSH.
///
/// This must be called before normal CLI parsing. It returns `Ok(false)` for a
/// normal invocation and `Ok(true)` after writing the password to stdout.
pub fn maybe_run_from_env() -> Result<bool> {
    if std::env::var_os(MODE_ENV).as_deref() != Some(OsStr::new(MODE_VALUE)) {
        return Ok(false);
    }

    // With LC_ALL=C on the SSH process, a password request contains this word.
    // Rejecting every other prompt is a final guard against host-key and key
    // passphrase prompts reaching the stored SSH password.
    let prompt = std::env::args_os().nth(1).unwrap_or_default();
    if !prompt
        .to_string_lossy()
        .to_ascii_lowercase()
        .contains("password")
    {
        return Err(ApError::coded(
            "AP_ASKPASS_UNEXPECTED_PROMPT",
            "refusing a non-password AskPass prompt",
        ));
    }

    let socket = required_env(SOCKET_ENV)?;
    let mut nonce = required_env(NONCE_ENV)?;
    let mut stream = StdUnixStream::connect(Path::new(&socket))?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    let request = Request {
        nonce: nonce.clone(),
        pid: std::process::id(),
        parent_pid: unsafe { libc::getppid() as u32 },
    };
    let mut encoded = serde_json::to_vec(&request)
        .map_err(|error| ApError::coded("AP_ASKPASS_PROTOCOL", error.to_string()))?;
    nonce.zeroize();
    if encoded.len() > MAX_REQUEST {
        encoded.zeroize();
        return Err(ApError::coded(
            "AP_ASKPASS_PROTOCOL",
            "request is too large",
        ));
    }
    stream.write_all(&(encoded.len() as u32).to_be_bytes())?;
    stream.write_all(&encoded)?;
    encoded.zeroize();

    let mut status = [0_u8; 1];
    stream.read_exact(&mut status)?;
    let mut size = [0_u8; 4];
    stream.read_exact(&mut size)?;
    let size = u32::from_be_bytes(size) as usize;
    if size > MAX_PASSWORD {
        return Err(ApError::coded(
            "AP_ASKPASS_PROTOCOL",
            "response is too large",
        ));
    }
    let mut payload = Zeroizing::new(vec![0_u8; size]);
    stream.read_exact(payload.as_mut_slice())?;
    if status[0] != 0 {
        return Err(ApError::coded(
            "AP_ASKPASS_REJECTED",
            String::from_utf8_lossy(&payload).into_owned(),
        ));
    }

    let stdout = std::io::stdout();
    let mut locked = stdout.lock();
    locked.write_all(&payload)?;
    locked.write_all(b"\n")?;
    locked.flush()?;
    Ok(true)
}

async fn serve_once(
    listener: UnixListener,
    nonce: &str,
    expected_ssh_pid: Arc<AtomicU32>,
    password_provider: PasswordProvider,
    expected_parent_executable: PathBuf,
) -> Result<()> {
    let (mut stream, _) = listener.accept().await?;
    let peer = peer_identity(&stream)?;
    let current_uid = unsafe { libc::geteuid() };
    if peer.uid != current_uid {
        send_rejection(&mut stream, "peer uid does not match").await?;
        return Err(ApError::coded("AP_ASKPASS_PEER", "peer uid does not match"));
    }

    let request = read_request(&mut stream).await?;
    let expected_pid = expected_ssh_pid.load(Ordering::Acquire);
    let valid_parent = expected_pid != 0 && request.parent_pid == expected_pid;
    let valid_peer_pid = peer.pid == Some(request.pid);
    let valid_kernel_parent = peer.parent_pid == Some(expected_pid);
    #[cfg(target_os = "linux")]
    let valid_peer_executable = peer.pid.is_some_and(peer_executable_is_current);
    #[cfg(target_os = "macos")]
    let valid_peer_executable = peer.pid.is_some_and(peer_executable_is_current)
        && peer
            .audit_token
            .as_ref()
            .is_some_and(audit_token_code_matches_current);
    let valid_parent_executable =
        expected_pid != 0 && process_executable_matches(expected_pid, &expected_parent_executable);
    let valid_nonce: bool =
        subtle::ConstantTimeEq::ct_eq(request.nonce.as_bytes(), nonce.as_bytes()).into();
    if !valid_parent
        || !valid_peer_pid
        || !valid_kernel_parent
        || !valid_peer_executable
        || !valid_parent_executable
        || !valid_nonce
    {
        send_rejection(&mut stream, "AskPass authorization failed").await?;
        return Err(ApError::coded(
            "AP_ASKPASS_REJECTED",
            "AskPass authorization failed",
        ));
    }

    // Fetch only after all authorization checks. The Zeroizing wrapper clears
    // the controllable allocation when this function returns.
    let password = match tokio::task::spawn_blocking(move || (password_provider)()).await {
        Ok(Ok(password)) => password,
        Ok(Err(error)) => {
            send_rejection(&mut stream, "stored credential is unavailable").await?;
            return Err(error);
        }
        Err(error) => {
            send_rejection(&mut stream, "stored credential is unavailable").await?;
            return Err(ApError::coded("AP_ASKPASS_TASK", error.to_string()));
        }
    };
    if password.len() > MAX_PASSWORD {
        send_rejection(&mut stream, "stored password is too large").await?;
        return Err(ApError::coded(
            "AP_ASKPASS_PASSWORD_SIZE",
            "stored password is too large",
        ));
    }
    stream.write_all(&[0]).await?;
    stream
        .write_all(&(password.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(password.as_bytes()).await?;
    stream.shutdown().await?;
    Ok(())
}

async fn read_request(stream: &mut UnixStream) -> Result<Request> {
    let mut size = [0_u8; 4];
    stream.read_exact(&mut size).await?;
    let size = u32::from_be_bytes(size) as usize;
    if size == 0 || size > MAX_REQUEST {
        return Err(ApError::coded(
            "AP_ASKPASS_PROTOCOL",
            "invalid request size",
        ));
    }
    let mut bytes = vec![0_u8; size];
    stream.read_exact(&mut bytes).await?;
    let request = serde_json::from_slice(&bytes)
        .map_err(|error| ApError::coded("AP_ASKPASS_PROTOCOL", error.to_string()))?;
    bytes.zeroize();
    Ok(request)
}

async fn send_rejection(stream: &mut UnixStream, reason: &str) -> Result<()> {
    let bytes = reason.as_bytes();
    stream.write_all(&[1]).await?;
    stream
        .write_all(&(bytes.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(bytes).await?;
    stream.shutdown().await?;
    Ok(())
}

#[derive(Debug)]
struct PeerIdentity {
    uid: libc::uid_t,
    pid: Option<u32>,
    parent_pid: Option<u32>,
    #[cfg(target_os = "macos")]
    audit_token: Option<[u32; 8]>,
}

#[cfg(target_os = "linux")]
fn peer_identity(stream: &UnixStream) -> Result<PeerIdentity> {
    let fd = stream.as_raw_fd();
    let mut credentials = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            std::ptr::addr_of_mut!(credentials).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let pid = u32::try_from(credentials.pid).ok();
    Ok(PeerIdentity {
        uid: credentials.uid,
        pid,
        parent_pid: pid.and_then(linux_parent_pid),
    })
}

#[cfg(target_os = "linux")]
fn linux_parent_pid(pid: u32) -> Option<u32> {
    // /proc/<pid>/stat starts with "pid (comm) state ppid"; comm may contain
    // spaces and parentheses, so split only after its final closing parenthesis.
    let stat = fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after_name = stat.rsplit_once(") ")?.1;
    after_name.split_whitespace().nth(1)?.parse().ok()
}

#[cfg(target_os = "macos")]
fn peer_identity(stream: &UnixStream) -> Result<PeerIdentity> {
    let mut uid = 0;
    let mut gid = 0;
    let result = unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let mut pid: libc::c_int = 0;
    let mut length = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    let result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERPID,
            std::ptr::addr_of_mut!(pid).cast(),
            &mut length,
        )
    };
    if result != 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    let pid = u32::try_from(pid).ok();

    // Unlike a pid, an audit token includes the kernel's pid-version and
    // therefore cannot be redirected to a reused pid between the peer check
    // and Security.framework's dynamic-code lookup.
    let mut audit_token = [0_u32; 8];
    let mut token_length = std::mem::size_of_val(&audit_token) as libc::socklen_t;
    let token_result = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_LOCAL,
            libc::LOCAL_PEERTOKEN,
            audit_token.as_mut_ptr().cast(),
            &mut token_length,
        )
    };
    if token_result != 0 || token_length as usize != std::mem::size_of_val(&audit_token) {
        return Err(ApError::coded(
            "AP_ASKPASS_PEER",
            "无法取得 AskPass peer 的 macOS audit token",
        ));
    }
    Ok(PeerIdentity {
        uid,
        pid,
        parent_pid: pid.and_then(macos_parent_pid),
        audit_token: Some(audit_token),
    })
}

#[cfg(target_os = "macos")]
fn macos_parent_pid(pid: u32) -> Option<u32> {
    let mut info = std::mem::MaybeUninit::<libc::proc_bsdinfo>::zeroed();
    let expected = std::mem::size_of::<libc::proc_bsdinfo>();
    let read = unsafe {
        libc::proc_pidinfo(
            pid as libc::c_int,
            libc::PROC_PIDTBSDINFO,
            0,
            info.as_mut_ptr().cast(),
            expected as libc::c_int,
        )
    };
    if read as usize != expected {
        return None;
    }
    Some(unsafe { info.assume_init() }.pbi_ppid)
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
compile_error!("ap currently supports only Linux and macOS");

#[cfg(target_os = "linux")]
fn peer_executable_is_current(pid: u32) -> bool {
    process_executable_path(pid).is_some_and(|peer| executable_paths_match(&peer))
}

#[cfg(target_os = "macos")]
fn peer_executable_is_current(pid: u32) -> bool {
    process_executable_path(pid).is_some_and(|peer| executable_paths_match(&peer))
}

#[cfg(target_os = "macos")]
#[link(name = "Security", kind = "framework")]
unsafe extern "C" {
    fn SecCodeCopyDesignatedRequirement(
        code: *mut std::ffi::c_void,
        flags: u32,
        requirement: *mut *mut std::ffi::c_void,
    ) -> i32;
    fn SecCodeCopySigningInformation(
        code: *mut std::ffi::c_void,
        flags: u32,
        information: *mut CFDictionaryRef,
    ) -> i32;
    static kSecCodeInfoUnique: CFStringRef;
}

#[cfg(target_os = "macos")]
const CS_OPS_CDHASH: libc::c_uint = 5;
#[cfg(target_os = "macos")]
const CS_CDHASH_LEN: usize = 20;

#[cfg(target_os = "macos")]
#[repr(C)]
struct AuditToken {
    value: [u32; 8],
}

#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn csops(
        pid: libc::pid_t,
        operations: libc::c_uint,
        user_address: *mut std::ffi::c_void,
        user_size: libc::size_t,
    ) -> libc::c_int;
    fn csops_audittoken(
        pid: libc::pid_t,
        operations: libc::c_uint,
        user_address: *mut std::ffi::c_void,
        user_size: libc::size_t,
        token: *mut AuditToken,
    ) -> libc::c_int;
}

/// Bind a macOS AskPass peer to the code-signing identity of the already
/// running broker, rather than only to a replaceable pathname. Both the
/// designated requirement and the exact CDHash must match. Thus replacing
/// `ap` after daemon startup cannot turn a different binary at the same path
/// into an authorized helper, including an older legitimately signed release.
#[cfg(target_os = "macos")]
fn audit_token_code_matches_current(audit_token: &[u32; 8]) -> bool {
    let Some(peer_running_hash) = audit_token_running_code_hash(audit_token) else {
        return false;
    };
    let token_bytes = unsafe {
        std::slice::from_raw_parts(
            audit_token.as_ptr().cast::<u8>(),
            std::mem::size_of_val(audit_token),
        )
    };
    let token = CFData::from_buffer(token_bytes);
    let mut attributes = GuestAttributes::new();
    attributes.set_audit_token(token.as_concrete_TypeRef());
    guest_code_matches_current(&attributes, &peer_running_hash)
}

/// Validate a just-spawned internal `ap` process against both the designated
/// code requirement and exact CDHash of this already-running process.
/// `SshMaster` applies this when production uses its own executable as the
/// watchdog path.
#[cfg(target_os = "macos")]
pub(crate) fn process_code_matches_current(pid: u32) -> bool {
    let Ok(pid) = libc::pid_t::try_from(pid) else {
        return false;
    };
    let Some(peer_running_hash) = process_running_code_hash(pid) else {
        return false;
    };
    let mut attributes = GuestAttributes::new();
    attributes.set_pid(pid);
    guest_code_matches_current(&attributes, &peer_running_hash)
}

#[cfg(target_os = "macos")]
fn guest_code_matches_current(
    attributes: &GuestAttributes,
    peer_running_hash: &[u8; CS_CDHASH_LEN],
) -> bool {
    let Ok(current) = SecCode::for_self(CodeFlags::NONE) else {
        return false;
    };
    let mut raw_requirement = std::ptr::null_mut();
    let status = unsafe {
        SecCodeCopyDesignatedRequirement(
            current.as_CFTypeRef().cast_mut(),
            CodeFlags::NONE.bits(),
            &mut raw_requirement,
        )
    };
    if status != 0 || raw_requirement.is_null() {
        return false;
    }
    let requirement = unsafe { SecRequirement::wrap_under_create_rule(raw_requirement.cast()) };
    let Ok(peer) = SecCode::copy_guest_with_attribues(None, attributes, CodeFlags::NONE) else {
        return false;
    };
    let validation_flags = CodeFlags::STRICT_VALIDATE | CodeFlags::NO_NETWORK_ACCESS;
    if current
        .check_validity(validation_flags, &requirement)
        .is_err()
        || peer.check_validity(validation_flags, &requirement).is_err()
    {
        return false;
    }

    // SecCodeCopySigningInformation obtains kSecCodeInfoUnique from the static
    // code on disk, so this comparison is only an additional fail-closed
    // consistency check. The authoritative comparison below uses cdhashes from
    // the kernel's running-process state; the peer lookup is pinned by its
    // socket audit token (including pid-version) and cannot be redirected by a
    // same-path replacement or pid reuse.
    let (Some(current_static_hash), Some(peer_static_hash)) =
        (code_unique_hash(&current), code_unique_hash(&peer))
    else {
        return false;
    };
    let Some(current_running_hash) = process_running_code_hash(unsafe { libc::getpid() }) else {
        return false;
    };
    constant_time_bytes_eq(&current_static_hash, &peer_static_hash)
        && constant_time_bytes_eq(&current_running_hash, peer_running_hash)
}

#[cfg(target_os = "macos")]
fn code_unique_hash(code: &SecCode) -> Option<Vec<u8>> {
    let mut raw_information = std::ptr::null();
    let status = unsafe {
        SecCodeCopySigningInformation(
            code.as_CFTypeRef().cast_mut(),
            CodeFlags::NONE.bits(),
            &mut raw_information,
        )
    };
    if status != 0 || raw_information.is_null() {
        return None;
    }
    let information: CFDictionary<*const std::ffi::c_void, *const std::ffi::c_void> =
        unsafe { CFDictionary::wrap_under_create_rule(raw_information) };
    let value = unsafe {
        CFDictionaryGetValue(information.as_concrete_TypeRef(), kSecCodeInfoUnique.cast())
    };
    if value.is_null() {
        return None;
    }
    let hash = unsafe { CFData::wrap_under_get_rule(value.cast()) };
    (!hash.is_empty()).then(|| hash.bytes().to_vec())
}

#[cfg(target_os = "macos")]
fn process_running_code_hash(pid: libc::pid_t) -> Option<[u8; CS_CDHASH_LEN]> {
    let mut hash = [0_u8; CS_CDHASH_LEN];
    let status = unsafe { csops(pid, CS_OPS_CDHASH, hash.as_mut_ptr().cast(), hash.len()) };
    (status == 0).then_some(hash)
}

#[cfg(target_os = "macos")]
fn audit_token_running_code_hash(audit_token: &[u32; 8]) -> Option<[u8; CS_CDHASH_LEN]> {
    // audit_token_t stores pid and pid-version in fields 5 and 7. The kernel
    // validates both through csops_audittoken before returning the loaded
    // process's cdhash.
    let pid = libc::pid_t::try_from(audit_token[5]).ok()?;
    let mut token = AuditToken {
        value: *audit_token,
    };
    let mut hash = [0_u8; CS_CDHASH_LEN];
    let status = unsafe {
        csops_audittoken(
            pid,
            CS_OPS_CDHASH,
            hash.as_mut_ptr().cast(),
            hash.len(),
            &mut token,
        )
    };
    (status == 0).then_some(hash)
}

#[cfg(target_os = "macos")]
fn constant_time_bytes_eq(left: &[u8], right: &[u8]) -> bool {
    subtle::ConstantTimeEq::ct_eq(left, right).into()
}

#[cfg(target_os = "linux")]
fn process_executable_path(pid: u32) -> Option<PathBuf> {
    fs::read_link(format!("/proc/{pid}/exe")).ok()
}

#[cfg(target_os = "macos")]
fn process_executable_path(pid: u32) -> Option<PathBuf> {
    let mut buffer = vec![0_u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    let length = unsafe {
        libc::proc_pidpath(
            pid as libc::c_int,
            buffer.as_mut_ptr().cast(),
            buffer.len() as u32,
        )
    };
    if length <= 0 {
        return None;
    }
    buffer.truncate(length as usize);
    let Ok(path) = std::str::from_utf8(&buffer) else {
        return None;
    };
    Some(PathBuf::from(path))
}

fn process_executable_matches(pid: u32, expected: &Path) -> bool {
    let Some(actual) = process_executable_path(pid) else {
        return false;
    };
    let actual = fs::canonicalize(&actual).unwrap_or(actual);
    let expected = fs::canonicalize(expected).unwrap_or_else(|_| expected.to_owned());
    actual == expected
}

fn executable_paths_match(peer: &Path) -> bool {
    let Ok(current) = std::env::current_exe() else {
        return false;
    };
    let current = fs::canonicalize(&current).unwrap_or(current);
    let peer = fs::canonicalize(peer).unwrap_or_else(|_| peer.to_owned());
    peer == current
}

fn prepare_socket_parent(socket_path: &Path) -> Result<()> {
    let parent = socket_path.parent().ok_or_else(|| {
        ApError::coded(
            "AP_ASKPASS_SOCKET",
            "AskPass socket has no parent directory",
        )
    })?;
    fs::create_dir_all(parent)?;
    fs::set_permissions(parent, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn required_env(name: &str) -> Result<String> {
    std::env::var(name).map_err(|_| {
        ApError::coded(
            "AP_ASKPASS_ENV",
            format!("required AskPass variable {name} is missing"),
        )
    })
}

fn random_nonce() -> Result<String> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|error| ApError::coded("AP_RANDOM", error.to_string()))?;
    let nonce = URL_SAFE_NO_PAD.encode(bytes);
    bytes.zeroize();
    Ok(nonce)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[tokio::test]
    async fn rejects_wrong_nonce_without_reading_secret() {
        let temp = tempdir().unwrap();
        let reads = Arc::new(AtomicU32::new(0));
        let reads_for_provider = Arc::clone(&reads);
        let broker = AskpassBroker::bind(
            temp.path().join("askpass.sock"),
            Duration::from_secs(2),
            Arc::new(move || {
                reads_for_provider.fetch_add(1, Ordering::Relaxed);
                Ok(Zeroizing::new("never-return-this".to_owned()))
            }),
            process_executable_path(unsafe { libc::getppid() as u32 }).unwrap(),
        )
        .await
        .unwrap();
        broker.set_ssh_pid(unsafe { libc::getppid() as u32 });

        let mut stream = UnixStream::connect(&broker.environment().socket)
            .await
            .unwrap();
        let request = Request {
            nonce: "wrong".to_owned(),
            pid: std::process::id(),
            parent_pid: unsafe { libc::getppid() as u32 },
        };
        let encoded = serde_json::to_vec(&request).unwrap();
        stream
            .write_all(&(encoded.len() as u32).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&encoded).await.unwrap();
        let mut response = [0_u8; 1];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response[0], 1);
        assert_eq!(reads.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn valid_nonce_returns_secret_once() {
        let temp = tempdir().unwrap();
        let broker = AskpassBroker::bind(
            temp.path().join("askpass.sock"),
            Duration::from_secs(2),
            Arc::new(|| Ok(Zeroizing::new("test-password".to_owned()))),
            process_executable_path(unsafe { libc::getppid() as u32 }).unwrap(),
        )
        .await
        .unwrap();
        broker.set_ssh_pid(unsafe { libc::getppid() as u32 });

        let mut stream = UnixStream::connect(&broker.environment().socket)
            .await
            .unwrap();
        let request = Request {
            nonce: broker.environment().nonce.clone(),
            pid: std::process::id(),
            parent_pid: unsafe { libc::getppid() as u32 },
        };
        let encoded = serde_json::to_vec(&request).unwrap();
        stream
            .write_all(&(encoded.len() as u32).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&encoded).await.unwrap();
        let mut header = [0_u8; 5];
        stream.read_exact(&mut header).await.unwrap();
        assert_eq!(header[0], 0);
        let size = u32::from_be_bytes(header[1..].try_into().unwrap()) as usize;
        let mut password = Zeroizing::new(vec![0_u8; size]);
        stream.read_exact(password.as_mut_slice()).await.unwrap();
        assert_eq!(password.as_slice(), b"test-password");
        broker.wait().await.unwrap();
    }

    #[tokio::test]
    async fn rejects_nonce_holder_when_expected_parent_executable_is_wrong() {
        let temp = tempdir().unwrap();
        let reads = Arc::new(AtomicU32::new(0));
        let provider_reads = Arc::clone(&reads);
        let broker = AskpassBroker::bind(
            temp.path().join("askpass.sock"),
            Duration::from_secs(2),
            Arc::new(move || {
                provider_reads.fetch_add(1, Ordering::Relaxed);
                Ok(Zeroizing::new("must-not-be-read".to_owned()))
            }),
            PathBuf::from("/definitely/not/the/parent/executable"),
        )
        .await
        .unwrap();
        broker.set_ssh_pid(unsafe { libc::getppid() as u32 });

        let mut stream = UnixStream::connect(&broker.environment().socket)
            .await
            .unwrap();
        let request = Request {
            nonce: broker.environment().nonce.clone(),
            pid: std::process::id(),
            parent_pid: unsafe { libc::getppid() as u32 },
        };
        let encoded = serde_json::to_vec(&request).unwrap();
        stream
            .write_all(&(encoded.len() as u32).to_be_bytes())
            .await
            .unwrap();
        stream.write_all(&encoded).await.unwrap();
        let mut response = [0_u8; 1];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [1]);
        assert_eq!(reads.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn environment_contains_nonce_but_not_password() {
        let environment = AskpassEnvironment {
            socket: PathBuf::from("/tmp/example.sock"),
            nonce: "one-time-value".to_owned(),
        };
        let variables = environment.variables(Path::new("/usr/local/bin/ap"));
        let rendered = format!("{variables:?}");
        assert!(rendered.contains("one-time-value"));
        assert!(!rendered.contains("password-secret"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_code_identity_accepts_self_and_rejects_different_binary() {
        assert!(process_code_matches_current(std::process::id()));

        let mut other = std::process::Command::new("/bin/sleep")
            .arg("30")
            .spawn()
            .expect("spawn differently signed process");
        let other_pid = other.id();
        let self_hash = process_running_code_hash(unsafe { libc::getpid() })
            .expect("kernel reports current running CDHash");
        let other_hash = process_running_code_hash(other_pid as libc::pid_t)
            .expect("kernel reports child running CDHash");
        assert!(!constant_time_bytes_eq(&self_hash, &other_hash));
        assert!(!process_code_matches_current(other_pid));
        let _ = other.kill();
        let _ = other.wait();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_current_static_and_running_hashes_are_nonempty_and_stable() {
        let current = SecCode::for_self(CodeFlags::NONE).expect("resolve current dynamic code");
        let first_static = code_unique_hash(&current).expect("current code has a static CDHash");
        let second_static =
            code_unique_hash(&current).expect("current code still has a static CDHash");
        let first_running = process_running_code_hash(unsafe { libc::getpid() })
            .expect("kernel reports current running CDHash");
        let second_running = process_running_code_hash(unsafe { libc::getpid() })
            .expect("kernel still reports current running CDHash");

        assert!(!first_static.is_empty());
        assert_eq!(first_static, second_static);
        assert_ne!(first_running, [0_u8; CS_CDHASH_LEN]);
        assert!(constant_time_bytes_eq(&first_running, &second_running));

        let mut different = first_running;
        different[0] ^= 1;
        assert!(!constant_time_bytes_eq(&first_running, &different));
        assert!(!constant_time_bytes_eq(
            &first_running,
            &different[..CS_CDHASH_LEN - 1],
        ));
    }
}
