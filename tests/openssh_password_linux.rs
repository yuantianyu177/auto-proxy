#![cfg(target_os = "linux")]

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::net::UnixStream as StdUnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use auto_proxy::askpass::{MODE_ENV, NONCE_ENV, PasswordProvider, SOCKET_ENV};
use auto_proxy::error::{ApError, Result};
use auto_proxy::ssh::{RemoteForward, SshAuth, SshMaster, SshOptions, SshTarget};
use tokio::net::TcpListener;
use tokio::time::timeout;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const ENABLE_ENV: &str = "AP_RUN_OPENSSH_PASSWORD_TEST";
const HOST_ENV: &str = "AP_TEST_SSH_PASSWORD_HOST";
const PORT_ENV: &str = "AP_TEST_SSH_PASSWORD_PORT";
const USER_ENV: &str = "AP_TEST_SSH_PASSWORD_USER";
const KNOWN_HOSTS_ENV: &str = "AP_TEST_SSH_PASSWORD_KNOWN_HOSTS";
const PASSWORD_FIXTURE_ENV: &str = "AP_TEST_SSH_PASSWORD_FIXTURE_PATH";
const MAX_PASSWORD_BYTES: u64 = 64 * 1024;
const ASKPASS_MODE: &str = "ssh-password-v1";
const ASKPASS_MAX_FRAME: usize = 64 * 1024;

// OpenSSH must execute the same binary that owns AskpassBroker; that identity
// check is an intentional production security boundary. When this integration
// test binary is re-executed as SSH_ASKPASS, process the one-shot request before
// libtest parses OpenSSH's human-readable prompt as a test filter. In an
// ordinary `cargo test` process AP_ASKPASS_MODE is absent and this is a no-op.
#[derive(serde::Serialize)]
struct AskpassRequest {
    nonce: String,
    pid: u32,
    parent_pid: u32,
}

extern "C" fn askpass_test_process_entry() {
    if std::env::var_os(MODE_ENV).as_deref() != Some(std::ffi::OsStr::new(ASKPASS_MODE)) {
        return;
    }
    let status = if run_test_askpass_helper().is_ok() {
        0
    } else {
        111
    };
    // Rust's normal argument runtime is not initialized until after ELF
    // constructors. `_exit` avoids entering libtest or running partially
    // initialized process-global destructors in this helper invocation.
    unsafe { libc::_exit(status) }
}

#[used]
#[unsafe(link_section = ".init_array")]
static ASKPASS_TEST_PROCESS_ENTRY: extern "C" fn() = askpass_test_process_entry;

fn run_test_askpass_helper() -> std::result::Result<(), ()> {
    // `std::env::args_os` is not available this early. /proc exposes the raw
    // OpenSSH prompt and retains the production helper's non-password guard.
    let command_line = fs::read("/proc/self/cmdline").map_err(|_| ())?;
    if !String::from_utf8_lossy(&command_line)
        .to_ascii_lowercase()
        .contains("password")
    {
        return Err(());
    }

    let socket = std::env::var_os(SOCKET_ENV).ok_or(())?;
    let nonce = std::env::var(NONCE_ENV).map_err(|_| ())?;
    let mut stream = StdUnixStream::connect(Path::new(&socket)).map_err(|_| ())?;
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| ())?;
    stream
        .set_write_timeout(Some(Duration::from_secs(10)))
        .map_err(|_| ())?;

    let request = AskpassRequest {
        nonce,
        pid: std::process::id(),
        parent_pid: unsafe { libc::getppid() as u32 },
    };
    let mut encoded = serde_json::to_vec(&request).map_err(|_| ())?;
    if encoded.len() > ASKPASS_MAX_FRAME {
        encoded.zeroize();
        return Err(());
    }
    stream
        .write_all(&(encoded.len() as u32).to_be_bytes())
        .map_err(|_| ())?;
    stream.write_all(&encoded).map_err(|_| ())?;
    encoded.zeroize();

    let mut status = [0_u8; 1];
    stream.read_exact(&mut status).map_err(|_| ())?;
    let mut length = [0_u8; 4];
    stream.read_exact(&mut length).map_err(|_| ())?;
    let length = u32::from_be_bytes(length) as usize;
    if status[0] != 0 || length > ASKPASS_MAX_FRAME {
        return Err(());
    }
    let mut password = Zeroizing::new(vec![0_u8; length]);
    stream.read_exact(&mut password).map_err(|_| ())?;
    write_all_fd(libc::STDOUT_FILENO, &password)?;
    write_all_fd(libc::STDOUT_FILENO, b"\n")
}

fn write_all_fd(fd: libc::c_int, mut bytes: &[u8]) -> std::result::Result<(), ()> {
    while !bytes.is_empty() {
        let written = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
        if written <= 0 {
            return Err(());
        }
        bytes = &bytes[written as usize..];
    }
    Ok(())
}

#[derive(Clone, Copy)]
enum PasswordVariant {
    Exact,
    IntentionallyWrong,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_password_only_openssh_uses_one_shot_askpass_and_cleans_up() {
    if std::env::var_os(ENABLE_ENV).as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }

    let target = password_target_from_env();
    let password_fixture = PathBuf::from(required_env(PASSWORD_FIXTURE_ENV));
    // Validate the file before opening any SSH connection. Providers repeat all
    // checks and read it afresh for each authentication request.
    drop(
        read_password_fixture(&password_fixture)
            .unwrap_or_else(|error| panic!("password fixture is invalid: {}", error.code())),
    );

    let local_target = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind an isolated local forwarding target");
    let local_gateway = local_target.local_addr().unwrap();
    let directory = tempfile::tempdir().expect("create private control directory");
    let mode_dispatcher = create_internal_mode_dispatcher(directory.path());
    let remote_port = random_remote_port();

    let first_control = directory.path().join("correct-first.sock");
    let first_calls = Arc::new(AtomicUsize::new(0));
    let first = expect_started(
        ssh_options(
            &target,
            &first_control,
            remote_port,
            local_gateway,
            &mode_dispatcher,
            fixture_provider(
                password_fixture.clone(),
                PasswordVariant::Exact,
                Arc::clone(&first_calls),
            ),
        ),
        "correct password",
    )
    .await;
    assert_eq!(first_calls.load(Ordering::SeqCst), 1);
    assert!(
        first_control.exists(),
        "ControlMaster socket was not created"
    );
    expect_shutdown(first).await;
    assert!(
        !first_control.exists(),
        "ControlMaster socket survived shutdown"
    );

    // This is a new explicit password connection, not an automatic reconnect.
    // Reusing the identical fixed remote port proves the first remote listener
    // was released as part of shutdown, without running any command remotely.
    let second_control = directory.path().join("correct-reuse.sock");
    let second_calls = Arc::new(AtomicUsize::new(0));
    let second = expect_started(
        ssh_options(
            &target,
            &second_control,
            remote_port,
            local_gateway,
            &mode_dispatcher,
            fixture_provider(
                password_fixture.clone(),
                PasswordVariant::Exact,
                Arc::clone(&second_calls),
            ),
        ),
        "remote port reuse after cleanup",
    )
    .await;
    assert_eq!(second_calls.load(Ordering::SeqCst), 1);
    expect_shutdown(second).await;
    assert!(!second_control.exists());

    let wrong_control = directory.path().join("wrong-password.sock");
    let wrong_calls = Arc::new(AtomicUsize::new(0));
    let wrong = timeout(
        Duration::from_secs(30),
        SshMaster::start(ssh_options(
            &target,
            &wrong_control,
            random_remote_port(),
            local_gateway,
            &mode_dispatcher,
            fixture_provider(
                password_fixture.clone(),
                PasswordVariant::IntentionallyWrong,
                Arc::clone(&wrong_calls),
            ),
        )),
    )
    .await;
    let error = match wrong {
        Ok(Err(error)) => error,
        Ok(Ok(master)) => {
            expect_shutdown(master).await;
            panic!("an intentionally wrong password authenticated")
        }
        Err(_) => panic!("wrong-password attempt did not terminate"),
    };
    assert_eq!(error.code(), "AP_SSH_AUTH_FAILED");
    assert_eq!(wrong_calls.load(Ordering::SeqCst), 1);
    assert!(!wrong_control.exists());
}

fn ssh_options(
    target: &SshTarget,
    control_socket: &Path,
    remote_port: u16,
    local_gateway: std::net::SocketAddr,
    mode_dispatcher: &Path,
    provider: PasswordProvider,
) -> SshOptions {
    let mut options = SshOptions::new(
        target.clone(),
        control_socket.to_owned(),
        vec![RemoteForward {
            remote_port,
            local_gateway,
        }],
        SshAuth::Password { provider },
    )
    .expect("construct password-authenticated SSH options")
    .with_ap_executable(mode_dispatcher);
    // SshMaster uses one executable for its watchdog and SSH_ASKPASS. The
    // private dispatcher sends watchdog mode to the real ap binary and
    // AskPass mode to this test binary's init-array entry.
    options.startup_timeout = Duration::from_secs(20);
    options
}

fn password_target_from_env() -> SshTarget {
    SshTarget {
        host: required_env(HOST_ENV),
        port: required_port(PORT_ENV),
        user: required_env(USER_ENV),
        known_hosts: PathBuf::from(required_env(KNOWN_HOSTS_ENV)),
        connect_timeout: Duration::from_secs(10),
    }
}

fn create_internal_mode_dispatcher(directory: &Path) -> PathBuf {
    let dispatcher = directory.join("ap-test-internal-dispatch");
    let ap = shell_quote(Path::new(env!("CARGO_BIN_EXE_ap")));
    let test = shell_quote(&std::env::current_exe().expect("resolve integration test executable"));
    let script = format!(
        "#!/bin/sh\n\
         if [ \"${{AP_SSH_WATCHDOG_MODE-}}\" = 'ssh-parent-v1' ]; then\n\
           exec {ap} \"$@\"\n\
         fi\n\
         if [ \"${{AP_ASKPASS_MODE-}}\" = 'ssh-password-v1' ]; then\n\
           exec {test} \"$@\"\n\
         fi\n\
         exit 127\n"
    );
    let mut options = OpenOptions::new();
    options.write(true).create_new(true).mode(0o700);
    let mut file = options
        .open(&dispatcher)
        .expect("create private internal-mode dispatcher");
    file.write_all(script.as_bytes())
        .expect("write internal-mode dispatcher");
    file.sync_all().expect("sync internal-mode dispatcher");
    drop(file);
    fs::set_permissions(&dispatcher, fs::Permissions::from_mode(0o500))
        .expect("protect internal-mode dispatcher");
    dispatcher
}

fn shell_quote(path: &Path) -> String {
    let value = path
        .to_str()
        .expect("test executable path must be valid UTF-8");
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn fixture_provider(
    password_fixture: PathBuf,
    variant: PasswordVariant,
    calls: Arc<AtomicUsize>,
) -> PasswordProvider {
    let wrong_prefix = format!("ap-invalid-{}-", Uuid::new_v4());
    Arc::new(move || {
        calls.fetch_add(1, Ordering::SeqCst);
        let mut password = read_password_fixture(&password_fixture)?;
        if matches!(variant, PasswordVariant::IntentionallyWrong) {
            password.insert_str(0, &wrong_prefix);
        }
        Ok(password)
    })
}

fn read_password_fixture(path: &Path) -> Result<Zeroizing<String>> {
    let metadata = fs::symlink_metadata(path).map_err(|_| {
        ApError::coded(
            "AP_TEST_PASSWORD_FIXTURE",
            "password fixture cannot be inspected",
        )
    })?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.permissions().mode() & 0o777 != 0o600
        || metadata.len() > MAX_PASSWORD_BYTES
    {
        return Err(ApError::coded(
            "AP_TEST_PASSWORD_FIXTURE",
            "password fixture must be a current-user regular file with mode 0600 and bounded size",
        ));
    }

    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let file = options.open(path).map_err(|_| {
        ApError::coded(
            "AP_TEST_PASSWORD_FIXTURE",
            "password fixture cannot be opened",
        )
    })?;
    let opened = file.metadata().map_err(|_| {
        ApError::coded(
            "AP_TEST_PASSWORD_FIXTURE",
            "password fixture metadata cannot be read",
        )
    })?;
    if !opened.is_file()
        || opened.uid() != unsafe { libc::geteuid() }
        || opened.permissions().mode() & 0o777 != 0o600
        || opened.len() > MAX_PASSWORD_BYTES
    {
        return Err(ApError::coded(
            "AP_TEST_PASSWORD_FIXTURE",
            "password fixture changed while it was opened",
        ));
    }

    let mut bytes = Zeroizing::new(Vec::with_capacity(opened.len() as usize));
    file.take(MAX_PASSWORD_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| {
            ApError::coded(
                "AP_TEST_PASSWORD_FIXTURE",
                "password fixture cannot be read",
            )
        })?;
    if bytes.len() as u64 > MAX_PASSWORD_BYTES {
        return Err(ApError::coded(
            "AP_TEST_PASSWORD_FIXTURE",
            "password fixture exceeds the size limit",
        ));
    }
    if bytes.last() == Some(&b'\n') {
        bytes.pop();
        if bytes.last() == Some(&b'\r') {
            bytes.pop();
        }
    }
    if bytes.is_empty()
        || bytes.contains(&b'\0')
        || bytes.contains(&b'\n')
        || bytes.contains(&b'\r')
    {
        return Err(ApError::coded(
            "AP_TEST_PASSWORD_FIXTURE",
            "password fixture is empty or contains an unsupported byte",
        ));
    }
    let password = std::str::from_utf8(&bytes)
        .map_err(|_| {
            ApError::coded(
                "AP_TEST_PASSWORD_FIXTURE",
                "password fixture is not valid UTF-8",
            )
        })?
        .to_owned();
    Ok(Zeroizing::new(password))
}

async fn expect_started(options: SshOptions, phase: &str) -> SshMaster {
    match timeout(Duration::from_secs(30), SshMaster::start(options)).await {
        Ok(Ok(master)) => master,
        Ok(Err(error)) => panic!("{phase} failed with {}", error.code()),
        Err(_) => panic!("{phase} timed out"),
    }
}

async fn expect_shutdown(master: SshMaster) {
    if let Err(error) = master.shutdown().await {
        panic!("ControlMaster shutdown failed with {}", error.code());
    }
}

fn required_env(name: &str) -> String {
    optional_env(name).unwrap_or_else(|| panic!("{name} must be set when {ENABLE_ENV}=1"))
}

fn optional_env(name: &str) -> Option<String> {
    std::env::var_os(name).map(|value| {
        value
            .into_string()
            .unwrap_or_else(|_| panic!("{name} must be valid UTF-8"))
    })
}

fn required_port(name: &str) -> u16 {
    required_env(name)
        .parse::<u16>()
        .unwrap_or_else(|_| panic!("{name} must be a valid SSH port"))
}

fn random_remote_port() -> u16 {
    let mut random = [0_u8; 2];
    getrandom::fill(&mut random).expect("obtain random remote port");
    40_000 + u16::from_ne_bytes(random) % 20_000
}
