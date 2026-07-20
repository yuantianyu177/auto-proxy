use auto_proxy::error::Result;
use auto_proxy::secrets::{SecretString, SshPasswordStatus, SshPasswordStore};
use uuid::Uuid;

const ENABLE_ENV: &str = "AP_RUN_SECRET_STORE_TEST";

struct DeleteGuard {
    store: SshPasswordStore,
    id: Uuid,
    armed: bool,
}

impl DeleteGuard {
    fn new(store: SshPasswordStore, id: Uuid) -> Self {
        Self {
            store,
            id,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for DeleteGuard {
    fn drop(&mut self) {
        if self.armed {
            let _ = self.store.delete(self.id);
        }
    }
}

#[test]
fn live_system_credential_store_crud() {
    if std::env::var_os(ENABLE_ENV).as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }

    let store = SshPasswordStore::new();
    let id = Uuid::new_v4();
    let mut cleanup = DeleteGuard::new(store, id);
    let first = random_secret();
    let second = random_secret();

    require(store.delete(id), "initial cleanup");
    assert!(matches!(
        require(store.status(id), "initial missing status"),
        SshPasswordStatus::Missing
    ));

    require(store.set(id, &first), "create");
    assert!(matches!(
        require(store.status(id), "created status"),
        SshPasswordStatus::Available
    ));
    let created = require(store.get(id), "read created credential");
    assert!(
        created.expose_secret() == first.expose_secret(),
        "created credential did not round-trip"
    );

    require(store.set(id, &second), "update");
    let updated = require(store.get(id), "read updated credential");
    assert!(
        updated.expose_secret() == second.expose_secret(),
        "updated credential did not round-trip"
    );
    assert!(
        updated.expose_secret() != first.expose_secret(),
        "credential update retained the old value"
    );

    require(store.delete(id), "delete");
    assert!(matches!(
        require(store.status(id), "deleted status"),
        SshPasswordStatus::Missing
    ));
    let missing = store.get(id).expect_err("deleted credential still exists");
    assert_eq!(missing.code(), "AP_SSH_PASSWORD_NOT_FOUND");
    // Delete is intentionally idempotent for cleanup and server removal.
    require(store.delete(id), "delete missing credential");
    cleanup.disarm();
}

fn random_secret() -> SecretString {
    SecretString::new(format!(
        "{}{}",
        Uuid::new_v4().simple(),
        Uuid::new_v4().simple()
    ))
}

fn require<T>(result: Result<T>, operation: &str) -> T {
    result.unwrap_or_else(|error| panic!("{operation} failed with {}", error.code()))
}

#[cfg(target_os = "linux")]
const NO_DBUS_CHILD_ENV: &str = "AP_SECRET_STORE_NO_DBUS_CHILD";
#[cfg(target_os = "linux")]
const NO_DBUS_ROOT_ENV: &str = "AP_SECRET_STORE_NO_DBUS_ROOT";

#[cfg(target_os = "linux")]
#[test]
fn linux_without_session_bus_never_falls_back_to_a_plain_file() {
    use std::fs;
    use std::process::{Command, Stdio};

    let isolated = tempfile::tempdir().expect("create isolated credential-store directory");
    let runtime = isolated.path().join("runtime");
    fs::create_dir(&runtime).expect("create empty XDG runtime directory");
    let output = Command::new(std::env::current_exe().expect("resolve integration test binary"))
        .arg("linux_no_session_bus_child")
        .arg("--exact")
        .arg("--test-threads=1")
        .env(NO_DBUS_CHILD_ENV, "1")
        .env(NO_DBUS_ROOT_ENV, isolated.path())
        .env("XDG_RUNTIME_DIR", &runtime)
        .env("HOME", isolated.path().join("home"))
        .env("XDG_CONFIG_HOME", isolated.path().join("config"))
        .env("XDG_DATA_HOME", isolated.path().join("data"))
        .env("XDG_STATE_HOME", isolated.path().join("state"))
        .env("AP_CONFIG_DIR", isolated.path().join("ap-config"))
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .current_dir(isolated.path())
        .status()
        .expect("run isolated no-D-Bus child test");
    assert!(output.success(), "isolated no-D-Bus child test failed");
    assert!(
        !contains_regular_file(isolated.path()),
        "credential-store failure created a regular file"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn linux_no_session_bus_child() {
    if std::env::var_os(NO_DBUS_CHILD_ENV).as_deref() != Some(std::ffi::OsStr::new("1")) {
        return;
    }
    assert!(std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none());
    let root = std::path::PathBuf::from(
        std::env::var_os(NO_DBUS_ROOT_ENV).expect("isolated root is configured"),
    );
    let store = SshPasswordStore::new();
    let id = Uuid::new_v4();
    let secret = random_secret();
    let error = store
        .set(id, &secret)
        .expect_err("credential unexpectedly persisted without a session bus");
    assert_eq!(error.code(), "AP_SECRET_STORE_UNAVAILABLE");
    assert!(
        !contains_regular_file(&root),
        "failed credential operation created a regular file"
    );
}

#[cfg(target_os = "linux")]
fn contains_regular_file(root: &std::path::Path) -> bool {
    let Ok(entries) = std::fs::read_dir(root) else {
        return false;
    };
    entries.filter_map(std::result::Result::ok).any(|entry| {
        let path = entry.path();
        match entry.file_type() {
            Ok(kind) if kind.is_file() || kind.is_symlink() => true,
            Ok(kind) if kind.is_dir() => contains_regular_file(&path),
            Ok(_) | Err(_) => false,
        }
    })
}
