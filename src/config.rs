use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::Read;
use std::path::{Path, PathBuf};

use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

use crate::error::{ApError, Result};
use crate::model::{
    Config, ConnectionConfig, ResolvedConnection, ResolvedSshAuth, ResolvedSshConfig,
};

const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;
const MAX_IDENTITY_BYTES: u64 = 4 * 1024 * 1024;
#[cfg(target_os = "linux")]
const STICKY_BIT: u32 = libc::S_ISVTX;
#[cfg(target_os = "macos")]
const STICKY_BIT: u32 = libc::S_ISVTX as u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeLocation {
    Xdg,
    Fallback,
}

/// Filesystem locations used by `ap`.
///
/// Configuration, persistent state, and runtime files are deliberately kept
/// in separate XDG locations on both Linux and macOS.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    pub config_dir: PathBuf,
    pub config_file: PathBuf,
    pub known_hosts_file: PathBuf,
    pub state_dir: PathBuf,
    pub runtime_dir: PathBuf,
    pub control_dir: PathBuf,
    runtime_base: PathBuf,
    runtime_location: RuntimeLocation,
}

impl AppPaths {
    pub fn discover() -> Result<Self> {
        let home = dirs::home_dir().ok_or_else(|| {
            ApError::coded(
                "AP_HOME_UNAVAILABLE",
                "Unable to determine the current user's home directory",
            )
        })?;
        require_absolute_xdg_path("HOME", &home)?;

        let config_home = xdg_home("XDG_CONFIG_HOME", home.join(".config"))?;
        let state_home = xdg_home("XDG_STATE_HOME", home.join(".local/state"))?;

        match nonempty_env("XDG_RUNTIME_DIR") {
            Some(runtime_base) => {
                require_absolute_xdg_path("XDG_RUNTIME_DIR", &runtime_base)?;
                Self::from_parts(
                    config_home,
                    state_home,
                    runtime_base.join("ap"),
                    runtime_base,
                    RuntimeLocation::Xdg,
                )
            }
            None => {
                let runtime_base = fallback_runtime_base();
                let runtime_dir = runtime_base.join(format!("ap-{}", effective_uid()));
                Self::from_parts(
                    config_home,
                    state_home,
                    runtime_dir,
                    runtime_base,
                    RuntimeLocation::Fallback,
                )
            }
        }
    }

    /// Construct paths from explicit XDG base directories.
    ///
    /// This is useful for tests and embedded callers. Each argument is an XDG
    /// base directory; `ap` is appended internally.
    pub fn from_xdg_dirs(
        config_home: impl Into<PathBuf>,
        state_home: impl Into<PathBuf>,
        runtime_base: impl Into<PathBuf>,
    ) -> Result<Self> {
        let config_home = config_home.into();
        let state_home = state_home.into();
        let runtime_base = runtime_base.into();
        require_absolute_xdg_path("XDG_CONFIG_HOME", &config_home)?;
        require_absolute_xdg_path("XDG_STATE_HOME", &state_home)?;
        require_absolute_xdg_path("XDG_RUNTIME_DIR", &runtime_base)?;
        Self::from_parts(
            config_home,
            state_home,
            runtime_base.join("ap"),
            runtime_base,
            RuntimeLocation::Xdg,
        )
    }

    fn from_parts(
        config_home: PathBuf,
        state_home: PathBuf,
        runtime_dir: PathBuf,
        runtime_base: PathBuf,
        runtime_location: RuntimeLocation,
    ) -> Result<Self> {
        let config_dir = config_home.join("ap");
        let state_dir = state_home.join("ap");
        let control_dir = runtime_dir.join("c");
        Ok(Self {
            config_file: config_dir.join("config.toml"),
            known_hosts_file: state_dir.join("known_hosts"),
            control_dir,
            config_dir,
            state_dir,
            runtime_dir,
            runtime_base,
            runtime_location,
        })
    }

    pub fn ensure_runtime(&self) -> Result<()> {
        match self.runtime_location {
            RuntimeLocation::Xdg => validate_xdg_runtime_base(&self.runtime_base)?,
            RuntimeLocation::Fallback => validate_sticky_system_tmp(&self.runtime_base)?,
        }
        ensure_owned_private_component(&self.runtime_dir)?;
        ensure_owned_private_component(&self.control_dir)
    }

    pub fn ensure_known_hosts(&self) -> Result<()> {
        ensure_private_dir(&self.state_dir)?;
        let mut options = OpenOptions::new();
        options.read(true).write(true).create(true);
        #[cfg(unix)]
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        let file = options.open(&self.known_hosts_file).map_err(|error| {
            ApError::coded(
                "AP_KNOWN_HOSTS_UNAVAILABLE",
                format!(
                    "Unable to open {}: {error}",
                    self.known_hosts_file.display()
                ),
            )
        })?;
        validate_owned_regular_file(&file, &self.known_hosts_file, "AP_INSECURE_PATH")?;
        #[cfg(unix)]
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
        Ok(())
    }

    pub fn control_socket(&self, instance_id: Uuid) -> PathBuf {
        self.control_dir
            .join(format!("p-{}.sock", instance_id.simple()))
    }

    pub fn doctor_control_socket(&self) -> PathBuf {
        self.control_dir
            .join(format!("d-{}.sock", Uuid::new_v4().simple()))
    }
}

#[derive(Debug, Clone)]
pub struct ConfigStore {
    paths: AppPaths,
}

impl ConfigStore {
    pub fn new(paths: AppPaths) -> Self {
        Self { paths }
    }

    pub fn discover() -> Result<Self> {
        Ok(Self::new(AppPaths::discover()?))
    }

    pub fn paths(&self) -> &AppPaths {
        &self.paths
    }

    /// Read and semantically validate one immutable configuration snapshot.
    pub fn load(&self) -> Result<Config> {
        ensure_private_dir(&self.paths.config_dir)?;
        let mut file = open_config_file(&self.paths.config_file)?;
        let metadata = file.metadata()?;
        if metadata.len() > MAX_CONFIG_BYTES {
            return Err(ApError::coded(
                "AP_CONFIG_TOO_LARGE",
                format!(
                    "Configuration file exceeds {MAX_CONFIG_BYTES} bytes: {}",
                    self.paths.config_file.display()
                ),
            ));
        }

        let mut text = String::with_capacity(metadata.len() as usize);
        file.by_ref()
            .take(MAX_CONFIG_BYTES + 1)
            .read_to_string(&mut text)
            .map_err(|error| {
                ApError::coded(
                    "AP_CONFIG_READ_FAILED",
                    format!(
                        "Unable to read configuration file {}: {error}",
                        self.paths.config_file.display()
                    ),
                )
            })?;
        if text.len() as u64 > MAX_CONFIG_BYTES {
            return Err(ApError::coded(
                "AP_CONFIG_TOO_LARGE",
                format!(
                    "Configuration file exceeds {MAX_CONFIG_BYTES} bytes: {}",
                    self.paths.config_file.display()
                ),
            ));
        }

        let config: Config = toml::from_str(&text).map_err(|error| {
            ApError::coded(
                "AP_CONFIG_PARSE_FAILED",
                format!("Invalid configuration: {error}"),
            )
        })?;
        config.validate()?;
        Ok(config)
    }

    /// Load, resolve, and validate one connection for a new lifecycle.
    pub fn load_connection(&self, name: &str) -> Result<ResolvedConnection> {
        self.load_selected_connections(&[name.to_owned()])?
            .into_iter()
            .next()
            .ok_or_else(|| {
                ApError::coded(
                    "AP_CONNECTION_NOT_FOUND",
                    format!("Connection {name:?} is not defined"),
                )
            })
    }

    /// Resolve selected connections from one configuration-file snapshot.
    /// Authentication material for unrelated connections is not accessed.
    pub fn load_selected_connections(&self, names: &[String]) -> Result<Vec<ResolvedConnection>> {
        let config = self.load()?;
        names
            .iter()
            .map(|name| {
                let connection = config.connections.get(name).ok_or_else(|| {
                    ApError::coded(
                        "AP_CONNECTION_NOT_FOUND",
                        format!("Connection {name:?} is not defined"),
                    )
                })?;
                resolve_connection(name, connection)
            })
            .collect()
    }
}

fn resolve_connection(name: &str, connection: &ConnectionConfig) -> Result<ResolvedConnection> {
    let auth = match &connection.ssh.identity_file {
        Some(identity_file) => {
            validate_identity_file(identity_file)?;
            ResolvedSshAuth::Key {
                identity_file: identity_file.clone(),
            }
        }
        None => ResolvedSshAuth::Password,
    };

    Ok(ResolvedConnection {
        name: name.to_owned(),
        ssh: ResolvedSshConfig {
            host: connection.ssh.host.clone(),
            port: connection.ssh.port,
            user: connection.ssh.user.clone(),
            connect_timeout_seconds: connection.ssh.connect_timeout_seconds,
            auth,
        },
        proxies: connection.proxies.clone(),
    })
}

pub(crate) fn validate_resolved_auth(auth: &ResolvedSshAuth) -> Result<()> {
    match auth {
        ResolvedSshAuth::Key { identity_file } => validate_identity_file(identity_file),
        ResolvedSshAuth::Password => Ok(()),
    }
}

fn validate_identity_file(path: &Path) -> Result<()> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path).map_err(|error| {
        ApError::coded(
            "AP_SSH_KEY_FILE_INVALID",
            format!(
                "Unable to open SSH identity file {}: {error}",
                path.display()
            ),
        )
    })?;
    let metadata = validate_owned_regular_file(&file, path, "AP_SSH_KEY_FILE_INVALID")?;
    #[cfg(unix)]
    if metadata.mode() & 0o077 != 0 {
        return Err(ApError::coded(
            "AP_SSH_KEY_FILE_PERMISSIONS",
            format!(
                "SSH identity file must not be accessible by group or other users: {}",
                path.display()
            ),
        ));
    }
    if metadata.len() > MAX_IDENTITY_BYTES {
        return Err(ApError::coded(
            "AP_SSH_KEY_FILE_INVALID",
            format!("SSH identity file exceeds {MAX_IDENTITY_BYTES} bytes"),
        ));
    }
    Ok(())
}

fn open_config_file(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ApError::coded(
                "AP_CONFIG_NOT_FOUND",
                format!("Configuration file not found: {}", path.display()),
            )
        } else {
            ApError::coded(
                "AP_CONFIG_READ_FAILED",
                format!(
                    "Unable to open configuration file {}: {error}",
                    path.display()
                ),
            )
        }
    })?;
    let metadata = validate_owned_regular_file(&file, path, "AP_INSECURE_CONFIG")?;
    #[cfg(unix)]
    if metadata.mode() & 0o022 != 0 {
        return Err(ApError::coded(
            "AP_INSECURE_CONFIG",
            format!(
                "Configuration file must not be writable by group or other users: {}",
                path.display()
            ),
        ));
    }
    Ok(file)
}

fn validate_owned_regular_file(
    file: &File,
    path: &Path,
    error_code: &'static str,
) -> Result<fs::Metadata> {
    let metadata = file.metadata()?;
    #[cfg(unix)]
    if !metadata.is_file() || metadata.uid() != effective_uid() {
        return Err(ApError::coded(
            error_code,
            format!(
                "Path must be a regular file owned by the current user: {}",
                path.display()
            ),
        ));
    }
    Ok(metadata)
}

pub(crate) fn ensure_private_dir(path: &Path) -> Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(path)?;
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(unix)]
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.uid() != effective_uid()
    {
        return Err(ApError::coded(
            "AP_INSECURE_PATH",
            format!(
                "Directory must be owned by the current user: {}",
                path.display()
            ),
        ));
    }
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

pub(crate) fn ensure_control_dir(path: &Path) -> Result<()> {
    ensure_owned_private_component(path)
}

fn ensure_owned_private_component(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            #[cfg(unix)]
            builder.mode(0o700);
            builder.create(path)?;
        }
        Err(error) => return Err(error.into()),
    }

    let metadata = fs::symlink_metadata(path)?;
    #[cfg(unix)]
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.uid() != effective_uid()
    {
        return Err(ApError::coded(
            "AP_INSECURE_PATH",
            format!(
                "Directory must be owned by the current user: {}",
                path.display()
            ),
        ));
    }
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

fn validate_xdg_runtime_base(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path).map_err(|error| {
        ApError::coded(
            "AP_XDG_RUNTIME_INVALID",
            format!(
                "Unable to access XDG_RUNTIME_DIR {}: {error}",
                path.display()
            ),
        )
    })?;
    #[cfg(unix)]
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != effective_uid()
        || metadata.mode() & 0o077 != 0
    {
        return Err(ApError::coded(
            "AP_XDG_RUNTIME_INVALID",
            "XDG_RUNTIME_DIR must be a private directory owned by the current user",
        ));
    }
    Ok(())
}

fn validate_sticky_system_tmp(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    #[cfg(unix)]
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & STICKY_BIT == 0
    {
        return Err(ApError::coded(
            "AP_INSECURE_PATH",
            format!(
                "Runtime fallback must be a root-owned sticky directory: {}",
                path.display()
            ),
        ));
    }
    Ok(())
}

fn xdg_home(name: &str, fallback: PathBuf) -> Result<PathBuf> {
    match nonempty_env(name) {
        Some(path) => {
            require_absolute_xdg_path(name, &path)?;
            Ok(path)
        }
        None => Ok(fallback),
    }
}

fn nonempty_env(name: &str) -> Option<PathBuf> {
    std::env::var_os(name)
        .filter(|value| !value.is_empty())
        .map(PathBuf::from)
}

fn require_absolute_xdg_path(name: &str, path: &Path) -> Result<()> {
    if !path.is_absolute() {
        return Err(ApError::coded(
            "AP_XDG_PATH_INVALID",
            format!("{name} must be an absolute path"),
        ));
    }
    Ok(())
}

fn fallback_runtime_base() -> PathBuf {
    #[cfg(target_os = "macos")]
    {
        PathBuf::from("/private/tmp")
    }
    #[cfg(not(target_os = "macos"))]
    {
        PathBuf::from("/tmp")
    }
}

fn effective_uid() -> libc::uid_t {
    unsafe { libc::geteuid() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{ProxyMapping, ProxyProtocol};
    use std::io::Write as _;
    use tempfile::TempDir;

    fn paths(temp: &TempDir) -> AppPaths {
        let config_home = temp.path().join("config");
        let state_home = temp.path().join("state");
        let runtime_home = temp.path().join("runtime");
        fs::create_dir(&runtime_home).unwrap();
        fs::set_permissions(&runtime_home, fs::Permissions::from_mode(0o700)).unwrap();
        AppPaths::from_xdg_dirs(config_home, state_home, runtime_home).unwrap()
    }

    fn write_private(path: &Path, contents: &str) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(path).unwrap();
        file.write_all(contents.as_bytes()).unwrap();
    }

    fn config_text(identity_file: Option<&Path>) -> String {
        let identity_file = identity_file
            .map(|path| format!("identity_file = {:?}\n", path.display().to_string()))
            .unwrap_or_default();
        format!(
            r#"
version = 2
[connections.dev.ssh]
host = "server.example"
port = 22
user = "alice"
{identity_file}
[[connections.dev.proxies]]
protocol = "mixed"
local = "127.0.0.1:7890"
remote_port = 17890
"#
        )
    }

    #[test]
    fn constructs_separate_xdg_paths() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(&temp);
        assert_eq!(paths.config_file, temp.path().join("config/ap/config.toml"));
        assert_eq!(
            paths.known_hosts_file,
            temp.path().join("state/ap/known_hosts")
        );
        assert_eq!(paths.state_dir, temp.path().join("state/ap"));
        assert_eq!(paths.runtime_dir, temp.path().join("runtime/ap"));
        assert_eq!(paths.control_dir, temp.path().join("runtime/ap/c"));
    }

    #[test]
    fn rejects_relative_xdg_paths() {
        assert_eq!(
            AppPaths::from_xdg_dirs("relative", "/state", "/runtime")
                .unwrap_err()
                .code(),
            "AP_XDG_PATH_INVALID"
        );
    }

    #[test]
    fn creates_private_runtime_and_known_hosts() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(&temp);
        paths.ensure_runtime().unwrap();
        paths.ensure_known_hosts().unwrap();
        assert_eq!(
            fs::metadata(&paths.runtime_dir).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&paths.known_hosts_file).unwrap().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn resolves_password_authentication_without_reading_a_secret() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(&temp);
        write_private(&paths.config_file, &config_text(None));

        let resolved = ConfigStore::new(paths).load_connection("dev").unwrap();
        assert_eq!(resolved.name, "dev");
        assert_eq!(resolved.ssh.auth, ResolvedSshAuth::Password);
    }

    #[test]
    fn resolves_key_authentication() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(&temp);
        let identity = temp.path().join("id_ed25519");
        write_private(&identity, "test identity");
        write_private(&paths.config_file, &config_text(Some(&identity)));
        let resolved = ConfigStore::new(paths).load_connection("dev").unwrap();
        assert!(matches!(resolved.ssh.auth, ResolvedSshAuth::Key { .. }));
    }

    #[test]
    fn selected_load_does_not_access_unrelated_authentication_material() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(&temp);
        let identity = temp.path().join("id_ed25519");
        write_private(&identity, "test identity");
        let text = format!(
            r#"
version = 2

[connections.dev.ssh]
host = "dev.example"
port = 22
user = "alice"
identity_file = {:?}
[[connections.dev.proxies]]
protocol = "http"
local = "127.0.0.1:7890"
remote_port = 17890

[connections.unrelated.ssh]
host = "other.example"
port = 22
user = "alice"
identity_file = "/missing/unrelated-key"
[[connections.unrelated.proxies]]
protocol = "http"
local = "127.0.0.1:7890"
remote_port = 17890
"#,
            identity.display().to_string()
        );
        write_private(&paths.config_file, &text);

        let selected = ConfigStore::new(paths)
            .load_selected_connections(&["dev".to_owned()])
            .unwrap();
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].name, "dev");
    }

    #[test]
    fn rejects_unknown_config_fields() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(&temp);
        write_private(&paths.config_file, "version = 2\nunknown = true\n");
        assert_eq!(
            ConfigStore::new(paths).load().unwrap_err().code(),
            "AP_CONFIG_PARSE_FAILED"
        );
    }

    #[test]
    fn rejects_legacy_authentication_fields() {
        let temp = tempfile::tempdir().unwrap();
        let paths = paths(&temp);
        write_private(
            &paths.config_file,
            r#"
version = 2
[connections.dev.ssh]
host = "server.example"
port = 22
user = "alice"
[connections.dev.ssh.auth]
method = "password-file"
password_file = "/tmp/password"
[[connections.dev.proxies]]
protocol = "http"
local = "127.0.0.1:7890"
remote_port = 17890
"#,
        );
        assert_eq!(
            ConfigStore::new(paths).load().unwrap_err().code(),
            "AP_CONFIG_PARSE_FAILED"
        );
    }

    #[test]
    fn resolved_connection_round_trips_through_json() {
        let value = ResolvedConnection {
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
        };
        let encoded = serde_json::to_string(&value).unwrap();
        assert_eq!(
            serde_json::from_str::<ResolvedConnection>(&encoded).unwrap(),
            value
        );
    }
}
