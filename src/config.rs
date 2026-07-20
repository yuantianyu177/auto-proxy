use std::fs::{self, DirBuilder, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use fs2::FileExt;
use uuid::Uuid;

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

use crate::error::{ApError, Result};
use crate::model::{Config, ProxyMapping, ServerConfig, validate_name};

const MAX_CONFIG_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppPaths {
    pub root: PathBuf,
    pub config_file: PathBuf,
    pub config_lock: PathBuf,
    pub proxy_secrets_file: PathBuf,
    pub proxy_secrets_lock: PathBuf,
    pub transaction_journal: PathBuf,
    pub transaction_lock: PathBuf,
    pub runtime_dir: PathBuf,
    pub daemon_socket: PathBuf,
    pub control_dir: PathBuf,
    pub logs_dir: PathBuf,
}

impl AppPaths {
    pub fn discover() -> Result<Self> {
        if let Some(root) = std::env::var_os("AP_CONFIG_DIR") {
            if root.is_empty() {
                return Err(ApError::coded(
                    "AP_INVALID_CONFIG_DIR",
                    "AP_CONFIG_DIR 不能为空",
                ));
            }
            return Ok(Self::from_root(root));
        }

        let base = dirs::config_dir().ok_or_else(|| {
            ApError::coded("AP_CONFIG_DIR_UNAVAILABLE", "无法确定当前用户的配置目录")
        })?;
        let paths = Self::from_root(base.join("ap"));
        // OpenSSH creates a temporary multiplex socket beside ControlPath
        // before renaming it into place. macOS has a short sockaddr_un path
        // limit, so ~/Library/Application Support/... leaves too little room
        // even when the final socket itself would fit. A private per-UID
        // directory below the sticky system /tmp keeps this runtime-only path
        // short; configuration, locks, logs, and secrets remain in the normal
        // application-support directory.
        #[cfg(target_os = "macos")]
        let paths = Self {
            control_dir: macos_control_dir(),
            ..paths
        };
        Ok(paths)
    }

    pub fn from_root(root: impl Into<PathBuf>) -> Self {
        let root = root.into();
        let runtime_dir = root.join("run");
        Self {
            config_file: root.join("config.toml"),
            config_lock: root.join("config.lock"),
            proxy_secrets_file: root.join("proxy-secrets.toml"),
            proxy_secrets_lock: root.join("proxy-secrets.lock"),
            transaction_journal: root.join("transaction.toml"),
            transaction_lock: root.join("transaction.lock"),
            daemon_socket: runtime_dir.join("daemon.sock"),
            control_dir: runtime_dir.join("control"),
            logs_dir: root.join("logs"),
            runtime_dir,
            root,
        }
    }

    pub fn ensure(&self) -> Result<()> {
        ensure_private_dir(&self.root)?;
        ensure_private_dir(&self.runtime_dir)?;
        ensure_control_dir(&self.control_dir)?;
        ensure_private_dir(&self.logs_dir)?;
        Ok(())
    }

    pub fn profile_control_socket(&self, server_id: Uuid) -> PathBuf {
        self.control_dir
            .join(format!("p-{}.sock", server_id.simple()))
    }

    pub fn doctor_control_socket(&self) -> PathBuf {
        self.control_dir
            .join(format!("d-{}.sock", Uuid::new_v4().simple()))
    }
}

#[cfg(target_os = "macos")]
fn macos_control_dir() -> PathBuf {
    PathBuf::from("/private/tmp")
        .join(format!("ap-{}", unsafe { libc::geteuid() }))
        .join("c")
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

    pub fn load(&self) -> Result<Config> {
        self.paths.ensure()?;
        let lock = open_lock_file(&self.paths.config_lock)?;
        FileExt::lock_shared(&lock).map_err(|error| {
            ApError::coded("AP_CONFIG_LOCK_FAILED", format!("无法读取配置锁：{error}"))
        })?;
        self.load_unlocked()
    }

    pub fn save(&self, config: &Config) -> Result<()> {
        config.validate()?;
        self.paths.ensure()?;
        let lock = open_lock_file(&self.paths.config_lock)?;
        lock.lock_exclusive().map_err(|error| {
            ApError::coded("AP_CONFIG_LOCK_FAILED", format!("无法取得配置锁：{error}"))
        })?;
        self.save_unlocked(config)
    }

    pub fn update_locked<T>(&self, update: impl FnOnce(&mut Config) -> Result<T>) -> Result<T> {
        self.paths.ensure()?;
        let lock = open_lock_file(&self.paths.config_lock)?;
        lock.lock_exclusive().map_err(|error| {
            ApError::coded("AP_CONFIG_LOCK_FAILED", format!("无法取得配置锁：{error}"))
        })?;

        let mut config = self.load_unlocked()?;
        let result = update(&mut config)?;
        config.validate()?;
        self.save_unlocked(&config)?;
        Ok(result)
    }

    pub fn add_server(&self, name: &str, ssh_host: &str) -> Result<ServerConfig> {
        validate_name("server", name)?;
        let server = ServerConfig::new(ssh_host);
        self.insert_server(name, server.clone())?;
        Ok(server)
    }

    /// Insert a fully constructed profile while preserving its immutable UUID.
    ///
    /// This is used by the cross-store transaction layer so a proxy credential
    /// can be prepared before the ordinary configuration starts referring to
    /// it, and to restore a profile after a failed transactional removal.
    pub fn insert_server(&self, name: &str, server: ServerConfig) -> Result<()> {
        validate_name("server", name)?;
        server.validate(name)?;
        self.update_locked(|config| {
            if config.servers.contains_key(name) {
                return Err(ApError::coded(
                    "AP_SERVER_EXISTS",
                    format!("server {name:?} 已存在"),
                ));
            }
            config.servers.insert(name.to_owned(), server);
            Ok(())
        })
    }

    pub fn get_server(&self, name: &str) -> Result<ServerConfig> {
        let config = self.load()?;
        config
            .servers
            .get(name)
            .cloned()
            .ok_or_else(|| ApError::coded("AP_SERVER_NOT_FOUND", format!("server {name:?} 不存在")))
    }

    pub fn remove_server(&self, name: &str) -> Result<ServerConfig> {
        self.update_locked(|config| {
            config.servers.remove(name).ok_or_else(|| {
                ApError::coded("AP_SERVER_NOT_FOUND", format!("server {name:?} 不存在"))
            })
        })
    }

    pub fn update_server<T>(
        &self,
        name: &str,
        update: impl FnOnce(&mut ServerConfig) -> Result<T>,
    ) -> Result<T> {
        self.update_locked(|config| {
            let server = config.servers.get_mut(name).ok_or_else(|| {
                ApError::coded("AP_SERVER_NOT_FOUND", format!("server {name:?} 不存在"))
            })?;
            update(server)
        })
    }

    pub fn add_proxy(&self, server_name: &str, mapping: ProxyMapping) -> Result<()> {
        mapping.validate()?;
        self.update_server(server_name, |server| {
            if server.proxies.iter().any(|item| item.name == mapping.name) {
                return Err(ApError::coded(
                    "AP_PROXY_EXISTS",
                    format!("proxy {:?} 已存在", mapping.name),
                ));
            }
            if server
                .proxies
                .iter()
                .any(|item| item.remote_port == mapping.remote_port)
            {
                return Err(ApError::coded(
                    "AP_REMOTE_PORT_IN_USE",
                    format!(
                        "远端端口 {} 已由此 server 的其他 mapping 使用",
                        mapping.remote_port
                    ),
                ));
            }
            server.proxies.push(mapping);
            Ok(())
        })
    }

    pub fn update_proxy(
        &self,
        server_name: &str,
        proxy_name: &str,
        replacement: ProxyMapping,
    ) -> Result<()> {
        replacement.validate()?;
        self.update_server(server_name, |server| {
            let index = server
                .proxies
                .iter()
                .position(|item| item.name == proxy_name)
                .ok_or_else(|| {
                    ApError::coded("AP_PROXY_NOT_FOUND", format!("proxy {proxy_name:?} 不存在"))
                })?;
            if server
                .proxies
                .iter()
                .enumerate()
                .any(|(other, item)| other != index && item.name == replacement.name)
            {
                return Err(ApError::coded(
                    "AP_PROXY_EXISTS",
                    format!("proxy {:?} 已存在", replacement.name),
                ));
            }
            if server
                .proxies
                .iter()
                .enumerate()
                .any(|(other, item)| other != index && item.remote_port == replacement.remote_port)
            {
                return Err(ApError::coded(
                    "AP_REMOTE_PORT_IN_USE",
                    format!(
                        "远端端口 {} 已由此 server 的其他 mapping 使用",
                        replacement.remote_port
                    ),
                ));
            }
            server.proxies[index] = replacement;
            Ok(())
        })
    }

    pub fn remove_proxy(&self, server_name: &str, proxy_name: &str) -> Result<ProxyMapping> {
        self.update_server(server_name, |server| {
            let index = server
                .proxies
                .iter()
                .position(|item| item.name == proxy_name)
                .ok_or_else(|| {
                    ApError::coded("AP_PROXY_NOT_FOUND", format!("proxy {proxy_name:?} 不存在"))
                })?;
            Ok(server.proxies.remove(index))
        })
    }

    fn load_unlocked(&self) -> Result<Config> {
        if !self.paths.config_file.exists() {
            return Ok(Config::default());
        }
        ensure_private_regular_file(&self.paths.config_file)?;
        let text = read_bounded(&self.paths.config_file, MAX_CONFIG_BYTES)?;
        let config: Config = toml::from_str(&text).map_err(|error| {
            ApError::coded(
                "AP_CONFIG_PARSE_FAILED",
                format!("配置文件无法解析：{error}"),
            )
        })?;
        config.validate()?;
        Ok(config)
    }

    fn save_unlocked(&self, config: &Config) -> Result<()> {
        let text = toml::to_string_pretty(config).map_err(|error| {
            ApError::coded(
                "AP_CONFIG_ENCODE_FAILED",
                format!("配置无法序列化：{error}"),
            )
        })?;
        atomic_write_private(&self.paths.config_file, text.as_bytes())
    }
}

pub(crate) fn ensure_private_dir(path: &Path) -> Result<()> {
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder.create(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(ApError::coded(
            "AP_INSECURE_PATH",
            format!("{} 必须是普通目录且不能是符号链接", path.display()),
        ));
    }
    #[cfg(unix)]
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(ApError::coded(
            "AP_INSECURE_PATH",
            format!("{} 必须由当前用户拥有", path.display()),
        ));
    }
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

pub(crate) fn ensure_control_dir(path: &Path) -> Result<()> {
    #[cfg(target_os = "macos")]
    if path == macos_control_dir() {
        return ensure_macos_control_dir(path);
    }
    ensure_private_dir(path)
}

#[cfg(target_os = "macos")]
fn ensure_macos_control_dir(path: &Path) -> Result<()> {
    let system_tmp = Path::new("/private/tmp");
    let metadata = fs::symlink_metadata(system_tmp)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != 0
        || metadata.mode() & libc::S_ISVTX as u32 == 0
    {
        return Err(ApError::coded(
            "AP_INSECURE_PATH",
            "/private/tmp 必须是 root 拥有的真实 sticky 目录",
        ));
    }

    let user_root = path.parent().ok_or_else(|| {
        ApError::coded(
            "AP_INSECURE_PATH",
            "macOS control socket 目录缺少用户级父目录",
        )
    })?;
    ensure_owned_private_component(user_root)?;
    ensure_owned_private_component(path)
}

#[cfg(target_os = "macos")]
fn ensure_owned_private_component(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            let mut builder = DirBuilder::new();
            builder.mode(0o700);
            builder.create(path)?;
        }
        Err(error) => return Err(error.into()),
    }

    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink()
        || !metadata.is_dir()
        || metadata.uid() != unsafe { libc::geteuid() }
    {
        return Err(ApError::coded(
            "AP_INSECURE_PATH",
            format!("{} 必须是当前用户拥有的真实目录", path.display()),
        ));
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    let verified = fs::symlink_metadata(path)?;
    if verified.file_type().is_symlink()
        || !verified.is_dir()
        || verified.uid() != unsafe { libc::geteuid() }
        || verified.mode() & 0o077 != 0
    {
        return Err(ApError::coded(
            "AP_INSECURE_PATH",
            format!("{} 无法固定为当前用户私有目录", path.display()),
        ));
    }
    Ok(())
}

pub(crate) fn open_lock_file(path: &Path) -> Result<File> {
    if let Ok(metadata) = fs::symlink_metadata(path)
        && (metadata.file_type().is_symlink() || !metadata.is_file())
    {
        return Err(ApError::coded(
            "AP_INSECURE_PATH",
            format!("{} 必须是普通文件且不能是符号链接", path.display()),
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path)?;
    set_private_file_permissions(path)?;
    Ok(file)
}

pub(crate) fn ensure_private_regular_file(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ApError::coded(
            "AP_INSECURE_PATH",
            format!("{} 必须是普通文件且不能是符号链接", path.display()),
        ));
    }
    set_private_file_permissions(path)
}

fn set_private_file_permissions(path: &Path) -> Result<()> {
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

pub(crate) fn read_bounded(path: &Path, max_bytes: u64) -> Result<String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file() {
        return Err(ApError::coded(
            "AP_INSECURE_PATH",
            format!("{} 必须是普通文件且不能是符号链接", path.display()),
        ));
    }
    if metadata.len() > max_bytes {
        return Err(ApError::coded(
            "AP_CONFIG_TOO_LARGE",
            format!("{} 超过允许的最大大小", path.display()),
        ));
    }
    let mut text = String::with_capacity(metadata.len() as usize);
    file.take(max_bytes + 1).read_to_string(&mut text)?;
    if text.len() as u64 > max_bytes {
        return Err(ApError::coded(
            "AP_CONFIG_TOO_LARGE",
            format!("{} 超过允许的最大大小", path.display()),
        ));
    }
    Ok(text)
}

pub(crate) fn atomic_write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        ApError::coded(
            "AP_INVALID_CONFIG_PATH",
            format!("{} 没有父目录", path.display()),
        )
    })?;
    ensure_private_dir(parent)?;
    if path.exists() {
        ensure_private_regular_file(path)?;
    }

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("ap-data");
    let temporary = parent.join(format!(".{file_name}.{}.tmp", Uuid::new_v4()));
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options.mode(0o600);

    let write_result = (|| -> std::io::Result<()> {
        let mut file = options.open(&temporary)?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()?;
        Ok(())
    })();

    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    set_private_file_permissions(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{CONFIG_VERSION, ProxyProtocol};
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;
    use tempfile::TempDir;

    fn store() -> (TempDir, ConfigStore) {
        let temp = tempfile::tempdir().unwrap();
        let store = ConfigStore::new(AppPaths::from_root(temp.path().join("ap")));
        (temp, store)
    }

    #[test]
    fn empty_store_has_current_version() {
        let (_temp, store) = store();
        let config = store.load().unwrap();
        assert_eq!(config.version, CONFIG_VERSION);
        assert!(config.servers.is_empty());
    }

    #[test]
    fn server_and_proxy_crud_round_trip() {
        let (_temp, store) = store();
        let server = store.add_server("dev", "server2").unwrap();
        assert_eq!(store.get_server("dev").unwrap(), server);

        let mapping = ProxyMapping {
            name: "web".into(),
            protocol: ProxyProtocol::Http,
            local: "127.0.0.1:7890".parse().unwrap(),
            remote_port: 17890,
        };
        store.add_proxy("dev", mapping.clone()).unwrap();
        assert_eq!(store.get_server("dev").unwrap().proxies, vec![mapping]);
        assert_eq!(store.remove_proxy("dev", "web").unwrap().name, "web");
        assert_eq!(store.remove_server("dev").unwrap().id, server.id);
    }

    #[test]
    fn failed_update_is_not_persisted() {
        let (_temp, store) = store();
        store.add_server("dev", "server2").unwrap();
        let result: Result<()> = store.update_locked(|config| {
            config.version = 999;
            Ok(())
        });
        assert!(result.is_err());
        assert_eq!(store.load().unwrap().version, CONFIG_VERSION);
    }

    #[cfg(unix)]
    #[test]
    fn writes_private_permissions() {
        let (_temp, store) = store();
        store.add_server("dev", "server2").unwrap();
        let root_mode = fs::metadata(&store.paths().root)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let file_mode = fs::metadata(&store.paths().config_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(root_mode, 0o700);
        assert_eq!(file_mode, 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_config() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let paths = AppPaths::from_root(temp.path().join("ap"));
        paths.ensure().unwrap();
        let target = temp.path().join("target");
        fs::write(&target, "version = 1\n").unwrap();
        symlink(&target, &paths.config_file).unwrap();
        let store = ConfigStore::new(paths);
        assert_eq!(store.load().unwrap_err().code(), "AP_INSECURE_PATH");
    }

    #[test]
    fn control_socket_names_are_stable_or_unique_as_required() {
        let paths = AppPaths::from_root("/tmp/ap-control-test");
        let id = Uuid::new_v4();
        assert_eq!(
            paths.profile_control_socket(id),
            paths.profile_control_socket(id)
        );
        assert_ne!(paths.doctor_control_socket(), paths.doctor_control_socket());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_default_control_paths_leave_openssh_temporary_headroom() {
        const MACOS_SUN_PATH_BYTES: usize = 104;
        const OPENSSH_TEMPORARY_SUFFIX_HEADROOM: usize = 24;

        let mut paths = AppPaths::from_root("/unused");
        paths.control_dir = macos_control_dir();
        let profile = paths.profile_control_socket(Uuid::nil());
        let doctor = paths.doctor_control_socket();
        for path in [profile, doctor] {
            assert!(
                path.as_os_str().as_encoded_bytes().len() + OPENSSH_TEMPORARY_SUFFIX_HEADROOM
                    < MACOS_SUN_PATH_BYTES,
                "{} leaves insufficient sockaddr_un headroom",
                path.display()
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_private_runtime_component_rejects_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::create_dir(&target).unwrap();
        let link = temp.path().join("link");
        symlink(&target, &link).unwrap();
        assert_eq!(
            ensure_owned_private_component(&link).unwrap_err().code(),
            "AP_INSECURE_PATH"
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_private_runtime_component_normalizes_permissions() {
        let temp = tempfile::tempdir().unwrap();
        let directory = temp.path().join("runtime");
        fs::create_dir(&directory).unwrap();
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o777)).unwrap();
        ensure_owned_private_component(&directory).unwrap();
        assert_eq!(
            fs::metadata(directory).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_system_tmp_is_a_root_owned_sticky_directory() {
        let metadata = fs::symlink_metadata("/private/tmp").unwrap();
        assert!(metadata.is_dir());
        assert!(!metadata.file_type().is_symlink());
        assert_eq!(metadata.uid(), 0);
        assert_ne!(metadata.mode() & libc::S_ISVTX as u32, 0);
    }
}
