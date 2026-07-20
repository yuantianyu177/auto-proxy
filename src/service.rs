use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt};

use crate::error::{ApError, Result};

#[cfg(any(target_os = "macos", test))]
const LABEL: &str = "dev.approxy.ap";
#[cfg(target_os = "linux")]
const SYSTEMD_UNIT: &str = "ap.service";
const MAX_SERVICE_DEFINITION_BYTES: u64 = 1024 * 1024;
#[cfg(target_os = "linux")]
const STICKY_MODE: u32 = libc::S_ISVTX;
#[cfg(target_os = "macos")]
const STICKY_MODE: u32 = libc::S_ISVTX as u32;

#[derive(Debug, Clone)]
pub struct ServicePaths {
    pub definition: PathBuf,
    pub log_dir: PathBuf,
}

pub fn service_paths() -> Result<ServicePaths> {
    let home = dirs::home_dir()
        .ok_or_else(|| ApError::coded("AP_HOME_UNAVAILABLE", "无法确定当前用户的主目录"))?;

    #[cfg(target_os = "macos")]
    return Ok(ServicePaths {
        definition: home
            .join("Library")
            .join("LaunchAgents")
            .join(format!("{LABEL}.plist")),
        log_dir: home.join("Library").join("Logs").join("ap"),
    });

    #[cfg(target_os = "linux")]
    {
        let config_home = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".config"));
        let state_home = std::env::var_os("XDG_STATE_HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| home.join(".local").join("state"));
        Ok(ServicePaths {
            definition: config_home.join("systemd/user").join(SYSTEMD_UNIT),
            log_dir: state_home.join("ap"),
        })
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    Err(ApError::coded(
        "AP_UNSUPPORTED_PLATFORM",
        "用户级服务目前只支持 macOS 和 Linux",
    ))
}

pub fn install(executable: &Path) -> Result<ServicePaths> {
    if !executable.is_absolute() {
        return Err(ApError::coded(
            "AP_INVALID_EXECUTABLE",
            "安装服务需要 ap 二进制的绝对路径",
        ));
    }
    let paths = service_paths()?;
    create_secure_directory_tree(
        paths
            .definition
            .parent()
            .ok_or_else(|| ApError::coded("AP_INVALID_PATH", "服务文件路径无父目录"))?,
    )?;
    create_private_dir(&paths.log_dir)?;

    #[cfg(target_os = "macos")]
    let contents = launch_agent(executable, &paths.log_dir)?;
    #[cfg(target_os = "linux")]
    let contents = systemd_unit(executable)?;

    let previous = read_existing_definition(&paths.definition)?;
    atomic_write(&paths.definition, contents.as_bytes(), 0o600)?;
    if let Err(error) = activate_service(&paths) {
        let mut rollback_failures = Vec::new();
        if let Err(rollback_error) = deactivate_service(&paths) {
            rollback_failures.push(format!("停止新服务失败: {rollback_error}"));
        }
        match previous.as_deref() {
            Some(contents) => match atomic_write(&paths.definition, contents, 0o600) {
                Ok(()) => {
                    if let Err(rollback_error) = activate_service(&paths) {
                        rollback_failures.push(format!("恢复原服务失败: {rollback_error}"));
                    }
                }
                Err(rollback_error) => {
                    rollback_failures.push(format!("恢复原服务定义失败: {rollback_error}"));
                }
            },
            None => {
                if let Err(rollback_error) = remove_if_exists(&paths.definition) {
                    rollback_failures.push(format!("删除新服务定义失败: {rollback_error}"));
                }
                if let Err(rollback_error) = reload_service_manager() {
                    rollback_failures.push(format!("重新加载服务管理器失败: {rollback_error}"));
                }
            }
        }
        return Err(with_rollback_failures(error, rollback_failures));
    }

    Ok(paths)
}

pub fn uninstall() -> Result<ServicePaths> {
    let paths = service_paths()?;
    let previous = read_existing_definition(&paths.definition)?;
    deactivate_service(&paths)?;

    if let Err(error) = remove_if_exists(&paths.definition) {
        let mut rollback_failures = Vec::new();
        if previous.is_some()
            && let Err(rollback_error) = activate_service(&paths)
        {
            rollback_failures.push(format!("重新启动原服务失败: {rollback_error}"));
        }
        return Err(with_rollback_failures(error, rollback_failures));
    }

    if let Err(error) = reload_service_manager() {
        let mut rollback_failures = Vec::new();
        if let Some(contents) = previous.as_deref() {
            match atomic_write(&paths.definition, contents, 0o600) {
                Ok(()) => {
                    if let Err(rollback_error) = activate_service(&paths) {
                        rollback_failures.push(format!("重新启动原服务失败: {rollback_error}"));
                    }
                }
                Err(rollback_error) => {
                    rollback_failures.push(format!("恢复原服务定义失败: {rollback_error}"));
                }
            }
        }
        return Err(with_rollback_failures(error, rollback_failures));
    }

    Ok(paths)
}

#[cfg(target_os = "macos")]
fn activate_service(paths: &ServicePaths) -> Result<()> {
    let domain = format!("gui/{}", unsafe { libc::geteuid() });
    let service = format!("{domain}/{LABEL}");
    let loaded = run_status("launchctl", ["print", &service]).map_err(|error| {
        ApError::coded(
            "AP_SERVICE_INSTALL_FAILED",
            format!("无法检查 launchd 服务状态: {error}"),
        )
    })?;
    if loaded {
        run_checked(
            "launchctl",
            ["bootout", &service],
            "AP_SERVICE_INSTALL_FAILED",
        )?;
    }
    run_checked(
        "launchctl",
        ["bootstrap", &domain, path_str(&paths.definition)?],
        "AP_SERVICE_INSTALL_FAILED",
    )?;
    run_checked(
        "launchctl",
        ["enable", &service],
        "AP_SERVICE_INSTALL_FAILED",
    )
}

#[cfg(target_os = "linux")]
fn activate_service(_paths: &ServicePaths) -> Result<()> {
    run_checked(
        "systemctl",
        ["--user", "daemon-reload"],
        "AP_SERVICE_INSTALL_FAILED",
    )?;
    run_checked(
        "systemctl",
        ["--user", "enable", "--now", SYSTEMD_UNIT],
        "AP_SERVICE_INSTALL_FAILED",
    )
}

#[cfg(target_os = "macos")]
fn deactivate_service(_paths: &ServicePaths) -> Result<()> {
    let service = format!("gui/{}/{LABEL}", unsafe { libc::geteuid() });
    let loaded = run_status("launchctl", ["print", &service]).map_err(|error| {
        ApError::coded(
            "AP_SERVICE_UNINSTALL_FAILED",
            format!("无法检查 launchd 服务状态: {error}"),
        )
    })?;
    if loaded {
        run_checked(
            "launchctl",
            ["bootout", &service],
            "AP_SERVICE_UNINSTALL_FAILED",
        )?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn deactivate_service(paths: &ServicePaths) -> Result<()> {
    let active = run_status(
        "systemctl",
        ["--user", "is-active", "--quiet", SYSTEMD_UNIT],
    )
    .map_err(|error| {
        ApError::coded(
            "AP_SERVICE_UNINSTALL_FAILED",
            format!("无法检查 systemd 服务状态: {error}"),
        )
    })?;
    let enabled = run_status(
        "systemctl",
        ["--user", "is-enabled", "--quiet", SYSTEMD_UNIT],
    )
    .map_err(|error| {
        ApError::coded(
            "AP_SERVICE_UNINSTALL_FAILED",
            format!("无法检查 systemd 服务启用状态: {error}"),
        )
    })?;
    if paths.definition.exists() || active || enabled {
        run_checked(
            "systemctl",
            ["--user", "disable", "--now", SYSTEMD_UNIT],
            "AP_SERVICE_UNINSTALL_FAILED",
        )?;
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn reload_service_manager() -> Result<()> {
    run_checked(
        "systemctl",
        ["--user", "daemon-reload"],
        "AP_SERVICE_UNINSTALL_FAILED",
    )
}

#[cfg(target_os = "macos")]
fn reload_service_manager() -> Result<()> {
    Ok(())
}

#[cfg(any(target_os = "macos", test))]
fn launch_agent(executable: &Path, log_dir: &Path) -> Result<String> {
    let executable = xml_escape(path_str(executable)?)?;
    let stdout_path = log_dir.join("daemon.log");
    let stderr_path = log_dir.join("daemon.err.log");
    let stdout = xml_escape(path_str(&stdout_path)?)?;
    let stderr = xml_escape(path_str(&stderr_path)?)?;
    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{LABEL}</string>
  <key>ProgramArguments</key>
  <array><string>{executable}</string><string>__daemon</string></array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>ProcessType</key><string>Background</string>
  <key>StandardOutPath</key><string>{stdout}</string>
  <key>StandardErrorPath</key><string>{stderr}</string>
  <key>Umask</key><integer>63</integer>
</dict>
</plist>
"#
    ))
}

#[cfg(any(target_os = "linux", test))]
fn systemd_unit(executable: &Path) -> Result<String> {
    let executable = systemd_escape_arg(path_str(executable)?)?;
    Ok(format!(
        r#"[Unit]
Description=ap local proxy sharing daemon

[Service]
Type=simple
ExecStart={executable} __daemon
Restart=on-failure
RestartSec=5
UMask=0077
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=default.target
"#
    ))
}

#[cfg(any(target_os = "macos", test))]
fn xml_escape(value: &str) -> Result<String> {
    if value.chars().any(|character| {
        !matches!(
            character,
            '\u{9}' | '\u{A}' | '\u{D}' | '\u{20}'..='\u{D7FF}' | '\u{E000}'..='\u{FFFD}' | '\u{10000}'..='\u{10FFFF}'
        )
    }) {
        return Err(ApError::coded(
            "AP_INVALID_PATH",
            "路径包含 XML 1.0 无法表示的控制字符",
        ));
    }
    Ok(value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;"))
}

#[cfg(any(target_os = "linux", test))]
fn systemd_escape_arg(value: &str) -> Result<String> {
    if value.chars().any(char::is_control) {
        return Err(ApError::coded(
            "AP_INVALID_PATH",
            "路径包含 systemd 服务定义无法安全表示的控制字符",
        ));
    }
    // systemd accepts C-style quoting. `%` starts a specifier and `$` starts
    // environment-variable expansion, so both must be doubled.
    let value = value
        .replace('%', "%%")
        .replace('$', "$$")
        .replace('\\', "\\\\")
        .replace('"', "\\\"");
    Ok(format!("\"{value}\""))
}

fn create_private_dir(path: &Path) -> Result<()> {
    validate_directory_tree(path, true)?;
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    validate_existing_directory_tree(path)
}

fn create_secure_directory_tree(path: &Path) -> Result<()> {
    validate_directory_tree(path, true)
}

fn validate_existing_directory_tree(path: &Path) -> Result<()> {
    validate_directory_tree(path, false)
}

fn validate_directory_tree(path: &Path, create_missing: bool) -> Result<()> {
    if !path.is_absolute() {
        return Err(ApError::coded(
            "AP_INSECURE_PATH",
            format!("{} 必须是绝对路径", path.display()),
        ));
    }

    let current_uid = unsafe { libc::geteuid() };
    let mut current = PathBuf::new();
    for component in path.components() {
        match component {
            Component::RootDir => current.push(Path::new("/")),
            Component::Normal(component) => current.push(component),
            Component::CurDir => continue,
            Component::ParentDir | Component::Prefix(_) => {
                return Err(ApError::coded(
                    "AP_INSECURE_PATH",
                    format!("{} 包含不允许的路径组件", path.display()),
                ));
            }
        }

        let metadata = match fs::symlink_metadata(&current) {
            Ok(metadata) => metadata,
            Err(error) if create_missing && error.kind() == std::io::ErrorKind::NotFound => {
                let mut builder = fs::DirBuilder::new();
                #[cfg(unix)]
                builder.mode(0o700);
                match builder.create(&current) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                    Err(error) => return Err(error.into()),
                }
                fs::symlink_metadata(&current)?
            }
            Err(error) => return Err(error.into()),
        };
        validate_directory_metadata(&current, &metadata, current_uid)?;
    }
    Ok(())
}

fn validate_directory_metadata(
    path: &Path,
    metadata: &fs::Metadata,
    current_uid: libc::uid_t,
) -> Result<()> {
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(ApError::coded(
            "AP_INSECURE_PATH",
            format!("{} 必须是目录且不能是符号链接", path.display()),
        ));
    }

    #[cfg(unix)]
    {
        let owner = metadata.uid();
        let mode = metadata.mode();
        if !trusted_directory_owner_and_mode(current_uid, owner, mode) {
            return Err(ApError::coded(
                "AP_INSECURE_PATH",
                format!(
                    "{} 的所有者或权限不安全（uid={owner}, mode={:04o}）",
                    path.display(),
                    mode & 0o7777
                ),
            ));
        }
    }
    Ok(())
}

#[cfg(unix)]
fn trusted_directory_owner_and_mode(
    current_uid: libc::uid_t,
    owner: libc::uid_t,
    mode: u32,
) -> bool {
    if owner == current_uid && owner != 0 {
        return mode & 0o022 == 0;
    }
    if owner != 0 {
        return false;
    }

    // System ancestors must not be writable by other users. Root-owned sticky
    // temporary directories (for example /tmp and /var/tmp) are the one safe
    // exception: sticky-bit semantics prevent other users from replacing our
    // entries, while the next user-owned component is still required to be
    // non-group/world-writable.
    mode & 0o022 == 0 || (mode & STICKY_MODE != 0 && mode & 0o002 != 0)
}

fn validate_service_file_metadata(path: &Path, metadata: &fs::Metadata) -> Result<()> {
    if !metadata.is_file() || metadata.file_type().is_symlink() {
        return Err(ApError::coded(
            "AP_INSECURE_SERVICE_FILE",
            format!("{} 必须是普通文件且不能是符号链接", path.display()),
        ));
    }

    #[cfg(unix)]
    if !trusted_service_file_owner_and_mode(
        unsafe { libc::geteuid() },
        metadata.uid(),
        metadata.mode(),
    ) {
        return Err(ApError::coded(
            "AP_INSECURE_SERVICE_FILE",
            format!(
                "{} 必须由当前用户拥有且不能允许组或其他用户写入",
                path.display()
            ),
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn trusted_service_file_owner_and_mode(
    current_uid: libc::uid_t,
    owner: libc::uid_t,
    mode: u32,
) -> bool {
    owner == current_uid && mode & 0o022 == 0
}

fn existing_service_file_metadata(path: &Path) -> Result<Option<fs::Metadata>> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    validate_service_file_metadata(path, &metadata)?;
    Ok(Some(metadata))
}

fn read_existing_definition(path: &Path) -> Result<Option<Vec<u8>>> {
    let parent = path
        .parent()
        .ok_or_else(|| ApError::coded("AP_INVALID_PATH", "服务文件路径无父目录"))?;
    match fs::symlink_metadata(parent) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    validate_existing_directory_tree(parent)?;
    let Some(metadata) = existing_service_file_metadata(path)? else {
        return Ok(None);
    };
    if metadata.len() > MAX_SERVICE_DEFINITION_BYTES {
        return Err(ApError::coded(
            "AP_SERVICE_FILE_TOO_LARGE",
            format!("{} 超过允许的最大大小", path.display()),
        ));
    }

    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let file = options.open(path)?;
    let opened_metadata = file.metadata()?;
    validate_service_file_metadata(path, &opened_metadata)?;
    #[cfg(unix)]
    let same_file =
        metadata.dev() == opened_metadata.dev() && metadata.ino() == opened_metadata.ino();
    #[cfg(not(unix))]
    let same_file = true;
    if !same_file || opened_metadata.len() > MAX_SERVICE_DEFINITION_BYTES {
        return Err(ApError::coded(
            "AP_INSECURE_SERVICE_FILE",
            format!("{} 在读取期间发生了不安全的变化", path.display()),
        ));
    }
    validate_existing_directory_tree(parent)?;

    let mut contents = Vec::with_capacity(opened_metadata.len() as usize);
    file.take(MAX_SERVICE_DEFINITION_BYTES + 1)
        .read_to_end(&mut contents)?;
    if contents.len() as u64 > MAX_SERVICE_DEFINITION_BYTES {
        return Err(ApError::coded(
            "AP_SERVICE_FILE_TOO_LARGE",
            format!("{} 超过允许的最大大小", path.display()),
        ));
    }
    Ok(Some(contents))
}

fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| ApError::coded("AP_INVALID_PATH", "目标文件路径无父目录"))?;
    validate_existing_directory_tree(parent)?;
    let _ = existing_service_file_metadata(path)?;
    if mode & 0o022 != 0 {
        return Err(ApError::coded(
            "AP_INSECURE_SERVICE_FILE",
            "服务文件模式不能允许组或其他用户写入",
        ));
    }
    let file_name = path
        .file_name()
        .and_then(OsStr::to_str)
        .ok_or_else(|| ApError::coded("AP_INVALID_PATH", "目标文件名不是有效 UTF-8"))?;
    let mut random = [0_u8; 8];
    getrandom::fill(&mut random).map_err(|error| ApError::coded("AP_RANDOM", error.to_string()))?;
    let temporary = parent.join(format!(
        ".{file_name}.{}-{}.tmp",
        std::process::id(),
        u64::from_ne_bytes(random)
    ));

    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    options
        .mode(mode)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let write_result = (|| -> Result<()> {
        let mut file = options.open(&temporary)?;
        #[cfg(unix)]
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        let temporary_metadata = file.metadata()?;
        if !temporary_metadata.is_file()
            || !trusted_service_file_owner_and_mode(
                unsafe { libc::geteuid() },
                temporary_metadata.uid(),
                temporary_metadata.mode(),
            )
        {
            return Err(ApError::coded(
                "AP_INSECURE_SERVICE_FILE",
                "临时服务文件的所有者或权限不安全",
            ));
        }
        file.write_all(contents)?;
        file.sync_all()?;
        drop(file);
        validate_existing_directory_tree(parent)?;
        existing_service_file_metadata(path)?;
        fs::rename(&temporary, path)?;
        let installed = fs::symlink_metadata(path)?;
        validate_service_file_metadata(path, &installed)?;
        if let Ok(directory) = fs::File::open(parent) {
            let _ = directory.sync_all();
        }
        Ok(())
    })();

    if let Err(error) = write_result {
        let _ = fs::remove_file(&temporary);
        return Err(error);
    }
    Ok(())
}

fn remove_if_exists(path: &Path) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| ApError::coded("AP_INVALID_PATH", "服务文件路径无父目录"))?;
    match fs::symlink_metadata(parent) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    validate_existing_directory_tree(parent)?;
    if existing_service_file_metadata(path)?.is_none() {
        return Ok(());
    }
    validate_existing_directory_tree(parent)?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn with_rollback_failures(error: ApError, rollback_failures: Vec<String>) -> ApError {
    if rollback_failures.is_empty() {
        return error;
    }
    let code = error.code();
    ApError::coded(
        code,
        format!("{error}; 回滚未完全成功: {}", rollback_failures.join("；")),
    )
}

fn run_checked<const N: usize>(program: &str, args: [&str; N], code: &'static str) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| ApError::coded(code, format!("无法执行 {program}: {error}")))?;
    if output.status.success() {
        return Ok(());
    }
    let stderr = String::from_utf8_lossy(&output.stderr);
    let detail = stderr.lines().take(3).collect::<Vec<_>>().join(" ");
    Err(ApError::coded(
        code,
        format!("{program} 返回 {}: {detail}", output.status),
    ))
}

fn run_status<const N: usize>(program: &str, args: [&str; N]) -> std::io::Result<bool> {
    Command::new(program)
        .args(args)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|status| status.success())
}

fn path_str(path: &Path) -> Result<&str> {
    path.to_str()
        .ok_or_else(|| ApError::coded("AP_INVALID_PATH", "路径不是有效 UTF-8"))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::{PermissionsExt, symlink};
    use tempfile::TempDir;

    fn canonical_temp(temp: &TempDir) -> PathBuf {
        fs::canonicalize(temp.path()).unwrap()
    }

    #[test]
    fn launch_agent_escapes_paths() {
        let output = launch_agent(Path::new("/tmp/a&b/'\"ap"), Path::new("/tmp/<logs>")).unwrap();
        assert!(output.contains("/tmp/a&amp;b/&apos;&quot;ap"));
        assert!(output.contains("/tmp/&lt;logs&gt;/daemon.log"));
        assert!(output.contains("<key>ProgramArguments</key>"));
        assert!(output.contains("<string>__daemon</string>"));
        assert!(output.contains("<key>Umask</key><integer>63</integer>"));
        assert!(!output.contains("/tmp/a&b"));
    }

    #[test]
    fn systemd_path_is_quoted_and_specifiers_are_escaped() {
        let output = systemd_unit(Path::new("/tmp/a b/%$\\\"ap")).unwrap();
        assert!(output.contains("ExecStart=\"/tmp/a b/%%$$\\\\\\\"ap\" __daemon"));
        assert!(output.contains("Restart=on-failure"));
        assert!(output.contains("UMask=0077"));
        assert!(output.contains("WantedBy=default.target"));
        assert!(!output.contains("After=default.target"));
    }

    #[test]
    fn renderers_reject_unsafe_control_characters() {
        let launch_error =
            launch_agent(Path::new("/tmp/ap\u{1}"), Path::new("/tmp/logs")).unwrap_err();
        assert_eq!(launch_error.code(), "AP_INVALID_PATH");

        let systemd_error = systemd_unit(Path::new("/tmp/ap\nname")).unwrap_err();
        assert_eq!(systemd_error.code(), "AP_INVALID_PATH");
    }

    #[test]
    fn atomic_write_replaces_contents_and_sets_private_mode() {
        let temp = TempDir::new().unwrap();
        let path = canonical_temp(&temp).join("service.definition");
        fs::write(&path, b"old").unwrap();

        atomic_write(&path, b"new", 0o600).unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"new");
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn atomic_write_removes_temporary_file_after_failure() {
        let temp = TempDir::new().unwrap();
        let base = canonical_temp(&temp);
        let target = base.join("service.definition");
        fs::create_dir(&target).unwrap();

        assert!(atomic_write(&target, b"contents", 0o600).is_err());

        let leftovers = fs::read_dir(base)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .filter(|name| name.to_string_lossy().starts_with(".service.definition."))
            .collect::<Vec<_>>();
        assert!(leftovers.is_empty(), "遗留临时文件: {leftovers:?}");
    }

    #[test]
    fn existing_definition_is_bounded() {
        let temp = TempDir::new().unwrap();
        let path = canonical_temp(&temp).join("service.definition");
        fs::write(
            &path,
            vec![0_u8; (MAX_SERVICE_DEFINITION_BYTES + 1) as usize],
        )
        .unwrap();

        let error = read_existing_definition(&path).unwrap_err();
        assert_eq!(error.code(), "AP_SERVICE_FILE_TOO_LARGE");
    }

    #[cfg(unix)]
    #[test]
    fn existing_definition_rejects_symlink() {
        let temp = TempDir::new().unwrap();
        let base = canonical_temp(&temp);
        let target = base.join("target");
        let link = base.join("service.definition");
        fs::write(&target, b"definition").unwrap();
        symlink(&target, &link).unwrap();

        let error = read_existing_definition(&link).unwrap_err();
        assert_eq!(error.code(), "AP_INSECURE_SERVICE_FILE");
    }

    #[cfg(unix)]
    #[test]
    fn private_log_directory_rejects_symlink() {
        let temp = TempDir::new().unwrap();
        let base = canonical_temp(&temp);
        let target = base.join("real-logs");
        let link = base.join("logs");
        fs::create_dir(&target).unwrap();
        symlink(&target, &link).unwrap();

        let error = create_private_dir(&link).unwrap_err();
        assert_eq!(error.code(), "AP_INSECURE_PATH");
    }

    #[cfg(unix)]
    #[test]
    fn directory_tree_creates_private_components_without_changing_existing_modes() {
        let temp = TempDir::new().unwrap();
        let standard = canonical_temp(&temp).join("standard");
        fs::create_dir(&standard).unwrap();
        fs::set_permissions(&standard, fs::Permissions::from_mode(0o755)).unwrap();

        let nested = standard.join("one/two");
        create_private_dir(&nested).unwrap();

        assert_eq!(fs::metadata(&standard).unwrap().mode() & 0o777, 0o755);
        assert_eq!(
            fs::metadata(standard.join("one")).unwrap().mode() & 0o777,
            0o700
        );
        assert_eq!(fs::metadata(nested).unwrap().mode() & 0o777, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn directory_tree_accepts_root_owned_sticky_tmp_ancestor() {
        let shared_tmp = fs::canonicalize("/tmp").unwrap();
        let metadata = fs::symlink_metadata(&shared_tmp).unwrap();
        assert_eq!(metadata.uid(), 0);
        assert_ne!(metadata.mode() & STICKY_MODE, 0);

        let temp = TempDir::new_in(&shared_tmp).unwrap();
        let nested = canonical_temp(&temp).join("logs/ap");
        create_private_dir(&nested).unwrap();

        assert_eq!(fs::metadata(nested).unwrap().mode() & 0o777, 0o700);
    }

    #[cfg(unix)]
    #[test]
    fn directory_tree_rejects_writable_user_component() {
        let temp = TempDir::new().unwrap();
        let writable = canonical_temp(&temp).join("writable");
        fs::create_dir(&writable).unwrap();
        fs::set_permissions(&writable, fs::Permissions::from_mode(0o770)).unwrap();

        let error = create_private_dir(&writable.join("child")).unwrap_err();

        assert_eq!(error.code(), "AP_INSECURE_PATH");
        assert!(!writable.join("child").exists());
    }

    #[cfg(unix)]
    #[test]
    fn directory_tree_rejects_symlink_in_ancestor() {
        let temp = TempDir::new().unwrap();
        let base = canonical_temp(&temp);
        let real = base.join("real");
        let link = base.join("link");
        fs::create_dir(&real).unwrap();
        symlink(&real, &link).unwrap();

        let error = create_private_dir(&link.join("child")).unwrap_err();

        assert_eq!(error.code(), "AP_INSECURE_PATH");
        assert!(!real.join("child").exists());
    }

    #[test]
    fn directory_tree_rejects_non_directory_component() {
        let temp = TempDir::new().unwrap();
        let base = canonical_temp(&temp);
        let file = base.join("not-a-directory");
        fs::write(&file, b"contents").unwrap();

        let error = create_private_dir(&file.join("child")).unwrap_err();

        assert_eq!(error.code(), "AP_INSECURE_PATH");
    }

    #[cfg(unix)]
    #[test]
    fn directory_owner_policy_accepts_only_current_user_or_safe_root() {
        let uid = 501;
        assert!(trusted_directory_owner_and_mode(uid, uid, 0o755));
        assert!(!trusted_directory_owner_and_mode(uid, uid, 0o775));
        assert!(trusted_directory_owner_and_mode(uid, 0, 0o755));
        assert!(trusted_directory_owner_and_mode(uid, 0, 0o1777));
        assert!(!trusted_directory_owner_and_mode(uid, 0, 0o0777));
        assert!(!trusted_directory_owner_and_mode(uid, 502, 0o700));
    }

    #[cfg(unix)]
    #[test]
    fn service_file_owner_policy_rejects_foreign_owner_and_writable_mode() {
        let uid = 501;
        assert!(trusted_service_file_owner_and_mode(uid, uid, 0o644));
        assert!(!trusted_service_file_owner_and_mode(uid, uid, 0o664));
        assert!(!trusted_service_file_owner_and_mode(uid, 502, 0o600));
        assert!(!trusted_service_file_owner_and_mode(uid, 0, 0o600));
    }

    #[cfg(unix)]
    #[test]
    fn existing_definition_rejects_group_or_world_writable_file() {
        let temp = TempDir::new().unwrap();
        let path = canonical_temp(&temp).join("service.definition");
        fs::write(&path, b"definition").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert_eq!(
            read_existing_definition(&path).unwrap().as_deref(),
            Some(b"definition".as_slice())
        );

        fs::set_permissions(&path, fs::Permissions::from_mode(0o664)).unwrap();
        let error = read_existing_definition(&path).unwrap_err();
        assert_eq!(error.code(), "AP_INSECURE_SERVICE_FILE");
    }

    #[cfg(unix)]
    #[test]
    fn atomic_write_rejects_symlink_target_without_touching_referent() {
        let temp = TempDir::new().unwrap();
        let base = canonical_temp(&temp);
        let target = base.join("target");
        let link = base.join("service.definition");
        fs::write(&target, b"keep").unwrap();
        symlink(&target, &link).unwrap();

        let error = atomic_write(&link, b"replace", 0o600).unwrap_err();

        assert_eq!(error.code(), "AP_INSECURE_SERVICE_FILE");
        assert_eq!(fs::read(target).unwrap(), b"keep");
    }

    #[cfg(unix)]
    #[test]
    fn remove_rejects_symlink_and_insecure_service_file() {
        let temp = TempDir::new().unwrap();
        let base = canonical_temp(&temp);
        let target = base.join("target");
        let link = base.join("service.definition");
        fs::write(&target, b"keep").unwrap();
        symlink(&target, &link).unwrap();

        let error = remove_if_exists(&link).unwrap_err();
        assert_eq!(error.code(), "AP_INSECURE_SERVICE_FILE");
        assert_eq!(fs::read(&target).unwrap(), b"keep");

        fs::remove_file(&link).unwrap();
        fs::rename(&target, &link).unwrap();
        fs::set_permissions(&link, fs::Permissions::from_mode(0o622)).unwrap();
        let error = remove_if_exists(&link).unwrap_err();
        assert_eq!(error.code(), "AP_INSECURE_SERVICE_FILE");
        assert!(link.exists());
    }

    #[test]
    fn absent_definition_under_absent_parent_is_a_noop() {
        let temp = TempDir::new().unwrap();
        let path = canonical_temp(&temp).join("missing/parent/service.definition");

        assert!(read_existing_definition(&path).unwrap().is_none());
        remove_if_exists(&path).unwrap();
    }
}
