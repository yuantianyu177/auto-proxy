use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use fs2::FileExt;
use serde_json::Value;
use tempfile::TempDir;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

struct CliSandbox {
    _temporary: TempDir,
    config_dir: PathBuf,
}

impl CliSandbox {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("create isolated CLI test directory");
        let config_dir = temporary.path().join("ap-config");
        Self {
            _temporary: temporary,
            config_dir,
        }
    }

    fn run<I, S>(&self, arguments: I) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        Command::new(env!("CARGO_BIN_EXE_ap"))
            .args(arguments)
            .env("AP_CONFIG_DIR", &self.config_dir)
            .env("RUST_LOG", "off")
            // A developer shell may itself be configured for AskPass. The CLI
            // integration tests must never accidentally enter that internal mode.
            .env_remove("SSH_ASKPASS")
            .env_remove("SSH_ASKPASS_REQUIRE")
            .env_remove("AP_ASKPASS_SOCKET")
            .env_remove("AP_ASKPASS_NONCE")
            .stdin(Stdio::null())
            .output()
            .expect("run ap test binary")
    }

    fn success<I, S>(&self, arguments: I) -> String
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = self.run(arguments);
        assert!(
            output.status.success(),
            "ap command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty(), "successful command wrote stderr");
        String::from_utf8(output.stdout).expect("ap stdout is UTF-8")
    }

    fn failure<I, S>(&self, arguments: I, expected_code: &str) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = self.run(arguments);
        assert!(
            !output.status.success(),
            "ap command unexpectedly succeeded"
        );
        assert!(output.stdout.is_empty(), "failed command wrote stdout");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains(expected_code),
            "stderr did not contain {expected_code}: {stderr}"
        );
        output
    }

    fn add_server(&self) -> Value {
        let output = self.success(["server", "add", "dev", "--ssh", "dev-alias"]);
        assert!(output.contains("已添加 server dev"));
        serde_json::from_str(&self.success(["server", "show", "dev", "--json"]))
            .expect("server show emits JSON")
    }

    fn config_bytes(&self) -> Vec<u8> {
        fs::read(self.config_dir.join("config.toml")).expect("read isolated config")
    }
}

#[test]
fn server_and_proxy_cli_lifecycle_is_isolated() {
    let cli = CliSandbox::new();

    let empty = cli.success(["server", "list"]);
    assert!(empty.contains("尚未配置 server"));

    let server = cli.add_server();
    assert_eq!(server["ssh_host"], "dev-alias");
    assert_eq!(server["auth_mode"], "ssh-config");
    assert_eq!(server["autostart"], false);
    assert!(server["ssh_secret_ref"].is_null());
    assert!(server["proxies"].as_array().is_some_and(Vec::is_empty));

    let list = cli.success(["server", "list"]);
    assert!(list.contains("dev\tdev-alias\tssh-config\t0\tno"));

    cli.success([
        "proxy",
        "add",
        "dev",
        "web",
        "--protocol",
        "http",
        "--local",
        "127.0.0.1:7890",
        "--remote-port",
        "17890",
    ]);
    cli.success([
        "proxy",
        "add",
        "dev",
        "socks",
        "--protocol",
        "socks5",
        "--local",
        "[::1]:7891",
        "--remote-port",
        "17891",
    ]);
    cli.success([
        "proxy",
        "add",
        "dev",
        "combo",
        "--protocol",
        "mixed",
        "--local",
        "127.0.0.1:7892",
        "--remote-port",
        "17892",
    ]);

    let proxies: Value = serde_json::from_str(&cli.success(["proxy", "list", "dev", "--json"]))
        .expect("proxy list emits JSON");
    let proxies = proxies.as_array().expect("proxy list is an array");
    assert_eq!(proxies.len(), 3);
    assert!(proxies.iter().any(|mapping| {
        mapping["name"] == "web"
            && mapping["protocol"] == "http"
            && mapping["local"] == "127.0.0.1:7890"
            && mapping["remote_port"] == 17890
    }));
    assert!(proxies.iter().any(|mapping| {
        mapping["name"] == "socks"
            && mapping["protocol"] == "socks5"
            && mapping["local"] == "[::1]:7891"
            && mapping["remote_port"] == 17891
    }));

    assert_http_env(&cli.success(["env", "dev", "web"]), 17890);
    assert_socks_env(&cli.success(["env", "dev", "socks"]), 17891);
    assert_mixed_env(&cli.success(["env", "dev", "combo"]), 17892);

    let before_rotation = proxy_password(&cli.success(["env", "dev", "web"]));
    cli.success(["proxy-credential", "rotate", "dev"]);
    let after_rotation = proxy_password(&cli.success(["env", "dev", "web"]));
    assert!(
        before_rotation != after_rotation,
        "proxy credential rotation did not replace the password"
    );

    cli.success([
        "proxy",
        "update",
        "dev",
        "web",
        "--rename",
        "combined",
        "--protocol",
        "mixed",
        "--local",
        "127.0.0.1:8890",
        "--remote-port",
        "18890",
    ]);
    let proxies: Value = serde_json::from_str(&cli.success(["proxy", "list", "dev", "--json"]))
        .expect("updated proxy list emits JSON");
    assert!(proxies.as_array().is_some_and(|mappings| {
        mappings.iter().any(|mapping| {
            mapping["name"] == "combined"
                && mapping["protocol"] == "mixed"
                && mapping["local"] == "127.0.0.1:8890"
                && mapping["remote_port"] == 18890
        })
    }));

    cli.success(["proxy", "remove", "dev", "socks"]);
    cli.success(["proxy", "remove", "dev", "combo"]);
    cli.success(["proxy", "remove", "dev", "combined"]);
    let proxies: Value = serde_json::from_str(&cli.success(["proxy", "list", "dev", "--json"]))
        .expect("empty proxy list emits JSON");
    assert!(proxies.as_array().is_some_and(Vec::is_empty));

    // An ssh-config profile must remain removable on headless Linux where no
    // Secret Service exists. The command must not touch the SSH password store.
    cli.success(["server", "remove", "dev"]);
    assert!(cli.success(["server", "list"]).contains("尚未配置 server"));

    // Test the command's not-found/atomic failure path too.
    let before_failed_remove = cli.config_bytes();
    cli.failure(
        ["server", "remove", "does-not-exist"],
        "AP_SERVER_NOT_FOUND",
    );
    assert_eq!(cli.config_bytes(), before_failed_remove);

    let config = fs::read_to_string(cli.config_dir.join("config.toml")).expect("read config TOML");
    assert!(!config.contains(&after_rotation));
    assert_private_layout(&cli.config_dir);
}

#[test]
fn invalid_and_conflicting_cli_changes_are_atomic() {
    let cli = CliSandbox::new();
    cli.add_server();

    let initial = cli.config_bytes();
    cli.failure(["enable", "dev"], "AP_NO_PROXY_MAPPING");
    assert_eq!(cli.config_bytes(), initial);
    cli.failure(
        ["server", "add", "dev", "--ssh", "another-alias"],
        "AP_SERVER_EXISTS",
    );
    assert_eq!(cli.config_bytes(), initial);

    cli.failure(
        ["server", "add", "bad name", "--ssh", "safe-alias"],
        "AP_INVALID_CONFIG",
    );
    assert_eq!(cli.config_bytes(), initial);
    cli.failure(
        ["server", "add", "another", "--ssh", "-oProxyCommand=bad"],
        "unexpected argument",
    );
    assert_eq!(cli.config_bytes(), initial);

    cli.failure(
        [
            "proxy",
            "add",
            "dev",
            "external",
            "--protocol",
            "http",
            "--local",
            "192.0.2.20:7890",
            "--remote-port",
            "17890",
        ],
        "AP_INVALID_CONFIG",
    );
    assert_eq!(cli.config_bytes(), initial);

    cli.success([
        "proxy",
        "add",
        "dev",
        "web",
        "--protocol",
        "http",
        "--local",
        "127.0.0.1:7890",
        "--remote-port",
        "17890",
    ]);
    let one_mapping = cli.config_bytes();

    cli.failure(
        [
            "proxy",
            "add",
            "dev",
            "web",
            "--protocol",
            "socks5",
            "--local",
            "127.0.0.1:7891",
            "--remote-port",
            "17891",
        ],
        "AP_PROXY_EXISTS",
    );
    assert_eq!(cli.config_bytes(), one_mapping);
    cli.failure(
        [
            "proxy",
            "add",
            "dev",
            "socks",
            "--protocol",
            "socks5",
            "--local",
            "127.0.0.1:7891",
            "--remote-port",
            "17890",
        ],
        "AP_REMOTE_PORT_IN_USE",
    );
    assert_eq!(cli.config_bytes(), one_mapping);
    cli.failure(
        [
            "proxy",
            "add",
            "dev",
            "too-low",
            "--protocol",
            "http",
            "--local",
            "127.0.0.1:7892",
            "--remote-port",
            "1023",
        ],
        "invalid value",
    );
    assert_eq!(cli.config_bytes(), one_mapping);

    cli.failure(["env", "dev", "missing"], "AP_PROXY_NOT_FOUND");
    cli.failure(["proxy", "remove", "dev", "missing"], "AP_PROXY_NOT_FOUND");
    assert_eq!(cli.config_bytes(), one_mapping);
}

#[test]
fn foreground_profile_lease_blocks_local_mutations_even_with_restart() {
    let cli = CliSandbox::new();
    let server = cli.add_server();
    let server_id = server["id"].as_str().expect("server UUID in show output");

    cli.success([
        "proxy",
        "add",
        "dev",
        "web",
        "--protocol",
        "http",
        "--local",
        "127.0.0.1:7890",
        "--remote-port",
        "17890",
    ]);
    let before = cli.config_bytes();

    let lease_path = cli
        .config_dir
        .join("run")
        .join(format!("profile-{server_id}.lock"));
    let lease = open_private_lock(&lease_path);
    lease
        .try_lock_exclusive()
        .expect("hold foreground profile lease");

    let status: Value =
        serde_json::from_str(&cli.success(["status", "dev", "--json"])).expect("status emits JSON");
    assert_eq!(status[0]["server"], "dev");
    assert_eq!(status[0]["phase"], "connected");

    for arguments in [
        vec!["proxy", "update", "dev", "web", "--remote-port", "18890"],
        vec![
            "proxy",
            "update",
            "dev",
            "web",
            "--remote-port",
            "18890",
            "--restart",
        ],
        vec!["proxy-credential", "rotate", "dev", "--restart"],
        vec!["server", "remove", "dev"],
    ] {
        cli.failure(arguments, "AP_PROFILE_FOREGROUND_RUNNING");
        assert_eq!(cli.config_bytes(), before);
    }

    FileExt::unlock(&lease).expect("release foreground profile lease");
    drop(lease);

    cli.success(["proxy", "update", "dev", "web", "--remote-port", "18890"]);
    let mappings: Value = serde_json::from_str(&cli.success(["proxy", "list", "dev", "--json"]))
        .expect("proxy list emits JSON");
    assert_eq!(mappings[0]["remote_port"], 18890);
}

fn assert_http_env(output: &str, remote_port: u16) {
    let lines = output.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 2);
    assert!(lines[0].starts_with("export http_proxy='http://ap:"));
    assert!(lines[0].ends_with(&format!("@127.0.0.1:{remote_port}'")));
    assert_eq!(lines[1], "export https_proxy=\"$http_proxy\"");
    assert!(!proxy_password(output).is_empty());
}

fn assert_socks_env(output: &str, remote_port: u16) {
    let lines = output.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 1);
    assert!(lines[0].starts_with("export all_proxy='socks5h://ap:"));
    assert!(lines[0].ends_with(&format!("@127.0.0.1:{remote_port}'")));
    assert!(!proxy_password(output).is_empty());
}

fn assert_mixed_env(output: &str, remote_port: u16) {
    let lines = output.lines().collect::<Vec<_>>();
    assert_eq!(lines.len(), 3);
    assert_http_env(&format!("{}\n{}\n", lines[0], lines[1]), remote_port);
    assert_socks_env(&format!("{}\n", lines[2]), remote_port);
}

fn proxy_password(output: &str) -> String {
    let uri = output
        .lines()
        .find_map(|line| line.split_once("//ap:").map(|(_, rest)| rest))
        .expect("env output contains a proxy URI");
    uri.split_once('@')
        .map(|(password, _)| password.to_owned())
        .expect("proxy URI contains an authority separator")
}

fn open_private_lock(path: &Path) -> File {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    options.mode(0o600);
    options.open(path).expect("open isolated profile lock")
}

#[cfg(unix)]
fn assert_private_layout(root: &Path) {
    for relative in ["", "run", "run/control", "logs"] {
        let path = root.join(relative);
        let metadata = fs::metadata(&path).expect("private directory exists");
        assert!(metadata.is_dir(), "{} is not a directory", path.display());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o700);
    }

    for relative in [
        "config.toml",
        "config.lock",
        "proxy-secrets.toml",
        "proxy-secrets.lock",
    ] {
        let path = root.join(relative);
        let metadata = fs::metadata(&path).expect("private file exists");
        assert!(metadata.is_file(), "{} is not a file", path.display());
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }
}

#[cfg(not(unix))]
fn assert_private_layout(_root: &Path) {}
