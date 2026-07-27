use std::ffi::OsStr;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use tempfile::TempDir;

#[cfg(unix)]
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};

struct CliSandbox {
    _temporary: TempDir,
    config_home: PathBuf,
    state_home: PathBuf,
    runtime_dir: PathBuf,
}

impl CliSandbox {
    fn new() -> Self {
        let temporary = tempfile::tempdir().expect("create isolated CLI test directory");
        let config_home = temporary.path().join("config");
        let state_home = temporary.path().join("state");
        let runtime_dir = temporary.path().join("runtime");

        fs::create_dir_all(config_home.join("ap")).expect("create XDG config directory");
        fs::create_dir_all(&state_home).expect("create XDG state directory");
        fs::create_dir_all(&runtime_dir).expect("create XDG runtime directory");
        #[cfg(unix)]
        fs::set_permissions(&runtime_dir, fs::Permissions::from_mode(0o700))
            .expect("make XDG runtime directory private");

        let config_file = config_home.join("ap/config.toml");
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(config_file).expect("create isolated config");
        file.write_all(b"version = 2\n\n[connections]\n")
            .expect("write isolated config");

        Self {
            _temporary: temporary,
            config_home,
            state_home,
            runtime_dir,
        }
    }

    fn run<I, S>(&self, arguments: I) -> Output
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        Command::new(env!("CARGO_BIN_EXE_ap"))
            .args(arguments)
            .env("XDG_CONFIG_HOME", &self.config_home)
            .env("XDG_STATE_HOME", &self.state_home)
            .env("XDG_RUNTIME_DIR", &self.runtime_dir)
            .env("RUST_LOG", "off")
            .env_remove("AP_CONFIG_DIR")
            .env_remove("SSH_ASKPASS")
            .env_remove("SSH_ASKPASS_REQUIRE")
            .env_remove("AP_ASKPASS_MODE")
            .env_remove("AP_ASKPASS_SOCKET")
            .env_remove("AP_ASKPASS_NONCE")
            .env_remove("AP_SSH_WATCHDOG_MODE")
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
            "command failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(output.stderr.is_empty(), "successful command wrote stderr");
        let stdout = String::from_utf8(output.stdout).expect("stdout is UTF-8");
        assert!(stdout.is_ascii(), "terminal output must be English ASCII");
        stdout
    }

    fn failure<I, S>(&self, arguments: I) -> String
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        let output = self.run(arguments);
        assert!(!output.status.success(), "command unexpectedly succeeded");
        assert!(output.stdout.is_empty(), "failed command wrote stdout");
        let stderr = String::from_utf8(output.stderr).expect("stderr is UTF-8");
        assert!(stderr.is_ascii(), "terminal output must be English ASCII");
        stderr
    }
}

#[test]
fn help_describes_only_the_flat_cli_in_english() {
    let cli = CliSandbox::new();
    for flag in ["-h", "--help"] {
        let help = cli.success([flag]);
        for expected in [
            "Usage: ap [OPTIONS] [CONNECTION]",
            "-f, --foreground",
            "-d, --doctor",
            "-r, --restart",
            "-c, --close",
            "-l, --list",
            "-v, --version",
            "-h, --help",
        ] {
            assert!(help.contains(expected), "missing {expected:?} in:\n{help}");
        }
        assert!(!help.contains("Commands:"));
        assert!(!help.contains("internal-supervisor"));
        assert!(!help.contains("--password"));
    }
}

#[test]
fn password_flags_are_rejected_without_echoing_the_value() {
    let cli = CliSandbox::new();
    let secret = "top-secret";
    for arguments in [["dev", "-p", secret], ["dev", "--password", secret]] {
        let error = cli.failure(arguments);
        assert!(
            error.contains("unexpected argument") || error.contains("unexpected option"),
            "unexpected parser error: {error}"
        );
        assert!(
            !error.contains(secret),
            "password value was echoed: {error}"
        );
        assert!(
            !error.contains("AP_CONNECTION_NOT_FOUND"),
            "configuration was read before rejecting the password flag: {error}"
        );
    }
}

#[test]
fn version_uses_the_requested_short_flag() {
    let cli = CliSandbox::new();
    for flag in ["-v", "--version"] {
        let version = cli.success([flag]);
        assert!(
            version.starts_with("ap "),
            "unexpected version: {version:?}"
        );
        assert_eq!(version.lines().count(), 1);
    }
}

#[test]
fn removed_command_words_are_ordinary_connection_names() {
    let cli = CliSandbox::new();
    for name in [
        "server",
        "proxy",
        "env",
        "auth",
        "connect",
        "service",
        "enable",
        "disable",
        "proxy-credential",
        "up",
        "down",
        "status",
        "doctor",
        "logs",
    ] {
        let error = cli.failure([name]);
        assert!(
            error.contains("AP_CONNECTION_NOT_FOUND"),
            "{name:?} was not treated as a connection name: {error}"
        );
        assert!(error.contains(&format!("Connection {name:?} is not defined")));
        assert!(!error.contains("Usage:"));
        assert!(!error.to_ascii_lowercase().contains("subcommand"));
    }
}

#[test]
fn connection_required_errors_are_short_and_english() {
    let cli = CliSandbox::new();
    for arguments in [vec![], vec!["-f"], vec!["-d"]] {
        let error = cli.failure(arguments);
        assert!(
            error.contains("A connection name is required."),
            "unexpected error: {error}"
        );
        assert!(!error.contains("Usage:"));
        assert!(error.lines().count() <= 2, "error is too verbose: {error}");
    }

    let error = cli.failure(["missing"]);
    assert!(error.contains("AP_CONNECTION_NOT_FOUND"));
    assert!(error.contains("Connection \"missing\" is not defined"));
}

#[test]
fn conflicting_actions_fail_before_reading_or_using_the_network() {
    let cli = CliSandbox::new();
    for arguments in [
        &["dev", "-f", "-d"][..],
        &["dev", "-d", "-r"][..],
        &["dev", "-r", "-c"][..],
        &["-c", "-l"][..],
    ] {
        let error = cli.failure(arguments);
        assert!(
            error.contains("cannot be used with") || error.contains("conflict"),
            "unexpected conflict error: {error}"
        );
        assert!(error.contains("Usage:"));
    }

    let error = cli.failure(["dev", "-l"]);
    assert!(error.contains("--list does not accept a connection name."));
    assert!(error.lines().count() <= 2, "error is too verbose: {error}");
}

#[test]
fn list_and_close_all_are_quiet_when_nothing_is_running() {
    let cli = CliSandbox::new();
    assert_eq!(cli.success(["-l"]), "No active connections.\n");
    assert_eq!(cli.success(["-c"]), "No active connections.\n");
}
