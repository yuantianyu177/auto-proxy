use std::process::ExitCode;

use auto_proxy::askpass;
use auto_proxy::cli::{Action, Cli, ConnectionScope};
use auto_proxy::config::{AppPaths, ConfigStore};
use auto_proxy::doctor::{self, CheckStatus};
use auto_proxy::error::{ApError, Result};
use auto_proxy::model::{ResolvedConnection, ResolvedSshAuth};
use auto_proxy::presentation::print_environment;
use auto_proxy::secrets::SshPassword;
use auto_proxy::ssh;
use auto_proxy::supervisor::{self, ConnectionPhase, StartResult};
use clap::Parser;

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(error) = auto_proxy::process_security::disable_core_dumps() {
        eprintln!("{error}");
        return ExitCode::FAILURE;
    }

    if ssh::watchdog_mode_requested() {
        return match ssh::run_ssh_watchdog_from_env().await {
            Ok(code) => ExitCode::from(code),
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }

    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<()> {
    if askpass::maybe_run_from_env()? {
        return Ok(());
    }

    let action = Cli::parse()
        .resolve()
        .map_err(|error| ApError::coded("AP_USAGE", error.to_string()))?;
    let paths = AppPaths::discover()?;
    let store = ConfigStore::new(paths.clone());

    match action {
        Action::Connect {
            connection,
            foreground,
        } => connect(&store, &paths, &connection, foreground).await,
        Action::Doctor { connection } => diagnose(&store, &paths, &connection).await,
        Action::Restart(scope) => restart(&store, &paths, scope).await,
        Action::Close(scope) => close(&paths, scope).await,
        Action::List => list(&paths).await,
        Action::InternalSupervisor { connection } => {
            supervisor::run_internal_supervisor(&connection, paths).await
        }
    }
}

async fn connect(
    store: &ConfigStore,
    paths: &AppPaths,
    name: &str,
    foreground: bool,
) -> Result<()> {
    if foreground {
        if supervisor::describe_one(name, paths).await?.is_some() {
            return Err(ApError::coded(
                "AP_CONNECTION_ACTIVE",
                format!("Connection {name:?} is already active"),
            ));
        }
        let snapshot = store.load_connection(name)?;
        let ssh_password = prompt_ssh_password(&snapshot)?;
        return supervisor::start_foreground(snapshot, ssh_password, paths).await;
    }

    if let Some(existing) = supervisor::environment_one(name, paths).await? {
        match existing.description.phase {
            ConnectionPhase::Failed => {
                let code = existing
                    .description
                    .error_code
                    .as_deref()
                    .unwrap_or("AP_SSH_FAILED");
                return Err(ApError::coded(
                    "AP_CONNECTION_FAILED",
                    format!("Connection {name:?} failed ({code}); restart it with `ap {name} -r`"),
                ));
            }
            ConnectionPhase::Closing => {
                supervisor::wait_until_inactive(&existing.description, paths).await?;
            }
            _ => {
                print_start_result(&existing, false);
                return Ok(());
            }
        }
    }

    let snapshot = store.load_connection(name)?;
    let ssh_password = prompt_ssh_password(&snapshot)?;
    let started = supervisor::start_background(snapshot, ssh_password, paths).await?;
    print_start_result(&started, true);
    Ok(())
}

async fn diagnose(store: &ConfigStore, paths: &AppPaths, name: &str) -> Result<()> {
    if supervisor::describe_one(name, paths).await?.is_some() {
        return Err(ApError::coded(
            "AP_CONNECTION_ACTIVE",
            format!("Close connection {name:?} before running diagnostics"),
        ));
    }
    let snapshot = store.load_connection(name)?;
    let ssh_password = prompt_ssh_password(&snapshot)?;
    let report = doctor::diagnose(&snapshot, ssh_password, paths).await;
    for check in &report.checks {
        let status = match check.status {
            CheckStatus::Passed => "PASS",
            CheckStatus::Failed => "FAIL",
        };
        println!("[{status}] {}: {}", check.name, check.message);
    }
    if report.is_healthy() {
        println!("Diagnostics passed: {name}");
        Ok(())
    } else {
        Err(ApError::coded(
            "AP_DOCTOR_FAILED",
            "One or more diagnostic checks failed",
        ))
    }
}

async fn restart(store: &ConfigStore, paths: &AppPaths, scope: ConnectionScope) -> Result<()> {
    let active = match scope {
        ConnectionScope::One(name) => {
            let description = supervisor::describe_one(&name, paths)
                .await?
                .ok_or_else(|| {
                    ApError::coded(
                        "AP_CONNECTION_NOT_ACTIVE",
                        format!("Connection {name:?} is not active"),
                    )
                })?;
            vec![description]
        }
        ConnectionScope::All => {
            let active = supervisor::list_active(paths).await?;
            if active.is_empty() {
                println!("No active connections.");
                return Ok(());
            }
            active
        }
    };

    // Resolve every new snapshot before stopping anything. A malformed edit
    // must never disrupt an existing connection.
    let names = active
        .iter()
        .map(|description| description.name.clone())
        .collect::<Vec<_>>();
    let snapshots = store.load_selected_connections(&names)?;

    // Collect every required password before closing any supervisor. A
    // cancelled prompt or invalid password must leave all active connections
    // untouched, just like a malformed configuration edit does.
    let prepared = snapshots
        .into_iter()
        .map(|snapshot| {
            let ssh_password = prompt_ssh_password(&snapshot)?;
            Ok((snapshot, ssh_password))
        })
        .collect::<Result<Vec<_>>>()?;

    let mut failures = Vec::new();
    for ((snapshot, ssh_password), previous) in prepared.into_iter().zip(active) {
        let name = snapshot.name.clone();
        match supervisor::close_instance(&previous, paths).await {
            Ok(true) => {}
            Ok(false) => {
                failures.push(format!("{name}: no longer active"));
                continue;
            }
            Err(error) => {
                failures.push(format!("{name}: {}", error.code()));
                continue;
            }
        }
        match supervisor::start_background(snapshot, ssh_password, paths).await {
            Ok(started) => print_start_result(&started, true),
            Err(error) => failures.push(format!("{name}: {}", error.code())),
        }
    }

    if failures.is_empty() {
        Ok(())
    } else {
        Err(ApError::coded(
            "AP_RESTART_FAILED",
            format!("Failed to restart {}", failures.join(", ")),
        ))
    }
}

fn prompt_ssh_password(snapshot: &ResolvedConnection) -> Result<Option<SshPassword>> {
    match &snapshot.ssh.auth {
        ResolvedSshAuth::Key { .. } => Ok(None),
        ResolvedSshAuth::Password => {
            let password = rpassword::prompt_password(format!("Password for {}: ", snapshot.name))
                .map_err(|error| {
                    ApError::coded(
                        "AP_PASSWORD_READ_FAILED",
                        format!("Unable to read SSH password from /dev/tty: {error}"),
                    )
                })?;
            SshPassword::new(password).map(Some)
        }
    }
}

async fn close(paths: &AppPaths, scope: ConnectionScope) -> Result<()> {
    match scope {
        ConnectionScope::One(name) => {
            if supervisor::close_one(&name, paths).await? {
                println!("Closed: {name}");
            } else {
                println!("Connection {name:?} is not active.");
            }
        }
        ConnectionScope::All => {
            let count = supervisor::close_all(paths).await?;
            if count == 0 {
                println!("No active connections.");
            } else {
                println!("Closed {count} connection(s).");
            }
        }
    }
    Ok(())
}

async fn list(paths: &AppPaths) -> Result<()> {
    let active = supervisor::list_active(paths).await?;
    if active.is_empty() {
        println!("No active connections.");
        return Ok(());
    }

    println!("NAME\tSTATUS\tSSH_PID\tPROXIES\tERROR");
    for connection in active {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            connection.name,
            phase_name(connection.phase),
            connection
                .ssh_pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            connection.proxies.len(),
            connection.error_code.as_deref().unwrap_or("-"),
        );
    }
    Ok(())
}

fn print_start_result(result: &StartResult, started: bool) {
    let name = &result.description.name;
    let phase = phase_name(result.description.phase);
    if started && result.description.phase == ConnectionPhase::Connected {
        println!("Connected: {name}");
    } else if let Some(error) = result.description.error_code.as_deref() {
        println!("Connection {name} is {phase} ({error}).");
    } else {
        println!("Connection {name} is {phase}.");
    }
    print_environment(&result.environment);
}

fn phase_name(phase: ConnectionPhase) -> &'static str {
    match phase {
        ConnectionPhase::Connecting => "connecting",
        ConnectionPhase::Connected => "connected",
        ConnectionPhase::Reconnecting => "reconnecting",
        ConnectionPhase::Failed => "failed",
        ConnectionPhase::Closing => "closing",
    }
}
