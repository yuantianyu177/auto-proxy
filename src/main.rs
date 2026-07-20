use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;
use std::time::Duration;

use auto_proxy::askpass;
use auto_proxy::cli::{
    AuthSubcommand, Cli, Command, PasswordSubcommand, ProxyCredentialSubcommand, ProxySubcommand,
    ServerSubcommand, ServiceSubcommand,
};
use auto_proxy::config::{AppPaths, ConfigStore};
use auto_proxy::daemon::{self, DaemonCommand, DaemonRequest, ProfilePhase, ProfileStatus};
use auto_proxy::doctor::{self, CheckStatus, DoctorRequest, LocalProxyCheck, RemoteForwardProbe};
use auto_proxy::error::{ApError, Result};
use auto_proxy::model::{AuthMode, ProxyMapping, ProxyProtocol, ServerConfig};
use auto_proxy::secrets::{ProxySecretStore, SecretString, SshPasswordStatus, SshPasswordStore};
use auto_proxy::service;
use auto_proxy::ssh::{self, SshAuthentication, system_ssh_executable};
use auto_proxy::transaction::{self, CrossStoreTransaction};
use clap::Parser;
use subtle::ConstantTimeEq;
use tracing_subscriber::EnvFilter;
use uuid::Uuid;
use zeroize::Zeroizing;

#[tokio::main]
async fn main() -> ExitCode {
    if let Err(error) = auto_proxy::process_security::disable_core_dumps() {
        eprintln!("{error}");
        return ExitCode::FAILURE;
    }
    // The watchdog is an internal process-lifecycle helper and must run before
    // AskPass handling and clap parsing. Its argv/environment contain no SSH
    // password; the actual password still crosses only the private AskPass IPC.
    if ssh::watchdog_mode_requested() {
        return match ssh::run_ssh_watchdog_from_env().await {
            Ok(code) => ExitCode::from(code),
            Err(error) => {
                eprintln!("{error}");
                ExitCode::FAILURE
            }
        };
    }
    match real_main().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{}", error);
            ExitCode::FAILURE
        }
    }
}

async fn real_main() -> Result<()> {
    // OpenSSH starts the same executable with a human-readable prompt as argv.
    // AskPass mode must therefore be recognized before clap sees that argv.
    if askpass::maybe_run_from_env()? {
        return Ok(());
    }

    init_tracing();
    let cli = Cli::parse();
    let store = ConfigStore::discover()?;
    let paths = store.paths().clone();
    // The daemon must bind IPC before attempting a recovery that may need a
    // locked desktop credential store. Its own event loop performs that work
    // on a blocking worker and exposes waiting-for-secret-store meanwhile.
    // All ordinary CLI operations keep the synchronous consistency barrier.
    if !matches!(&cli.command, Command::InternalDaemon) {
        transaction::recover_pending(&paths)?;
    }

    match cli.command {
        Command::Server(command) => match command.command {
            ServerSubcommand::Add { name, ssh_host } => {
                let server = ServerConfig::new(&ssh_host);
                server.validate(&name)?;
                let transaction =
                    CrossStoreTransaction::begin_server_add(&paths, &name, server.id)?;
                let proxy_secrets = ProxySecretStore::new(paths.clone());
                let result = proxy_secrets
                    .get_or_create(server.id)
                    .and_then(|_| store.insert_server(&name, server.clone()));
                if let Err(error) = result {
                    return Err(recover_failed_transaction(
                        transaction,
                        error,
                        "AP_SERVER_ADD_ROLLBACK_FAILED",
                        "创建 server",
                    ));
                }
                transaction.commit()?;
                println!("已添加 server {name}（SSH Host: {ssh_host}）");
            }
            ServerSubcommand::List => server_list(&store)?,
            ServerSubcommand::Show { name, json } => server_show(&store, &name, json)?,
            ServerSubcommand::Remove { name } => {
                let _change = begin_profile_change(&paths, &name, false).await?;
                let server = store.get_server(&name)?;
                let proxy_store = ProxySecretStore::new(paths.clone());
                let proxy_backup = proxy_store.get(server.id)?;
                let password_store =
                    (server.auth_mode == AuthMode::StoredPassword).then(SshPasswordStore::new);
                let ssh_backup = match password_store.as_ref() {
                    Some(password_store) => match password_store.status(server.id)? {
                        SshPasswordStatus::Available => Some(password_store.get(server.id)?),
                        SshPasswordStatus::Missing => {
                            return Err(ApError::coded(
                                "AP_SSH_PASSWORD_NOT_FOUND",
                                "profile 使用 stored-password，但系统凭据库中没有对应密码；请先修复认证状态",
                            ));
                        }
                    },
                    None => None,
                };

                let transaction = CrossStoreTransaction::begin_server_remove(
                    &paths,
                    &name,
                    server.id,
                    password_store.is_some(),
                )?;
                let removal = (|| -> Result<()> {
                    // Remove the reference first. A crash from this point can
                    // leave only journal-tracked orphans, never a live profile
                    // that points at already-deleted secret material.
                    store.remove_server(&name)?;
                    if let Some(password_store) = password_store.as_ref() {
                        password_store.delete(server.id)?;
                    }
                    proxy_store.delete(server.id)?;
                    Ok(())
                })();
                if let Err(error) = removal {
                    let rollback = restore_server_after_failed_removal(
                        &store,
                        &name,
                        &server,
                        &proxy_store,
                        password_store.as_ref(),
                        &proxy_backup,
                        ssh_backup.as_ref(),
                    );
                    return match rollback {
                        Ok(()) => {
                            transaction.commit()?;
                            Err(error)
                        }
                        Err(rollback_error) => Err(ApError::coded(
                            "AP_SERVER_REMOVE_ROLLBACK_FAILED",
                            format!(
                                "删除 server 失败且无法恢复一致状态（删除错误 {}，恢复错误 {}）；无秘密事务日志已保留，将在下次启动继续恢复",
                                error.code(),
                                rollback_error.code()
                            ),
                        )),
                    };
                }
                transaction.commit()?;
                println!("已删除 server {name}");
            }
        },
        Command::Proxy(command) => match command.command {
            ProxySubcommand::Add(arguments) => {
                let change =
                    begin_profile_change(&paths, &arguments.server, arguments.restart).await?;
                let mapping = ProxyMapping {
                    name: arguments.name.clone(),
                    protocol: arguments.protocol,
                    local: arguments.local,
                    remote_port: arguments.remote_port,
                };
                complete_profile_change(
                    &paths,
                    &arguments.server,
                    change,
                    store.add_proxy(&arguments.server, mapping),
                )
                .await?;
                println!(
                    "已添加 proxy {}（{} -> 远端 127.0.0.1:{}）",
                    arguments.name, arguments.local, arguments.remote_port
                );
            }
            ProxySubcommand::List { server, json } => {
                proxy_list(&store, &server, json)?;
            }
            ProxySubcommand::Update(arguments) => {
                let change =
                    begin_profile_change(&paths, &arguments.server, arguments.restart).await?;
                let result = (|| -> Result<()> {
                    let server = store.get_server(&arguments.server)?;
                    let current = server
                        .proxies
                        .iter()
                        .find(|mapping| mapping.name == arguments.name)
                        .cloned()
                        .ok_or_else(|| {
                            ApError::coded(
                                "AP_PROXY_NOT_FOUND",
                                format!("proxy {:?} 不存在", arguments.name),
                            )
                        })?;
                    let replacement = ProxyMapping {
                        name: arguments.rename.unwrap_or_else(|| current.name.clone()),
                        protocol: arguments.protocol.unwrap_or(current.protocol),
                        local: arguments.local.unwrap_or(current.local),
                        remote_port: arguments.remote_port.unwrap_or(current.remote_port),
                    };
                    store.update_proxy(&arguments.server, &arguments.name, replacement)
                })();
                complete_profile_change(&paths, &arguments.server, change, result).await?;
                println!("已更新 proxy {}", arguments.name);
            }
            ProxySubcommand::Remove {
                server,
                name,
                restart,
            } => {
                let change = begin_profile_change(&paths, &server, restart).await?;
                complete_profile_change(
                    &paths,
                    &server,
                    change,
                    store.remove_proxy(&server, &name).map(|_| ()),
                )
                .await?;
                println!("已删除 proxy {name}");
            }
        },
        Command::Auth(command) => match command.command {
            AuthSubcommand::Password(password) => match password.command {
                PasswordSubcommand::Set { server, restart } => {
                    let change = begin_profile_change(&paths, &server, restart).await?;
                    let result = set_ssh_password(&store, &server);
                    complete_profile_change(&paths, &server, change, result).await?;
                    println!("SSH 密码已保存到系统凭据库；{server} 已切换为 stored-password");
                }
                PasswordSubcommand::Status { server } => {
                    password_status(&store, &server)?;
                }
                PasswordSubcommand::Remove { server, restart } => {
                    let change = begin_profile_change(&paths, &server, restart).await?;
                    let result = remove_ssh_password(&store, &server);
                    complete_profile_change(&paths, &server, change, result).await?;
                    println!("已删除系统凭据库中的 SSH 密码；{server} 已切换为 ssh-config");
                }
            },
        },
        Command::Connect { server } => {
            daemon::run_foreground(paths, &server).await?;
        }
        Command::Up { server } => {
            let expected_server_id = store.get_server(&server)?.id;
            daemon_request(
                &paths,
                DaemonCommand::Up {
                    server: server.clone(),
                    expected_server_id,
                },
            )
            .await?;
            println!("已请求连接 {server}");
        }
        Command::Down { server } => {
            let expected_server_id = store.get_server(&server)?.id;
            daemon_request(
                &paths,
                DaemonCommand::Down {
                    server: server.clone(),
                    expected_server_id,
                },
            )
            .await?;
            println!("已停止 {server}");
        }
        Command::Status { server, json } => {
            print_status(&store, &paths, server, json).await?;
        }
        Command::Logs { server, follow } => {
            store.get_server(&server)?;
            show_logs(&paths.logs_dir.join(format!("{server}.log")), follow).await?;
        }
        Command::Doctor { server } => run_doctor(&store, &paths, &server).await?,
        Command::Env { server, proxy } => print_env(&store, &paths, &server, &proxy)?,
        Command::Service(command) => match command.command {
            ServiceSubcommand::Install => {
                let executable = fs::canonicalize(std::env::current_exe()?)?;
                let installed = service::install(&executable)?;
                println!("已安装用户级服务：{}", installed.definition.display());
            }
            ServiceSubcommand::Uninstall => {
                let removed = service::uninstall()?;
                println!("已卸载用户级服务：{}", removed.definition.display());
            }
        },
        Command::Enable { server } => {
            let change = begin_profile_change(&paths, &server, true).await?;
            let was_running = change.was_running;
            let expected_server_id = change.server_id;
            complete_profile_change(
                &paths,
                &server,
                change,
                store.update_server(&server, |profile| {
                    if profile.proxies.is_empty() {
                        return Err(ApError::coded(
                            "AP_NO_PROXY_MAPPING",
                            "至少配置一个 proxy mapping 后才能 enable 此 profile",
                        ));
                    }
                    profile.autostart = true;
                    Ok(())
                }),
            )
            .await?;
            if !was_running {
                daemon_request(
                    &paths,
                    DaemonCommand::Up {
                        server: server.clone(),
                        expected_server_id,
                    },
                )
                .await?;
            }
            println!("已启用 {server} 的登录自启动并请求立即连接");
        }
        Command::Disable { server } => {
            let change = begin_profile_change(&paths, &server, true).await?;
            let expected_server_id = change.server_id;
            let result = store.update_server(&server, |profile| {
                profile.autostart = false;
                Ok(())
            });
            // Keep the profile lease through the configuration write. Dropping
            // it first would let a concurrent same-name delete/recreate race
            // this mutation and make the rollback target ambiguous.
            let was_running = change.release();
            if let Err(error) = result {
                if was_running
                    && let Err(restart_error) = daemon_request(
                        &paths,
                        DaemonCommand::Up {
                            server: server.clone(),
                            expected_server_id,
                        },
                    )
                    .await
                {
                    return Err(ApError::coded(
                        "AP_PROFILE_RESTORE_FAILED",
                        format!(
                            "取消自启动失败，且原连接未能恢复（配置错误 {}，恢复错误 {}）",
                            error.code(),
                            restart_error.code()
                        ),
                    ));
                }
                return Err(error);
            }
            println!("已禁用 {server} 的登录自启动并停止连接");
        }
        Command::ProxyCredential(command) => match command.command {
            ProxyCredentialSubcommand::Rotate { server, restart } => {
                let change = begin_profile_change(&paths, &server, restart).await?;
                let server_id = change.server_id;
                complete_profile_change(
                    &paths,
                    &server,
                    change,
                    ProxySecretStore::new(paths.clone())
                        .rotate(server_id)
                        .map(|_| ()),
                )
                .await?;
                println!("已轮换 {server} 的代理凭据；旧凭据已失效");
            }
        },
        Command::InternalDaemon => daemon::run(paths).await?,
    }
    Ok(())
}

fn init_tracing() {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("warn"));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_target(false)
        .without_time()
        .try_init();
}

fn server_list(store: &ConfigStore) -> Result<()> {
    let config = store.load()?;
    if config.servers.is_empty() {
        println!("尚未配置 server");
        return Ok(());
    }
    println!("NAME\tSSH HOST\tAUTH\tPROXIES\tAUTOSTART");
    for (name, server) in config.servers {
        println!(
            "{name}\t{}\t{}\t{}\t{}",
            server.ssh_host,
            server.auth_mode,
            server.proxies.len(),
            if server.autostart { "yes" } else { "no" }
        );
    }
    Ok(())
}

fn server_show(store: &ConfigStore, name: &str, json: bool) -> Result<()> {
    let server = store.get_server(name)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&server)
                .map_err(|error| ApError::coded("AP_ENCODE_ERROR", error.to_string()))?
        );
    } else {
        println!(
            "{}",
            toml::to_string_pretty(&server)
                .map_err(|error| ApError::coded("AP_ENCODE_ERROR", error.to_string()))?
        );
    }
    Ok(())
}

fn proxy_list(store: &ConfigStore, server_name: &str, json: bool) -> Result<()> {
    let server = store.get_server(server_name)?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&server.proxies)
                .map_err(|error| ApError::coded("AP_ENCODE_ERROR", error.to_string()))?
        );
        return Ok(());
    }
    if server.proxies.is_empty() {
        println!("{server_name} 尚未配置 proxy mapping");
        return Ok(());
    }
    println!("NAME\tPROTOCOL\tLOCAL\tREMOTE");
    for mapping in server.proxies {
        println!(
            "{}\t{}\t{}\t127.0.0.1:{}",
            mapping.name, mapping.protocol, mapping.local, mapping.remote_port
        );
    }
    Ok(())
}

fn set_ssh_password(store: &ConfigStore, server_name: &str) -> Result<()> {
    let server = store.get_server(server_name)?;
    let first = SecretString::new(rpassword::prompt_password("SSH 密码: ")?);
    let second = SecretString::new(rpassword::prompt_password("再次输入 SSH 密码: ")?);
    let same: bool = first
        .expose_secret()
        .as_bytes()
        .ct_eq(second.expose_secret().as_bytes())
        .into();
    if !same {
        return Err(ApError::coded(
            "AP_PASSWORD_MISMATCH",
            "两次输入的 SSH 密码不一致",
        ));
    }

    let password_store = SshPasswordStore::new();
    let transaction = CrossStoreTransaction::begin_password_set(
        store.paths(),
        server_name,
        server.id,
        server.auth_mode,
    )?;
    let result = password_store.set(server.id, &first).and_then(|()| {
        store.update_server(server_name, |profile| {
            if profile.id != server.id {
                return Err(ApError::coded(
                    "AP_PROFILE_CHANGED_DURING_MUTATION",
                    "server 在保存 SSH 密码期间被替换",
                ));
            }
            profile.use_stored_password();
            Ok(())
        })
    });
    if let Err(error) = result {
        return Err(recover_failed_transaction(
            transaction,
            error,
            "AP_SSH_PASSWORD_ROLLBACK_FAILED",
            "保存 SSH 密码",
        ));
    }
    transaction.commit()?;
    Ok(())
}

fn password_status(store: &ConfigStore, server_name: &str) -> Result<()> {
    let server = store.get_server(server_name)?;
    let status = SshPasswordStore::new().status(server.id)?;
    let credential = match status {
        SshPasswordStatus::Available => "available",
        SshPasswordStatus::Missing => "missing",
    };
    println!("auth_mode={}\ncredential={credential}", server.auth_mode);
    Ok(())
}

fn remove_ssh_password(store: &ConfigStore, server_name: &str) -> Result<()> {
    let server = store.get_server(server_name)?;
    let password_store = SshPasswordStore::new();
    let transaction =
        CrossStoreTransaction::begin_password_remove(store.paths(), server_name, server.id)?;
    let result = password_store.delete(server.id).and_then(|()| {
        store.update_server(server_name, |profile| {
            if profile.id != server.id {
                return Err(ApError::coded(
                    "AP_PROFILE_CHANGED_DURING_MUTATION",
                    "server 在删除 SSH 密码期间被替换",
                ));
            }
            profile.use_ssh_config();
            Ok(())
        })
    });
    if let Err(error) = result {
        // Deleting a password is not safely reversible after a crash. Finish
        // the requested transition instead, so no stored-password profile can
        // remain pointed at a missing credential.
        if let Err(recovery_error) = transaction.recover() {
            return Err(ApError::coded(
                "AP_SSH_PASSWORD_REMOVE_RECOVERY_FAILED",
                format!(
                    "删除 SSH 密码时发生错误且无法完成崩溃安全恢复（操作错误 {}，恢复错误 {}）；无秘密事务日志已保留",
                    error.code(),
                    recovery_error.code()
                ),
            ));
        }
    } else {
        transaction.commit()?;
    }
    Ok(())
}

fn restore_server_after_failed_removal(
    store: &ConfigStore,
    server_name: &str,
    server: &ServerConfig,
    proxy_store: &ProxySecretStore,
    password_store: Option<&SshPasswordStore>,
    proxy_backup: &auto_proxy::secrets::ProxyCredential,
    ssh_backup: Option<&SecretString>,
) -> Result<()> {
    let proxy_result = proxy_store.set(server.id, proxy_backup);
    let ssh_result = match (password_store, ssh_backup) {
        (Some(password_store), Some(password)) => password_store.set(server.id, password),
        (Some(password_store), None) => password_store.delete(server.id),
        (None, _) => Ok(()),
    };
    // Restore the non-secret profile even when a secret backend is currently
    // unavailable. The retained journal blocks later commands and will repair
    // the proxy token or safely fall back to ssh-config after the credential
    // store becomes available, rather than silently turning a failed delete
    // into a completed removal.
    let config_result = match store.get_server(server_name) {
        Ok(current) if current.id == server.id => Ok(()),
        Ok(_) => Err(ApError::coded(
            "AP_PROFILE_CHANGED_DURING_MUTATION",
            "同名 server 已被另一个 UUID 替换，拒绝覆盖",
        )),
        Err(error) if error.code() == "AP_SERVER_NOT_FOUND" => {
            store.insert_server(server_name, server.clone())
        }
        Err(error) => Err(error),
    };
    if proxy_result.is_ok() && ssh_result.is_ok() && config_result.is_ok() {
        Ok(())
    } else {
        Err(ApError::coded(
            "AP_SERVER_REMOVE_ROLLBACK_FAILED",
            format!(
                "server 恢复未完全成功（代理恢复={}，SSH 恢复={}，配置恢复={}）",
                if proxy_result.is_ok() { "ok" } else { "failed" },
                if ssh_result.is_ok() { "ok" } else { "failed" },
                if config_result.is_ok() {
                    "ok"
                } else {
                    "failed"
                },
            ),
        ))
    }
}

fn recover_failed_transaction(
    transaction: CrossStoreTransaction,
    original: ApError,
    code: &'static str,
    action: &str,
) -> ApError {
    match transaction.recover() {
        Ok(()) => original,
        Err(recovery) => ApError::coded(
            code,
            format!(
                "{action}失败且无法立即恢复一致状态（操作错误 {}，恢复错误 {}）；无秘密事务日志已保留，将在下次启动继续恢复",
                original.code(),
                recovery.code()
            ),
        ),
    }
}

fn print_env(store: &ConfigStore, paths: &AppPaths, server_name: &str, proxy: &str) -> Result<()> {
    let server = store.get_server(server_name)?;
    let mapping = server
        .proxies
        .iter()
        .find(|mapping| mapping.name == proxy)
        .ok_or_else(|| ApError::coded("AP_PROXY_NOT_FOUND", format!("proxy {proxy:?} 不存在")))?;
    let credential = ProxySecretStore::new(paths.clone()).get(server.id)?;
    let username = url_component(credential.username());
    let password = url_component(credential.password());
    let authority = format!("{username}:{password}@127.0.0.1:{}", mapping.remote_port);

    match mapping.protocol {
        ProxyProtocol::Http => {
            println!("export http_proxy='http://{authority}'");
            println!("export https_proxy=\"$http_proxy\"");
        }
        ProxyProtocol::Socks5 => {
            println!("export all_proxy='socks5h://{authority}'");
        }
        ProxyProtocol::Mixed => {
            println!("export http_proxy='http://{authority}'");
            println!("export https_proxy=\"$http_proxy\"");
            println!("export all_proxy='socks5h://{authority}'");
        }
    }
    Ok(())
}

fn url_component(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

async fn run_doctor(store: &ConfigStore, paths: &AppPaths, server_name: &str) -> Result<()> {
    let server = store.get_server(server_name)?;
    if server.auth_mode == AuthMode::StoredPassword {
        match SshPasswordStore::new().status(server.id)? {
            SshPasswordStatus::Available => {
                println!("[pass] secret-store: SSH 密码可读取");
            }
            SshPasswordStatus::Missing => {
                return Err(ApError::coded(
                    "AP_SSH_PASSWORD_NOT_FOUND",
                    "profile 使用 stored-password，但系统凭据库中没有密码",
                ));
            }
        }
    }

    let local_proxies = server
        .proxies
        .iter()
        .map(|mapping| LocalProxyCheck {
            name: mapping.name.clone(),
            address: mapping.local,
            protocol: match mapping.protocol {
                ProxyProtocol::Http => doctor::ProxyProtocol::Http,
                ProxyProtocol::Socks5 => doctor::ProxyProtocol::Socks5,
                ProxyProtocol::Mixed => doctor::ProxyProtocol::Mixed,
            },
        })
        .collect::<Vec<_>>();
    let authentication = ssh_authentication(&server, false);
    let remote_forward = (!server.proxies.is_empty()).then(|| RemoteForwardProbe {
        authentication,
        remote_ports: server
            .proxies
            .iter()
            .map(|mapping| mapping.remote_port)
            .collect(),
        control_socket: paths.doctor_control_socket(),
    });
    let report = doctor::run(DoctorRequest {
        ssh_executable: system_ssh_executable()?,
        ap_executable: std::env::current_exe()?,
        host: server.ssh_host,
        local_proxies,
        remote_forward,
    })
    .await;

    for check in &report.checks {
        let label = match check.status {
            CheckStatus::Passed => "pass",
            CheckStatus::Warning => "warn",
            CheckStatus::Failed => "fail",
        };
        println!("[{label}] {}: {}", check.name, check.message);
    }
    if report.is_healthy() {
        Ok(())
    } else {
        Err(ApError::coded("AP_DOCTOR_FAILED", "一项或多项检查失败"))
    }
}

fn ssh_authentication(server: &ServerConfig, background: bool) -> SshAuthentication {
    match server.auth_mode {
        AuthMode::SshConfig => SshAuthentication::SshConfig {
            batch_mode: background,
        },
        AuthMode::StoredPassword => {
            let id = server.id;
            SshAuthentication::StoredPassword {
                provider: Arc::new(move || {
                    let password = SshPasswordStore::new().get(id)?;
                    Ok(Zeroizing::new(password.expose_secret().to_owned()))
                }),
            }
        }
    }
}

async fn daemon_request(paths: &AppPaths, command: DaemonCommand) -> Result<Vec<ProfileStatus>> {
    let reply = daemon::request(&paths.daemon_socket, &DaemonRequest::new(command)).await?;
    Ok(reply.statuses)
}

struct ProfileChange {
    server_id: Uuid,
    was_running: bool,
    _guard: daemon::ProfileMutationGuard,
}

impl ProfileChange {
    fn release(self) -> bool {
        self.was_running
    }
}

async fn begin_profile_change(
    paths: &AppPaths,
    server: &str,
    restart_allowed: bool,
) -> Result<ProfileChange> {
    let store = ConfigStore::new(paths.clone());
    // The first read fixes the immutable identity targeted by this command.
    // If the human-readable name is deleted/recreated at any later point, the
    // command aborts; it must never migrate its mutation or restart intent to
    // the replacement UUID.
    let observed_id = store.get_server(server)?.id;
    let response = daemon::request(
        &paths.daemon_socket,
        &DaemonRequest::new(DaemonCommand::Status {
            server: Some(server.to_owned()),
        }),
    )
    .await;
    let daemon_running = match response {
        Ok(reply) => reply
            .statuses
            .iter()
            .any(|status| !matches!(status.phase, ProfilePhase::Stopped | ProfilePhase::Failed)),
        Err(error) if error.code() == "AP_DAEMON_UNAVAILABLE" => false,
        Err(error) => return Err(error),
    };
    let process_running = daemon::profile_is_running(paths, observed_id)?;
    if process_running && !daemon_running {
        ensure_profile_identity(&store, server, observed_id)?;
        return Err(ApError::coded(
            "AP_PROFILE_FOREGROUND_RUNNING",
            format!("{server} 正由 `ap connect` 前台运行；请在该终端按 Ctrl-C 后再修改配置"),
        ));
    }
    if daemon_running && !restart_allowed {
        return Err(ApError::coded(
            "AP_PROFILE_RUNNING",
            format!(
                "{server} 正在运行；先执行 `ap down {server}`，或在支持的配置命令中传入 --restart"
            ),
        ));
    }
    if daemon_running {
        daemon_request(
            paths,
            DaemonCommand::Down {
                server: server.to_owned(),
                expected_server_id: observed_id,
            },
        )
        .await?;
    }

    let guard = daemon::lock_profile_for_mutation(paths, observed_id)?;
    ensure_profile_identity(&store, server, observed_id)?;
    Ok(ProfileChange {
        server_id: observed_id,
        was_running: daemon_running,
        _guard: guard,
    })
}

fn ensure_profile_identity(store: &ConfigStore, server: &str, expected_id: Uuid) -> Result<()> {
    match store.get_server(server) {
        Ok(current) if current.id == expected_id => Ok(()),
        Ok(_)
        | Err(ApError::Coded {
            code: "AP_SERVER_NOT_FOUND",
            ..
        }) => Err(ApError::coded(
            "AP_PROFILE_CHANGED_DURING_MUTATION",
            format!("server {server:?} 在配置修改期间被删除或重建；本次操作已中止"),
        )),
        Err(error) => Err(error),
    }
}

async fn complete_profile_change<T>(
    paths: &AppPaths,
    server: &str,
    change: ProfileChange,
    result: Result<T>,
) -> Result<T> {
    let expected_server_id = change.server_id;
    let was_running = change.release();
    match result {
        Ok(value) => {
            if was_running {
                // Removing the final mapping intentionally leaves the profile
                // stopped; there is no valid SSH forward to restart. Every
                // other successful mutation restores the prior running state.
                let current = ConfigStore::new(paths.clone()).get_server(server)?;
                if !current.proxies.is_empty() {
                    daemon_request(
                        paths,
                        DaemonCommand::Up {
                            server: server.to_owned(),
                            expected_server_id,
                        },
                    )
                    .await?;
                }
            }
            Ok(value)
        }
        Err(error) => {
            if was_running
                && let Err(restart_error) = daemon_request(
                    paths,
                    DaemonCommand::Up {
                        server: server.to_owned(),
                        expected_server_id,
                    },
                )
                .await
            {
                return Err(ApError::coded(
                    "AP_PROFILE_RESTORE_FAILED",
                    format!(
                        "配置修改失败，且原连接未能恢复（修改错误 {}，恢复错误 {}）",
                        error.code(),
                        restart_error.code()
                    ),
                ));
            }
            Err(error)
        }
    }
}

async fn print_status(
    store: &ConfigStore,
    paths: &AppPaths,
    requested: Option<String>,
    json: bool,
) -> Result<()> {
    if let Some(server) = requested.as_deref() {
        store.get_server(server)?;
    }
    let response = daemon::request(
        &paths.daemon_socket,
        &DaemonRequest::new(DaemonCommand::Status {
            server: requested.clone(),
        }),
    )
    .await;
    let statuses = match response {
        Ok(reply) => reply.statuses,
        Err(error) if error.code() == "AP_DAEMON_UNAVAILABLE" => {
            let config = store.load()?;
            let mut statuses = Vec::new();
            for (name, server) in config
                .servers
                .into_iter()
                .filter(|(name, _)| requested.as_ref().is_none_or(|wanted| wanted == name))
            {
                let mut status = ProfileStatus::stopped(name, server.autostart);
                if daemon::profile_is_running(paths, server.id)? {
                    status.phase = ProfilePhase::Connected;
                }
                statuses.push(status);
            }
            statuses
        }
        Err(error) => return Err(error),
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&statuses)
                .map_err(|error| ApError::coded("AP_ENCODE_ERROR", error.to_string()))?
        );
        return Ok(());
    }
    println!("SERVER\tSTATE\tPID\tRETRIES\tAUTOSTART");
    for status in statuses {
        println!(
            "{}\t{}\t{}\t{}\t{}",
            status.server,
            status.phase,
            status
                .ssh_pid
                .map(|pid| pid.to_string())
                .unwrap_or_else(|| "-".to_owned()),
            status.retry_count,
            if status.autostart { "yes" } else { "no" }
        );
        if let Some(error) = status.last_error {
            println!("  last-error: {error}");
        }
        for mapping in status.mappings {
            println!(
                "  {}: active={} tx={} rx={} auth-fail={} upstream-error={}",
                mapping.name,
                mapping.active_connections,
                mapping.bytes_from_remote,
                mapping.bytes_to_remote,
                mapping.auth_failures,
                mapping.upstream_errors
            );
        }
    }
    Ok(())
}

async fn show_logs(path: &Path, follow: bool) -> Result<()> {
    if !path.exists() {
        return Err(ApError::coded(
            "AP_LOG_NOT_FOUND",
            format!("日志文件 {} 尚不存在", path.display()),
        ));
    }
    let mut file = fs::File::open(path)?;
    if !follow {
        let size = file.metadata()?.len();
        file.seek(SeekFrom::Start(size.saturating_sub(256 * 1024)))?;
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        print!("{text}");
        return Ok(());
    }

    file.seek(SeekFrom::End(0))?;
    loop {
        let mut text = String::new();
        file.read_to_string(&mut text)?;
        if !text.is_empty() {
            print!("{text}");
        }
        tokio::select! {
            _ = tokio::signal::ctrl_c() => return Ok(()),
            _ = tokio::time::sleep(Duration::from_millis(500)) => {}
        }
    }
}
