//! Crash recovery for operations that span the ordinary configuration, the
//! proxy-secret file, and the platform credential store.
//!
//! The journal intentionally contains no secret material. A single private
//! lock serializes cross-store mutations and recovery so another `ap` process
//! cannot mistake an in-flight operation for one left behind by a crash.

use std::fs::{self, File};

use fs2::FileExt;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::config::{
    AppPaths, ConfigStore, atomic_write_private, ensure_private_regular_file, open_lock_file,
    read_bounded,
};
use crate::error::{ApError, Result};
use crate::model::AuthMode;
use crate::secrets::{ProxySecretStore, SshPasswordStatus, SshPasswordStore};

const JOURNAL_VERSION: u32 = 1;
const MAX_JOURNAL_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "operation", rename_all = "kebab-case", deny_unknown_fields)]
enum Operation {
    ServerAdd {
        server_name: String,
        server_id: Uuid,
    },
    ServerRemove {
        server_name: String,
        server_id: Uuid,
        had_stored_password: bool,
    },
    PasswordSet {
        server_name: String,
        server_id: Uuid,
        previous_auth_mode: AuthMode,
    },
    PasswordRemove {
        server_name: String,
        server_id: Uuid,
    },
}

impl Operation {
    fn profile(&self) -> PendingProfile {
        let (server_name, server_id) = match self {
            Self::ServerAdd {
                server_name,
                server_id,
            }
            | Self::ServerRemove {
                server_name,
                server_id,
                ..
            }
            | Self::PasswordSet {
                server_name,
                server_id,
                ..
            }
            | Self::PasswordRemove {
                server_name,
                server_id,
            } => (server_name, server_id),
        };
        PendingProfile {
            server_name: server_name.clone(),
            server_id: *server_id,
        }
    }

    fn validate(&self) -> Result<()> {
        let (server_name, server_id) = match self {
            Self::ServerAdd {
                server_name,
                server_id,
            }
            | Self::ServerRemove {
                server_name,
                server_id,
                ..
            }
            | Self::PasswordSet {
                server_name,
                server_id,
                ..
            }
            | Self::PasswordRemove {
                server_name,
                server_id,
            } => (server_name, server_id),
        };
        crate::model::validate_name("server", server_name)?;
        if server_id.is_nil() {
            return Err(ApError::coded(
                "AP_TRANSACTION_INVALID",
                "事务日志中的 server UUID 不能为 nil",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Journal {
    version: u32,
    operation: Operation,
}

/// Immutable profile identity carried by the no-secret recovery journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingProfile {
    pub server_name: String,
    pub server_id: Uuid,
}

/// Result of a daemon's non-blocking recovery attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryOutcome {
    /// No journal remained after the transaction lock was acquired. This is
    /// also the expected result when an active CLI operation committed before
    /// the daemon got the lock.
    NoPending,
    /// A live CLI process currently owns the transaction lock. The daemon must
    /// retry later instead of blocking its IPC event loop.
    Busy,
    /// A crash journal was recovered and removed.
    Recovered(PendingProfile),
}

/// Recovery errors retain the affected immutable profile identity when the
/// journal could be decoded. This lets the daemon expose an actionable status
/// without copying any secret into IPC state.
#[derive(Debug)]
pub struct RecoveryFailure {
    pub profile: Option<PendingProfile>,
    pub error: ApError,
}

/// Holds the global transaction lock until the operation is committed or the
/// value is dropped. Dropping without `commit` deliberately leaves the journal
/// for the next process to recover.
pub struct CrossStoreTransaction {
    paths: AppPaths,
    operation: Operation,
    _lock: File,
}

impl CrossStoreTransaction {
    pub fn begin_server_add(paths: &AppPaths, server_name: &str, server_id: Uuid) -> Result<Self> {
        Self::begin(
            paths,
            Operation::ServerAdd {
                server_name: server_name.to_owned(),
                server_id,
            },
        )
    }

    pub fn begin_server_remove(
        paths: &AppPaths,
        server_name: &str,
        server_id: Uuid,
        had_stored_password: bool,
    ) -> Result<Self> {
        Self::begin(
            paths,
            Operation::ServerRemove {
                server_name: server_name.to_owned(),
                server_id,
                had_stored_password,
            },
        )
    }

    pub fn begin_password_set(
        paths: &AppPaths,
        server_name: &str,
        server_id: Uuid,
        previous_auth_mode: AuthMode,
    ) -> Result<Self> {
        Self::begin(
            paths,
            Operation::PasswordSet {
                server_name: server_name.to_owned(),
                server_id,
                previous_auth_mode,
            },
        )
    }

    pub fn begin_password_remove(
        paths: &AppPaths,
        server_name: &str,
        server_id: Uuid,
    ) -> Result<Self> {
        Self::begin(
            paths,
            Operation::PasswordRemove {
                server_name: server_name.to_owned(),
                server_id,
            },
        )
    }

    fn begin(paths: &AppPaths, operation: Operation) -> Result<Self> {
        operation.validate()?;
        let lock = acquire_lock(paths)?;
        recover_pending_locked(paths, &RealSecrets)?;
        write_journal(paths, &operation)?;
        Ok(Self {
            paths: paths.clone(),
            operation,
            _lock: lock,
        })
    }

    /// Mark a fully consistent operation durable. If journal removal itself
    /// fails, the still-present record is safe: recovery is idempotent.
    pub fn commit(self) -> Result<()> {
        clear_journal(&self.paths)
    }

    /// Resolve an interrupted/failed operation according to its durable state,
    /// then remove the journal. This is useful for immediate error recovery;
    /// dropping the value instead defers the same work to the next invocation.
    pub fn recover(self) -> Result<()> {
        recover_operation(&self.paths, &self.operation, &RealSecrets)?;
        clear_journal(&self.paths)
    }
}

/// Recover a journal left by `SIGKILL`, power loss, or an earlier I/O error.
pub fn recover_pending(paths: &AppPaths) -> Result<()> {
    let _lock = acquire_lock(paths)?;
    recover_pending_locked(paths, &RealSecrets).map(|_| ())
}

/// Attempt crash recovery without waiting for a CLI process that currently
/// owns the transaction lock. Credential-store work may still be synchronous,
/// so daemon callers should invoke this from `spawn_blocking`.
pub fn try_recover_pending(
    paths: &AppPaths,
) -> std::result::Result<RecoveryOutcome, RecoveryFailure> {
    let lock = match try_acquire_lock(paths) {
        Ok(Some(lock)) => lock,
        Ok(None) => return Ok(RecoveryOutcome::Busy),
        Err(error) => {
            return Err(RecoveryFailure {
                profile: None,
                error,
            });
        }
    };
    let _lock = lock;
    let journal = match read_journal(paths) {
        Ok(Some(journal)) => journal,
        Ok(None) => return Ok(RecoveryOutcome::NoPending),
        Err(error) => {
            return Err(RecoveryFailure {
                profile: None,
                error,
            });
        }
    };
    let profile = journal.operation.profile();
    if let Err(error) = recover_operation(paths, &journal.operation, &RealSecrets)
        .and_then(|()| clear_journal(paths))
    {
        return Err(RecoveryFailure {
            profile: Some(profile),
            error,
        });
    }
    Ok(RecoveryOutcome::Recovered(profile))
}

fn acquire_lock(paths: &AppPaths) -> Result<File> {
    paths.ensure()?;
    let lock = open_lock_file(&paths.transaction_lock)?;
    lock.lock_exclusive().map_err(|error| {
        ApError::coded(
            "AP_TRANSACTION_LOCK_FAILED",
            format!("无法取得跨存储事务锁：{error}"),
        )
    })?;
    Ok(lock)
}

fn try_acquire_lock(paths: &AppPaths) -> Result<Option<File>> {
    paths.ensure()?;
    let lock = open_lock_file(&paths.transaction_lock)?;
    match lock.try_lock_exclusive() {
        Ok(()) => Ok(Some(lock)),
        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
        Err(error) => Err(ApError::coded(
            "AP_TRANSACTION_LOCK_FAILED",
            format!("无法取得跨存储事务锁：{error}"),
        )),
    }
}

fn recover_pending_locked(
    paths: &AppPaths,
    secrets: &impl RecoverySecrets,
) -> Result<Option<PendingProfile>> {
    let Some(journal) = read_journal(paths)? else {
        return Ok(None);
    };
    let profile = journal.operation.profile();
    recover_operation(paths, &journal.operation, secrets)?;
    clear_journal(paths)?;
    Ok(Some(profile))
}

fn write_journal(paths: &AppPaths, operation: &Operation) -> Result<()> {
    let journal = Journal {
        version: JOURNAL_VERSION,
        operation: operation.clone(),
    };
    let text = toml::to_string_pretty(&journal)
        .map_err(|_| ApError::coded("AP_TRANSACTION_ENCODE_FAILED", "无法序列化跨存储事务日志"))?;
    atomic_write_private(&paths.transaction_journal, text.as_bytes())
}

fn read_journal(paths: &AppPaths) -> Result<Option<Journal>> {
    match fs::symlink_metadata(&paths.transaction_journal) {
        Ok(_) => ensure_private_regular_file(&paths.transaction_journal)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    }
    let text = read_bounded(&paths.transaction_journal, MAX_JOURNAL_BYTES)?;
    let journal: Journal = toml::from_str(&text).map_err(|_| {
        ApError::coded(
            "AP_TRANSACTION_PARSE_FAILED",
            "跨存储事务日志损坏；为避免错误删除凭据，ap 拒绝继续",
        )
    })?;
    if journal.version != JOURNAL_VERSION {
        return Err(ApError::coded(
            "AP_TRANSACTION_VERSION_UNSUPPORTED",
            format!(
                "事务日志版本 {} 不受支持，当前仅支持版本 {JOURNAL_VERSION}",
                journal.version
            ),
        ));
    }
    journal.operation.validate()?;
    Ok(Some(journal))
}

fn clear_journal(paths: &AppPaths) -> Result<()> {
    match fs::symlink_metadata(&paths.transaction_journal) {
        Ok(_) => ensure_private_regular_file(&paths.transaction_journal)?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error.into()),
    }
    fs::remove_file(&paths.transaction_journal)?;
    File::open(&paths.root)?.sync_all()?;
    Ok(())
}

trait RecoverySecrets {
    fn ensure_proxy(&self, paths: &AppPaths, server_id: Uuid) -> Result<()>;
    fn delete_proxy(&self, paths: &AppPaths, server_id: Uuid) -> Result<()>;
    fn ssh_status(&self, server_id: Uuid) -> Result<SshPasswordStatus>;
    fn delete_ssh(&self, server_id: Uuid) -> Result<()>;
}

struct RealSecrets;

impl RecoverySecrets for RealSecrets {
    fn ensure_proxy(&self, paths: &AppPaths, server_id: Uuid) -> Result<()> {
        ProxySecretStore::new(paths.clone())
            .get_or_create(server_id)
            .map(|_| ())
    }

    fn delete_proxy(&self, paths: &AppPaths, server_id: Uuid) -> Result<()> {
        ProxySecretStore::new(paths.clone())
            .delete(server_id)
            .map(|_| ())
    }

    fn ssh_status(&self, server_id: Uuid) -> Result<SshPasswordStatus> {
        SshPasswordStore::new().status(server_id)
    }

    fn delete_ssh(&self, server_id: Uuid) -> Result<()> {
        SshPasswordStore::new().delete(server_id)
    }
}

fn recover_operation(
    paths: &AppPaths,
    operation: &Operation,
    secrets: &impl RecoverySecrets,
) -> Result<()> {
    let store = ConfigStore::new(paths.clone());
    let config = store.load()?;
    match operation {
        Operation::ServerAdd {
            server_name,
            server_id,
        } => {
            if config.servers.get(server_name).map(|server| server.id) == Some(*server_id) {
                secrets.ensure_proxy(paths, *server_id)?;
            } else {
                secrets.delete_proxy(paths, *server_id)?;
            }
        }
        Operation::ServerRemove {
            server_name,
            server_id,
            had_stored_password,
        } => {
            if let Some(server) = config
                .servers
                .get(server_name)
                .filter(|server| server.id == *server_id)
            {
                // The removal was rolled back (or never reached the config
                // commit). Make the retained profile internally consistent.
                secrets.ensure_proxy(paths, *server_id)?;
                if server.auth_mode == AuthMode::StoredPassword
                    && secrets.ssh_status(*server_id)? == SshPasswordStatus::Missing
                {
                    update_auth_mode_if_same(&store, server_name, *server_id, false)?;
                }
            } else {
                // Once the config no longer refers to this immutable UUID,
                // completing secret cleanup cannot affect a replacement that
                // reused the human-readable name.
                secrets.delete_proxy(paths, *server_id)?;
                if *had_stored_password {
                    secrets.delete_ssh(*server_id)?;
                }
            }
        }
        Operation::PasswordSet {
            server_name,
            server_id,
            previous_auth_mode: _,
        } => {
            let committed = config
                .servers
                .get(server_name)
                .filter(|server| server.id == *server_id)
                .is_some_and(|server| server.auth_mode == AuthMode::StoredPassword);
            if committed {
                if secrets.ssh_status(*server_id)? != SshPasswordStatus::Available {
                    // The intended password cannot be reconstructed. Prefer a
                    // usable ssh-config profile over a permanent journal that
                    // would block every future CLI operation.
                    update_auth_mode_if_same(&store, server_name, *server_id, false)?;
                }
            } else {
                secrets.delete_ssh(*server_id)?;
            }
        }
        Operation::PasswordRemove {
            server_name,
            server_id,
        } => {
            secrets.delete_ssh(*server_id)?;
            if config
                .servers
                .get(server_name)
                .filter(|server| server.id == *server_id)
                .is_some_and(|server| server.auth_mode == AuthMode::StoredPassword)
            {
                update_auth_mode_if_same(&store, server_name, *server_id, false)?;
            }
        }
    }
    Ok(())
}

fn update_auth_mode_if_same(
    store: &ConfigStore,
    server_name: &str,
    expected_id: Uuid,
    stored_password: bool,
) -> Result<()> {
    store.update_server(server_name, |server| {
        if server.id != expected_id {
            return Err(ApError::coded(
                "AP_PROFILE_CHANGED_DURING_RECOVERY",
                "server 在事务恢复期间被替换；事务日志已保留",
            ));
        }
        if stored_password {
            server.use_stored_password();
        } else {
            server.use_ssh_config();
        }
        Ok(())
    })
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;
    use std::sync::Mutex;

    use tempfile::TempDir;

    use super::*;
    use crate::model::ServerConfig;

    #[derive(Default)]
    struct FakeSecrets {
        proxy: Mutex<HashSet<Uuid>>,
        ssh: Mutex<HashSet<Uuid>>,
    }

    impl RecoverySecrets for FakeSecrets {
        fn ensure_proxy(&self, _paths: &AppPaths, server_id: Uuid) -> Result<()> {
            self.proxy.lock().unwrap().insert(server_id);
            Ok(())
        }

        fn delete_proxy(&self, _paths: &AppPaths, server_id: Uuid) -> Result<()> {
            self.proxy.lock().unwrap().remove(&server_id);
            Ok(())
        }

        fn ssh_status(&self, server_id: Uuid) -> Result<SshPasswordStatus> {
            Ok(if self.ssh.lock().unwrap().contains(&server_id) {
                SshPasswordStatus::Available
            } else {
                SshPasswordStatus::Missing
            })
        }

        fn delete_ssh(&self, server_id: Uuid) -> Result<()> {
            self.ssh.lock().unwrap().remove(&server_id);
            Ok(())
        }
    }

    fn fixture() -> (TempDir, AppPaths, ConfigStore) {
        let temp = tempfile::tempdir().unwrap();
        let paths = AppPaths::from_root(temp.path().join("ap"));
        let store = ConfigStore::new(paths.clone());
        (temp, paths, store)
    }

    #[test]
    fn orphaned_server_add_secret_is_removed() {
        let (_temp, paths, _store) = fixture();
        let id = Uuid::new_v4();
        let secrets = FakeSecrets::default();
        secrets.proxy.lock().unwrap().insert(id);
        let operation = Operation::ServerAdd {
            server_name: "dev".into(),
            server_id: id,
        };
        recover_operation(&paths, &operation, &secrets).unwrap();
        assert!(!secrets.proxy.lock().unwrap().contains(&id));
    }

    #[test]
    fn committed_server_add_repairs_missing_proxy_secret() {
        let (_temp, paths, store) = fixture();
        let server = store.add_server("dev", "server2").unwrap();
        let secrets = FakeSecrets::default();
        let operation = Operation::ServerAdd {
            server_name: "dev".into(),
            server_id: server.id,
        };
        recover_operation(&paths, &operation, &secrets).unwrap();
        assert!(secrets.proxy.lock().unwrap().contains(&server.id));
    }

    #[test]
    fn interrupted_password_set_is_removed_when_config_not_committed() {
        let (_temp, paths, store) = fixture();
        let server = store.add_server("dev", "server2").unwrap();
        let secrets = FakeSecrets::default();
        secrets.ssh.lock().unwrap().insert(server.id);
        let operation = Operation::PasswordSet {
            server_name: "dev".into(),
            server_id: server.id,
            previous_auth_mode: AuthMode::SshConfig,
        };
        recover_operation(&paths, &operation, &secrets).unwrap();
        assert!(!secrets.ssh.lock().unwrap().contains(&server.id));
    }

    #[test]
    fn committed_password_set_without_secret_falls_back_to_ssh_config() {
        let (_temp, paths, store) = fixture();
        let mut server = ServerConfig::new("server2");
        server.use_stored_password();
        let id = server.id;
        store.insert_server("dev", server).unwrap();
        let secrets = FakeSecrets::default();
        let operation = Operation::PasswordSet {
            server_name: "dev".into(),
            server_id: id,
            previous_auth_mode: AuthMode::SshConfig,
        };

        recover_operation(&paths, &operation, &secrets).unwrap();

        assert_eq!(
            store.get_server("dev").unwrap().auth_mode,
            AuthMode::SshConfig
        );
    }

    #[test]
    fn interrupted_password_remove_finishes_both_stores() {
        let (_temp, paths, store) = fixture();
        let mut server = ServerConfig::new("server2");
        server.use_stored_password();
        let id = server.id;
        store.insert_server("dev", server).unwrap();
        let secrets = FakeSecrets::default();
        secrets.ssh.lock().unwrap().insert(id);
        let operation = Operation::PasswordRemove {
            server_name: "dev".into(),
            server_id: id,
        };
        recover_operation(&paths, &operation, &secrets).unwrap();
        assert!(!secrets.ssh.lock().unwrap().contains(&id));
        assert_eq!(
            store.get_server("dev").unwrap().auth_mode,
            AuthMode::SshConfig
        );
    }

    #[test]
    fn interrupted_server_remove_completes_or_repairs_consistently() {
        let (_temp, paths, store) = fixture();
        let mut server = ServerConfig::new("server2");
        server.use_stored_password();
        let id = server.id;
        store.insert_server("dev", server.clone()).unwrap();
        let secrets = FakeSecrets::default();
        let operation = Operation::ServerRemove {
            server_name: "dev".into(),
            server_id: id,
            had_stored_password: true,
        };

        // Config still present: repair the proxy token and fall back to
        // ssh-config if the deleted password cannot be restored after a crash.
        recover_operation(&paths, &operation, &secrets).unwrap();
        assert!(secrets.proxy.lock().unwrap().contains(&id));
        assert_eq!(
            store.get_server("dev").unwrap().auth_mode,
            AuthMode::SshConfig
        );

        // Config committed as removed: all remaining secrets are cleaned.
        secrets.ssh.lock().unwrap().insert(id);
        store.remove_server("dev").unwrap();
        recover_operation(&paths, &operation, &secrets).unwrap();
        assert!(!secrets.proxy.lock().unwrap().contains(&id));
        assert!(!secrets.ssh.lock().unwrap().contains(&id));
    }

    #[test]
    fn journal_is_private_and_recovers_after_owner_drop() {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;

        let (_temp, paths, _store) = fixture();
        let id = Uuid::new_v4();
        let transaction = CrossStoreTransaction::begin_server_add(&paths, "dev", id).unwrap();
        let text = fs::read_to_string(&paths.transaction_journal).unwrap();
        assert!(!text.contains("password"));
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(&paths.transaction_journal)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(transaction); // simulate a process dying before commit
        recover_pending(&paths).unwrap();
        assert!(!paths.transaction_journal.exists());
    }

    #[test]
    fn daemon_recovery_attempt_never_waits_for_a_live_cli_transaction() {
        let (_temp, paths, _store) = fixture();
        let id = Uuid::new_v4();
        let transaction = CrossStoreTransaction::begin_server_add(&paths, "dev", id).unwrap();

        assert_eq!(try_recover_pending(&paths).unwrap(), RecoveryOutcome::Busy);

        drop(transaction); // simulate the CLI dying before commit
        assert_eq!(
            try_recover_pending(&paths).unwrap(),
            RecoveryOutcome::Recovered(PendingProfile {
                server_name: "dev".to_owned(),
                server_id: id,
            })
        );
        assert_eq!(
            try_recover_pending(&paths).unwrap(),
            RecoveryOutcome::NoPending
        );
    }
}
