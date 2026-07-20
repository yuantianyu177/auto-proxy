use std::borrow::Borrow;
use std::collections::BTreeMap;
use std::fmt;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;
use uuid::Uuid;
use zeroize::{Zeroize, ZeroizeOnDrop};

#[cfg(target_os = "macos")]
use keyring::v1::{Entry as KeyringEntry, Error as KeyringError};
#[cfg(target_os = "linux")]
use keyring_core::{Entry as KeyringEntry, Error as KeyringError, api::CredentialStoreApi};

use crate::config::{
    AppPaths, atomic_write_private, ensure_private_regular_file, open_lock_file, read_bounded,
};
use crate::error::{ApError, Result};

const PROXY_SECRET_VERSION: u32 = 1;
const MAX_PROXY_SECRET_BYTES: u64 = 4 * 1024 * 1024;
const PROXY_USERNAME: &str = "ap";
const SSH_PASSWORD_SERVICE: &str = "ap:ssh-password";

#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct SecretString(String);

impl SecretString {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl fmt::Debug for SecretString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretString([REDACTED])")
    }
}

#[derive(Clone)]
pub struct ProxyCredential {
    username: String,
    password: SecretString,
}

impl ProxyCredential {
    pub fn username(&self) -> &str {
        &self.username
    }

    pub fn password(&self) -> &str {
        self.password.expose_secret()
    }

    pub fn verify(&self, username: &[u8], password: &[u8]) -> bool {
        let username_matches: bool = self.username.as_bytes().ct_eq(username).into();
        let password_matches: bool = self.password().as_bytes().ct_eq(password).into();
        username_matches & password_matches
    }
}

impl fmt::Debug for ProxyCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProxyCredential")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SshPasswordStatus {
    Available,
    Missing,
}

#[derive(Debug, Clone)]
pub struct ProxySecretStore {
    paths: AppPaths,
}

impl ProxySecretStore {
    pub fn new(paths: AppPaths) -> Self {
        Self { paths }
    }

    pub fn get_or_create(&self, server_id: impl Borrow<Uuid>) -> Result<ProxyCredential> {
        self.with_exclusive_document(|document| {
            let key = server_id.borrow().to_string();
            if let Some(stored) = document.credentials.get(&key) {
                return Ok((stored.to_public(), false));
            }
            let credential = generate_proxy_credential()?;
            document
                .credentials
                .insert(key, StoredProxyCredential::from_public(&credential));
            Ok((credential, true))
        })
    }

    pub fn get(&self, server_id: impl Borrow<Uuid>) -> Result<ProxyCredential> {
        self.paths.ensure()?;
        let lock = open_lock_file(&self.paths.proxy_secrets_lock)?;
        FileExt::lock_shared(&lock).map_err(|error| {
            ApError::coded(
                "AP_PROXY_SECRET_LOCK_FAILED",
                format!("无法读取代理凭据锁：{error}"),
            )
        })?;
        let document = self.load_unlocked()?;
        document
            .credentials
            .get(&server_id.borrow().to_string())
            .map(StoredProxyCredential::to_public)
            .ok_or_else(|| {
                ApError::coded("AP_PROXY_SECRET_NOT_FOUND", "此 server 尚未生成代理凭据")
            })
    }

    pub fn rotate(&self, server_id: impl Borrow<Uuid>) -> Result<ProxyCredential> {
        self.with_exclusive_document(|document| {
            let credential = generate_proxy_credential()?;
            document.credentials.insert(
                server_id.borrow().to_string(),
                StoredProxyCredential::from_public(&credential),
            );
            Ok((credential, true))
        })
    }

    /// Restore an already-generated proxy credential during a failed
    /// multi-store operation. This never exposes the value in logs or errors.
    pub fn set(&self, server_id: impl Borrow<Uuid>, credential: &ProxyCredential) -> Result<()> {
        self.with_exclusive_document(|document| {
            document.credentials.insert(
                server_id.borrow().to_string(),
                StoredProxyCredential::from_public(credential),
            );
            Ok(((), true))
        })
    }

    pub fn delete(&self, server_id: impl Borrow<Uuid>) -> Result<bool> {
        self.with_exclusive_document(|document| {
            let removed = document
                .credentials
                .remove(&server_id.borrow().to_string())
                .is_some();
            Ok((removed, removed))
        })
    }

    fn with_exclusive_document<T>(
        &self,
        operation: impl FnOnce(&mut ProxySecretDocument) -> Result<(T, bool)>,
    ) -> Result<T> {
        self.paths.ensure()?;
        let lock = open_lock_file(&self.paths.proxy_secrets_lock)?;
        lock.lock_exclusive().map_err(|error| {
            ApError::coded(
                "AP_PROXY_SECRET_LOCK_FAILED",
                format!("无法取得代理凭据锁：{error}"),
            )
        })?;
        let mut document = self.load_unlocked()?;
        let (result, changed) = operation(&mut document)?;
        if changed {
            self.save_unlocked(&document)?;
        }
        Ok(result)
    }

    fn load_unlocked(&self) -> Result<ProxySecretDocument> {
        if !self.paths.proxy_secrets_file.exists() {
            return Ok(ProxySecretDocument::default());
        }
        ensure_private_regular_file(&self.paths.proxy_secrets_file)?;
        let mut text = read_bounded(&self.paths.proxy_secrets_file, MAX_PROXY_SECRET_BYTES)?;
        let parsed = toml::from_str::<ProxySecretDocument>(&text);
        text.zeroize();
        let document = parsed.map_err(|_| {
            ApError::coded(
                "AP_PROXY_SECRET_PARSE_FAILED",
                "代理凭据文件格式损坏（为避免泄露，未显示原始内容）",
            )
        })?;
        if document.version != PROXY_SECRET_VERSION {
            return Err(ApError::coded(
                "AP_PROXY_SECRET_VERSION_UNSUPPORTED",
                format!(
                    "代理凭据版本 {} 不受支持，当前仅支持版本 {PROXY_SECRET_VERSION}",
                    document.version
                ),
            ));
        }
        Ok(document)
    }

    fn save_unlocked(&self, document: &ProxySecretDocument) -> Result<()> {
        let mut text = toml::to_string_pretty(document).map_err(|error| {
            ApError::coded(
                "AP_PROXY_SECRET_ENCODE_FAILED",
                format!("代理凭据无法序列化：{error}"),
            )
        })?;
        let result = atomic_write_private(&self.paths.proxy_secrets_file, text.as_bytes());
        text.zeroize();
        result
    }
}

#[derive(Debug, Default, Clone, Copy)]
pub struct SshPasswordStore;

impl SshPasswordStore {
    pub fn new() -> Self {
        Self
    }

    pub fn set(&self, server_id: impl Borrow<Uuid>, password: &SecretString) -> Result<()> {
        if password.is_empty() {
            return Err(ApError::coded("AP_EMPTY_PASSWORD", "SSH 密码不能为空"));
        }
        let entry = ssh_password_entry(server_id.borrow())?;
        entry
            .set_password(password.expose_secret())
            .map_err(map_keyring_error)
    }

    pub fn get(&self, server_id: impl Borrow<Uuid>) -> Result<SecretString> {
        let entry = ssh_password_entry(server_id.borrow())?;
        entry
            .get_password()
            .map(SecretString::new)
            .map_err(map_keyring_error)
    }

    pub fn delete(&self, server_id: impl Borrow<Uuid>) -> Result<()> {
        let entry = ssh_password_entry(server_id.borrow())?;
        match entry.delete_credential() {
            Ok(()) | Err(KeyringError::NoEntry) => Ok(()),
            Err(error) => Err(map_keyring_error(error)),
        }
    }

    pub fn status(&self, server_id: impl Borrow<Uuid>) -> Result<SshPasswordStatus> {
        let entry = ssh_password_entry(server_id.borrow())?;
        match entry.get_password() {
            Ok(mut password) => {
                password.zeroize();
                Ok(SshPasswordStatus::Available)
            }
            Err(KeyringError::NoEntry) => Ok(SshPasswordStatus::Missing),
            Err(error) => Err(map_keyring_error(error)),
        }
    }
}

fn ssh_password_entry(server_id: &Uuid) -> Result<KeyringEntry> {
    platform_ssh_password_entry(server_id).map_err(map_keyring_error)
}

#[cfg(target_os = "macos")]
fn platform_ssh_password_entry(
    server_id: &Uuid,
) -> std::result::Result<KeyringEntry, KeyringError> {
    KeyringEntry::new(SSH_PASSWORD_SERVICE, &server_id.to_string())
}

#[cfg(target_os = "linux")]
fn platform_ssh_password_entry(
    server_id: &Uuid,
) -> std::result::Result<KeyringEntry, KeyringError> {
    // Do not use keyring::v1 here. Its process-global, one-shot default-store
    // initialization remains poisoned after an early session D-Bus failure,
    // which prevents a long-lived daemon from recovering when Secret Service
    // appears later. A fresh store owns a fresh D-Bus connection for every
    // credential operation, so the daemon's normal retry loop can recover from
    // both an initially absent service and a restarted service.
    let store = zbus_secret_service_keyring_store::Store::new()?;
    store.build(SSH_PASSWORD_SERVICE, &server_id.to_string(), None)
}

fn map_keyring_error(error: KeyringError) -> ApError {
    use KeyringError as Error;

    match error {
        Error::NoEntry => ApError::coded(
            "AP_SSH_PASSWORD_NOT_FOUND",
            "系统凭据库中没有此 server 的 SSH 密码",
        ),
        Error::NoStorageAccess(_) => ApError::coded(
            "AP_SECRET_STORE_LOCKED",
            "系统凭据库当前不可访问或仍处于锁定状态",
        ),
        Error::NoDefaultStore | Error::NotSupportedByStore(_) | Error::PlatformFailure(_) => {
            ApError::coded(
                "AP_SECRET_STORE_UNAVAILABLE",
                "系统凭据库不可用；Linux 需要当前用户会话提供 Secret Service",
            )
        }
        Error::Ambiguous(_) => ApError::coded(
            "AP_SECRET_STORE_AMBIGUOUS",
            "系统凭据库中存在多个匹配的 SSH 密码项",
        ),
        Error::BadEncoding(_) | Error::BadDataFormat(_, _) | Error::BadStoreFormat(_) => {
            ApError::coded(
                "AP_SECRET_STORE_CORRUPT",
                "系统凭据库返回了无法解析的 SSH 密码项",
            )
        }
        Error::TooLong(_, _) | Error::Invalid(_, _) => {
            ApError::coded("AP_SECRET_STORE_ERROR", "系统凭据库拒绝了 SSH 密码项的属性")
        }
        _ => ApError::coded("AP_SECRET_STORE_ERROR", "系统凭据库操作失败"),
    }
}

fn generate_proxy_credential() -> Result<ProxyCredential> {
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random)
        .map_err(|_| ApError::coded("AP_RANDOM_UNAVAILABLE", "操作系统安全随机数生成器不可用"))?;
    let password = URL_SAFE_NO_PAD.encode(random);
    random.zeroize();
    Ok(ProxyCredential {
        username: PROXY_USERNAME.to_owned(),
        password: SecretString::new(password),
    })
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProxySecretDocument {
    version: u32,
    #[serde(default)]
    credentials: BTreeMap<String, StoredProxyCredential>,
}

impl Default for ProxySecretDocument {
    fn default() -> Self {
        Self {
            version: PROXY_SECRET_VERSION,
            credentials: BTreeMap::new(),
        }
    }
}

impl Drop for ProxySecretDocument {
    fn drop(&mut self) {
        for credential in self.credentials.values_mut() {
            credential.zeroize();
        }
    }
}

#[derive(Serialize, Deserialize, Zeroize)]
#[serde(deny_unknown_fields)]
struct StoredProxyCredential {
    username: String,
    password: String,
}

impl StoredProxyCredential {
    fn from_public(credential: &ProxyCredential) -> Self {
        Self {
            username: credential.username().to_owned(),
            password: credential.password().to_owned(),
        }
    }

    fn to_public(&self) -> ProxyCredential {
        ProxyCredential {
            username: self.username.clone(),
            password: SecretString::new(self.password.clone()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AppPaths;
    #[cfg(unix)]
    use std::fs;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn store() -> (tempfile::TempDir, ProxySecretStore) {
        let temp = tempfile::tempdir().unwrap();
        let paths = AppPaths::from_root(temp.path().join("ap"));
        (temp, ProxySecretStore::new(paths))
    }

    #[test]
    fn creates_stable_random_credential_and_rotates() {
        let (_temp, store) = store();
        let id = Uuid::new_v4();
        let first = store.get_or_create(id).unwrap();
        let second = store.get_or_create(id).unwrap();
        assert_eq!(first.username(), PROXY_USERNAME);
        assert_eq!(first.password(), second.password());
        assert!(first.password().len() >= 43);

        let rotated = store.rotate(id).unwrap();
        assert_ne!(first.password(), rotated.password());
        assert_eq!(store.get(id).unwrap().password(), rotated.password());
        assert!(store.delete(id).unwrap());
        assert!(store.get(id).is_err());
        store.set(id, &first).unwrap();
        assert_eq!(store.get(id).unwrap().password(), first.password());
    }

    #[test]
    fn debug_output_is_redacted() {
        let credential = generate_proxy_credential().unwrap();
        let debug = format!("{credential:?}");
        assert!(!debug.contains(credential.password()));
        assert!(debug.contains("REDACTED"));
    }

    #[test]
    fn verifies_credentials() {
        let credential = generate_proxy_credential().unwrap();
        assert!(credential.verify(b"ap", credential.password().as_bytes()));
        assert!(!credential.verify(b"other", credential.password().as_bytes()));
        assert!(!credential.verify(b"ap", b"wrong"));
    }

    #[cfg(unix)]
    #[test]
    fn proxy_secret_file_is_private() {
        let (_temp, store) = store();
        let id = Uuid::new_v4();
        store.get_or_create(id).unwrap();
        let mode = fs::metadata(&store.paths.proxy_secrets_file)
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
    }

    #[test]
    fn keyring_errors_are_categorized_without_platform_details() {
        assert_eq!(
            map_keyring_error(KeyringError::NoDefaultStore).code(),
            "AP_SECRET_STORE_UNAVAILABLE"
        );
        assert_eq!(
            map_keyring_error(KeyringError::NoEntry).code(),
            "AP_SSH_PASSWORD_NOT_FOUND"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_secret_service_factory_can_retry_after_initialization_failure() {
        let id = Uuid::new_v4();
        for result in [
            platform_ssh_password_entry(&id),
            platform_ssh_password_entry(&id),
        ] {
            // A missing or unavailable session service is expected on a
            // headless test runner. The important invariant is that a failed
            // first attempt cannot poison a process-global default store and
            // turn later attempts into NoDefaultStore.
            assert!(!matches!(result, Err(KeyringError::NoDefaultStore)));
        }
    }
}
