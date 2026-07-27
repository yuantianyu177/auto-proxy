use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::error::{ApError, Result};

const PROXY_USERNAME: &str = "ap";
const PROXY_PASSWORD_BYTES: usize = 32;
const MAX_SSH_PASSWORD_BYTES: usize = 64 * 1024;

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
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretString([REDACTED])")
    }
}

/// An SSH password owned only by one authentication attempt.
///
/// This value is never serialised as configuration, exposed through status
/// IPC, or included in process arguments or environment variables. Password
/// connections consume and clear it after the initial OpenSSH authentication;
/// a later connection attempt must ask the user again.
pub struct SshPassword(SecretString);

impl SshPassword {
    pub fn new(value: String) -> Result<Self> {
        let value = SecretString::new(value);
        if value.expose_secret().len() > MAX_SSH_PASSWORD_BYTES {
            return Err(ApError::coded(
                "AP_PASSWORD_INVALID",
                format!("SSH password exceeds {MAX_SSH_PASSWORD_BYTES} bytes"),
            ));
        }
        if value
            .expose_secret()
            .bytes()
            .any(|byte| matches!(byte, b'\r' | b'\n'))
        {
            return Err(ApError::coded(
                "AP_PASSWORD_INVALID",
                "SSH password must not contain a line break",
            ));
        }
        Ok(Self(value))
    }

    pub(crate) fn expose_secret(&self) -> &str {
        self.0.expose_secret()
    }

    pub(crate) fn copy(&self) -> Zeroizing<String> {
        Zeroizing::new(self.expose_secret().to_owned())
    }
}

impl fmt::Debug for SshPassword {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SshPassword([REDACTED])")
    }
}

#[derive(Clone)]
pub struct ProxyCredential {
    username: String,
    password: SecretString,
}

impl ProxyCredential {
    pub fn generate() -> Result<Self> {
        let mut random = [0_u8; PROXY_PASSWORD_BYTES];
        getrandom::fill(&mut random)
            .map_err(|error| ApError::coded("AP_RANDOM_FAILED", error.to_string()))?;
        let password = URL_SAFE_NO_PAD.encode(random);
        random.zeroize();
        Ok(Self {
            username: PROXY_USERNAME.to_owned(),
            password: SecretString::new(password),
        })
    }

    #[cfg(test)]
    pub fn from_parts(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: SecretString::new(password),
        }
    }

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
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyCredential")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_credentials_are_fresh_and_url_safe() {
        let first = ProxyCredential::generate().unwrap();
        let second = ProxyCredential::generate().unwrap();
        assert_eq!(first.username(), "ap");
        assert_ne!(first.password(), second.password());
        assert!(
            first
                .password()
                .bytes()
                .all(|byte| { byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_') })
        );
    }

    #[test]
    fn debug_output_never_contains_the_password() {
        let credential = ProxyCredential::from_parts("ap", "top-secret");
        assert!(!format!("{credential:?}").contains("top-secret"));
    }

    #[test]
    fn credential_verification_is_exact() {
        let credential = ProxyCredential::from_parts("ap", "secret");
        assert!(credential.verify(b"ap", b"secret"));
        assert!(!credential.verify(b"ap", b"secre"));
        assert!(!credential.verify(b"other", b"secret"));
    }

    #[test]
    fn ssh_password_is_redacted_and_copied_into_zeroizing_memory() {
        let password = SshPassword::new("top-secret".to_owned()).unwrap();
        assert!(!format!("{password:?}").contains("top-secret"));
        assert_eq!(password.copy().as_str(), "top-secret");
    }

    #[test]
    fn ssh_password_rejects_line_breaks() {
        assert_eq!(
            SshPassword::new("two\nlines".to_owned())
                .unwrap_err()
                .code(),
            "AP_PASSWORD_INVALID"
        );
    }
}
