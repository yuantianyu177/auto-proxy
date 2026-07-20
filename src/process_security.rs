//! Process-wide hardening that must be applied before any credential is read.

use crate::error::{ApError, Result};

/// Disable core dumps for this process and every child it later spawns.
///
/// SSH passwords necessarily exist briefly in the broker/helper pipe and in
/// OpenSSH's address space. A zero soft *and* hard core-size limit prevents
/// those transient bytes from being written to a crash image. The limit is
/// inherited by the watchdog and OpenSSH children and cannot be raised again
/// by this unprivileged process.
pub fn disable_core_dumps() -> Result<()> {
    let limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid, initialized rlimit structure and remains
    // alive for the duration of the syscall.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &limit) } == 0 {
        Ok(())
    } else {
        Err(ApError::coded(
            "AP_PROCESS_HARDENING_FAILED",
            format!(
                "无法禁用 core dump；为避免凭据进入崩溃文件，ap 拒绝继续：{}",
                std::io::Error::last_os_error()
            ),
        ))
    }
}

#[cfg(test)]
mod tests {
    use std::process::{Command, Stdio};

    use super::*;

    const CHILD_ENV: &str = "AP_CORE_LIMIT_TEST_CHILD";

    #[test]
    fn core_limit_is_zero_in_hardened_subprocess() {
        if std::env::var_os(CHILD_ENV).is_some() {
            return;
        }
        let status = Command::new(std::env::current_exe().unwrap())
            .arg("process_security::tests::core_limit_child")
            .arg("--exact")
            .env(CHILD_ENV, "1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn core_limit_child() {
        if std::env::var_os(CHILD_ENV).as_deref() != Some(std::ffi::OsStr::new("1")) {
            return;
        }
        disable_core_dumps().unwrap();
        let mut limit = std::mem::MaybeUninit::<libc::rlimit>::uninit();
        // SAFETY: `getrlimit` initializes the supplied structure on success.
        assert_eq!(
            unsafe { libc::getrlimit(libc::RLIMIT_CORE, limit.as_mut_ptr()) },
            0
        );
        let limit = unsafe { limit.assume_init() };
        assert_eq!(limit.rlim_cur, 0);
        assert_eq!(limit.rlim_max, 0);
    }
}
