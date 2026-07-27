use std::error::Error;
use std::fmt;

use clap::{ArgAction, ArgGroup, Parser};

/// Command-line arguments for the public `ap` interface.
///
/// The public grammar is intentionally flat: an optional connection name and
/// one optional action flag. The hidden supervisor flag is used only when a
/// background-starting CLI process hands an immutable connection snapshot to a detached
/// child over standard input.
#[derive(Debug, Parser)]
#[command(
    name = "ap",
    version,
    disable_version_flag = true,
    about = "Share a local proxy with an SSH-reachable host",
    long_about = None,
    disable_help_subcommand = true,
    group(
        ArgGroup::new("action")
            .args([
                "foreground",
                "doctor",
                "restart",
                "close",
                "list",
                "internal_supervisor",
            ])
            .multiple(false)
    )
)]
pub struct Cli {
    /// Connection name from the configuration file
    #[arg(value_name = "CONNECTION")]
    pub connection: Option<String>,

    /// Keep the connection in the foreground
    #[arg(short = 'f', long)]
    pub foreground: bool,

    /// Diagnose a connection without starting it
    #[arg(short = 'd', long)]
    pub doctor: bool,

    /// Restart one connection, or all active connections when omitted
    #[arg(short = 'r', long)]
    pub restart: bool,

    /// Close one connection, or all active connections when omitted
    #[arg(short = 'c', long)]
    pub close: bool,

    /// List active connections
    #[arg(short = 'l', long)]
    pub list: bool,

    /// Print version
    #[arg(
        short = 'v',
        long = "version",
        action = ArgAction::Version,
        help = "Print version"
    )]
    version: Option<bool>,

    /// Run the detached connection supervisor.
    ///
    /// This is a private process boundary, not a user-facing operation. The
    /// supervisor reads its connection snapshot and optional in-memory SSH
    /// password from stdin, then reports readiness on stdout.
    #[arg(long = "internal-supervisor", hide = true)]
    pub internal_supervisor: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Connect {
        connection: String,
        foreground: bool,
    },
    Doctor {
        connection: String,
    },
    Restart(ConnectionScope),
    Close(ConnectionScope),
    List,
    InternalSupervisor {
        connection: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConnectionScope {
    One(String),
    All,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResolveError {
    MissingConnection,
    ListWithConnection,
}

impl fmt::Display for ResolveError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingConnection => formatter.write_str("A connection name is required."),
            Self::ListWithConnection => {
                formatter.write_str("--list does not accept a connection name.")
            }
        }
    }
}

impl Error for ResolveError {}

impl Cli {
    pub fn resolve(self) -> Result<Action, ResolveError> {
        if self.internal_supervisor {
            return Ok(Action::InternalSupervisor {
                connection: self.require_connection()?,
            });
        }

        if self.list {
            if self.connection.is_some() {
                return Err(ResolveError::ListWithConnection);
            }
            return Ok(Action::List);
        }

        if self.restart {
            return Ok(Action::Restart(scope(self.connection)));
        }

        if self.close {
            return Ok(Action::Close(scope(self.connection)));
        }

        if self.doctor {
            return Ok(Action::Doctor {
                connection: self.require_connection()?,
            });
        }

        let foreground = self.foreground;
        Ok(Action::Connect {
            connection: self.require_connection()?,
            foreground,
        })
    }

    fn require_connection(self) -> Result<String, ResolveError> {
        self.connection.ok_or(ResolveError::MissingConnection)
    }
}

fn scope(connection: Option<String>) -> ConnectionScope {
    match connection {
        Some(connection) => ConnectionScope::One(connection),
        None => ConnectionScope::All,
    }
}

#[cfg(test)]
mod tests {
    use clap::error::ErrorKind;

    use super::*;

    fn resolve(arguments: &[&str]) -> Action {
        Cli::try_parse_from(arguments).unwrap().resolve().unwrap()
    }

    #[test]
    fn connection_defaults_to_background_connect() {
        assert_eq!(
            resolve(&["ap", "dev"]),
            Action::Connect {
                connection: "dev".to_owned(),
                foreground: false,
            }
        );
        assert_eq!(
            resolve(&["ap", "dev", "-f"]),
            Action::Connect {
                connection: "dev".to_owned(),
                foreground: true,
            }
        );
    }

    #[test]
    fn connection_scoped_actions_resolve() {
        assert_eq!(
            resolve(&["ap", "dev", "-d"]),
            Action::Doctor {
                connection: "dev".to_owned(),
            }
        );
        assert_eq!(
            resolve(&["ap", "dev", "-r"]),
            Action::Restart(ConnectionScope::One("dev".to_owned()))
        );
        assert_eq!(
            resolve(&["ap", "dev", "-c"]),
            Action::Close(ConnectionScope::One("dev".to_owned()))
        );
    }

    #[test]
    fn global_actions_resolve() {
        assert_eq!(
            resolve(&["ap", "-r"]),
            Action::Restart(ConnectionScope::All)
        );
        assert_eq!(resolve(&["ap", "-c"]), Action::Close(ConnectionScope::All));
        assert_eq!(resolve(&["ap", "-l"]), Action::List);
    }

    #[test]
    fn action_flags_are_mutually_exclusive() {
        for arguments in [
            &["ap", "dev", "-f", "-d"][..],
            &["ap", "dev", "-d", "-r"][..],
            &["ap", "dev", "-r", "-c"][..],
            &["ap", "-c", "-l"][..],
            &["ap", "dev", "-f", "--internal-supervisor"][..],
        ] {
            let error = Cli::try_parse_from(arguments).unwrap_err();
            assert_eq!(error.kind(), ErrorKind::ArgumentConflict, "{arguments:?}");
            assert!(error.to_string().is_ascii());
        }
    }

    #[test]
    fn action_scope_is_validated() {
        for arguments in [
            &["ap"][..],
            &["ap", "-f"][..],
            &["ap", "-d"][..],
            &["ap", "--internal-supervisor"][..],
        ] {
            assert_eq!(
                Cli::try_parse_from(arguments).unwrap().resolve(),
                Err(ResolveError::MissingConnection),
                "{arguments:?}"
            );
        }

        assert_eq!(
            Cli::try_parse_from(["ap", "dev", "-l"]).unwrap().resolve(),
            Err(ResolveError::ListWithConnection)
        );
    }

    #[test]
    fn internal_supervisor_is_hidden_and_connection_scoped() {
        assert_eq!(
            resolve(&["ap", "dev", "--internal-supervisor"]),
            Action::InternalSupervisor {
                connection: "dev".to_owned(),
            }
        );

        let help = Cli::try_parse_from(["ap", "-h"]).unwrap_err().to_string();
        assert!(!help.contains("internal-supervisor"));
        assert!(help.is_ascii());
    }

    #[test]
    fn legacy_command_words_are_unreserved_connection_names() {
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
            assert_eq!(
                resolve(&["ap", name]),
                Action::Connect {
                    connection: name.to_owned(),
                    foreground: false,
                }
            );
        }
    }

    #[test]
    fn help_and_version_use_the_requested_short_flags() {
        let help = Cli::try_parse_from(["ap", "-h"]).unwrap_err();
        assert_eq!(help.kind(), ErrorKind::DisplayHelp);
        let help = help.to_string();
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
        assert!(help.is_ascii());

        for flag in ["-v", "--version"] {
            let version = Cli::try_parse_from(["ap", flag]).unwrap_err();
            assert_eq!(version.kind(), ErrorKind::DisplayVersion);
            let version = version.to_string();
            assert!(version.starts_with("ap "));
            assert!(version.is_ascii());
        }
    }
}
