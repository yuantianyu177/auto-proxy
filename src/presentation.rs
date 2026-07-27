use std::fmt::Write as _;

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::model::{ProxyMapping, ProxyProtocol, ResolvedConnection};
use crate::secrets::ProxyCredential;

/// Environment data is intentionally serializable for the private supervisor
/// IPC channel but does not implement `Debug`, preventing accidental logging.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentBlock {
    pub protocol: ProxyProtocol,
    pub remote_port: u16,
    pub variables: Vec<EnvironmentVariable>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentVariable {
    pub name: String,
    pub value: String,
}

impl Drop for EnvironmentVariable {
    fn drop(&mut self) {
        self.name.zeroize();
        self.value.zeroize();
    }
}

pub fn environment_blocks(
    connection: &ResolvedConnection,
    credential: &ProxyCredential,
) -> Vec<EnvironmentBlock> {
    connection
        .proxies
        .iter()
        .map(|mapping| environment_block(mapping, credential))
        .collect()
}

fn environment_block(mapping: &ProxyMapping, credential: &ProxyCredential) -> EnvironmentBlock {
    let authority = Zeroizing::new(format!(
        "{}:{}@127.0.0.1:{}",
        credential.username(),
        credential.password(),
        mapping.remote_port
    ));
    let http = Zeroizing::new(format!("http://{}", authority.as_str()));
    let socks = Zeroizing::new(format!("socks5h://{}", authority.as_str()));
    let variables = match mapping.protocol {
        ProxyProtocol::Http => vec![
            variable("http_proxy", &http),
            variable("https_proxy", &http),
        ],
        ProxyProtocol::Socks5 => vec![variable("all_proxy", &socks)],
        ProxyProtocol::Mixed => vec![
            variable("http_proxy", &http),
            variable("https_proxy", &http),
            variable("all_proxy", &socks),
        ],
    };
    EnvironmentBlock {
        protocol: mapping.protocol,
        remote_port: mapping.remote_port,
        variables,
    }
}

fn variable(name: &str, value: &str) -> EnvironmentVariable {
    EnvironmentVariable {
        name: name.to_owned(),
        value: value.to_owned(),
    }
}

pub fn print_environment(blocks: &[EnvironmentBlock]) {
    if blocks.len() > 1 {
        println!("Choose one proxy block for each application; blocks may reuse variable names.");
    }
    for block in blocks {
        println!();
        println!(
            "Proxy ({} on 127.0.0.1:{}):",
            block.protocol, block.remote_port
        );
        for variable in &block.variables {
            println!(
                "export {}={}",
                variable.name,
                shell_single_quote(&variable.value)
            );
        }
    }
}

pub fn render_table<const COLUMNS: usize>(
    headers: [&str; COLUMNS],
    rows: &[[String; COLUMNS]],
) -> String {
    let mut widths = std::array::from_fn(|column| headers[column].len());
    for row in rows {
        for (column, value) in row.iter().enumerate() {
            widths[column] = widths[column].max(value.len());
        }
    }

    let mut output = String::new();
    write_table_row(&mut output, &headers, &widths);
    for row in rows {
        let values = std::array::from_fn(|column| row[column].as_str());
        write_table_row(&mut output, &values, &widths);
    }
    output
}

fn write_table_row<const COLUMNS: usize>(
    output: &mut String,
    values: &[&str; COLUMNS],
    widths: &[usize; COLUMNS],
) {
    for (column, value) in values.iter().enumerate() {
        if column + 1 == COLUMNS {
            output.push_str(value);
        } else {
            write!(output, "{value:<width$}  ", width = widths[column])
                .expect("writing to a String cannot fail");
        }
    }
    output.push('\n');
}

fn shell_single_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::model::{ResolvedSshAuth, ResolvedSshConfig};

    use super::*;

    fn connection(protocol: ProxyProtocol) -> ResolvedConnection {
        ResolvedConnection {
            name: "dev".into(),
            ssh: ResolvedSshConfig {
                host: "server.example".into(),
                port: 22,
                user: "alice".into(),
                connect_timeout_seconds: 15,
                auth: ResolvedSshAuth::Key {
                    identity_file: PathBuf::from("/keys/id"),
                },
            },
            proxies: vec![ProxyMapping {
                protocol,
                local: "127.0.0.1:7890".parse().unwrap(),
                remote_port: 17890,
            }],
        }
    }

    #[test]
    fn mixed_environment_contains_http_and_remote_dns_socks() {
        let credential = ProxyCredential::from_parts("ap", "secret");
        let blocks = environment_blocks(&connection(ProxyProtocol::Mixed), &credential);
        assert_eq!(blocks.len(), 1);
        assert_eq!(blocks[0].remote_port, 17890);
        assert_eq!(blocks[0].variables.len(), 3);
        assert_eq!(blocks[0].variables[0].name, "http_proxy");
        assert!(blocks[0].variables[0].value.contains("ap:secret@"));
        assert_eq!(blocks[0].variables[2].name, "all_proxy");
        assert!(blocks[0].variables[2].value.starts_with("socks5h://"));
    }

    #[test]
    fn shell_quoting_handles_single_quotes() {
        assert_eq!(shell_single_quote("a'b"), "'a'\\''b'");
    }

    #[test]
    fn table_uses_content_widths_instead_of_terminal_tabs() {
        let rows = [
            [
                "dev".to_owned(),
                "connected".to_owned(),
                "88931".to_owned(),
                "1".to_owned(),
                "-".to_owned(),
            ],
            [
                "production".to_owned(),
                "failed".to_owned(),
                "-".to_owned(),
                "12".to_owned(),
                "AP_SSH_EXITED".to_owned(),
            ],
        ];

        let rendered = render_table(["NAME", "STATUS", "SSH_PID", "PROXIES", "ERROR"], &rows);

        assert_eq!(
            rendered,
            concat!(
                "NAME        STATUS     SSH_PID  PROXIES  ERROR\n",
                "dev         connected  88931    1        -\n",
                "production  failed     -        12       AP_SSH_EXITED\n",
            )
        );
        assert!(!rendered.contains('\t'));
    }
}
