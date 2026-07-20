use std::net::SocketAddr;

use clap::{Args, Parser, Subcommand};

use crate::model::ProxyProtocol;

#[derive(Debug, Parser)]
#[command(
    name = "ap",
    version,
    about = "通过 SSH 将本机代理安全地共享给远程服务器",
    disable_help_subcommand = true
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// 管理远程服务器 profile
    Server(ServerCommand),
    /// 管理代理映射
    Proxy(ProxyCommand),
    /// 管理 SSH 认证
    Auth(AuthCommand),
    /// 前台连接，Ctrl-C 后关闭
    Connect { server: String },
    /// 通过用户级 daemon 启动连接
    Up { server: String },
    /// 停止连接但保留登录自启动状态
    Down { server: String },
    /// 查看一个或全部 profile 的状态
    Status {
        server: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// 查看后台日志
    Logs {
        server: String,
        #[arg(long, short = 'f')]
        follow: bool,
    },
    /// 检查本机环境、代理端点和 SSH 转发
    Doctor { server: String },
    /// 输出供远程用户自行执行的代理环境变量
    Env { server: String, proxy: String },
    /// 安装或卸载用户级 daemon
    Service(ServiceCommand),
    /// 设置登录自启动并立即连接
    Enable { server: String },
    /// 取消登录自启动并停止连接
    Disable { server: String },
    /// 轮换某个 profile 的共享代理凭据
    #[command(name = "proxy-credential")]
    ProxyCredential(ProxyCredentialCommand),
    /// daemon 的内部入口；不属于稳定 CLI
    #[command(name = "__daemon", hide = true)]
    InternalDaemon,
}

#[derive(Debug, Args)]
pub struct ServerCommand {
    #[command(subcommand)]
    pub command: ServerSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ServerSubcommand {
    Add {
        name: String,
        #[arg(long = "ssh", value_name = "HOST_ALIAS")]
        ssh_host: String,
    },
    List,
    Show {
        name: String,
        #[arg(long)]
        json: bool,
    },
    Remove {
        name: String,
    },
}

#[derive(Debug, Args)]
pub struct ProxyCommand {
    #[command(subcommand)]
    pub command: ProxySubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ProxySubcommand {
    Add(ProxyAddArgs),
    List {
        server: String,
        #[arg(long)]
        json: bool,
    },
    Update(ProxyUpdateArgs),
    Remove {
        server: String,
        name: String,
        #[arg(long)]
        restart: bool,
    },
}

#[derive(Debug, Args)]
pub struct ProxyAddArgs {
    pub server: String,
    pub name: String,
    #[arg(long, value_enum)]
    pub protocol: ProxyProtocol,
    #[arg(long, value_name = "LOOPBACK:PORT")]
    pub local: SocketAddr,
    #[arg(long, value_parser = clap::value_parser!(u16).range(1024..=65535))]
    pub remote_port: u16,
    /// 若 profile 正在运行，保存后重启整个 profile
    #[arg(long)]
    pub restart: bool,
}

#[derive(Debug, Args)]
pub struct ProxyUpdateArgs {
    pub server: String,
    pub name: String,
    #[arg(long, value_enum)]
    pub protocol: Option<ProxyProtocol>,
    #[arg(long, value_name = "LOOPBACK:PORT")]
    pub local: Option<SocketAddr>,
    #[arg(long, value_parser = clap::value_parser!(u16).range(1024..=65535))]
    pub remote_port: Option<u16>,
    #[arg(long)]
    pub rename: Option<String>,
    #[arg(long)]
    pub restart: bool,
}

#[derive(Debug, Args)]
pub struct AuthCommand {
    #[command(subcommand)]
    pub command: AuthSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum AuthSubcommand {
    Password(PasswordCommand),
}

#[derive(Debug, Args)]
pub struct PasswordCommand {
    #[command(subcommand)]
    pub command: PasswordSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum PasswordSubcommand {
    Set {
        server: String,
        /// 若 profile 正在运行，保存后重启整个 profile
        #[arg(long)]
        restart: bool,
    },
    Status {
        server: String,
    },
    Remove {
        server: String,
        /// 若 profile 正在运行，删除后以 ssh-config 模式重启
        #[arg(long)]
        restart: bool,
    },
}

#[derive(Debug, Args)]
pub struct ServiceCommand {
    #[command(subcommand)]
    pub command: ServiceSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ServiceSubcommand {
    Install,
    Uninstall,
}

#[derive(Debug, Args)]
pub struct ProxyCredentialCommand {
    #[command(subcommand)]
    pub command: ProxyCredentialSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum ProxyCredentialSubcommand {
    Rotate {
        server: String,
        #[arg(long)]
        restart: bool,
    },
}
