//! Opt-in throughput and stream-integrity harness for the isolated CI sshd.
//!
//! Both measured paths traverse a temporary local `-L`, the isolated sshd's
//! loopback interface, and an OpenSSH `-R`. The baseline terminates directly at
//! a local echo server; the comparison adds ap's authenticated HTTP CONNECT
//! gateway and a local mock HTTP proxy. Every SSH process uses `-N -T`, so the
//! remote host runs no command and needs neither software nor network access.

use std::{
    io::{Error, ErrorKind},
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
    time::Duration,
};

use auto_proxy::{
    gateway::{GatewayCredential, GatewayProtocol, start_gateway},
    ssh::{RemoteForward, SshAuth, SshMaster, SshOptions, SshTarget, system_ssh_executable},
};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    sync::{Barrier, mpsc},
    task::{JoinHandle, JoinSet},
    time::{Instant, sleep, timeout},
};
use tokio_util::sync::CancellationToken;

const RUN_ENV: &str = "AP_RUN_THROUGHPUT_TEST";
const HOST_ENV: &str = "AP_THROUGHPUT_SSH_HOST";
const PORT_ENV: &str = "AP_THROUGHPUT_SSH_PORT";
const USER_ENV: &str = "AP_THROUGHPUT_SSH_USER";
const IDENTITY_ENV: &str = "AP_THROUGHPUT_SSH_IDENTITY_FILE";
const KNOWN_HOSTS_ENV: &str = "AP_THROUGHPUT_SSH_KNOWN_HOSTS";
const ENFORCE_ENV: &str = "AP_ENFORCE_THROUGHPUT";
const CONNECTIONS_ENV: &str = "AP_THROUGHPUT_CONNECTIONS";
const BYTES_ENV: &str = "AP_THROUGHPUT_BYTES_PER_CONNECTION";
const DEFAULT_CONNECTIONS: usize = 32;
const DEFAULT_BYTES_PER_CONNECTION: usize = 2 * 1024 * 1024;
const MIN_RATIO: f64 = 0.85;
const PATTERN_SIZE: usize = 64 * 1024;

#[derive(Clone, Copy)]
enum LoadKind {
    Raw,
    HttpConnect,
}

#[derive(Clone, Copy)]
struct Measurement {
    bytes: u64,
    elapsed: Duration,
}

impl Measurement {
    fn mebibytes_per_second(self) -> f64 {
        self.bytes as f64 / (1024.0 * 1024.0) / self.elapsed.as_secs_f64()
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the explicitly provisioned isolated CI sshd"]
async fn connect_gateway_throughput_tracks_raw_openssh() {
    if std::env::var(RUN_ENV).as_deref() != Ok("1") {
        eprintln!("skipped: set {RUN_ENV}=1 only for the isolated sshd fixture");
        return;
    }

    let target = key_target_from_env();
    let connections = bounded_env_usize(CONNECTIONS_ENV, DEFAULT_CONNECTIONS, 1, 128);
    let bytes_per_connection = bounded_env_usize(
        BYTES_ENV,
        DEFAULT_BYTES_PER_CONNECTION,
        64 * 1024,
        64 * 1024 * 1024,
    );
    let enforce = std::env::var(ENFORCE_ENV).as_deref() == Ok("1");
    let executable = system_ssh_executable().expect("trusted system OpenSSH is unavailable");

    let (echo_addr, echo_task) = spawn_echo_server().await;
    let (proxy_addr, proxy_task) = spawn_connect_echo_proxy().await;
    let proxy_token = "isolated-throughput-token";
    let gateway = start_gateway(
        "throughput-connect",
        GatewayProtocol::Http,
        proxy_addr,
        GatewayCredential::new("ap", proxy_token),
        CancellationToken::new(),
    )
    .await
    .expect("failed to start throughput authentication gateway");
    let gateway_addr = gateway.listen_addr;

    let (raw_remote_port, gateway_remote_port) = distinct_high_ports();
    let temporary = tempfile::tempdir().expect("failed to create private test directory");
    let raw_control = temporary.path().join("raw-master.sock");
    let gateway_control = temporary.path().join("gateway-master.sock");
    let raw_master = SshMaster::start(options(&target, raw_remote_port, echo_addr, &raw_control))
        .await
        .expect("failed to establish raw baseline reverse forward");
    let gateway_master = SshMaster::start(options(
        &target,
        gateway_remote_port,
        gateway_addr,
        &gateway_control,
    ))
    .await
    .expect("failed to establish gateway reverse forward");

    let local_ports = choose_local_ports(2).await;
    let mut local_forward = spawn_local_forward(
        &executable,
        &target,
        &[
            (local_ports[0], raw_remote_port),
            (local_ports[1], gateway_remote_port),
        ],
    );
    wait_for_local_forward(&mut local_forward, local_ports[0]).await;

    // `ssh -L` can bind its local sockets just before the authenticated SSH
    // transport is ready to open channels. Verify both end-to-end paths (and
    // warm their cipher/Hyper state) with retryable, unmeasured round trips.
    wait_for_tunnel(LoadKind::Raw, local_ports[0], proxy_token).await;
    wait_for_tunnel(LoadKind::HttpConnect, local_ports[1], proxy_token).await;

    let raw = run_load(
        LoadKind::Raw,
        local_ports[0],
        connections,
        bytes_per_connection,
        proxy_token,
    )
    .await;
    let through_gateway = run_load(
        LoadKind::HttpConnect,
        local_ports[1],
        connections,
        bytes_per_connection,
        proxy_token,
    )
    .await;
    assert_eq!(raw.bytes, through_gateway.bytes);

    let raw_rate = raw.mebibytes_per_second();
    let gateway_rate = through_gateway.mebibytes_per_second();
    let ratio = gateway_rate / raw_rate;
    println!(
        "throughput: connections={connections} bytes_per_connection={bytes_per_connection} \
         raw={raw_rate:.2} MiB/s gateway={gateway_rate:.2} MiB/s ratio={ratio:.3}"
    );
    if !enforce && ratio < MIN_RATIO {
        println!(
            "throughput observation only: ratio is below {:.0}% on this shared runner",
            MIN_RATIO * 100.0
        );
    }

    raw_master
        .shutdown()
        .await
        .expect("failed to stop raw baseline master");
    gateway_master
        .shutdown()
        .await
        .expect("failed to stop gateway master");
    assert!(!raw_control.exists());
    assert!(!gateway_control.exists());
    assert_remote_closed(&mut local_forward, local_ports[0]).await;
    assert_remote_closed(&mut local_forward, local_ports[1]).await;

    gateway.shutdown().await;
    assert_listener_closed(gateway_addr).await;
    echo_task.abort();
    proxy_task.abort();
    let _ = echo_task.await;
    let _ = proxy_task.await;
    assert_listener_closed(echo_addr).await;
    assert_listener_closed(proxy_addr).await;

    let _ = local_forward.start_kill();
    timeout(Duration::from_secs(5), local_forward.wait())
        .await
        .expect("local-forward SSH did not exit")
        .expect("failed to wait for local-forward SSH");
    assert_listener_closed(([127, 0, 0, 1], local_ports[0]).into()).await;
    assert_listener_closed(([127, 0, 0, 1], local_ports[1]).into()).await;

    // Apply an optional performance gate only after orderly cleanup. Normal
    // shared-runner CI always records the ratio without failing on variance.
    if enforce {
        assert!(
            ratio >= MIN_RATIO,
            "gateway throughput ratio {ratio:.3} is below enforced minimum {MIN_RATIO:.2}"
        );
    }
}

async fn run_load(
    kind: LoadKind,
    local_port: u16,
    connections: usize,
    bytes_per_connection: usize,
    proxy_token: &str,
) -> Measurement {
    let barrier = Arc::new(Barrier::new(connections + 1));
    let (ready_tx, mut ready_rx) = mpsc::channel(connections);
    let mut clients = JoinSet::new();
    for connection in 0..connections {
        let barrier = Arc::clone(&barrier);
        let ready_tx = ready_tx.clone();
        let proxy_token = proxy_token.to_owned();
        clients.spawn(async move {
            let mut stream = timeout(
                Duration::from_secs(10),
                TcpStream::connect(("127.0.0.1", local_port)),
            )
            .await
            .map_err(|_| Error::new(ErrorKind::TimedOut, "client connection timed out"))??;
            if matches!(kind, LoadKind::HttpConnect) {
                establish_connect(&mut stream, &proxy_token).await?;
            }
            ready_tx
                .send(())
                .await
                .map_err(|_| Error::new(ErrorKind::BrokenPipe, "ready channel closed"))?;
            barrier.wait().await;
            transfer_and_verify(stream, connection, bytes_per_connection).await
        });
    }
    drop(ready_tx);
    for _ in 0..connections {
        timeout(Duration::from_secs(20), ready_rx.recv())
            .await
            .expect("clients did not become ready")
            .expect("client failed before the measurement barrier");
    }
    let start = Instant::now();
    barrier.wait().await;

    let mut received = 0_u64;
    while let Some(result) = clients.join_next().await {
        received += result
            .expect("throughput client task panicked")
            .expect("throughput client failed");
    }
    let elapsed = start.elapsed();
    let expected = (connections as u64) * (bytes_per_connection as u64);
    assert_eq!(received, expected, "large transfer was truncated");
    Measurement {
        bytes: received,
        elapsed,
    }
}

async fn wait_for_tunnel(kind: LoadKind, local_port: u16, proxy_token: &str) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if tunnel_readiness_attempt(kind, local_port, proxy_token)
            .await
            .is_ok()
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "SSH forwarding path did not become usable"
        );
        sleep(Duration::from_millis(100)).await;
    }
}

async fn tunnel_readiness_attempt(
    kind: LoadKind,
    local_port: u16,
    proxy_token: &str,
) -> std::io::Result<()> {
    let mut stream = timeout(
        Duration::from_secs(2),
        TcpStream::connect(("127.0.0.1", local_port)),
    )
    .await
    .map_err(|_| Error::new(ErrorKind::TimedOut, "readiness connection timed out"))??;
    if matches!(kind, LoadKind::HttpConnect) {
        establish_connect(&mut stream, proxy_token).await?;
    }
    const PAYLOAD: &[u8] = b"ap-forward-ready";
    stream.write_all(PAYLOAD).await?;
    stream.shutdown().await?;
    let mut echoed = Vec::with_capacity(PAYLOAD.len());
    timeout(Duration::from_secs(5), stream.read_to_end(&mut echoed))
        .await
        .map_err(|_| Error::new(ErrorKind::TimedOut, "readiness echo timed out"))??;
    if echoed != PAYLOAD {
        return Err(Error::new(
            ErrorKind::InvalidData,
            "readiness echo was truncated or corrupted",
        ));
    }
    Ok(())
}

async fn transfer_and_verify(
    stream: TcpStream,
    connection: usize,
    byte_count: usize,
) -> std::io::Result<u64> {
    let pattern = Arc::new(pattern(connection));
    let writer_pattern = Arc::clone(&pattern);
    let (mut reader, mut writer) = stream.into_split();
    let write = async move {
        let mut sent = 0;
        while sent < byte_count {
            let amount = (byte_count - sent).min(writer_pattern.len());
            writer.write_all(&writer_pattern[..amount]).await?;
            sent += amount;
        }
        // The echo endpoint only closes its write side after observing this
        // half-close, so successful EOF below verifies FIN propagation.
        writer.shutdown().await
    };
    let read = async move {
        let mut received = 0_usize;
        let mut buffer = vec![0_u8; PATTERN_SIZE];
        loop {
            let amount = reader.read(&mut buffer).await?;
            if amount == 0 {
                break;
            }
            verify_pattern(&buffer[..amount], received, pattern.as_slice())?;
            received += amount;
            if received > byte_count {
                return Err(Error::new(
                    ErrorKind::InvalidData,
                    "echo returned more data than was sent",
                ));
            }
        }
        if received != byte_count {
            return Err(Error::new(
                ErrorKind::UnexpectedEof,
                format!("echo truncated at {received} of {byte_count} bytes"),
            ));
        }
        Ok(received as u64)
    };
    let (_, received) = timeout(Duration::from_secs(120), async {
        tokio::try_join!(write, read)
    })
    .await
    .map_err(|_| Error::new(ErrorKind::TimedOut, "large transfer timed out"))??;
    Ok(received)
}

fn pattern(connection: usize) -> Vec<u8> {
    let mut state = (connection as u64).wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut bytes = vec![0_u8; PATTERN_SIZE];
    for byte in &mut bytes {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        *byte = state as u8;
    }
    bytes
}

fn verify_pattern(bytes: &[u8], offset: usize, pattern: &[u8]) -> std::io::Result<()> {
    let mut verified = 0;
    while verified < bytes.len() {
        let pattern_offset = (offset + verified) % pattern.len();
        let amount = (bytes.len() - verified).min(pattern.len() - pattern_offset);
        if bytes[verified..verified + amount] != pattern[pattern_offset..pattern_offset + amount] {
            return Err(Error::new(
                ErrorKind::InvalidData,
                "echo payload did not match the sent bytes",
            ));
        }
        verified += amount;
    }
    Ok(())
}

async fn establish_connect(stream: &mut TcpStream, proxy_token: &str) -> std::io::Result<()> {
    let authorization = BASE64.encode(format!("ap:{proxy_token}"));
    stream
        .write_all(
            format!(
                "CONNECT throughput.invalid:443 HTTP/1.1\r\n\
                 Host: throughput.invalid:443\r\n\
                 Proxy-Authorization: Basic {authorization}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await?;
    let response = read_headers(stream).await?;
    if !response.starts_with(b"HTTP/1.1 200") {
        return Err(Error::new(
            ErrorKind::PermissionDenied,
            "CONNECT authentication or upstream handshake failed",
        ));
    }
    Ok(())
}

async fn spawn_echo_server() -> (std::net::SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind echo server");
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { break };
                    connections.spawn(echo_stream(stream));
                }
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    });
    (address, task)
}

async fn spawn_connect_echo_proxy() -> (std::net::SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind mock CONNECT proxy");
    let address = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                accepted = listener.accept() => {
                    let Ok((mut stream, _)) = accepted else { break };
                    connections.spawn(async move {
                        let request = read_headers(&mut stream).await?;
                        if !request.starts_with(b"CONNECT ") {
                            return Err(Error::new(ErrorKind::InvalidInput, "expected CONNECT"));
                        }
                        stream
                            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                            .await?;
                        echo_stream(stream).await
                    });
                }
                Some(_) = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    });
    (address, task)
}

async fn echo_stream(stream: TcpStream) -> std::io::Result<()> {
    let (mut reader, mut writer) = stream.into_split();
    tokio::io::copy(&mut reader, &mut writer).await?;
    writer.shutdown().await
}

async fn read_headers(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut headers = Vec::new();
    let mut byte = [0_u8; 1];
    while !headers.ends_with(b"\r\n\r\n") {
        timeout(Duration::from_secs(10), stream.read_exact(&mut byte))
            .await
            .map_err(|_| Error::new(ErrorKind::TimedOut, "HTTP headers timed out"))??;
        headers.push(byte[0]);
        if headers.len() > 32 * 1024 {
            return Err(Error::new(ErrorKind::InvalidData, "HTTP headers too large"));
        }
    }
    Ok(headers)
}

fn options(
    target: &DirectKeyTarget,
    remote_port: u16,
    local_endpoint: std::net::SocketAddr,
    control_socket: &Path,
) -> SshOptions {
    SshOptions::new(
        target.target.clone(),
        control_socket.to_owned(),
        vec![RemoteForward {
            remote_port,
            local_gateway: local_endpoint,
        }],
        SshAuth::Key {
            identity_file: target.identity_file.clone(),
        },
    )
    .expect("failed to construct SSH options")
    .with_ap_executable(env!("CARGO_BIN_EXE_ap"))
}

fn spawn_local_forward(
    executable: &Path,
    target: &DirectKeyTarget,
    forwards: &[(u16, u16)],
) -> Child {
    let mut command = Command::new(executable);
    command
        .args([
            "-F",
            "/dev/null",
            "-N",
            "-T",
            "-o",
            "ExitOnForwardFailure=yes",
            "-o",
            "BatchMode=yes",
            "-o",
            "ForwardAgent=no",
            "-o",
            "ForwardX11=no",
            "-o",
            "PermitLocalCommand=no",
            "-o",
            "RemoteCommand=none",
            "-o",
            "ControlMaster=no",
            "-o",
            "ControlPath=none",
        ])
        .arg("-p")
        .arg(target.target.port.to_string())
        .arg("-l")
        .arg(&target.target.user)
        .arg("-i")
        .arg(&target.identity_file)
        .arg("-o")
        .arg("IdentitiesOnly=yes")
        .arg("-o")
        .arg("IdentityAgent=none")
        .arg("-o")
        .arg("PasswordAuthentication=no")
        .arg("-o")
        .arg("KbdInteractiveAuthentication=no")
        .arg("-o")
        .arg("GlobalKnownHostsFile=/dev/null")
        .arg("-o")
        .arg(format!(
            "UserKnownHostsFile={}",
            target.target.known_hosts.display()
        ))
        .arg("-o")
        .arg("StrictHostKeyChecking=yes")
        .arg("-o")
        .arg("CanonicalizeHostname=no")
        .arg("-o")
        .arg("ProxyCommand=none")
        .arg("-o")
        .arg("ProxyJump=none")
        .arg("-o")
        .arg("KnownHostsCommand=none")
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    for (local_port, remote_port) in forwards {
        command
            .arg("-L")
            .arg(format!("127.0.0.1:{local_port}:127.0.0.1:{remote_port}"));
    }
    command.arg("--").arg(&target.target.host);
    command
        .spawn()
        .expect("failed to start throughput local-forward SSH")
}

async fn wait_for_local_forward(child: &mut Child, local_port: u16) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child
            .try_wait()
            .expect("failed to inspect local-forward SSH")
        {
            panic!("local-forward SSH exited before readiness: {status}");
        }
        if TcpStream::connect(("127.0.0.1", local_port)).await.is_ok() {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "local-forward SSH did not become ready"
        );
        sleep(Duration::from_millis(100)).await;
    }
}

async fn assert_remote_closed(child: &mut Child, local_port: u16) {
    assert!(
        child
            .try_wait()
            .expect("failed to inspect local-forward SSH")
            .is_none(),
        "local-forward SSH exited before cleanup checks"
    );
    let mut stream = TcpStream::connect(("127.0.0.1", local_port))
        .await
        .expect("local-forward listener disappeared early");
    if stream.write_all(b"cleanup-probe").await.is_err() {
        return;
    }
    let mut one = [0_u8; 1];
    match timeout(Duration::from_secs(3), stream.read(&mut one)).await {
        Ok(Ok(0) | Err(_)) => {}
        Ok(Ok(_)) => panic!("remote reverse-forward listener survived master shutdown"),
        Err(_) => panic!("remote cleanup probe reached a surviving listener"),
    }
}

async fn assert_listener_closed(address: std::net::SocketAddr) {
    match timeout(Duration::from_secs(2), TcpStream::connect(address)).await {
        Ok(Err(_)) => {}
        Ok(Ok(_)) => panic!("listener survived explicit cleanup"),
        Err(_) => panic!("listener cleanup check timed out"),
    }
}

async fn choose_local_ports(count: usize) -> Vec<u16> {
    let mut listeners = Vec::with_capacity(count);
    for _ in 0..count {
        listeners.push(
            TcpListener::bind("127.0.0.1:0")
                .await
                .expect("failed to reserve local-forward port"),
        );
    }
    let ports = listeners
        .iter()
        .map(|listener| listener.local_addr().unwrap().port())
        .collect();
    drop(listeners);
    ports
}

fn distinct_high_ports() -> (u16, u16) {
    let first = random_high_port();
    loop {
        let second = random_high_port();
        if first != second {
            return (first, second);
        }
    }
}

fn random_high_port() -> u16 {
    let mut random = [0_u8; 2];
    getrandom::fill(&mut random).expect("OS randomness unavailable");
    40_000 + (u16::from_ne_bytes(random) % 20_000)
}

#[derive(Clone)]
struct DirectKeyTarget {
    target: SshTarget,
    identity_file: PathBuf,
}

fn key_target_from_env() -> DirectKeyTarget {
    DirectKeyTarget {
        target: SshTarget {
            host: required_env(HOST_ENV),
            port: required_ssh_port(PORT_ENV),
            user: required_env(USER_ENV),
            known_hosts: PathBuf::from(required_env(KNOWN_HOSTS_ENV)),
            connect_timeout: Duration::from_secs(10),
        },
        identity_file: PathBuf::from(required_env(IDENTITY_ENV)),
    }
}

fn required_env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("missing {name}"))
}

fn required_ssh_port(name: &str) -> u16 {
    required_env(name)
        .parse::<u16>()
        .unwrap_or_else(|_| panic!("invalid SSH port in {name}"))
}

fn bounded_env_usize(name: &str, default: usize, minimum: usize, maximum: usize) -> usize {
    let value = match std::env::var(name) {
        Ok(value) => value
            .parse::<usize>()
            .unwrap_or_else(|_| panic!("invalid {name}")),
        Err(_) => default,
    };
    assert!(
        (minimum..=maximum).contains(&value),
        "{name} must be between {minimum} and {maximum}"
    );
    value
}
