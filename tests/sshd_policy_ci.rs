//! Opt-in integration coverage for remote-forward policy failures.
//!
//! The CI workflow supplies three explicit ordinary-user SSH destinations in
//! one network namespace: a probe server, a server with all
//! TCP forwarding disabled, and a server whose `PermitListen` excludes the
//! requested port. Every SSH process in this test uses `-N -T`; no remote
//! command, shell, installation, Internet access, or DNS is required.

use std::{
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use auto_proxy::{
    gateway::{GatewayCredential, GatewayProtocol, RunningGateway, start_gateway},
    ssh::{RemoteForward, SshAuth, SshMaster, SshOptions, SshTarget, system_ssh_executable},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    time::{Instant, sleep, timeout},
};
use tokio_util::sync::CancellationToken;

const RUN_ENV: &str = "AP_RUN_SSH_POLICY_TEST";
const HOST_ENV: &str = "AP_SSH_POLICY_HOST";
const USER_ENV: &str = "AP_SSH_POLICY_USER";
const IDENTITY_ENV: &str = "AP_SSH_POLICY_IDENTITY_FILE";
const KNOWN_HOSTS_ENV: &str = "AP_SSH_POLICY_KNOWN_HOSTS";
const PROBE_SSH_PORT_ENV: &str = "AP_SSH_POLICY_PROBE_SSH_PORT";
const FORWARDING_DENIED_SSH_PORT_ENV: &str = "AP_SSH_POLICY_FORWARDING_DENIED_SSH_PORT";
const LISTEN_DENIED_SSH_PORT_ENV: &str = "AP_SSH_POLICY_LISTEN_DENIED_SSH_PORT";
const FORWARDING_DENIED_PORT_ENV: &str = "AP_SSH_POLICY_FORWARDING_DENIED_PORT";
const LISTEN_DENIED_PORT_ENV: &str = "AP_SSH_POLICY_LISTEN_DENIED_PORT";
const CONFLICT_PORT_ENV: &str = "AP_SSH_POLICY_CONFLICT_PORT";

#[tokio::test]
#[ignore = "requires the explicitly provisioned isolated CI sshd instances"]
async fn remote_forward_policy_failures_leave_no_resources() {
    if std::env::var(RUN_ENV).as_deref() != Ok("1") {
        eprintln!("skipped: set {RUN_ENV}=1 only for the isolated sshd fixture");
        return;
    }

    let probe_target = key_target_from_env(PROBE_SSH_PORT_ENV);
    let forwarding_denied_target = key_target_from_env(FORWARDING_DENIED_SSH_PORT_ENV);
    let listen_denied_target = key_target_from_env(LISTEN_DENIED_SSH_PORT_ENV);
    let forwarding_denied_port = required_port(FORWARDING_DENIED_PORT_ENV);
    let listen_denied_port = required_port(LISTEN_DENIED_PORT_ENV);
    let conflict_port = required_port(CONFLICT_PORT_ENV);
    assert_ne!(forwarding_denied_port, listen_denied_port);
    assert_ne!(forwarding_denied_port, conflict_port);
    assert_ne!(listen_denied_port, conflict_port);

    let executable = system_ssh_executable().expect("trusted system OpenSSH is unavailable");
    let local_ports = choose_local_ports(3).await;
    let mut probe = spawn_probe_forward(
        &executable,
        &probe_target,
        &[
            (local_ports[0], forwarding_denied_port),
            (local_ports[1], listen_denied_port),
            (local_ports[2], conflict_port),
        ],
    );
    wait_for_probe(&mut probe, local_ports[0]).await;

    let temporary = tempfile::tempdir().expect("failed to create private test directory");
    assert_remote_closed(&mut probe, local_ports[0]).await;
    exercise_policy_rejection(
        &forwarding_denied_target,
        forwarding_denied_port,
        local_ports[0],
        &temporary.path().join("forwarding-denied.sock"),
        &mut probe,
    )
    .await;

    assert_remote_closed(&mut probe, local_ports[1]).await;
    exercise_policy_rejection(
        &listen_denied_target,
        listen_denied_port,
        local_ports[1],
        &temporary.path().join("listen-denied.sock"),
        &mut probe,
    )
    .await;

    exercise_fixed_port_conflict(
        &probe_target,
        conflict_port,
        local_ports[2],
        temporary.path(),
        &mut probe,
    )
    .await;

    let _ = probe.start_kill();
    let _ = timeout(Duration::from_secs(5), probe.wait()).await;
}

async fn exercise_policy_rejection(
    target: &DirectKeyTarget,
    remote_port: u16,
    probe_port: u16,
    control_socket: &Path,
    probe: &mut Child,
) {
    let (_upstream, gateway) = new_gateway("policy-rejection").await;
    let gateway_addr = gateway.listen_addr;
    assert_gateway_open(gateway_addr).await;

    let options = options(target, remote_port, gateway_addr, control_socket);
    match timeout(Duration::from_secs(10), SshMaster::start(options)).await {
        Ok(Err(error)) => assert_forward_rejection(&error),
        Ok(Ok(master)) => {
            let _ = master.shutdown().await;
            panic!("remote forwarding unexpectedly succeeded for a rejecting sshd policy");
        }
        Err(_) => panic!("policy rejection did not terminate promptly"),
    }

    wait_for_path_absent(control_socket).await;
    assert_remote_closed(probe, probe_port).await;
    gateway.shutdown().await;
    assert_local_closed(gateway_addr).await;
    assert_remote_closed(probe, probe_port).await;
}

async fn exercise_fixed_port_conflict(
    target: &DirectKeyTarget,
    remote_port: u16,
    probe_port: u16,
    directory: &Path,
    probe: &mut Child,
) {
    let occupant_control = directory.join("conflict-occupant.sock");
    let challenger_control = directory.join("conflict-challenger.sock");
    let recovered_control = directory.join("conflict-recovered.sock");
    assert_remote_closed(probe, probe_port).await;

    let (_occupant_upstream, occupant_gateway) = new_gateway("conflict-occupant").await;
    let occupant_addr = occupant_gateway.listen_addr;
    let occupant = SshMaster::start(options(
        target,
        remote_port,
        occupant_addr,
        &occupant_control,
    ))
    .await
    .expect("failed to create the intentional remote-port occupant");
    assert!(
        occupant_control.exists(),
        "occupant control socket is missing"
    );
    assert_remote_open(probe, probe_port).await;

    let (_challenger_upstream, challenger_gateway) = new_gateway("conflict-challenger").await;
    let challenger_addr = challenger_gateway.listen_addr;
    assert_gateway_open(challenger_addr).await;
    match timeout(
        Duration::from_secs(10),
        SshMaster::start(options(
            target,
            remote_port,
            challenger_addr,
            &challenger_control,
        )),
    )
    .await
    {
        Ok(Err(error)) => assert_forward_rejection(&error),
        Ok(Ok(master)) => {
            let _ = master.shutdown().await;
            panic!("a second SSH master unexpectedly acquired the occupied remote port");
        }
        Err(_) => panic!("remote-port conflict did not terminate promptly"),
    }
    wait_for_path_absent(&challenger_control).await;
    challenger_gateway.shutdown().await;
    assert_local_closed(challenger_addr).await;
    // The failed challenger must neither replace nor tear down the owner.
    assert_remote_open(probe, probe_port).await;

    occupant
        .shutdown()
        .await
        .expect("failed to stop the intentional port occupant");
    occupant_gateway.shutdown().await;
    wait_for_path_absent(&occupant_control).await;
    assert_local_closed(occupant_addr).await;
    assert_remote_closed(probe, probe_port).await;

    // Reusing the same fixed port proves that the failed and stopped masters
    // left no listener behind. A final shutdown proves cleanup once more.
    let (_recovered_upstream, recovered_gateway) = new_gateway("conflict-recovered").await;
    let recovered_addr = recovered_gateway.listen_addr;
    let recovered = SshMaster::start(options(
        target,
        remote_port,
        recovered_addr,
        &recovered_control,
    ))
    .await
    .expect("the fixed remote port was not reusable after cleanup");
    assert_remote_open(probe, probe_port).await;
    recovered
        .shutdown()
        .await
        .expect("failed to stop the recovered SSH master");
    recovered_gateway.shutdown().await;
    wait_for_path_absent(&recovered_control).await;
    assert_local_closed(recovered_addr).await;
    assert_remote_closed(probe, probe_port).await;
}

fn assert_forward_rejection(error: &auto_proxy::error::ApError) {
    assert!(
        matches!(
            error.code(),
            "AP_SSH_FORWARD_FAILED" | "AP_SSH_FORWARDING_DISABLED"
        ),
        "sshd policy/conflict failed for an unrelated reason: {}",
        error.code()
    );
}

fn options(
    target: &DirectKeyTarget,
    remote_port: u16,
    gateway: std::net::SocketAddr,
    control_socket: &Path,
) -> SshOptions {
    let mut options = SshOptions::new(
        target.target.clone(),
        control_socket.to_owned(),
        vec![RemoteForward {
            remote_port,
            local_gateway: gateway,
        }],
        SshAuth::Key {
            identity_file: target.identity_file.clone(),
        },
    )
    .expect("failed to construct SSH options")
    .with_ap_executable(env!("CARGO_BIN_EXE_ap"));
    options.startup_timeout = Duration::from_secs(6);
    options
}

async fn new_gateway(name: &str) -> (TcpListener, RunningGateway) {
    let upstream = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind unused local upstream");
    let gateway = start_gateway(
        name,
        GatewayProtocol::Http,
        upstream.local_addr().unwrap(),
        GatewayCredential::new("ap", "isolated-policy-token"),
        CancellationToken::new(),
    )
    .await
    .expect("failed to start local authentication gateway");
    (upstream, gateway)
}

fn spawn_probe_forward(
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
        .expect("failed to start isolated remote-listener probe")
}

async fn wait_for_probe(child: &mut Child, local_port: u16) {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().expect("failed to inspect probe SSH") {
            panic!("remote-listener probe exited before readiness: {status}");
        }
        if TcpStream::connect(("127.0.0.1", local_port)).await.is_ok() {
            return;
        }
        assert!(Instant::now() < deadline, "probe SSH did not become ready");
        sleep(Duration::from_millis(100)).await;
    }
}

async fn assert_remote_open(probe: &mut Child, local_port: u16) {
    assert!(
        probe
            .try_wait()
            .expect("failed to inspect probe SSH")
            .is_none(),
        "remote-listener probe exited unexpectedly"
    );
    let response = request_unauthenticated_proxy(local_port).await;
    assert!(
        response.starts_with(b"HTTP/1.1 407"),
        "remote listener did not reach the expected authentication gateway"
    );
}

async fn assert_remote_closed(probe: &mut Child, local_port: u16) {
    assert!(
        probe
            .try_wait()
            .expect("failed to inspect probe SSH")
            .is_none(),
        "remote-listener probe exited unexpectedly"
    );
    let mut stream = TcpStream::connect(("127.0.0.1", local_port))
        .await
        .expect("local probe listener disappeared");
    let request =
        b"GET http://policy.invalid/ HTTP/1.1\r\nHost: policy.invalid\r\nConnection: close\r\n\r\n";
    if stream.write_all(request).await.is_err() {
        return;
    }
    let mut one = [0_u8; 1];
    match timeout(Duration::from_secs(3), stream.read(&mut one)).await {
        Ok(Ok(0) | Err(_)) => {}
        Ok(Ok(_)) => panic!("a rejected or cleaned-up remote listener is still reachable"),
        Err(_) => panic!("a remote listener accepted the probe instead of failing closed"),
    }
}

async fn assert_gateway_open(address: std::net::SocketAddr) {
    let response = request_proxy_at(address).await;
    assert!(response.starts_with(b"HTTP/1.1 407"));
}

async fn assert_local_closed(address: std::net::SocketAddr) {
    match timeout(Duration::from_secs(2), TcpStream::connect(address)).await {
        Ok(Err(_)) => {}
        Ok(Ok(_)) => panic!("local gateway listener survived shutdown"),
        Err(_) => panic!("timed out checking local gateway shutdown"),
    }
}

async fn request_unauthenticated_proxy(local_port: u16) -> Vec<u8> {
    let address = std::net::SocketAddr::from(([127, 0, 0, 1], local_port));
    request_proxy_at(address).await
}

async fn request_proxy_at(address: std::net::SocketAddr) -> Vec<u8> {
    let mut stream = timeout(Duration::from_secs(5), TcpStream::connect(address))
        .await
        .expect("proxy connection timed out")
        .expect("proxy connection failed");
    stream
        .write_all(
            b"GET http://policy.invalid/ HTTP/1.1\r\nHost: policy.invalid\r\nConnection: close\r\n\r\n",
        )
        .await
        .expect("proxy request failed");
    let mut response = Vec::new();
    timeout(Duration::from_secs(5), stream.read_to_end(&mut response))
        .await
        .expect("proxy response timed out")
        .expect("proxy response failed");
    response
}

async fn wait_for_path_absent(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(3);
    while path.exists() && Instant::now() < deadline {
        sleep(Duration::from_millis(50)).await;
    }
    assert!(
        !path.exists(),
        "failed SSH attempt left its ControlMaster socket behind"
    );
}

async fn choose_local_ports(count: usize) -> Vec<u16> {
    let mut listeners = Vec::with_capacity(count);
    for _ in 0..count {
        listeners.push(
            TcpListener::bind("127.0.0.1:0")
                .await
                .expect("failed to reserve a local probe port"),
        );
    }
    let ports = listeners
        .iter()
        .map(|listener| listener.local_addr().unwrap().port())
        .collect();
    drop(listeners);
    ports
}

#[derive(Clone)]
struct DirectKeyTarget {
    target: SshTarget,
    identity_file: PathBuf,
}

fn key_target_from_env(port_env: &str) -> DirectKeyTarget {
    DirectKeyTarget {
        target: SshTarget {
            host: required_env(HOST_ENV),
            port: required_ssh_port(port_env),
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

fn required_port(name: &str) -> u16 {
    let port = std::env::var(name)
        .unwrap_or_else(|_| panic!("missing {name}"))
        .parse::<u16>()
        .unwrap_or_else(|_| panic!("invalid {name}"));
    assert!(port >= 1024, "{name} must be an unprivileged port");
    port
}
