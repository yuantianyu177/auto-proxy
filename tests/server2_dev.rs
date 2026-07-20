//! Real, opt-in development integration test for the local `server2` SSH alias.
//!
//! This test never executes a remote command and does not install or modify
//! anything remotely. Both SSH processes use `-N -T`; their remote listeners
//! disappear with the connections. All proxy and origin behavior is provided
//! by temporary listeners on this machine, so `server2` needs no Internet or
//! DNS access.

use std::{net::SocketAddr, process::Stdio, time::Duration};

use auto_proxy::{
    gateway::{GatewayCredential, GatewayProtocol, start_gateway},
    ssh::{RemoteForward, SshAuthentication, SshMaster, SshOptions, system_ssh_executable},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD as BASE64, URL_SAFE_NO_PAD},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    sync::{mpsc, oneshot},
    time::{Instant, sleep, timeout},
};
use tokio_util::sync::CancellationToken;

const DEFAULT_HOST: &str = "server2";
const HOST_OVERRIDE_ENV: &str = "AP_SERVER2_TEST_HOST";

/// Run explicitly with:
///
/// `AP_RUN_SERVER2_TEST=1 cargo test --test server2_dev -- --ignored --nocapture`
///
/// CI may additionally set `AP_SERVER2_TEST_HOST` to an ephemeral SSH config
/// alias. Without that override the test always uses `server2`.
#[tokio::test]
#[ignore = "requires explicit AP_RUN_SERVER2_TEST=1 and an authorized SSH Host alias"]
async fn server2_reverse_forward_protocols_and_reconnect() {
    if std::env::var("AP_RUN_SERVER2_TEST").as_deref() != Ok("1") {
        eprintln!("skipped: set AP_RUN_SERVER2_TEST=1 to authorize the real server2 test");
        return;
    }

    // CI supplies an ephemeral Host alias backed by an isolated sshd. Keeping
    // the override opt-in preserves `server2` as the developer-test default.
    let host = std::env::var(HOST_OVERRIDE_ENV).unwrap_or_else(|_| DEFAULT_HOST.to_owned());
    assert!(
        !host.is_empty()
            && host.len() <= 255
            && host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')),
        "{HOST_OVERRIDE_ENV} must be a plain OpenSSH Host alias"
    );

    // Resolve the alias using OpenSSH itself. Do not print the expanded output,
    // because it can contain real host names, users, and key paths.
    let ssh_executable = system_ssh_executable().expect("trusted system OpenSSH is unavailable");
    let config = Command::new(&ssh_executable)
        .args(["-G", "--", &host])
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .await
        .expect("failed to execute system ssh -G");
    assert!(config.success(), "ssh -G test Host alias failed");

    let (http_upstream, mut observed_http, http_mock_task) = spawn_mock_http_proxy().await;
    let (socks_upstream, observed_socks, socks_mock_task) = spawn_mock_socks_proxy().await;
    let proxy_token = random_proxy_token();
    let credential = GatewayCredential::new("ap", &proxy_token);
    let http_gateway = start_gateway(
        "server2-http",
        GatewayProtocol::Http,
        http_upstream,
        credential.clone(),
        CancellationToken::new(),
    )
    .await
    .expect("failed to start local HTTP authentication gateway");
    let socks_gateway = start_gateway(
        "server2-socks",
        GatewayProtocol::Socks5,
        socks_upstream,
        credential,
        CancellationToken::new(),
    )
    .await
    .expect("failed to start local SOCKS5 authentication gateway");

    let (http_remote_port, socks_remote_port) = random_distinct_high_ports();
    let temporary = tempfile::tempdir_in("/tmp").expect("failed to create private temp directory");
    let options = SshOptions::new(
        host.clone(),
        temporary.path().join("master.sock"),
        vec![
            RemoteForward {
                remote_port: http_remote_port,
                local_gateway: http_gateway.listen_addr,
            },
            RemoteForward {
                remote_port: socks_remote_port,
                local_gateway: socks_gateway.listen_addr,
            },
        ],
        SshAuthentication::SshConfig { batch_mode: true },
    )
    .expect("failed to construct SSH options")
    .with_ap_executable(env!("CARGO_BIN_EXE_ap"));
    let master = SshMaster::start(options.clone())
        .await
        .expect("failed to establish server2 reverse forwards");

    // The second SSH connection only exposes the two remote loopback listeners
    // back to this test. The dedicated alias has already been checked by
    // SshMaster for inherited forwards and remote/local commands.
    let (http_local_port, socks_local_port) = choose_distinct_local_ports().await;
    let mut local_forward = spawn_local_forward(
        &ssh_executable,
        &host,
        http_local_port,
        http_remote_port,
        socks_local_port,
        socks_remote_port,
    );
    let wrong_authorization = BASE64.encode("ap:definitely-wrong");
    let bad_request = format!(
        "GET http://server2-test.invalid/rejected HTTP/1.1\r\nHost: server2-test.invalid\r\nProxy-Authorization: Basic {wrong_authorization}\r\nConnection: close\r\n\r\n"
    );
    // A freshly started `ssh -L` can bind its local listener just before its
    // transport is ready to open channels. Retry only this readiness probe so
    // a transient reset does not make the opt-in real-host test flaky.
    let bad_response =
        wait_for_http_gateway(&mut local_forward, http_local_port, &bad_request).await;
    assert!(bad_response.starts_with(b"HTTP/1.1 407"));
    assert!(http_gateway.stats.snapshot().authentication_failures >= 1);
    assert!(
        timeout(Duration::from_millis(300), observed_http.recv())
            .await
            .is_err(),
        "wrong proxy credentials reached the local proxy"
    );

    let authorization = BASE64.encode(format!("ap:{proxy_token}"));
    let response = send_http_request(
        &mut local_forward,
        http_local_port,
        &format!(
            "GET http://server2-test.invalid/check HTTP/1.1\r\nHost: server2-test.invalid\r\nProxy-Authorization: Basic {authorization}\r\nProxy-Connection: keep-alive\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(response.ends_with(b"server2-ok"));
    let observed = recv_http_observation(&mut observed_http).await;
    assert!(observed.starts_with("GET http://server2-test.invalid/check HTTP/1.1\r\n"));
    assert!(
        !observed
            .to_ascii_lowercase()
            .contains("proxy-authorization")
    );
    assert!(!observed.to_ascii_lowercase().contains("proxy-connection"));

    exercise_http_connect(
        &mut local_forward,
        http_local_port,
        &authorization,
        &mut observed_http,
    )
    .await;
    exercise_socks_domain(
        &mut local_forward,
        socks_local_port,
        &proxy_token,
        observed_socks,
    )
    .await;

    // Closing the master must release the remote listeners. The independent
    // local-forward SSH remains alive, allowing us to prove that a new channel
    // can no longer reach the HTTP gateway.
    master.shutdown().await.expect("failed to stop SSH master");
    assert_reverse_forward_gone(&mut local_forward, http_local_port, &authorization).await;

    // Reusing the exact same fixed ports proves cleanup, and the request proves
    // that a full profile-style reconnect restores forwarding.
    let reconnected = SshMaster::start(options)
        .await
        .expect("failed to restore the same server2 reverse forwards");
    // The long-lived `-L` probe connection may observe the remote listener's
    // teardown/rebind slightly after the new ControlMaster reports success.
    // Re-establish end-to-end readiness with a request that cannot reach the
    // upstream proxy before asserting the successful request below.
    let readiness = wait_for_http_gateway(&mut local_forward, http_local_port, &bad_request).await;
    assert!(readiness.starts_with(b"HTTP/1.1 407"));
    let response = send_http_request(
        &mut local_forward,
        http_local_port,
        &format!(
            "GET http://server2-test.invalid/reconnected HTTP/1.1\r\nHost: server2-test.invalid\r\nProxy-Authorization: Basic {authorization}\r\nConnection: close\r\n\r\n"
        ),
    )
    .await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(response.ends_with(b"server2-ok"));
    let observed = recv_http_observation(&mut observed_http).await;
    assert!(observed.starts_with("GET http://server2-test.invalid/reconnected HTTP/1.1\r\n"));

    reconnected
        .shutdown()
        .await
        .expect("failed to stop reconnected SSH master");
    assert_reverse_forward_gone(&mut local_forward, http_local_port, &authorization).await;

    // Prefer orderly cleanup. All handles also have exceptional-path cleanup:
    // Child.kill_on_drop, SshMaster::drop, and RunningGateway::drop.
    let _ = local_forward.start_kill();
    let _ = timeout(Duration::from_secs(5), local_forward.wait()).await;
    http_gateway.shutdown().await;
    socks_gateway.shutdown().await;
    http_mock_task.abort();
    socks_mock_task.abort();
}

async fn spawn_mock_http_proxy() -> (
    SocketAddr,
    mpsc::Receiver<Vec<u8>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind mock HTTP proxy");
    let address = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::channel(8);
    let task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.expect("mock HTTP accept failed");
            let tx = tx.clone();
            tokio::spawn(async move {
                handle_mock_http_connection(stream, tx).await;
            });
        }
    });
    (address, rx, task)
}

async fn handle_mock_http_connection(mut stream: TcpStream, observed: mpsc::Sender<Vec<u8>>) {
    let request = read_headers(&mut stream).await;
    let is_connect = request.starts_with(b"CONNECT ");
    observed
        .send(request)
        .await
        .expect("HTTP observation receiver closed");
    if is_connect {
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .expect("mock CONNECT response failed");
        let mut payload = [0_u8; 4];
        stream
            .read_exact(&mut payload)
            .await
            .expect("mock CONNECT payload read failed");
        stream
            .write_all(&payload)
            .await
            .expect("mock CONNECT payload write failed");
    } else {
        stream
            .write_all(
                b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\nConnection: close\r\n\r\nserver2-ok",
            )
            .await
            .expect("mock HTTP response failed");
    }
}

async fn spawn_mock_socks_proxy() -> (
    SocketAddr,
    oneshot::Receiver<Vec<u8>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to bind mock SOCKS5 proxy");
    let address = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("mock SOCKS accept failed");
        let mut greeting = [0_u8; 3];
        stream
            .read_exact(&mut greeting)
            .await
            .expect("mock SOCKS greeting read failed");
        assert_eq!(greeting, [5, 1, 0]);
        stream
            .write_all(&[5, 0])
            .await
            .expect("mock SOCKS greeting response failed");

        let mut head = [0_u8; 5];
        stream
            .read_exact(&mut head)
            .await
            .expect("mock SOCKS request head failed");
        assert_eq!(&head[..4], &[5, 1, 0, 3]);
        let mut tail = vec![0_u8; head[4] as usize + 2];
        stream
            .read_exact(&mut tail)
            .await
            .expect("mock SOCKS request tail failed");
        let mut request = head.to_vec();
        request.extend_from_slice(&tail);
        tx.send(request).ok();
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0x20, 0x00])
            .await
            .expect("mock SOCKS CONNECT response failed");
        let mut payload = [0_u8; 4];
        stream
            .read_exact(&mut payload)
            .await
            .expect("mock SOCKS payload read failed");
        stream
            .write_all(&payload)
            .await
            .expect("mock SOCKS payload write failed");
    });
    (address, rx, task)
}

async fn exercise_http_connect(
    local_forward: &mut Child,
    local_port: u16,
    authorization: &str,
    observed_http: &mut mpsc::Receiver<Vec<u8>>,
) {
    let mut client = connect_local(local_forward, local_port).await;
    client
        .write_all(
            format!(
                "CONNECT target-without-remote-dns.invalid:443 HTTP/1.1\r\nHost: target-without-remote-dns.invalid:443\r\nProxy-Authorization: Basic {authorization}\r\n\r\n"
            )
            .as_bytes(),
        )
        .await
        .expect("failed to send CONNECT through server2 loopback");
    let response = read_headers(&mut client).await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    client
        .write_all(b"ping")
        .await
        .expect("failed to send CONNECT payload");
    let mut echoed = [0_u8; 4];
    timeout(Duration::from_secs(10), client.read_exact(&mut echoed))
        .await
        .expect("timed out waiting for CONNECT echo")
        .expect("failed to read CONNECT echo");
    assert_eq!(&echoed, b"ping");

    let observed = recv_http_observation(observed_http).await;
    assert!(observed.starts_with("CONNECT target-without-remote-dns.invalid:443 HTTP/1.1\r\n"));
    assert!(
        !observed
            .to_ascii_lowercase()
            .contains("proxy-authorization")
    );
}

async fn exercise_socks_domain(
    local_forward: &mut Child,
    local_port: u16,
    proxy_token: &str,
    observed: oneshot::Receiver<Vec<u8>>,
) {
    let mut client = connect_local(local_forward, local_port).await;
    client
        .write_all(&[5, 1, 2])
        .await
        .expect("failed to send SOCKS greeting");
    let mut two = [0_u8; 2];
    client
        .read_exact(&mut two)
        .await
        .expect("failed to read SOCKS method selection");
    assert_eq!(two, [5, 2]);

    let mut authentication = vec![1, 2, b'a', b'p', proxy_token.len() as u8];
    authentication.extend_from_slice(proxy_token.as_bytes());
    client
        .write_all(&authentication)
        .await
        .expect("failed to send SOCKS authentication");
    client
        .read_exact(&mut two)
        .await
        .expect("failed to read SOCKS authentication response");
    assert_eq!(two, [1, 0]);

    let domain = b"only-local-proxy-resolves.invalid";
    let mut request = vec![5, 1, 0, 3, domain.len() as u8];
    request.extend_from_slice(domain);
    request.extend_from_slice(&443_u16.to_be_bytes());
    client
        .write_all(&request)
        .await
        .expect("failed to send SOCKS domain request");
    let mut response = [0_u8; 10];
    timeout(Duration::from_secs(10), client.read_exact(&mut response))
        .await
        .expect("timed out waiting for SOCKS response")
        .expect("failed to read SOCKS response");
    assert_eq!(&response[..2], &[5, 0]);
    client
        .write_all(b"echo")
        .await
        .expect("failed to send SOCKS payload");
    let mut echoed = [0_u8; 4];
    client
        .read_exact(&mut echoed)
        .await
        .expect("failed to read SOCKS echo");
    assert_eq!(&echoed, b"echo");

    let observed = timeout(Duration::from_secs(5), observed)
        .await
        .expect("mock SOCKS proxy did not receive the request")
        .expect("mock SOCKS observation channel closed");
    assert_eq!(
        observed, request,
        "SOCKS domain was not preserved byte-for-byte"
    );
}

fn spawn_local_forward(
    ssh_executable: &std::path::Path,
    host: &str,
    http_local_port: u16,
    http_remote_port: u16,
    socks_local_port: u16,
    socks_remote_port: u16,
) -> Child {
    let mut command = Command::new(ssh_executable);
    command
        .args([
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
            "-L",
            &format!("127.0.0.1:{http_local_port}:127.0.0.1:{http_remote_port}"),
            "-L",
            &format!("127.0.0.1:{socks_local_port}:127.0.0.1:{socks_remote_port}"),
            "--",
            host,
        ])
        .env("LC_ALL", "C")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .kill_on_drop(true);
    command
        .spawn()
        .expect("failed to start server2 local-forward process")
}

async fn send_http_request(local_forward: &mut Child, port: u16, request: &str) -> Vec<u8> {
    let mut client = connect_local(local_forward, port).await;
    send_http_request_on(&mut client, request).await
}

async fn send_http_request_on(client: &mut TcpStream, request: &str) -> Vec<u8> {
    try_send_http_request_on(client, request)
        .await
        .unwrap_or_else(|error| panic!("failed to read proxied HTTP response: {error}"))
}

async fn try_send_http_request_on(
    client: &mut TcpStream,
    request: &str,
) -> std::io::Result<Vec<u8>> {
    client.write_all(request.as_bytes()).await?;
    let mut response = Vec::new();
    let read = timeout(Duration::from_secs(10), client.read_to_end(&mut response))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "HTTP response timeout"))?;
    if let Err(error) = read
        && !(error.kind() == std::io::ErrorKind::ConnectionReset
            && complete_http_response(&response))
    {
        return Err(std::io::Error::new(
            error.kind(),
            format!(
                "{error}; received {} bytes before reset (complete={})",
                response.len(),
                complete_http_response(&response)
            ),
        ));
    }
    Ok(response)
}

fn complete_http_response(response: &[u8]) -> bool {
    let Some(header_end) = response.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let body_start = header_end + 4;
    let headers = String::from_utf8_lossy(&response[..body_start]).to_ascii_lowercase();
    let content_length = headers
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(0);
    response.len() >= body_start + content_length
}

async fn recv_http_observation(receiver: &mut mpsc::Receiver<Vec<u8>>) -> String {
    let observed = timeout(Duration::from_secs(5), receiver.recv())
        .await
        .expect("mock HTTP proxy did not receive the request")
        .expect("mock HTTP observation channel closed");
    String::from_utf8(observed).expect("mock HTTP request was not UTF-8")
}

async fn assert_reverse_forward_gone(local_forward: &mut Child, port: u16, authorization: &str) {
    assert!(
        local_forward
            .try_wait()
            .expect("failed to inspect local SSH")
            .is_none(),
        "independent local-forward SSH exited unexpectedly"
    );
    let mut client = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("local-forward listener disappeared unexpectedly");
    let request = format!(
        "GET http://server2-test.invalid/must-be-gone HTTP/1.1\r\nHost: server2-test.invalid\r\nProxy-Authorization: Basic {authorization}\r\nConnection: close\r\n\r\n"
    );
    if client.write_all(request.as_bytes()).await.is_err() {
        return;
    }
    let mut one = [0_u8; 1];
    match timeout(Duration::from_secs(3), client.read(&mut one)).await {
        Ok(Ok(0) | Err(_)) => {}
        Ok(Ok(_)) => panic!("remote reverse-forward listener survived SSH master shutdown"),
        Err(_) => panic!("remote reverse-forward cleanup probe did not terminate"),
    }
}

async fn read_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut byte = [0_u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        timeout(Duration::from_secs(10), stream.read_exact(&mut byte))
            .await
            .expect("mock proxy header timeout")
            .expect("mock proxy header read failed");
        bytes.push(byte[0]);
        assert!(bytes.len() <= 32 * 1024, "mock proxy header too large");
    }
    bytes
}

fn random_distinct_high_ports() -> (u16, u16) {
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

fn random_proxy_token() -> String {
    let mut random = [0_u8; 32];
    getrandom::fill(&mut random).expect("OS randomness unavailable");
    let token = URL_SAFE_NO_PAD.encode(random);
    random.fill(0);
    token
}

async fn choose_distinct_local_ports() -> (u16, u16) {
    let first = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to select first local forwarding port");
    let second = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("failed to select second local forwarding port");
    (
        first.local_addr().unwrap().port(),
        second.local_addr().unwrap().port(),
    )
}

async fn connect_local(child: &mut Child, port: u16) -> TcpStream {
    if let Some(status) = child.try_wait().expect("failed to inspect local SSH") {
        panic!("server2 local-forward SSH exited unexpectedly: {status}");
    }
    timeout(
        Duration::from_secs(5),
        TcpStream::connect(("127.0.0.1", port)),
    )
    .await
    .expect("timed out connecting to local SSH forward")
    .expect("failed to connect to local SSH forward")
}

async fn wait_for_local_forward(child: &mut Child, port: u16) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if let Some(status) = child.try_wait().expect("failed to inspect local SSH") {
            panic!("server2 local-forward SSH exited before readiness: {status}");
        }
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", port)).await {
            return stream;
        }
        assert!(
            Instant::now() < deadline,
            "timed out waiting for local SSH forward"
        );
        sleep(Duration::from_millis(100)).await;
    }
}

async fn wait_for_http_gateway(child: &mut Child, port: u16, request: &str) -> Vec<u8> {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let mut stream = wait_for_local_forward(child, port).await;
        match try_send_http_request_on(&mut stream, request).await {
            Ok(response) if complete_http_response(&response) => return response,
            Ok(_) | Err(_) if Instant::now() < deadline => {
                sleep(Duration::from_millis(100)).await;
            }
            Ok(response) => panic!(
                "local SSH forward became reachable but returned an incomplete HTTP response ({} bytes)",
                response.len()
            ),
            Err(error) => panic!("local SSH forward did not become usable: {error}"),
        }
    }
}
