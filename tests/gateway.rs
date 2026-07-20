use std::{net::SocketAddr, time::Duration};

use auto_proxy::gateway::{GatewayCredential, GatewayProtocol, start_gateway};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::oneshot,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

async fn read_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    let mut one = [0_u8; 1];
    while !bytes.ends_with(b"\r\n\r\n") {
        timeout(Duration::from_secs(2), stream.read_exact(&mut one))
            .await
            .expect("header timeout")
            .expect("read header");
        bytes.push(one[0]);
        assert!(bytes.len() < 32 * 1024, "header too large");
    }
    bytes
}

async fn read_http_response(stream: &mut TcpStream) -> (Vec<u8>, Vec<u8>) {
    let headers = read_headers(stream).await;
    let text = String::from_utf8_lossy(&headers).to_ascii_lowercase();
    let content_length = text
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .map(str::trim)
        .map(|value| value.parse::<usize>().unwrap())
        .unwrap_or(0);
    let mut body = vec![0_u8; content_length];
    stream.read_exact(&mut body).await.unwrap();
    (headers, body)
}

async fn mock_http_response() -> (SocketAddr, oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = read_headers(&mut stream).await;
        let content_length = String::from_utf8_lossy(&request)
            .to_ascii_lowercase()
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .map(str::trim)
            .map(|value| value.parse::<usize>().unwrap())
            .unwrap_or(0);
        let old_len = request.len();
        request.resize(old_len + content_length, 0);
        stream.read_exact(&mut request[old_len..]).await.unwrap();
        tx.send(request).ok();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK")
            .await
            .unwrap();
    });
    (address, rx)
}

fn auth_value() -> String {
    format!("Basic {}", BASE64.encode("ap:correct horse"))
}

#[tokio::test]
async fn http_requires_basic_and_strips_gateway_headers() {
    let (upstream, observed) = mock_http_response().await;
    let cancel = CancellationToken::new();
    let gateway = start_gateway(
        "web",
        GatewayProtocol::Http,
        upstream,
        GatewayCredential::new("ap", "correct horse"),
        cancel,
    )
    .await
    .unwrap();

    let mut client = TcpStream::connect(gateway.listen_addr).await.unwrap();
    client
        .write_all(
            format!(
                "POST http://example.invalid/a HTTP/1.1\r\nHost: example.invalid\r\nContent-Length: 4\r\nProxy-Authorization: {}\r\nProxy-Connection: keep-alive\r\nConnection: x-private, close\r\nX-Private: must-strip\r\n\r\nDATA",
                auth_value()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = Vec::new();
    timeout(Duration::from_secs(2), client.read_to_end(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200"));
    assert!(response.ends_with(b"OK"));

    let request = String::from_utf8(observed.await.unwrap()).unwrap();
    assert!(request.starts_with("POST http://example.invalid/a HTTP/1.1\r\n"));
    assert!(request.ends_with("\r\n\r\nDATA"));
    assert!(!request.to_ascii_lowercase().contains("proxy-authorization"));
    assert!(!request.to_ascii_lowercase().contains("proxy-connection"));
    assert!(!request.to_ascii_lowercase().contains("x-private"));
    let snapshot = gateway.stats.snapshot();
    assert_eq!(snapshot.bytes_to_upstream, 4);
    assert_eq!(snapshot.bytes_to_client, 2);
    gateway.shutdown().await;
}

#[tokio::test]
async fn http_rejects_missing_or_wrong_credentials_without_contacting_upstream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway = start_gateway(
        "web",
        GatewayProtocol::Http,
        listener.local_addr().unwrap(),
        GatewayCredential::new("ap", "secret"),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let mut client = TcpStream::connect(gateway.listen_addr).await.unwrap();
    client
        .write_all(b"GET http://example.invalid/ HTTP/1.1\r\nHost: example.invalid\r\n\r\n")
        .await
        .unwrap();
    let response = read_headers(&mut client).await;
    assert!(response.starts_with(b"HTTP/1.1 407"));
    assert!(
        String::from_utf8(response)
            .unwrap()
            .to_ascii_lowercase()
            .contains("proxy-authenticate: basic")
    );
    assert!(
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    assert_eq!(gateway.stats.snapshot().authentication_failures, 1);
    gateway.shutdown().await;
}

#[tokio::test]
async fn http_keep_alive_reauthenticates_every_request() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let (request_tx, request_rx) = oneshot::channel();
    let (second_tx, second_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        request_tx.send(read_headers(&mut stream).await).ok();
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
            .await
            .unwrap();
        // A second upstream connection would prove that authentication was
        // incorrectly remembered for the downstream keep-alive connection.
        second_tx
            .send(
                timeout(Duration::from_millis(300), listener.accept())
                    .await
                    .is_ok(),
            )
            .ok();
    });
    let gateway = start_gateway(
        "web",
        GatewayProtocol::Http,
        upstream,
        GatewayCredential::new("ap", "correct horse"),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let mut client = TcpStream::connect(gateway.listen_addr).await.unwrap();
    client
        .write_all(
            format!(
                "GET http://one.invalid/ HTTP/1.1\r\nHost: one.invalid\r\nProxy-Authorization: {}\r\n\r\n",
                auth_value()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let (first_headers, first_body) = read_http_response(&mut client).await;
    assert!(first_headers.starts_with(b"HTTP/1.1 200"));
    assert_eq!(first_body, b"OK");

    client
        .write_all(
            b"GET http://two.invalid/ HTTP/1.1\r\nHost: two.invalid\r\nConnection: close\r\n\r\n",
        )
        .await
        .unwrap();
    let (second_headers, _) = read_http_response(&mut client).await;
    assert!(second_headers.starts_with(b"HTTP/1.1 407"));
    assert_eq!(gateway.stats.snapshot().authentication_failures, 1);
    let first_request = String::from_utf8(request_rx.await.unwrap()).unwrap();
    assert!(first_request.starts_with("GET http://one.invalid/"));
    assert!(!second_rx.await.unwrap(), "second request reached upstream");
    gateway.shutdown().await;
}

#[tokio::test]
async fn http_rejects_origin_form_before_contacting_upstream() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway = start_gateway(
        "web",
        GatewayProtocol::Http,
        listener.local_addr().unwrap(),
        GatewayCredential::new("ap", "correct horse"),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let mut client = TcpStream::connect(gateway.listen_addr).await.unwrap();
    client
        .write_all(
            format!(
                "GET /origin-form HTTP/1.1\r\nHost: example.invalid\r\nProxy-Authorization: {}\r\n\r\n",
                auth_value()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let (headers, _) = read_http_response(&mut client).await;
    assert!(headers.starts_with(b"HTTP/1.1 400"));
    assert!(
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
    gateway.shutdown().await;
}

#[tokio::test]
async fn http_connect_establishes_a_bidirectional_tunnel() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let (headers_tx, headers_rx) = oneshot::channel();
    let (release_tx, release_rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let headers = read_headers(&mut stream).await;
        headers_tx.send(headers).ok();
        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await
            .unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).await.unwrap();
        stream.write_all(&payload).await.unwrap();
        let _ = release_rx.await;
    });

    let gateway = start_gateway(
        "web",
        GatewayProtocol::Http,
        upstream,
        GatewayCredential::new("ap", "correct horse"),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let mut client = TcpStream::connect(gateway.listen_addr).await.unwrap();
    client
        .write_all(
            format!(
                "CONNECT target.invalid:443 HTTP/1.1\r\nHost: target.invalid:443\r\nProxy-Authorization: {}\r\n\r\n",
                auth_value()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let response = read_headers(&mut client).await;
    assert!(response.starts_with(b"HTTP/1.1 200"));
    client.write_all(b"ping").await.unwrap();
    let mut echo = [0_u8; 4];
    timeout(Duration::from_secs(2), client.read_exact(&mut echo))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echo, b"ping");

    let headers = String::from_utf8(headers_rx.await.unwrap()).unwrap();
    assert!(headers.starts_with("CONNECT target.invalid:443 HTTP/1.1"));
    assert!(!headers.to_ascii_lowercase().contains("proxy-authorization"));
    assert_eq!(gateway.stats.snapshot().active_connections, 1);
    gateway.shutdown().await;
    let mut after_shutdown = [0_u8; 1];
    let closed = timeout(Duration::from_secs(2), client.read(&mut after_shutdown))
        .await
        .expect("gateway shutdown left CONNECT alive");
    assert!(
        matches!(closed, Ok(0) | Err(_)),
        "CONNECT remained readable after shutdown"
    );
    let _ = release_tx.send(());
}

async fn spawn_mock_socks() -> (SocketAddr, oneshot::Receiver<Vec<u8>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = oneshot::channel();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut greeting = [0_u8; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0]).await.unwrap();

        let mut head = [0_u8; 4];
        stream.read_exact(&mut head).await.unwrap();
        assert_eq!(&head[..3], &[5, 1, 0]);
        let mut request = head.to_vec();
        match head[3] {
            1 => {
                let mut tail = [0_u8; 6];
                stream.read_exact(&mut tail).await.unwrap();
                request.extend_from_slice(&tail);
            }
            4 => {
                let mut tail = [0_u8; 18];
                stream.read_exact(&mut tail).await.unwrap();
                request.extend_from_slice(&tail);
            }
            3 => {
                let length = stream.read_u8().await.unwrap();
                request.push(length);
                let mut tail = vec![0_u8; length as usize + 2];
                stream.read_exact(&mut tail).await.unwrap();
                request.extend_from_slice(&tail);
            }
            other => panic!("unexpected SOCKS address type {other}"),
        }
        tx.send(request).ok();
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0x20, 0x00])
            .await
            .unwrap();
        let mut payload = [0_u8; 4];
        stream.read_exact(&mut payload).await.unwrap();
        stream.write_all(&payload).await.unwrap();
    });
    (address, rx)
}

async fn socks_domain_round_trip(protocol: GatewayProtocol) {
    let (upstream, observed) = spawn_mock_socks().await;
    let gateway = start_gateway(
        "socks",
        protocol,
        upstream,
        GatewayCredential::new("ap", "secret"),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let mut client = TcpStream::connect(gateway.listen_addr).await.unwrap();

    // Fragment every handshake byte to exercise state-machine boundaries.
    for byte in [5_u8, 2, 0, 2] {
        client.write_all(&[byte]).await.unwrap();
    }
    let mut selection = [0_u8; 2];
    client.read_exact(&mut selection).await.unwrap();
    assert_eq!(selection, [5, 2]);
    for byte in [1_u8, 2, b'a', b'p', 6, b's', b'e', b'c', b'r', b'e', b't'] {
        client.write_all(&[byte]).await.unwrap();
    }
    let mut auth = [0_u8; 2];
    client.read_exact(&mut auth).await.unwrap();
    assert_eq!(auth, [1, 0]);

    let domain = b"not-in-remote-dns.invalid";
    let mut request = vec![5, 1, 0, 3, domain.len() as u8];
    request.extend_from_slice(domain);
    request.extend_from_slice(&443_u16.to_be_bytes());
    for byte in &request {
        client.write_all(&[*byte]).await.unwrap();
    }
    let mut response = [0_u8; 10];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response[..2], &[5, 0]);
    client.write_all(b"echo").await.unwrap();
    let mut echo = [0_u8; 4];
    client.read_exact(&mut echo).await.unwrap();
    assert_eq!(&echo, b"echo");

    assert_eq!(observed.await.unwrap(), request);
    gateway.shutdown().await;
}

#[tokio::test]
async fn socks5_authenticates_and_preserves_domain_for_local_resolution() {
    socks_domain_round_trip(GatewayProtocol::Socks5).await;
}

#[tokio::test]
async fn mixed_recognizes_socks5_from_the_first_byte() {
    socks_domain_round_trip(GatewayProtocol::Mixed).await;
}

#[tokio::test]
async fn socks5_preserves_ipv4_and_ipv6_targets() {
    let targets = [vec![5, 1, 0, 1, 192, 0, 2, 25, 0x01, 0xbb], {
        let mut request = vec![5, 1, 0, 4];
        request.extend_from_slice(&[0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        request.extend_from_slice(&443_u16.to_be_bytes());
        request
    }];

    for request in targets {
        let (upstream, observed) = spawn_mock_socks().await;
        let gateway = start_gateway(
            "socks-address",
            GatewayProtocol::Socks5,
            upstream,
            GatewayCredential::new("ap", "secret"),
            CancellationToken::new(),
        )
        .await
        .unwrap();
        let mut client = TcpStream::connect(gateway.listen_addr).await.unwrap();
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut response = [0_u8; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [5, 2]);
        client
            .write_all(&[1, 2, b'a', b'p', 6, b's', b'e', b'c', b'r', b'e', b't'])
            .await
            .unwrap();
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [1, 0]);
        client.write_all(&request).await.unwrap();
        let mut connect_response = [0_u8; 10];
        client.read_exact(&mut connect_response).await.unwrap();
        assert_eq!(&connect_response[..2], &[5, 0]);
        client.write_all(b"echo").await.unwrap();
        let mut echo = [0_u8; 4];
        client.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"echo");
        assert_eq!(observed.await.unwrap(), request);
        gateway.shutdown().await;
    }
}

#[tokio::test]
async fn socks5_rejects_bad_password_and_unsupported_command() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let gateway = start_gateway(
        "socks",
        GatewayProtocol::Socks5,
        listener.local_addr().unwrap(),
        GatewayCredential::new("ap", "secret"),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let mut client = TcpStream::connect(gateway.listen_addr).await.unwrap();
    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut response = [0_u8; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [5, 2]);
    client
        .write_all(&[1, 2, b'a', b'p', 5, b'w', b'r', b'o', b'n', b'g'])
        .await
        .unwrap();
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [1, 1]);
    assert_eq!(gateway.stats.snapshot().authentication_failures, 1);
    assert!(
        timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );

    let mut client = TcpStream::connect(gateway.listen_addr).await.unwrap();
    client.write_all(&[5, 1, 2]).await.unwrap();
    client.read_exact(&mut response).await.unwrap();
    client
        .write_all(&[1, 2, b'a', b'p', 6, b's', b'e', b'c', b'r', b'e', b't'])
        .await
        .unwrap();
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [1, 0]);
    // BIND (command 2) must be rejected without involving the upstream proxy.
    client
        .write_all(&[5, 2, 0, 1, 127, 0, 0, 1, 0, 80])
        .await
        .unwrap();
    let mut command_response = [0_u8; 10];
    client.read_exact(&mut command_response).await.unwrap();
    assert_eq!(command_response[1], 7);

    let mut client = TcpStream::connect(gateway.listen_addr).await.unwrap();
    client.write_all(&[5, 1, 2]).await.unwrap();
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [5, 2]);
    client
        .write_all(&[1, 2, b'a', b'p', 6, b's', b'e', b'c', b'r', b'e', b't'])
        .await
        .unwrap();
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [1, 0]);
    // UDP ASSOCIATE (command 3) is outside the v1 feature set as well.
    client
        .write_all(&[5, 3, 0, 1, 127, 0, 0, 1, 0, 53])
        .await
        .unwrap();
    client.read_exact(&mut command_response).await.unwrap();
    assert_eq!(command_response[1], 7);
    gateway.shutdown().await;
}

#[tokio::test]
async fn socks5_turns_malformed_upstream_replies_into_general_failure() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream_addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut greeting = [0_u8; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0]).await.unwrap();

        let mut request = [0_u8; 10];
        stream.read_exact(&mut request).await.unwrap();
        assert_eq!(&request[..4], &[5, 1, 0, 1]);
        // Invalid VER: the gateway must not expose an EOF/protocol fragment to
        // the remote client after RFC 1929 authentication has succeeded.
        stream
            .write_all(&[4, 0, 0, 1, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
    });

    let gateway = start_gateway(
        "socks",
        GatewayProtocol::Socks5,
        upstream_addr,
        GatewayCredential::new("ap", "secret"),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let mut client = TcpStream::connect(gateway.listen_addr).await.unwrap();
    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut response = [0_u8; 2];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [5, 2]);
    client
        .write_all(&[1, 2, b'a', b'p', 6, b's', b'e', b'c', b'r', b'e', b't'])
        .await
        .unwrap();
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [1, 0]);
    client
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 80])
        .await
        .unwrap();
    let mut failure = [0_u8; 10];
    client.read_exact(&mut failure).await.unwrap();
    assert_eq!(failure, [5, 1, 0, 1, 0, 0, 0, 0, 0, 0]);
    assert_eq!(gateway.stats.snapshot().upstream_errors, 1);
    gateway.shutdown().await;
}

#[tokio::test]
async fn http_handles_at_least_32_concurrent_connections() {
    const CONNECTIONS: usize = 32;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let mut handlers = Vec::with_capacity(CONNECTIONS);
        for _ in 0..CONNECTIONS {
            let (mut stream, _) = listener.accept().await.unwrap();
            handlers.push(tokio::spawn(async move {
                let _ = read_headers(&mut stream).await;
                stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK",
                    )
                    .await
                    .unwrap();
            }));
        }
        for handler in handlers {
            handler.await.unwrap();
        }
    });
    let gateway = start_gateway(
        "web",
        GatewayProtocol::Http,
        upstream,
        GatewayCredential::new("ap", "correct horse"),
        CancellationToken::new(),
    )
    .await
    .unwrap();

    let mut clients = Vec::with_capacity(CONNECTIONS);
    for sequence in 0..CONNECTIONS {
        let address = gateway.listen_addr;
        clients.push(tokio::spawn(async move {
            let mut client = TcpStream::connect(address).await.unwrap();
            client
                .write_all(
                    format!(
                        "GET http://parallel.invalid/{sequence} HTTP/1.1\r\nHost: parallel.invalid\r\nProxy-Authorization: {}\r\nConnection: close\r\n\r\n",
                        auth_value()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            let mut response = Vec::new();
            client.read_to_end(&mut response).await.unwrap();
            assert!(response.starts_with(b"HTTP/1.1 200"));
            assert!(response.ends_with(b"OK"));
        }));
    }
    for client in clients {
        client.await.unwrap();
    }
    upstream_task.await.unwrap();
    assert_eq!(
        gateway.stats.snapshot().total_connections,
        CONNECTIONS as u64
    );
    assert_eq!(gateway.stats.snapshot().upstream_errors, 0);
    gateway.shutdown().await;
}

#[tokio::test]
async fn socks5_preserves_large_streams_and_half_close() {
    const PAYLOAD_SIZE: usize = 2 * 1024 * 1024;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut greeting = [0_u8; 3];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [5, 1, 0]);
        stream.write_all(&[5, 0]).await.unwrap();
        let mut request = [0_u8; 10];
        stream.read_exact(&mut request).await.unwrap();
        stream
            .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 1])
            .await
            .unwrap();
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload.len(), PAYLOAD_SIZE);
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();
    });

    let gateway = start_gateway(
        "socks",
        GatewayProtocol::Socks5,
        upstream,
        GatewayCredential::new("ap", "secret"),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let mut client = TcpStream::connect(gateway.listen_addr).await.unwrap();
    client.write_all(&[5, 1, 2]).await.unwrap();
    let mut two = [0_u8; 2];
    client.read_exact(&mut two).await.unwrap();
    assert_eq!(two, [5, 2]);
    client
        .write_all(&[1, 2, b'a', b'p', 6, b's', b'e', b'c', b'r', b'e', b't'])
        .await
        .unwrap();
    client.read_exact(&mut two).await.unwrap();
    assert_eq!(two, [1, 0]);
    client
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, 0, 1])
        .await
        .unwrap();
    let mut response = [0_u8; 10];
    client.read_exact(&mut response).await.unwrap();
    assert_eq!(&response[..2], &[5, 0]);

    let payload = (0..PAYLOAD_SIZE)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    client.write_all(&payload).await.unwrap();
    client.shutdown().await.unwrap();
    let mut echoed = Vec::new();
    timeout(Duration::from_secs(10), client.read_to_end(&mut echoed))
        .await
        .expect("large SOCKS half-close timed out")
        .unwrap();
    assert_eq!(echoed, payload);
    upstream_task.await.unwrap();
    gateway.shutdown().await;
}

#[tokio::test]
async fn http_shutdown_aborts_an_unregistered_hung_upstream_driver() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let upstream = listener.local_addr().unwrap();
    let (request_seen_tx, request_seen_rx) = oneshot::channel();
    let upstream_task = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_headers(&mut stream).await;
        request_seen_tx.send(()).unwrap();
        let mut tail = Vec::new();
        timeout(Duration::from_secs(2), stream.read_to_end(&mut tail))
            .await
            .expect("gateway shutdown left the upstream driver detached")
            .unwrap();
        request
    });

    let gateway = start_gateway(
        "hung-http",
        GatewayProtocol::Http,
        upstream,
        GatewayCredential::new("ap", "correct horse"),
        CancellationToken::new(),
    )
    .await
    .unwrap();
    let mut client = TcpStream::connect(gateway.listen_addr).await.unwrap();
    client
        .write_all(
            format!(
                "CONNECT stalled.invalid:443 HTTP/1.1\r\nHost: stalled.invalid:443\r\nProxy-Authorization: {}\r\n\r\n",
                auth_value()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    timeout(Duration::from_secs(2), request_seen_rx)
        .await
        .expect("gateway never contacted the hung upstream")
        .unwrap();

    timeout(Duration::from_secs(2), gateway.shutdown())
        .await
        .expect("gateway shutdown waited for the upstream handshake deadline");
    let request = upstream_task.await.unwrap();
    assert!(request.starts_with(b"CONNECT stalled.invalid:443 HTTP/1.1\r\n"));
}
