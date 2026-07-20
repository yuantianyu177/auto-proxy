//! Local authenticated proxy gateways used as SSH reverse-forward targets.
//!
//! A gateway listens only on an ephemeral IPv4 loopback port.  It authenticates
//! the remote client, removes `ap`'s credentials, and talks to the user's local
//! unauthenticated proxy.

use std::{
    convert::Infallible,
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};

use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use bytes::Bytes;
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::{
    HeaderMap, Method, Request, Response, StatusCode,
    body::Incoming,
    client::conn::http1 as client_http1,
    header::{CONNECTION, HeaderName, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION},
    server::conn::http1 as server_http1,
    service::service_fn,
};
use hyper_util::rt::{TokioIo, TokioTimer};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{OwnedSemaphorePermit, Semaphore},
    task::JoinHandle,
    time::timeout,
};
use tokio_util::sync::CancellationToken;

use crate::{
    model::{ProxyMapping, ProxyProtocol},
    secrets::ProxyCredential,
};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 256;
const PROXY_CONNECTION: HeaderName = HeaderName::from_static("proxy-connection");
const KEEP_ALIVE: HeaderName = HeaderName::from_static("keep-alive");
const TRAILER: HeaderName = HeaderName::from_static("trailer");
const TRANSFER_ENCODING: HeaderName = HeaderName::from_static("transfer-encoding");
const UPGRADE: HeaderName = HeaderName::from_static("upgrade");
const TE: HeaderName = HeaderName::from_static("te");

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type HttpBody = BoxBody<Bytes, BoxError>;

#[derive(Default)]
struct ConnectionTasks(Mutex<Vec<JoinHandle<()>>>);

impl ConnectionTasks {
    fn register(&self, task: JoinHandle<()>) {
        let mut tasks = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        // Completed HTTP upstream drivers no longer own any sockets. Reap
        // their handles opportunistically so a long-lived downstream
        // keep-alive connection cannot grow this registry without bound.
        tasks.retain(|registered| !registered.is_finished());
        tasks.push(task);
    }

    fn take_all(&self) -> Vec<JoinHandle<()>> {
        std::mem::take(
            &mut *self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}

impl Drop for ConnectionTasks {
    fn drop(&mut self) {
        let tasks = self
            .0
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for task in tasks.drain(..) {
            task.abort();
        }
    }
}

/// Own a freshly spawned upstream driver until it is registered with the
/// connection-wide task set. Dropping a request future at any await point must
/// abort the driver instead of detaching it from gateway shutdown.
struct PendingConnectionTask(Option<JoinHandle<()>>);

impl PendingConnectionTask {
    fn new(task: JoinHandle<()>) -> Self {
        Self(Some(task))
    }

    fn register(mut self, tasks: &ConnectionTasks) {
        tasks.register(self.0.take().expect("pending task is present"));
    }
}

impl Drop for PendingConnectionTask {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

/// Protocol accepted by one local gateway listener.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GatewayProtocol {
    Http,
    Socks5,
    Mixed,
}

impl From<ProxyProtocol> for GatewayProtocol {
    fn from(value: ProxyProtocol) -> Self {
        match value {
            ProxyProtocol::Http => Self::Http,
            ProxyProtocol::Socks5 => Self::Socks5,
            ProxyProtocol::Mixed => Self::Mixed,
        }
    }
}

/// Secret material needed by a gateway.
///
/// Deliberately does not implement `Debug`, so accidental structured logging
/// cannot expose either value.
#[derive(Clone)]
pub struct GatewayCredential {
    username: Arc<SecretBytes>,
    password: Arc<SecretBytes>,
    http_plain: Arc<SecretBytes>,
}

struct SecretBytes(Vec<u8>);

impl SecretBytes {
    fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl GatewayCredential {
    pub fn new(username: impl AsRef<[u8]>, password: impl AsRef<[u8]>) -> Self {
        let username = Arc::new(SecretBytes(username.as_ref().to_vec()));
        let password = Arc::new(SecretBytes(password.as_ref().to_vec()));
        let mut plain =
            Vec::with_capacity(username.as_slice().len() + password.as_slice().len() + 1);
        plain.extend_from_slice(username.as_slice());
        plain.push(b':');
        plain.extend_from_slice(password.as_slice());
        Self {
            username,
            password,
            http_plain: Arc::new(SecretBytes(plain)),
        }
    }

    fn http_matches(&self, candidate: &[u8]) -> bool {
        let Some(separator) = candidate.iter().position(u8::is_ascii_whitespace) else {
            return false;
        };
        if !candidate[..separator].eq_ignore_ascii_case(b"basic") {
            return false;
        }
        let encoded = candidate[separator..].trim_ascii_start();
        if encoded.is_empty() || encoded.iter().any(u8::is_ascii_whitespace) {
            return false;
        }
        let Ok(mut decoded) = BASE64.decode(encoded) else {
            return false;
        };
        let matches = constant_time_eq(&decoded, self.http_plain.as_slice());
        decoded.fill(0);
        matches
    }

    fn socks_matches(&self, username: &[u8], password: &[u8]) -> bool {
        constant_time_eq(username, self.username.as_slice())
            & constant_time_eq(password, self.password.as_slice())
    }
}

impl fmt::Debug for GatewayCredential {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GatewayCredential([REDACTED])")
    }
}

fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    // Compare padded buffers as well as lengths.  This avoids an early byte
    // mismatch while retaining exact (not prefix) credential semantics.
    let max_len = left.len().max(right.len());
    let mut difference = (left.len() ^ right.len()) as u8;
    for index in 0..max_len {
        let a = left.get(index).copied().unwrap_or(0);
        let b = right.get(index).copied().unwrap_or(0);
        difference |= a ^ b;
    }
    let bytes_match = difference.ct_eq(&0);
    let lengths_match = (left.len() as u64).ct_eq(&(right.len() as u64));
    (bytes_match & lengths_match).into()
}

/// Immutable snapshot suitable for CLI status output.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct GatewayStatsSnapshot {
    pub active_connections: usize,
    pub total_connections: u64,
    pub bytes_to_upstream: u64,
    pub bytes_to_client: u64,
    pub authentication_failures: u64,
    pub upstream_errors: u64,
}

#[derive(Clone, Debug, Default)]
pub struct GatewayStats(Arc<GatewayStatsInner>);

#[derive(Debug, Default)]
struct GatewayStatsInner {
    active_connections: AtomicUsize,
    total_connections: AtomicU64,
    bytes_to_upstream: AtomicU64,
    bytes_to_client: AtomicU64,
    authentication_failures: AtomicU64,
    upstream_errors: AtomicU64,
}

impl GatewayStats {
    pub fn snapshot(&self) -> GatewayStatsSnapshot {
        GatewayStatsSnapshot {
            active_connections: self.0.active_connections.load(Ordering::Relaxed),
            total_connections: self.0.total_connections.load(Ordering::Relaxed),
            bytes_to_upstream: self.0.bytes_to_upstream.load(Ordering::Relaxed),
            bytes_to_client: self.0.bytes_to_client.load(Ordering::Relaxed),
            authentication_failures: self.0.authentication_failures.load(Ordering::Relaxed),
            upstream_errors: self.0.upstream_errors.load(Ordering::Relaxed),
        }
    }
}

struct ActiveConnection {
    stats: GatewayStats,
    _permit: OwnedSemaphorePermit,
}

impl ActiveConnection {
    fn new(stats: GatewayStats, permit: OwnedSemaphorePermit) -> Self {
        stats.0.total_connections.fetch_add(1, Ordering::Relaxed);
        stats.0.active_connections.fetch_add(1, Ordering::Relaxed);
        Self {
            stats,
            _permit: permit,
        }
    }
}

impl Drop for ActiveConnection {
    fn drop(&mut self) {
        self.stats
            .0
            .active_connections
            .fetch_sub(1, Ordering::Relaxed);
    }
}

/// A running listener. Dropping it aborts only the accept loop; call
/// [`RunningGateway::shutdown`] for orderly cancellation of child connections.
pub struct RunningGateway {
    pub name: String,
    pub listen_addr: SocketAddr,
    pub stats: GatewayStats,
    cancel: CancellationToken,
    task: Option<JoinHandle<()>>,
}

impl fmt::Debug for RunningGateway {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RunningGateway")
            .field("name", &self.name)
            .field("listen_addr", &self.listen_addr)
            .field("stats", &self.stats.snapshot())
            .finish_non_exhaustive()
    }
}

impl RunningGateway {
    pub fn local_port(&self) -> u16 {
        self.listen_addr.port()
    }

    pub async fn shutdown(mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}

impl Drop for RunningGateway {
    fn drop(&mut self) {
        self.cancel.cancel();
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}

/// Start one authenticated gateway on `127.0.0.1:0`.
pub async fn start_gateway(
    name: impl Into<String>,
    protocol: GatewayProtocol,
    upstream: SocketAddr,
    credential: GatewayCredential,
    parent_cancel: CancellationToken,
) -> std::io::Result<RunningGateway> {
    if !upstream.ip().is_loopback() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "upstream proxy must use a loopback address",
        ));
    }

    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)).await?;
    let listen_addr = listener.local_addr()?;
    let name = name.into();
    let stats = GatewayStats::default();
    let cancel = parent_cancel.child_token();
    let task_cancel = cancel.clone();
    let task_stats = stats.clone();
    let task = tokio::spawn(async move {
        run_accept_loop(
            listener,
            protocol,
            upstream,
            credential,
            task_stats,
            task_cancel,
        )
        .await;
    });

    Ok(RunningGateway {
        name,
        listen_addr,
        stats,
        cancel,
        task: Some(task),
    })
}

/// Start a gateway directly from persisted profile data.
pub async fn start_mapping_gateway(
    mapping: &ProxyMapping,
    credential: &ProxyCredential,
    parent_cancel: CancellationToken,
) -> std::io::Result<RunningGateway> {
    start_gateway(
        mapping.name.clone(),
        mapping.protocol.into(),
        mapping.local,
        GatewayCredential::new(credential.username(), credential.password()),
        parent_cancel,
    )
    .await
}

async fn run_accept_loop(
    listener: TcpListener,
    protocol: GatewayProtocol,
    upstream: SocketAddr,
    credential: GatewayCredential,
    stats: GatewayStats,
    cancel: CancellationToken,
) {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    let mut children = tokio::task::JoinSet::new();

    loop {
        tokio::select! {
            _ = cancel.cancelled() => break,
            accepted = listener.accept() => {
                let Ok((stream, _peer)) = accepted else { break };
                let Ok(permit) = permits.clone().try_acquire_owned() else {
                    // Refuse overload instead of queueing unauthenticated sockets.
                    drop(stream);
                    continue;
                };
                let connection = ActiveConnection::new(stats.clone(), permit);
                let credential = credential.clone();
                let child_stats = stats.clone();
                let child_cancel = cancel.child_token();
                children.spawn(async move {
                    let _active = connection;
                    handle_connection(
                        stream,
                        protocol,
                        upstream,
                        credential,
                        child_stats,
                        child_cancel,
                    )
                    .await;
                });
            }
            Some(_) = children.join_next(), if !children.is_empty() => {}
        }
    }

    cancel.cancel();
    while children.join_next().await.is_some() {}
}

async fn handle_connection(
    stream: TcpStream,
    protocol: GatewayProtocol,
    upstream: SocketAddr,
    credential: GatewayCredential,
    stats: GatewayStats,
    cancel: CancellationToken,
) {
    match protocol {
        GatewayProtocol::Http => serve_http(stream, upstream, credential, stats, cancel).await,
        GatewayProtocol::Socks5 => serve_socks(stream, upstream, credential, stats, cancel).await,
        GatewayProtocol::Mixed => {
            let mut first = [0_u8; 1];
            let detected = tokio::select! {
                _ = cancel.cancelled() => return,
                detected = timeout(HANDSHAKE_TIMEOUT, stream.peek(&mut first)) => detected,
            };
            match detected {
                Ok(Ok(1)) if first[0] == 0x05 => {
                    serve_socks(stream, upstream, credential, stats, cancel).await
                }
                Ok(Ok(1)) => serve_http(stream, upstream, credential, stats, cancel).await,
                _ => {}
            }
        }
    }
}

fn boxed_full(value: impl Into<Bytes>) -> HttpBody {
    Full::new(value.into())
        .map_err(|never: Infallible| match never {})
        .boxed()
}

fn boxed_empty() -> HttpBody {
    Empty::<Bytes>::new()
        .map_err(|never: Infallible| match never {})
        .boxed()
}

#[derive(Clone, Copy)]
enum ByteDirection {
    ToUpstream,
    ToClient,
}

fn boxed_counted_incoming(
    body: Incoming,
    stats: GatewayStats,
    direction: ByteDirection,
) -> HttpBody {
    body.map_frame(move |frame| {
        if let Some(data) = frame.data_ref() {
            let counter = match direction {
                ByteDirection::ToUpstream => &stats.0.bytes_to_upstream,
                ByteDirection::ToClient => &stats.0.bytes_to_client,
            };
            counter.fetch_add(data.len() as u64, Ordering::Relaxed);
        }
        frame
    })
    .map_err(|error| -> BoxError { Box::new(error) })
    .boxed()
}

fn simple_response(status: StatusCode, body: &'static str) -> Response<HttpBody> {
    Response::builder()
        .status(status)
        .header(CONNECTION, "close")
        .body(boxed_full(body))
        .expect("static HTTP response is valid")
}

fn authentication_required() -> Response<HttpBody> {
    Response::builder()
        .status(StatusCode::PROXY_AUTHENTICATION_REQUIRED)
        .header(PROXY_AUTHENTICATE, "Basic realm=\"ap\"")
        .header(CONNECTION, "close")
        .body(boxed_empty())
        .expect("static HTTP response is valid")
}

fn strip_hop_by_hop(headers: &mut HeaderMap) {
    let nominated = headers
        .get_all(CONNECTION)
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .filter_map(|name| HeaderName::from_bytes(name.trim().as_bytes()).ok())
        .collect::<Vec<_>>();
    for name in nominated {
        headers.remove(name);
    }
    for name in [
        CONNECTION,
        KEEP_ALIVE,
        PROXY_CONNECTION,
        PROXY_AUTHENTICATE,
        PROXY_AUTHORIZATION,
        TE,
        TRAILER,
        TRANSFER_ENCODING,
        UPGRADE,
    ] {
        headers.remove(name);
    }
}

async fn serve_http(
    stream: TcpStream,
    upstream: SocketAddr,
    credential: GatewayCredential,
    stats: GatewayStats,
    cancel: CancellationToken,
) {
    let tasks = Arc::new(ConnectionTasks::default());
    let service_tasks = Arc::clone(&tasks);
    let service = service_fn(move |request| {
        handle_http_request(
            request,
            upstream,
            credential.clone(),
            stats.clone(),
            Arc::clone(&service_tasks),
        )
    });
    let mut builder = server_http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(HANDSHAKE_TIMEOUT)
        .keep_alive(true);
    let connection = builder
        .serve_connection(TokioIo::new(stream), service)
        .with_upgrades();
    tokio::pin!(connection);
    let cancelled = tokio::select! {
        _ = cancel.cancelled() => true,
        _ = &mut connection => false,
    };
    let mut registered = tasks.take_all();
    if cancelled {
        for task in &registered {
            task.abort();
        }
    }
    while let Some(mut task) = registered.pop() {
        if cancelled {
            let _ = task.await;
            continue;
        }
        tokio::select! {
            _ = cancel.cancelled() => {
                task.abort();
                for pending in &registered {
                    pending.abort();
                }
                let _ = task.await;
                for pending in registered {
                    let _ = pending.await;
                }
                return;
            }
            _ = &mut task => {}
        }
    }
}

async fn handle_http_request(
    mut request: Request<Incoming>,
    upstream: SocketAddr,
    credential: GatewayCredential,
    stats: GatewayStats,
    tasks: Arc<ConnectionTasks>,
) -> Result<Response<HttpBody>, Infallible> {
    let supplied: Vec<_> = request
        .headers()
        .get_all(PROXY_AUTHORIZATION)
        .iter()
        .collect();
    let authenticated = supplied.len() == 1
        && supplied[0]
            .to_str()
            .ok()
            .is_some_and(|value| credential.http_matches(value.as_bytes()));
    if !authenticated {
        stats
            .0
            .authentication_failures
            .fetch_add(1, Ordering::Relaxed);
        return Ok(authentication_required());
    }

    strip_hop_by_hop(request.headers_mut());

    if request.method() == Method::CONNECT {
        if request.uri().scheme().is_some() || request.uri().authority().is_none() {
            return Ok(simple_response(
                StatusCode::BAD_REQUEST,
                "CONNECT target must use authority-form\n",
            ));
        }
        Ok(forward_http_connect(request, upstream, stats, tasks).await)
    } else {
        if request.uri().scheme().is_none() || request.uri().authority().is_none() {
            return Ok(simple_response(
                StatusCode::BAD_REQUEST,
                "proxy request target must use absolute-form\n",
            ));
        }
        Ok(forward_http_request(request, upstream, stats, tasks).await)
    }
}

async fn open_http_upstream(
    upstream: SocketAddr,
) -> std::io::Result<(
    client_http1::SendRequest<HttpBody>,
    client_http1::Connection<TokioIo<TcpStream>, HttpBody>,
)> {
    let stream = timeout(HANDSHAKE_TIMEOUT, TcpStream::connect(upstream))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "upstream timeout"))??;
    client_http1::handshake::<_, HttpBody>(TokioIo::new(stream))
        .await
        .map_err(std::io::Error::other)
}

async fn send_http_upstream_request(
    sender: &mut client_http1::SendRequest<HttpBody>,
    request: Request<HttpBody>,
    limit: Duration,
) -> std::result::Result<Response<Incoming>, ()> {
    match timeout(limit, sender.send_request(request)).await {
        Ok(Ok(response)) => Ok(response),
        Ok(Err(_)) | Err(_) => Err(()),
    }
}

async fn forward_http_request(
    request: Request<Incoming>,
    upstream: SocketAddr,
    stats: GatewayStats,
    tasks: Arc<ConnectionTasks>,
) -> Response<HttpBody> {
    // A fresh upstream connection per request makes downstream keep-alive safe:
    // every downstream request returns through the authentication path.
    let Ok((mut sender, connection)) = open_http_upstream(upstream).await else {
        stats.0.upstream_errors.fetch_add(1, Ordering::Relaxed);
        return simple_response(StatusCode::BAD_GATEWAY, "upstream proxy unavailable\n");
    };
    let connection_task = PendingConnectionTask::new(tokio::spawn(async move {
        let _ = connection.await;
    }));

    let request_stats = stats.clone();
    let request =
        request.map(|body| boxed_counted_incoming(body, request_stats, ByteDirection::ToUpstream));
    match send_http_upstream_request(&mut sender, request, HANDSHAKE_TIMEOUT).await {
        Ok(mut response) => {
            connection_task.register(&tasks);
            strip_hop_by_hop(response.headers_mut());
            response.map(|body| boxed_counted_incoming(body, stats, ByteDirection::ToClient))
        }
        Err(()) => {
            stats.0.upstream_errors.fetch_add(1, Ordering::Relaxed);
            simple_response(StatusCode::BAD_GATEWAY, "upstream proxy error\n")
        }
    }
}

async fn forward_http_connect(
    mut request: Request<Incoming>,
    upstream: SocketAddr,
    stats: GatewayStats,
    tasks: Arc<ConnectionTasks>,
) -> Response<HttpBody> {
    let downstream_upgrade = hyper::upgrade::on(&mut request);
    let Ok((mut sender, connection)) = open_http_upstream(upstream).await else {
        stats.0.upstream_errors.fetch_add(1, Ordering::Relaxed);
        return simple_response(StatusCode::BAD_GATEWAY, "upstream proxy unavailable\n");
    };
    let connection_task = PendingConnectionTask::new(tokio::spawn(async move {
        // The upstream CONNECT response transfers ownership of the underlying
        // socket through Hyper's upgrade channel. Driving the plain
        // connection future would close it as soon as the HTTP exchange ends.
        let _ = connection.with_upgrades().await;
    }));

    let (parts, _body) = request.into_parts();
    let upstream_request = Request::from_parts(parts, boxed_empty());
    let mut response =
        match send_http_upstream_request(&mut sender, upstream_request, HANDSHAKE_TIMEOUT).await {
            Ok(response) => {
                connection_task.register(&tasks);
                response
            }
            Err(()) => {
                stats.0.upstream_errors.fetch_add(1, Ordering::Relaxed);
                return simple_response(StatusCode::BAD_GATEWAY, "upstream proxy error\n");
            }
        };

    if response.status().is_success() {
        let upstream_upgrade = hyper::upgrade::on(&mut response);
        let tunnel_stats = stats.clone();
        tasks.register(tokio::spawn(async move {
            let upgraded = timeout(HANDSHAKE_TIMEOUT, async {
                tokio::try_join!(downstream_upgrade, upstream_upgrade)
            })
            .await;
            let Ok(Ok((downstream, upstream))) = upgraded else {
                tunnel_stats
                    .0
                    .upstream_errors
                    .fetch_add(1, Ordering::Relaxed);
                return;
            };
            let mut downstream = TokioIo::new(downstream);
            let mut upstream = TokioIo::new(upstream);
            match tokio::io::copy_bidirectional(&mut downstream, &mut upstream).await {
                Ok((to_upstream, to_client)) => {
                    tunnel_stats
                        .0
                        .bytes_to_upstream
                        .fetch_add(to_upstream, Ordering::Relaxed);
                    tunnel_stats
                        .0
                        .bytes_to_client
                        .fetch_add(to_client, Ordering::Relaxed);
                }
                Err(_) => {
                    tunnel_stats
                        .0
                        .upstream_errors
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }));
    }

    strip_hop_by_hop(response.headers_mut());

    response.map(|body| {
        body.map_err(|error| -> BoxError { Box::new(error) })
            .boxed()
    })
}

async fn serve_socks(
    mut client: TcpStream,
    upstream: SocketAddr,
    credential: GatewayCredential,
    stats: GatewayStats,
    cancel: CancellationToken,
) {
    let negotiation = tokio::select! {
        _ = cancel.cancelled() => return,
        negotiation = timeout(
            HANDSHAKE_TIMEOUT,
            negotiate_socks(&mut client, upstream, &credential, &stats),
        ) => negotiation,
    };
    let Ok(Ok(Some(mut upstream_stream))) = negotiation else {
        return;
    };

    let copied = tokio::select! {
        _ = cancel.cancelled() => return,
        copied = tokio::io::copy_bidirectional(&mut client, &mut upstream_stream) => copied,
    };
    match copied {
        Ok((to_upstream, to_client)) => {
            stats
                .0
                .bytes_to_upstream
                .fetch_add(to_upstream, Ordering::Relaxed);
            stats
                .0
                .bytes_to_client
                .fetch_add(to_client, Ordering::Relaxed);
        }
        Err(_) => {
            stats.0.upstream_errors.fetch_add(1, Ordering::Relaxed);
        }
    }
}

async fn negotiate_socks(
    client: &mut TcpStream,
    upstream_addr: SocketAddr,
    credential: &GatewayCredential,
    stats: &GatewayStats,
) -> std::io::Result<Option<TcpStream>> {
    let mut greeting = [0_u8; 2];
    client.read_exact(&mut greeting).await?;
    if greeting[0] != 0x05 {
        return Ok(None);
    }
    let mut methods = vec![0_u8; greeting[1] as usize];
    client.read_exact(&mut methods).await?;
    if !methods.contains(&0x02) {
        client.write_all(&[0x05, 0xff]).await?;
        return Ok(None);
    }
    client.write_all(&[0x05, 0x02]).await?;

    let mut auth_head = [0_u8; 2];
    client.read_exact(&mut auth_head).await?;
    if auth_head[0] != 0x01 || auth_head[1] == 0 {
        stats
            .0
            .authentication_failures
            .fetch_add(1, Ordering::Relaxed);
        client.write_all(&[0x01, 0x01]).await?;
        return Ok(None);
    }
    let mut username = vec![0_u8; auth_head[1] as usize];
    client.read_exact(&mut username).await?;
    let password_len = client.read_u8().await?;
    if password_len == 0 {
        stats
            .0
            .authentication_failures
            .fetch_add(1, Ordering::Relaxed);
        client.write_all(&[0x01, 0x01]).await?;
        return Ok(None);
    }
    let mut password = vec![0_u8; password_len as usize];
    client.read_exact(&mut password).await?;
    let valid = credential.socks_matches(&username, &password);
    username.fill(0);
    password.fill(0);
    if !valid {
        stats
            .0
            .authentication_failures
            .fetch_add(1, Ordering::Relaxed);
        client.write_all(&[0x01, 0x01]).await?;
        return Ok(None);
    }
    client.write_all(&[0x01, 0x00]).await?;

    let mut request_head = [0_u8; 4];
    client.read_exact(&mut request_head).await?;
    if request_head[0] != 0x05 || request_head[2] != 0x00 {
        send_socks_failure(client, 0x01).await?;
        return Ok(None);
    }
    if request_head[1] != 0x01 {
        send_socks_failure(client, 0x07).await?;
        return Ok(None);
    }

    // Retain the exact wire representation, especially domain names. DNS must
    // be performed by the user's local SOCKS proxy, never by this gateway.
    let mut target = Vec::with_capacity(260);
    target.extend_from_slice(&request_head);
    match request_head[3] {
        0x01 => read_append(client, &mut target, 4 + 2).await?,
        0x04 => read_append(client, &mut target, 16 + 2).await?,
        0x03 => {
            let length = client.read_u8().await?;
            if length == 0 {
                send_socks_failure(client, 0x08).await?;
                return Ok(None);
            }
            target.push(length);
            read_append(client, &mut target, length as usize + 2).await?;
        }
        _ => {
            send_socks_failure(client, 0x08).await?;
            return Ok(None);
        }
    }

    let mut upstream = match TcpStream::connect(upstream_addr).await {
        Ok(stream) => stream,
        Err(_) => {
            stats.0.upstream_errors.fetch_add(1, Ordering::Relaxed);
            send_socks_failure(client, 0x01).await?;
            return Ok(None);
        }
    };
    if upstream.write_all(&[0x05, 0x01, 0x00]).await.is_err() {
        return report_socks_upstream_failure(client, stats).await;
    }
    let mut upstream_method = [0_u8; 2];
    if upstream.read_exact(&mut upstream_method).await.is_err() {
        return report_socks_upstream_failure(client, stats).await;
    }
    if upstream_method != [0x05, 0x00] {
        return report_socks_upstream_failure(client, stats).await;
    }
    if upstream.write_all(&target).await.is_err() {
        return report_socks_upstream_failure(client, stats).await;
    }

    let response = match read_socks_response(&mut upstream).await {
        Ok(response) => response,
        Err(_) => return report_socks_upstream_failure(client, stats).await,
    };
    let succeeded = response.get(1) == Some(&0x00);
    client.write_all(&response).await?;
    if succeeded {
        Ok(Some(upstream))
    } else {
        Ok(None)
    }
}

async fn report_socks_upstream_failure(
    client: &mut TcpStream,
    stats: &GatewayStats,
) -> std::io::Result<Option<TcpStream>> {
    stats.0.upstream_errors.fetch_add(1, Ordering::Relaxed);
    send_socks_failure(client, 0x01).await?;
    Ok(None)
}

async fn read_append(
    stream: &mut TcpStream,
    destination: &mut Vec<u8>,
    length: usize,
) -> std::io::Result<()> {
    let old_len = destination.len();
    destination.resize(old_len + length, 0);
    stream.read_exact(&mut destination[old_len..]).await?;
    Ok(())
}

async fn read_socks_response(stream: &mut TcpStream) -> std::io::Result<Vec<u8>> {
    let mut response = vec![0_u8; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != 0x05 || response[2] != 0x00 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid SOCKS5 upstream response",
        ));
    }
    match response[3] {
        0x01 => read_append(stream, &mut response, 4 + 2).await?,
        0x04 => read_append(stream, &mut response, 16 + 2).await?,
        0x03 => {
            let length = stream.read_u8().await?;
            response.push(length);
            read_append(stream, &mut response, length as usize + 2).await?;
        }
        _ => {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid SOCKS5 upstream address type",
            ));
        }
    }
    Ok(response)
}

async fn send_socks_failure(stream: &mut TcpStream, reply: u8) -> std::io::Result<()> {
    stream
        .write_all(&[0x05, reply, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
}

#[cfg(test)]
mod unit_tests {
    use super::*;

    #[test]
    fn credential_comparisons_are_exact() {
        let credential = GatewayCredential::new("ap", "secret");
        assert!(credential.http_matches(b"Basic YXA6c2VjcmV0"));
        assert!(credential.http_matches(b"basic YXA6c2VjcmV0"));
        assert!(!credential.http_matches(b"Basic YXA6d3Jvbmc="));
        assert!(credential.socks_matches(b"ap", b"secret"));
        assert!(!credential.socks_matches(b"ap", b"secret-extra"));
    }

    #[tokio::test]
    async fn http_upstream_response_headers_have_a_deadline() {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let address = listener.local_addr().unwrap();
        let peer = tokio::spawn(async move {
            let (_stream, _) = listener.accept().await.unwrap();
            std::future::pending::<()>().await;
        });
        let stream = TcpStream::connect(address).await.unwrap();
        let (mut sender, connection) = client_http1::handshake::<_, HttpBody>(TokioIo::new(stream))
            .await
            .unwrap();
        let driver = tokio::spawn(async move {
            let _ = connection.await;
        });
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri("example.test:443")
            .body(boxed_empty())
            .unwrap();

        assert!(
            send_http_upstream_request(&mut sender, request, Duration::from_millis(25))
                .await
                .is_err()
        );
        driver.abort();
        peer.abort();
    }
}
