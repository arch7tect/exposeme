use crate::{ChallengeStore, Message, RoutingMode, ServerConfig, SslManager, SslProvider};
use base64::Engine;
use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::upgrade::Upgraded;
use hyper::{Request, Response, StatusCode, body::Incoming};
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig as RustlsConfig;
use serde_json::json;
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::sync::{RwLock, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message as WsMessage};
use tower::Service;
use tracing::{debug, error, info, warn};

pub type TunnelMap = Arc<RwLock<HashMap<String, mpsc::UnboundedSender<Message>>>>;
pub type ActiveRequests = Arc<RwLock<HashMap<String, ActiveRequest>>>;
pub type ActiveWebSockets = Arc<RwLock<HashMap<String, WebSocketConnection>>>;
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ResponseBody = BoxBody<Bytes, BoxError>;

const CHANNEL_BUFFER_SIZE: usize = 32; // Backpressure control
const SMALL_BODY_THRESHOLD: usize = 256 * 1024; // 256KB

#[derive(Debug)]
pub struct ActiveRequest {
    tunnel_id: String,
    response_tx: mpsc::Sender<ResponseEvent>, // Bounded channel
    client_disconnected: Arc<AtomicBool>,
}

#[derive(Debug)]
pub enum ResponseEvent {
    Start {
        status: u16,
        headers: HashMap<String, String>,
        initial_data: Vec<u8>,
    },
    Data(Bytes),
    End,
    Error(String),
}

async fn create_streaming_body(
    response_rx: mpsc::Receiver<ResponseEvent>,
    request_id: String,
    active_requests: ActiveRequests,
) -> ResponseBody {
    // Create a custom streaming body
    let stream_body = StreamingResponseBody::new(response_rx, request_id, active_requests);
    stream_body.boxed()
}

async fn create_streaming_body_with_initial(
    initial_data: Vec<u8>,
    response_rx: mpsc::Receiver<ResponseEvent>,
    request_id: String,
    active_requests: ActiveRequests,
) -> ResponseBody {
    // Create a custom streaming body with initial data
    let stream_body = StreamingResponseBody::new_with_initial(
        initial_data,
        response_rx,
        request_id,
        active_requests,
    );
    stream_body.boxed()
}

// Custom streaming body implementation
struct StreamingResponseBody {
    initial_data: Option<Bytes>,
    response_rx: Option<mpsc::Receiver<ResponseEvent>>,
    request_id: String,
    active_requests: ActiveRequests,
    is_complete: bool,
}

impl StreamingResponseBody {
    fn new(
        response_rx: mpsc::Receiver<ResponseEvent>,
        request_id: String,
        active_requests: ActiveRequests,
    ) -> Self {
        Self {
            initial_data: None,
            response_rx: Some(response_rx),
            request_id,
            active_requests,
            is_complete: false,
        }
    }

    fn new_with_initial(
        initial_data: Vec<u8>,
        response_rx: mpsc::Receiver<ResponseEvent>,
        request_id: String,
        active_requests: ActiveRequests,
    ) -> Self {
        Self {
            initial_data: Some(initial_data.into()),
            response_rx: Some(response_rx),
            request_id,
            active_requests,
            is_complete: false,
        }
    }
}

impl hyper::body::Body for StreamingResponseBody {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        // Return initial data first if available
        if let Some(initial) = self.initial_data.take() {
            return Poll::Ready(Some(Ok(hyper::body::Frame::data(initial))));
        }

        // If already complete, return None
        if self.is_complete {
            return Poll::Ready(None);
        }

        // Poll the receiver for more data
        if let Some(receiver) = &mut self.response_rx {
            match receiver.poll_recv(cx) {
                Poll::Ready(Some(event)) => {
                    match event {
                        ResponseEvent::Data(chunk) => {
                            Poll::Ready(Some(Ok(hyper::body::Frame::data(chunk))))
                        }
                        ResponseEvent::End => {
                            self.is_complete = true;
                            self.response_rx = None;

                            // Cleanup
                            let request_id = self.request_id.clone();
                            let active_requests = self.active_requests.clone();
                            tokio::spawn(async move {
                                active_requests.write().await.remove(&request_id);
                            });

                            Poll::Ready(None)
                        }
                        ResponseEvent::Error(e) => {
                            self.is_complete = true;
                            self.response_rx = None;

                            // Cleanup
                            let request_id = self.request_id.clone();
                            let active_requests = self.active_requests.clone();
                            tokio::spawn(async move {
                                active_requests.write().await.remove(&request_id);
                            });

                            Poll::Ready(Some(Err(e.into())))
                        }
                        _ => {
                            // Continue polling for the next event
                            cx.waker().wake_by_ref();
                            Poll::Pending
                        }
                    }
                }
                Poll::Ready(None) => {
                    // Channel closed
                    self.is_complete = true;
                    self.response_rx = None;

                    // Cleanup
                    let request_id = self.request_id.clone();
                    let active_requests = self.active_requests.clone();
                    tokio::spawn(async move {
                        active_requests.write().await.remove(&request_id);
                    });

                    Poll::Ready(None)
                }
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(None)
        }
    }
}

#[derive(Debug, Clone, Copy)]
enum BodySize {
    Empty,
    Small,   // <= 256KB
    Large,   // > 256KB
    Unknown, // No Content-Length
}

#[derive(Debug)]
pub struct WebSocketConnection {
    tunnel_id: String,
    created_at: std::time::Instant,
    // Channel to send messages to this WebSocket connection
    ws_tx: Option<mpsc::UnboundedSender<WsMessage>>,
}

impl WebSocketConnection {
    fn new(tunnel_id: String) -> Self {
        Self {
            tunnel_id,
            created_at: std::time::Instant::now(),
            ws_tx: None,
        }
    }

    fn connection_age(&self) -> Duration {
        self.created_at.elapsed()
    }

    fn age_info(&self) -> String {
        let age = self.connection_age();
        if age.as_secs() < 60 {
            format!("{}s", age.as_secs())
        } else {
            format!("{}m", age.as_secs() / 60)
        }
    }

    fn status_summary(&self) -> String {
        format!(
            "tunnel: {}, age: {}, ws: {}",
            self.tunnel_id,
            self.age_info(),
            if self.ws_tx.is_some() {
                "active"
            } else {
                "upgrading"
            }
        )
    }
}

fn analyze_request_body(req: &Request<Incoming>) -> BodySize {
    // SSE always streams
    if req
        .headers()
        .get("accept")
        .and_then(|h| h.to_str().ok())
        .map(|accept| accept.contains("text/event-stream"))
        .unwrap_or(false)
    {
        return BodySize::Unknown;
    }

    // ✨ FIX: GET, HEAD, DELETE requests are always empty body
    match req.method() {
        &hyper::Method::GET | &hyper::Method::HEAD | &hyper::Method::DELETE => {
            return BodySize::Empty;
        }
        _ => {} // Continue with content-length analysis for POST/PUT/PATCH
    }

    // Check Content-Length for POST/PUT/PATCH requests
    match req
        .headers()
        .get("content-length")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok())
    {
        Some(0) => BodySize::Empty,
        Some(len) if len <= SMALL_BODY_THRESHOLD => BodySize::Small,
        Some(_) => BodySize::Large,
        None => {
            // No content-length header
            match req.method() {
                &hyper::Method::POST | &hyper::Method::PUT | &hyper::Method::PATCH => {
                    // POST/PUT/PATCH without content-length might be chunked
                    BodySize::Unknown
                }
                _ => {
                    // Other methods without body
                    BodySize::Empty
                }
            }
        }
    }
}
#[derive(Clone)]
struct UnifiedService {
    tunnels: TunnelMap,
    active_requests: ActiveRequests,
    active_websockets: ActiveWebSockets,
    config: ServerConfig,
    challenge_store: ChallengeStore,
    ssl_manager: Arc<RwLock<SslManager>>,
    is_https: bool,
}

impl Service<Request<Incoming>> for UnifiedService {
    type Response = Response<ResponseBody>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        let tunnels = self.tunnels.clone();
        let active_requests = self.active_requests.clone();
        let active_websockets = self.active_websockets.clone();
        let config = self.config.clone();
        let challenge_store = self.challenge_store.clone();
        let ssl_manager = self.ssl_manager.clone();
        let is_https = self.is_https;

        Box::pin(async move {
            handle_unified_request(
                req,
                tunnels,
                active_requests,
                active_websockets,
                config,
                challenge_store,
                ssl_manager,
                is_https,
            )
            .await
        })
    }
}

fn is_websocket_upgrade(req: &Request<Incoming>) -> bool {
    let connection_header = req
        .headers()
        .get("connection")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let upgrade_header = req
        .headers()
        .get("upgrade")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    connection_header.to_lowercase().contains("upgrade")
        && upgrade_header.to_lowercase() == "websocket"
}

fn boxed_body(text: impl Into<Bytes>) -> BoxBody<Bytes, BoxError> {
    Full::new(text.into())
        .map_err(|e: Infallible| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
        .boxed()
}

async fn handle_unified_request(
    req: Request<Incoming>,
    tunnels: TunnelMap,
    active_requests: ActiveRequests,
    active_websockets: ActiveWebSockets,
    config: ServerConfig,
    challenge_store: ChallengeStore,
    ssl_manager: Arc<RwLock<SslManager>>,
    is_https: bool,
) -> Result<Response<ResponseBody>, BoxError> {
    let path = req.uri().path();
    let method = req.method();
    let is_websocket = is_websocket_upgrade(&req);

    info!(
        "📥 {} request: {} {} (WebSocket: {})",
        if is_https { "HTTPS" } else { "HTTP" },
        method,
        path,
        is_websocket
    );

    if path.starts_with("/.well-known/acme-challenge/") {
        info!(
            "🔍 ACME challenge via {}",
            if is_https { "HTTPS" } else { "HTTP" }
        );
        return handle_acme_challenge(req, challenge_store).await;
    }

    // Health check
    if path == "/api/health" {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("X-Served-By", if is_https { "HTTPS" } else { "HTTP" })
            .body(boxed_body("OK"))
            .unwrap());
    }

    // Certificate API
    if path.starts_with("/api/certificates/") {
        return handle_certificate_api(req, ssl_manager, config).await;
    }

    if is_websocket {
        return if path == config.server.tunnel_path {
            info!(
                "🔌 Tunnel management WebSocket via {}",
                if is_https { "HTTPS" } else { "HTTP" }
            );
            handle_tunnel_management_websocket(
                req,
                tunnels,
                active_requests,
                active_websockets,
                config,
            )
            .await
        } else {
            info!(
                "🔌 Tunneled WebSocket via {}",
                if is_https { "HTTPS" } else { "HTTP" }
            );
            handle_websocket_upgrade_request(req, tunnels, active_websockets, config).await
        };
    }

    // === HTTP/HTTPS Differentiation ===

    if is_https {
        debug!("🔒 Processing tunneled HTTP request via HTTPS");
        handle_tunnel_request(req, tunnels, active_requests, config).await
    } else {
        if config.ssl.enabled {
            debug!("🔄 Redirecting to HTTPS");
            let https_url = format!(
                "https://{}{}",
                config.server.domain,
                req.uri()
                    .path_and_query()
                    .map(|pq| pq.as_str())
                    .unwrap_or("")
            );

            Ok(Response::builder()
                .status(StatusCode::MOVED_PERMANENTLY)
                .header("Location", https_url)
                .body(boxed_body("Redirecting to HTTPS"))
                .unwrap())
        } else {
            info!("🌐 Processing tunneled HTTP request via HTTP (SSL disabled)");
            handle_tunnel_request(req, tunnels, active_requests, config).await
        }
    }
}

pub async fn start_http_server(
    config: ServerConfig,
    tunnels: TunnelMap,
    active_requests: ActiveRequests,
    active_websockets: ActiveWebSockets,
    challenge_store: ChallengeStore,
    ssl_manager: Arc<RwLock<SslManager>>,
) -> Result<(), BoxError> {
    let addr: std::net::SocketAddr = config.http_addr().parse()?;
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    info!("✅ HTTP server listening on http://{}", config.http_addr());

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        let service = UnifiedService {
            tunnels: tunnels.clone(),
            active_requests: active_requests.clone(),
            active_websockets: active_websockets.clone(),
            config: config.clone(),
            challenge_store: challenge_store.clone(),
            ssl_manager: ssl_manager.clone(),
            is_https: false,
        };

        tokio::spawn(async move {
            if let Err(err) = Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection_with_upgrades(io, TowerToHyperService::new(service))
                .await
            {
                error!("Failed to serve HTTP connection: {}", err);
            }
        });
    }
}

pub async fn start_https_server(
    config: ServerConfig,
    tunnels: TunnelMap,
    active_requests: ActiveRequests,
    active_websockets: ActiveWebSockets,
    ssl_manager: Arc<RwLock<SslManager>>,
    tls_config: Arc<RustlsConfig>,
) -> Result<(), BoxError> {
    let tls_acceptor = TlsAcceptor::from(tls_config);
    let addr: std::net::SocketAddr = config.https_addr().parse()?;
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    info!(
        "✅ HTTPS server listening on https://{}",
        config.https_addr()
    );

    loop {
        let (stream, _) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        let tunnels = tunnels.clone();
        let active_requests = active_requests.clone();
        let active_websockets = active_websockets.clone();
        let config = config.clone();
        let ssl_manager = ssl_manager.clone();

        tokio::spawn(async move {
            match tls_acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    let io = TokioIo::new(tls_stream);

                    // HTTPS server is_https = true
                    let service = UnifiedService {
                        tunnels,
                        active_requests,
                        active_websockets,
                        config: config.clone(),
                        challenge_store: Arc::new(RwLock::new(HashMap::new())),
                        ssl_manager,
                        is_https: true,
                    };

                    if let Err(e) = Builder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection_with_upgrades(io, TowerToHyperService::new(service))
                        .await
                    {
                        error!("Failed to serve HTTPS connection: {}", e);
                    }
                }
                Err(e) => {
                    error!("TLS handshake error: {}", e);
                }
            }
        });
    }
}

async fn handle_tunnel_request(
    req: Request<Incoming>,
    tunnels: TunnelMap,
    active_requests: ActiveRequests,
    config: ServerConfig,
) -> Result<Response<ResponseBody>, BoxError> {
    let (tunnel_id, forwarded_path) = match extract_tunnel_id_from_request(&req, &config) {
        Ok(result) => result,
        Err(e) => {
            warn!("Failed to extract tunnel ID: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(boxed_body(format!("Invalid request: {}", e)))
                .unwrap());
        }
    };

    let request_id = uuid::Uuid::new_v4().to_string();

    // Get tunnel sender
    let tunnel_sender = {
        let tunnels_guard = tunnels.read().await;
        tunnels_guard.get(&tunnel_id).cloned()
    };

    let tunnel_sender = match tunnel_sender {
        Some(sender) => sender,
        None => {
            warn!("Tunnel '{}' not found", tunnel_id);
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(boxed_body("Tunnel not available"))
                .unwrap());
        }
    };

    // Analyze request
    let body_size = analyze_request_body(&req);
    let method = req.method().clone();
    let headers = extract_headers(&req);

    // Create response channel with backpressure
    let (response_tx, response_rx) = mpsc::channel(CHANNEL_BUFFER_SIZE);
    let client_disconnected = Arc::new(AtomicBool::new(false));

    // Register request
    active_requests.write().await.insert(
        request_id.clone(),
        ActiveRequest {
            tunnel_id: tunnel_id.clone(),
            response_tx,
            client_disconnected: client_disconnected.clone(),
        },
    );

    // Process request body based on size
    match body_size {
        BodySize::Empty => {
            info!("🔍 Processing empty body request (id: {})", request_id);

            // Send single complete message - no DataChunk needed!
            let complete_request = Message::HttpRequestStart {
                id: request_id.clone(),
                method: method.to_string(),
                path: forwarded_path,
                headers,
                initial_data: vec![], // Empty body
                is_complete: Some(true),
            };

            if let Err(_) = tunnel_sender.send(complete_request) {
                active_requests.write().await.remove(&request_id);
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(boxed_body("Tunnel communication error"))
                    .unwrap());
            }

            info!("✅ Sent complete empty body request {}", request_id);
        }

        BodySize::Small => {
            info!("🔍 Processing small body request (id: {})", request_id);

            // Collect small body efficiently
            let body_bytes = match req.into_body().collect().await {
                Ok(collected) => collected.to_bytes(),
                Err(_) => {
                    active_requests.write().await.remove(&request_id);
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_REQUEST)
                        .body(boxed_body("Failed to read request body"))
                        .unwrap());
                }
            };

            // Send single complete message with all data - no DataChunk needed!
            let complete_request = Message::HttpRequestStart {
                id: request_id.clone(),
                method: method.to_string(),
                path: forwarded_path,
                headers,
                initial_data: body_bytes.to_vec(),
                is_complete: Some(true),
            };

            if let Err(_) = tunnel_sender.send(complete_request) {
                active_requests.write().await.remove(&request_id);
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(boxed_body("Tunnel communication error"))
                    .unwrap());
            }

            info!(
                "✅ Sent complete small body request {} ({} bytes)",
                request_id,
                body_bytes.len()
            );
        }

        BodySize::Large | BodySize::Unknown => {
            info!("🔍 Processing streaming body request (id: {})", request_id);

            // Stream from the start - use existing streaming protocol
            if let Err(_) = tunnel_sender.send(Message::HttpRequestStart {
                id: request_id.clone(),
                method: method.to_string(),
                path: forwarded_path,
                headers,
                initial_data: vec![],
                is_complete: None,
            }) {
                active_requests.write().await.remove(&request_id);
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(boxed_body("Tunnel communication error"))
                    .unwrap());
            }

            info!("✅ Sent streaming request start {}", request_id);

            // Stream body chunks (existing logic remains unchanged)
            tokio::spawn(stream_request_body(
                req.into_body(),
                request_id.clone(),
                tunnel_sender,
                client_disconnected.clone(),
            ));
        }
    }

    // Build streaming response
    build_streaming_response(request_id, response_rx, active_requests).await
}

async fn stream_request_body(
    body: Incoming,
    request_id: String,
    tunnel_sender: mpsc::UnboundedSender<Message>,
    client_disconnected: Arc<AtomicBool>,
) -> Result<(), BoxError> {
    let mut body_stream = body.into_data_stream();

    while let Some(result) = body_stream.next().await {
        if client_disconnected.load(Ordering::Relaxed) {
            break; // Client gone, stop processing
        }

        match result {
            Ok(chunk) => {
                if !chunk.is_empty() {
                    tunnel_sender.send(Message::DataChunk {
                        id: request_id.clone(),
                        data: chunk.to_vec(),
                        is_final: false,
                    })?;
                }
            }
            Err(e) => {
                error!("Body stream error: {}", e);
                break;
            }
        }
    }

    // Send final chunk
    tunnel_sender.send(Message::DataChunk {
        id: request_id,
        data: vec![],
        is_final: true,
    })?;

    Ok(())
}

async fn build_streaming_response(
    request_id: String,
    mut response_rx: mpsc::Receiver<ResponseEvent>,
    active_requests: ActiveRequests,
) -> Result<Response<ResponseBody>, BoxError> {
    // Wait for response start
    match response_rx.recv().await {
        Some(ResponseEvent::Start {
            status,
            headers,
            initial_data,
        }) => {
            // Build response
            let mut builder = Response::builder().status(status);
            for (key, value) in headers {
                builder = builder.header(key, value);
            }

            // Create response body
            if initial_data.is_empty() {
                // Create streaming body from channel
                let body =
                    create_streaming_body(response_rx, request_id.clone(), active_requests.clone())
                        .await;
                Ok(builder.body(body)?)
            } else {
                // Check if there's more data coming
                let has_more_data = !response_rx.is_closed();

                if has_more_data {
                    // Combine initial data with streaming data
                    let body = create_streaming_body_with_initial(
                        initial_data,
                        response_rx,
                        request_id.clone(),
                        active_requests.clone(),
                    )
                    .await;
                    Ok(builder.body(body)?)
                } else {
                    // Just return the initial data
                    active_requests.write().await.remove(&request_id);
                    Ok(builder.body(boxed_body(initial_data))?)
                }
            }
        }

        Some(ResponseEvent::Error(e)) => {
            active_requests.write().await.remove(&request_id);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(boxed_body(e))?)
        }

        Some(ResponseEvent::Data(_)) | Some(ResponseEvent::End) => {
            // These events should not be received when waiting for response start
            warn!(
                "Received unexpected Data/End event when waiting for response start for request {}",
                request_id
            );
            active_requests.write().await.remove(&request_id);
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(boxed_body("Protocol error: unexpected response event"))?)
        }

        None => {
            active_requests.write().await.remove(&request_id);
            Ok(Response::builder()
                .status(StatusCode::GATEWAY_TIMEOUT)
                .body(boxed_body("No response from tunnel"))?)
        }
    }
}

fn extract_headers(req: &Request<Incoming>) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    for (name, value) in req.headers() {
        headers.insert(name.to_string(), value.to_str().unwrap_or("").to_string());
    }
    headers
}

async fn handle_tunnel_management_websocket(
    req: Request<Incoming>,
    tunnels: TunnelMap,
    active_requests: ActiveRequests,
    active_websockets: ActiveWebSockets,
    config: ServerConfig,
) -> Result<Response<ResponseBody>, BoxError> {
    // This is the HTTP upgrade handler for tunnel management
    // It's called when exposeme-client connects to /tunnel-ws

    info!("🔌 Tunnel management WebSocket upgrade request");

    // Extract WebSocket key for response
    let ws_key = req
        .headers()
        .get("sec-websocket-key")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    if ws_key.is_empty() {
        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(boxed_body("Missing Sec-WebSocket-Key"))
            .unwrap());
    }

    let accept_key = calculate_websocket_accept_key(ws_key);

    // Create HTTP 101 response
    let response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Accept", accept_key)
        .body(boxed_body(""))
        .unwrap();

    // Spawn task to handle the upgraded connection
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                info!("✅ Tunnel management WebSocket upgrade successful");
                if let Err(e) = handle_tunnel_management_connection(
                    upgraded,
                    tunnels,
                    active_requests,
                    active_websockets,
                    config,
                )
                .await
                {
                    error!("❌ Tunnel management connection error: {}", e);
                }
            }
            Err(e) => {
                error!("❌ Tunnel management WebSocket upgrade failed: {}", e);
            }
        }
    });

    Ok(response)
}

async fn handle_tunnel_management_connection(
    upgraded: Upgraded,
    tunnels: TunnelMap,
    active_requests: ActiveRequests,
    active_websockets: ActiveWebSockets,
    config: ServerConfig,
) -> Result<(), BoxError> {
    // Convert upgraded connection to WebSocket
    let ws_stream = WebSocketStream::from_raw_socket(
        TokioIo::new(upgraded),
        Role::Server,
        Some(WebSocketConfig::default()),
    )
    .await;

    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    // Create channel for outgoing messages
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    // Spawn task to handle outgoing messages
    let outgoing_task = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            // Add debug logging for sent messages
            match &message {
                Message::HttpRequestStart {
                    id, method, path, ..
                } => {
                    info!(
                        "📤 Sending HttpRequestStart: {} {} (id: {})",
                        method, path, id
                    );
                }
                Message::DataChunk { id, data, is_final } => {
                    info!(
                        "📤 Sending DataChunk: {} bytes, final={} (id: {})",
                        data.len(),
                        is_final,
                        id
                    );
                }
                _ => {}
            }

            if let Ok(json) = message.to_json() {
                if let Err(e) = ws_sender.send(WsMessage::Text(json.into())).await {
                    error!("Failed to send WS message to client: {}", e);
                    break;
                }
            } else {
                error!("Failed to serialize message to JSON");
            }
        }
    });

    let mut tunnel_id: Option<String> = None;
    debug!("🔍 Server: Starting WebSocket message processing loop");
    let mut message_count = 0;

    while let Some(message) = ws_receiver.next().await {
        message_count += 1;
        debug!("🔍 Server: Received WebSocket message #{}", message_count);

        match message {
            Ok(WsMessage::Text(text)) => {
                debug!("🔍 Server: Processing text message #{} ({} chars)", message_count, text.len());

                if let Ok(msg) = Message::from_json(&text.to_string()) {
                    debug!("🔍 Server: Successfully parsed message #{}: {:?}", message_count, std::mem::discriminant(&msg));

                    match msg {
                        Message::Auth {
                            token,
                            tunnel_id: requested_tunnel_id,
                        } => {
                            info!("Auth request for tunnel '{}'", requested_tunnel_id);

                            // Validate tunnel ID
                            if let Err(e) = config.validate_tunnel_id(&requested_tunnel_id) {
                                let error_msg = Message::AuthError {
                                    error: "invalid_tunnel_id".to_string(),
                                    message: format!("Invalid tunnel ID: {}", e),
                                };
                                if let Err(err) = tx.send(error_msg) {
                                    error!("Failed to send tunnel ID validation error: {}", err);
                                    break;
                                }
                                continue;
                            }

                            // Token validation
                            if !config.auth.tokens.contains(&token) {
                                let error_msg = Message::AuthError {
                                    error: "invalid_token".to_string(),
                                    message: "Invalid authentication token".to_string(),
                                };
                                if let Err(err) = tx.send(error_msg) {
                                    error!("Failed to send auth error: {}", err);
                                    break;
                                }
                                continue;
                            }

                            // Check if tunnel_id is already taken
                            {
                                let tunnels_guard = tunnels.read().await;
                                if tunnels_guard.contains_key(&requested_tunnel_id) {
                                    let error_msg = Message::AuthError {
                                        error: "tunnel_id_taken".to_string(),
                                        message: format!(
                                            "Tunnel ID '{}' is already in use",
                                            requested_tunnel_id
                                        ),
                                    };
                                    if let Err(err) = tx.send(error_msg) {
                                        error!("Failed to send tunnel_taken error: {}", err);
                                        break;
                                    }
                                    continue;
                                }
                            }

                            // Register tunnel
                            {
                                let mut tunnels_guard = tunnels.write().await;
                                tunnels_guard.insert(requested_tunnel_id.clone(), tx.clone());
                            }

                            tunnel_id = Some(requested_tunnel_id.clone());

                            let success_msg = Message::AuthSuccess {
                                tunnel_id: requested_tunnel_id.clone(),
                                public_url: config.get_public_url(&requested_tunnel_id),
                            };

                            if let Err(err) = tx.send(success_msg) {
                                error!("Failed to send auth success: {}", err);
                                break;
                            }
                            info!("Tunnel '{}' registered successfully", requested_tunnel_id);
                        }

                        // Streaming message handlers
                        Message::HttpResponseStart {
                            id,
                            status,
                            headers,
                            initial_data,
                            is_complete,
                        } => {
                            info!(
                                "📥 Received HttpResponseStart: {} (id: {}, complete: {:?}, {} bytes)",
                                status,
                                id,
                                is_complete,
                                initial_data.len()
                            );
                            // Find the active request waiting for this response
                            if let Some(request) = active_requests.read().await.get(&id) {
                                debug!("✅ Server: Found active request for {}", id);
                                
                                if is_complete == Some(true) {
                                    // ✨ COMPLETE RESPONSE: Process immediately and finish
                                    info!("📦 Processing complete response: {} (id: {}, {} bytes)", status, id, initial_data.len());

                                    let start_event = ResponseEvent::Start {
                                        status,
                                        headers,
                                        initial_data: initial_data.clone(),
                                    };

                                    // Send start event
                                    match request.response_tx.send(start_event).await {
                                        Ok(_) => {
                                            // Immediately send end event for complete responses
                                            match request.response_tx.send(ResponseEvent::End).await {
                                                Ok(_) => {
                                                    info!("✅ Complete response sent to browser for {}", id);
                                                }
                                                Err(e) => {
                                                    error!("❌ Server: Failed to send end event for {}: {}", id, e);
                                                }
                                            }
                                        }
                                        Err(e) => {
                                            error!("❌ Server: Failed to send start event for {}: {}", id, e);
                                            request.client_disconnected.store(true, Ordering::Relaxed);
                                        }
                                    }

                                    // Clean up immediately - no DataChunks expected
                                    active_requests.write().await.remove(&id);
                                    debug!("🧹 Server: Cleaned up complete response request {}", id);

                                } else {
                                    // ✨ STREAMING RESPONSE: Expect DataChunk messages to follow
                                    info!("🔄 Processing streaming response start: {} (id: {})", status, id);

                                    let start_event = ResponseEvent::Start {
                                        status,
                                        headers,
                                        initial_data,
                                    };

                                    match request.response_tx.send(start_event).await {
                                        Ok(_) => {
                                            info!("✅ Streaming response start sent, waiting for DataChunks for {}", id);
                                            // Keep request active - DataChunks will follow
                                        }
                                        Err(e) => {
                                            error!("❌ Server: Failed to send streaming response start for {}: {}", id, e);
                                            request.client_disconnected.store(true, Ordering::Relaxed);
                                            active_requests.write().await.remove(&id);
                                        }
                                    }
                                }
                            } else {
                                error!("❌ Server: Received HttpResponseStart for unknown request: {}", id);

                                // Debug: List active requests
                                let requests = active_requests.read().await;
                                let active_ids: Vec<String> = requests.keys().cloned().collect();
                                error!("📋 Server: Active request IDs: {:?}", active_ids);
                            }
                        }

                        Message::DataChunk { id, data, is_final } => {
                            info!("📥 Received DataChunk: {} bytes, final={} (id: {})", data.len(), is_final, id);

                            // Find the active request waiting for this data
                            if let Some(request) = active_requests.read().await.get(&id) {
                                let mut should_cleanup = false;
                                let mut send_success = true;

                                // Send response body chunk if not empty
                                if !data.is_empty() {
                                    if request.response_tx.send(ResponseEvent::Data(data.into())).await.is_err() {
                                        warn!("❌ Failed to send DataChunk for streaming response {}", id);
                                        request.client_disconnected.store(true, Ordering::Relaxed);
                                        should_cleanup = true;
                                        send_success = false;
                                    }
                                }

                                // If final chunk and previous send was successful, end the streaming response
                                if is_final && send_success {
                                    if request.response_tx.send(ResponseEvent::End).await.is_ok() {
                                        info!("✅ Streaming response completed for {}", id);
                                    } else {
                                        warn!("❌ Failed to send end event for streaming response {}", id);
                                    }
                                    should_cleanup = true;
                                }

                                // Clean up if needed
                                if should_cleanup {
                                    active_requests.write().await.remove(&id);
                                    info!("🧹 Cleaned up streaming response request {}", id);
                                }
                            } else {
                                warn!("❌ Received DataChunk for unknown request: {}", id);
                                warn!("🚨 This might indicate a protocol issue - DataChunk without prior HttpResponseStart");

                                // Debug: List active requests
                                let requests = active_requests.read().await;
                                let active_ids: Vec<String> = requests.keys().cloned().collect();
                                warn!("📋 Active request IDs: {:?}", active_ids);
                            }
                        }
                        
                        Message::WebSocketUpgradeResponse {
                            connection_id,
                            status,
                            headers: _,
                        } => {
                            info!(
                                "📡 WebSocket upgrade response: {} (status: {})",
                                connection_id, status
                            );
                            // Nothing to do here as we've already upgraded incoming connection.
                        }

                        Message::WebSocketData {
                            connection_id,
                            data,
                        } => {
                            // Handle WebSocket data from tunnel client
                            if let Some(connection) =
                                active_websockets.read().await.get(&connection_id)
                            {
                                debug!(
                                    "📡 Received data for {} (age: {}, {} bytes)",
                                    connection_id,
                                    connection.age_info(),
                                    data.len()
                                );
                                if let Some(ws_tx) = &connection.ws_tx {
                                    match base64::engine::general_purpose::STANDARD.decode(&data) {
                                        Ok(binary_data) => {
                                            let ws_message = if let Ok(text) =
                                                String::from_utf8(binary_data.clone())
                                            {
                                                WsMessage::Text(text.into())
                                            } else {
                                                WsMessage::Binary(binary_data.into())
                                            };

                                            if let Err(e) = ws_tx.send(ws_message) {
                                                error!(
                                                    "Failed to forward WebSocket data to client {}: {}",
                                                    connection_id, e
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            error!(
                                                "Failed to decode WebSocket data for {}: {}",
                                                connection_id, e
                                            );
                                        }
                                    }
                                }
                            } else {
                                warn!(
                                    "Received data for unknown WebSocket connection: {}",
                                    connection_id
                                );
                            }
                        }

                        Message::WebSocketClose {
                            connection_id,
                            code,
                            reason,
                        } => {
                            // Handle WebSocket close from tunnel client
                            if let Some(connection) =
                                active_websockets.write().await.remove(&connection_id)
                            {
                                info!(
                                    "📡 Close for {}: code={:?}, reason={:?}, final_status={}",
                                    connection_id,
                                    code,
                                    reason,
                                    connection.status_summary()
                                );
                                if let Some(ws_tx) = &connection.ws_tx {
                                    let close_frame = if let Some(code) = code {
                                        Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
                                            code: code.into(),
                                            reason: reason.unwrap_or_default().into(),
                                        })
                                    } else {
                                        None
                                    };

                                    if let Err(e) = ws_tx.send(WsMessage::Close(close_frame)) {
                                        error!(
                                            "Failed to send close frame for {}: {:?}",
                                            connection_id, e
                                        );
                                    };
                                }
                                info!("✅ Cleaned up WebSocket connection {}", connection_id);
                            }
                        }

                        _ => {
                            warn!("Unexpected message type from tunnel client");
                        }
                    }
                }
            }
            Ok(WsMessage::Close(_)) => {
                info!("Tunnel management WebSocket closed");
                break;
            }
            Err(e) => {
                error!("Tunnel management WebSocket error: {}", e);
                break;
            }
            _ => {}
        }
    }

    // Clean up tunnel on disconnect
    if let Some(tunnel_id) = tunnel_id {
        shutdown_tunnel(tunnels, active_requests, active_websockets, tunnel_id).await;
    }

    outgoing_task.abort();
    Ok(())
}

async fn shutdown_tunnel(
    tunnels: TunnelMap,
    active_requests: ActiveRequests,
    active_websockets: ActiveWebSockets,
    tunnel_id: String,
) {
    {
        let mut tunnels_guard = tunnels.write().await;
        tunnels_guard.remove(&tunnel_id);
        info!(
            "ExposeME client disconnected. Tunnel '{}' removed",
            tunnel_id
        );
    }

    // Clean up active requests for this tunnel
    let requests_to_cleanup = {
        let requests = active_requests.read().await;
        requests
            .iter()
            .filter(|(_, req)| req.tunnel_id == tunnel_id)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>()
    };

    for request_id in requests_to_cleanup {
        if let Some(request) = active_requests.write().await.remove(&request_id) {
            request.client_disconnected.store(true, Ordering::Relaxed);
            let _ = request
                .response_tx
                .send(ResponseEvent::Error("Tunnel disconnected".to_string()))
                .await;
        }
    }

    let websocket_connections_to_cleanup = {
        let websockets = active_websockets.read().await;
        websockets
            .iter()
            .filter(|(_, conn)| conn.tunnel_id == tunnel_id)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>()
    };
    if !websocket_connections_to_cleanup.is_empty() {
        info!(
            "🧹 Cleaning up {} WebSocket connections",
            websocket_connections_to_cleanup.len()
        );
        for connection_id in websocket_connections_to_cleanup {
            if let Some(connection) = active_websockets.write().await.remove(&connection_id) {
                info!("🗑️  Cleaned up WebSocket connection: {}", connection_id);
                // Close the browser WebSocket connection gracefully
                if let Some(ws_tx) = &connection.ws_tx {
                    let close_msg = WsMessage::Close(Some(
                        tokio_tungstenite::tungstenite::protocol::CloseFrame {
                            code: 1001u16.into(), // Going away
                            reason: "ExposeME client disconnected".into(),
                        },
                    ));
                    if let Err(e) = ws_tx.send(close_msg) {
                        warn!("Failed to close browser WebSocket {}: {}", connection_id, e);
                    }
                }
            }
        }
    }
}

fn calculate_websocket_accept_key(ws_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(ws_key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"); // WebSocket magic string
    let hash = hasher.finalize();
    base64::engine::general_purpose::STANDARD.encode(&hash)
}

async fn handle_acme_challenge(
    req: Request<Incoming>,
    challenge_store: ChallengeStore,
) -> Result<Response<ResponseBody>, BoxError> {
    let path = req.uri().path();
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");
    info!("🔍 ACME challenge request received");
    info!("   Path: {}", path);
    info!("   Method: {}", req.method());
    info!("   User-Agent: {}", user_agent);
    info!("   Remote IP: {:?}", req.headers().get("x-forwarded-for"));

    // Extract token from path: /.well-known/acme-challenge/{token}
    if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
        info!("🔍 ACME challenge request for token: {}", token);

        // Look up challenge in store
        let store = challenge_store.read().await;
        info!(
            "📋 Available challenge tokens: {:?}",
            store.keys().collect::<Vec<_>>()
        );

        if let Some(key_auth) = store.get(token) {
            info!("✅ ACME challenge found, responding with key authorization");
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain")
                .body(boxed_body(key_auth.clone()))
                .unwrap());
        } else {
            warn!("❌ ACME challenge not found for token: {}", token);
        }
    } else {
        warn!("❌ Invalid ACME challenge path: {}", path);
    }

    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(boxed_body("ACME challenge not found"))
        .unwrap())
}

async fn handle_certificate_api(
    req: Request<Incoming>,
    ssl_manager: Arc<RwLock<SslManager>>,
    config: ServerConfig,
) -> Result<Response<ResponseBody>, BoxError> {
    let path = req.uri().path();
    let method = req.method();

    match (method, path) {
        // GET /api/certificates/status - Get certificate status
        (&hyper::Method::GET, "/api/certificates/status") => {
            let manager = ssl_manager.read().await;
            match manager.get_certificate_info() {
                Ok(cert_info) => {
                    let response = json!({
                        "domain": cert_info.domain,
                        "exists": cert_info.exists,
                        "expiry_date": cert_info.expiry_date,
                        "days_until_expiry": cert_info.days_until_expiry,
                        "needs_renewal": cert_info.needs_renewal,
                        "auto_renewal": config.ssl.provider != SslProvider::Manual,
                        "wildcard": config.ssl.wildcard,
                    });

                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/json")
                        .body(boxed_body(response.to_string()))
                        .unwrap())
                }
                Err(e) => {
                    let response =
                        json!({"error": format!("Failed to get certificate info: {}", e)});
                    Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header("Content-Type", "application/json")
                        .body(boxed_body(response.to_string()))
                        .unwrap())
                }
            }
        }

        // POST /api/certificates/renew - Force certificate renewal
        (&hyper::Method::POST, "/api/certificates/renew") => {
            info!("🔄 Manual certificate renewal requested via API");

            let mut manager = ssl_manager.write().await;
            match manager.force_renewal().await {
                Ok(_) => {
                    let response = json!({
                        "success": true,
                        "message": "Certificate renewed successfully",
                        "domain": config.server.domain
                    });

                    Ok(Response::builder()
                        .status(StatusCode::OK)
                        .header("Content-Type", "application/json")
                        .body(boxed_body(response.to_string()))
                        .unwrap())
                }
                Err(e) => {
                    let response = json!({
                        "success": false,
                        "error": format!("Certificate renewal failed: {}", e),
                        "domain": config.server.domain
                    });

                    Ok(Response::builder()
                        .status(StatusCode::INTERNAL_SERVER_ERROR)
                        .header("Content-Type", "application/json")
                        .body(boxed_body(response.to_string()))
                        .unwrap())
                }
            }
        }

        _ => {
            let response = json!({"error": "Certificate API endpoint not found"});
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("Content-Type", "application/json")
                .body(boxed_body(response.to_string()))
                .unwrap())
        }
    }
}

async fn handle_websocket_upgrade_request(
    req: Request<Incoming>,
    tunnels: TunnelMap,
    active_websockets: ActiveWebSockets,
    config: ServerConfig,
) -> Result<Response<ResponseBody>, BoxError> {
    let method = req.method().clone();

    // Extract tunnel ID and forwarded path
    let (tunnel_id, forwarded_path) = match extract_tunnel_id_from_request(&req, &config) {
        Ok(result) => result,
        Err(e) => {
            warn!("Failed to extract tunnel ID for WebSocket: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(boxed_body(format!("Invalid WebSocket request: {}", e)))
                .unwrap());
        }
    };

    info!(
        "🔌 WebSocket upgrade for tunnel '{}': {} {}",
        tunnel_id, method, forwarded_path
    );

    // Check if tunnel exists
    let tunnel_sender = tunnels.read().await.get(&tunnel_id).cloned();
    let tunnel_sender = match tunnel_sender {
        Some(sender) => sender,
        None => {
            warn!("Tunnel '{}' not found for WebSocket upgrade", tunnel_id);
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(boxed_body("Tunnel not available"))
                .unwrap());
        }
    };

    // Generate connection ID
    let connection_id = uuid::Uuid::new_v4().to_string();

    // Extract headers for forwarding
    let mut headers = HashMap::new();
    for (name, value) in req.headers() {
        headers.insert(name.to_string(), value.to_str().unwrap_or("").to_string());
    }

    info!(
        "🔌 Processing WebSocket upgrade for connection {}",
        connection_id
    );

    // Calculate WebSocket accept key
    let ws_key = req
        .headers()
        .get("sec-websocket-key")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let accept_key = calculate_websocket_accept_key(ws_key);

    // Create successful WebSocket upgrade response
    let response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Accept", accept_key)
        .body(boxed_body(""))
        .unwrap();

    // Register WebSocket connection (initially without ws_tx)
    {
        let mut websockets = active_websockets.write().await;
        websockets.insert(
            connection_id.clone(),
            WebSocketConnection::new(tunnel_id.clone()),
        );
    }

    // Send upgrade request to tunnel client
    let upgrade_message = Message::WebSocketUpgrade {
        connection_id: connection_id.clone(),
        method: method.to_string(),
        path: forwarded_path,
        headers,
    };

    if let Err(e) = tunnel_sender.send(upgrade_message) {
        error!(
            "Failed to send WebSocket upgrade to tunnel '{}': {}",
            tunnel_id, e
        );
        // Clean up connection on error
        active_websockets.write().await.remove(&connection_id);
        return Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(boxed_body("Tunnel communication error"))
            .unwrap());
    }

    // Start WebSocket proxy task
    let tunnels_clone = tunnels.clone();
    let active_websockets_clone = active_websockets.clone();
    let config_clone = config.clone();
    let connection_id_clone = connection_id.clone();

    tokio::spawn(async move {
        // Get the upgraded connection
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                // Handle upgraded connection
                if let Err(e) = handle_websocket_proxy_connection(
                    upgraded,
                    connection_id_clone,
                    tunnels_clone,
                    active_websockets_clone,
                    config_clone,
                )
                .await
                {
                    error!("WebSocket proxy error: {}", e);
                }
            }
            Err(e) => {
                error!("Failed to upgrade connection: {}", e);
            }
        }
    });

    info!("✅ WebSocket upgrade response sent for {}", connection_id);
    Ok(response)
}

// function to handle the upgraded WebSocket connection
async fn handle_websocket_proxy_connection(
    upgraded: Upgraded,
    connection_id: String,
    tunnels: TunnelMap,
    active_websockets: ActiveWebSockets,
    _config: ServerConfig,
) -> Result<(), BoxError> {
    info!(
        "🔌 Starting WebSocket proxy for connection {}",
        connection_id
    );

    // Create channels for communication with tunnel client
    let (ws_tx, mut ws_rx) = mpsc::unbounded_channel::<WsMessage>();

    // Update the stored connection with ws_tx
    {
        let mut websockets = active_websockets.write().await;
        if let Some(connection) = websockets.get_mut(&connection_id) {
            connection.ws_tx = Some(ws_tx);
        } else {
            return Err(
                format!("WebSocket proxy for connection {} not found", connection_id).into(),
            );
        }
    }

    // Convert to WebSocket
    let ws_stream = WebSocketStream::from_raw_socket(
        TokioIo::new(upgraded),
        Role::Server,
        Some(WebSocketConfig::default()),
    )
    .await;

    let (mut original_sink, mut original_stream) = ws_stream.split();

    let connection_status = {
        let websockets = active_websockets.read().await;
        websockets
            .get(&connection_id)
            .map(|conn| conn.status_summary())
            .unwrap_or_else(|| "unknown".to_string())
    };
    info!("🔌 WebSocket proxy established: {}", connection_status);

    // Forward messages FROM original client TO tunnel client
    let connection_id_clone = connection_id.clone();
    let tunnels_clone = tunnels.clone();
    let active_websockets_clone = active_websockets.clone();

    let original_to_tunnel_task = tokio::spawn(async move {
        while let Some(msg) = original_stream.next().await {
            match msg {
                Ok(WsMessage::Text(text)) => {
                    let data = base64::engine::general_purpose::STANDARD.encode(text.as_bytes());
                    let message = Message::WebSocketData {
                        connection_id: connection_id_clone.clone(),
                        data,
                    };

                    // Send to tunnel client
                    if let Err(e) = send_to_tunnel(
                        &connection_id_clone,
                        message,
                        &active_websockets_clone,
                        &tunnels_clone,
                    )
                    .await
                    {
                        error!("Failed to send WebSocket text: {}", e);
                    }
                }
                Ok(WsMessage::Binary(bytes)) => {
                    let data = base64::engine::general_purpose::STANDARD.encode(&bytes);
                    let message = Message::WebSocketData {
                        connection_id: connection_id_clone.clone(),
                        data,
                    };

                    // Send to tunnel client
                    if let Err(e) = send_to_tunnel(
                        &connection_id_clone,
                        message,
                        &active_websockets_clone,
                        &tunnels_clone,
                    )
                    .await
                    {
                        error!("Failed to send WebSocket binary: {}", e);
                    }
                }
                Ok(WsMessage::Close(close_frame)) => {
                    let (code, reason) = if let Some(frame) = close_frame {
                        (Some(frame.code.into()), Some(frame.reason.to_string()))
                    } else {
                        (None, None)
                    };

                    info!(
                        "WebSocket connection {} closed by server with code={:?}, reason={:?}",
                        connection_id_clone, code, reason
                    );

                    let message = Message::WebSocketClose {
                        connection_id: connection_id_clone.clone(),
                        code,
                        reason,
                    };

                    // Send close to tunnel client
                    if let Err(e) = send_to_tunnel(
                        &connection_id_clone,
                        message,
                        &active_websockets_clone,
                        &tunnels_clone,
                    )
                    .await
                    {
                        error!("Failed to send close message: {}", e);
                    }
                    break;
                }
                Err(e) => {
                    error!(
                        "Original WebSocket error for {}: {}",
                        connection_id_clone, e
                    );
                    break;
                }
                _ => {} // Handle Ping/Pong
            }
        }

        info!(
            "🔌 Original-to-tunnel task ended for {}",
            connection_id_clone
        );
    });

    // Forward messages FROM tunnel client TO original client
    let connection_id_clone = connection_id.clone();
    let tunnel_to_original_task = tokio::spawn(async move {
        while let Some(ws_message) = ws_rx.recv().await {
            if original_sink.send(ws_message).await.is_err() {
                error!(
                    "Failed to send to original WebSocket client for {}",
                    connection_id_clone
                );
                break;
            }
        }

        info!(
            "🔌 Tunnel-to-original task ended for {}",
            connection_id_clone
        );
    });

    // Wait for either task to complete
    tokio::select! {
        _ = original_to_tunnel_task => {
            info!("Original client disconnected for {}", connection_id);
        }
        _ = tunnel_to_original_task => {
            info!("Tunnel client disconnected for {}", connection_id);
        }
    }

    // Final cleanup
    {
        let mut websockets = active_websockets.write().await;
        websockets.remove(&connection_id);
    }

    info!(
        "🔌 WebSocket proxy connection {} fully closed",
        connection_id
    );
    Ok(())
}

async fn send_to_tunnel(
    connection_id: &str,
    message: Message,
    active_websockets: &ActiveWebSockets,
    tunnels: &TunnelMap,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Get tunnel_id from connection
    let tunnel_id = {
        let websockets = active_websockets.read().await;
        websockets
            .get(connection_id)
            .map(|conn| conn.tunnel_id.clone())
            .ok_or("Connection not found")?
    };

    // Send to correct tunnel
    {
        let tunnels_guard = tunnels.read().await;
        let tunnel_sender = tunnels_guard.get(&tunnel_id).ok_or("Tunnel not found")?;
        tunnel_sender
            .send(message)
            .map_err(|e| format!("Failed to send: {}", e))?;
    }

    Ok(())
}

fn extract_tunnel_id_from_request(
    req: &Request<Incoming>,
    config: &ServerConfig,
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    let query = req
        .uri()
        .query()
        .map_or(String::new(), |q| format!("?{}", q));
    let path = req.uri().path();

    // tunnel-id.domain.com/path
    if matches!(
        config.server.routing_mode,
        RoutingMode::Subdomain | RoutingMode::Both
    ) {
        let base_domain = &config.server.domain;
        let host = req
            .headers()
            .get("host")
            .and_then(|h| h.to_str().ok())
            .ok_or("Missing Host header")?;
        let host_without_port = host.split(':').next().unwrap_or(host);

        if host_without_port != base_domain {
            if let Some(subdomain) = host_without_port.strip_suffix(&format!(".{}", base_domain)) {
                let tunnel_id = subdomain.to_string();
                let forwarded_path = format!("{}{}", path, query);
                return Ok((tunnel_id, forwarded_path));
            }
        }
        if let RoutingMode::Subdomain = config.server.routing_mode {
            return Err("Invalid subdomain format".into());
        }
    }

    // domain.com/tunnel-id/path
    let path_parts: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    if path_parts.is_empty() {
        return Err("Tunnel ID required in path or subdomain".into());
    }

    let tunnel_id = path_parts[0].to_string();
    let forwarded_path = if path_parts.len() > 1 {
        format!("/{}{}", path_parts[1..].join("/"), query)
    } else {
        format!("/{}", query)
    };

    Ok((tunnel_id, forwarded_path))
}
