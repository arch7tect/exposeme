use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use tokio::sync::{mpsc, RwLock};
use crate::{ChallengeStore, Message, RoutingMode, ServerConfig, SslManager, SslProvider};
use tokio_tungstenite::{tungstenite::Message as WsMessage, WebSocketStream};
use tower::Service;
use hyper::{body::Incoming, Request, Response, StatusCode};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use tokio_rustls::TlsAcceptor;
use rustls::ServerConfig as RustlsConfig;
use serde_json::json;
use tracing::{debug, error, info, warn};
use sha1::{Digest, Sha1};
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};

pub type TunnelMap = Arc<RwLock<HashMap<String, mpsc::UnboundedSender<Message>>>>;
pub type PendingRequests = Arc<RwLock<HashMap<String, mpsc::UnboundedSender<(u16, HashMap<String, String>, String)>>>>;
pub type ActiveWebSockets = Arc<RwLock<HashMap<String, WebSocketConnection>>>;
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ResponseBody = BoxBody<bytes::Bytes, BoxError>;

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
            if self.ws_tx.is_some() { "active" } else { "upgrading" }
        )
    }
}

#[derive(Clone)]
struct UnifiedService {
    tunnels: TunnelMap,
    pending_requests: PendingRequests,
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
        let pending_requests = self.pending_requests.clone();
        let active_websockets = self.active_websockets.clone();
        let config = self.config.clone();
        let challenge_store = self.challenge_store.clone();
        let ssl_manager = self.ssl_manager.clone();
        let is_https = self.is_https;

        Box::pin(async move {
            handle_unified_request(
                req,
                tunnels,
                pending_requests,
                active_websockets,
                config,
                challenge_store,
                ssl_manager,
                is_https,
            ).await
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

fn boxed_body(
    text: impl Into<bytes::Bytes>,
) -> BoxBody<bytes::Bytes, Box<dyn std::error::Error + Send + Sync>> {
    Full::new(text.into())
        .map_err(|e: Infallible| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
        .boxed()
}

async fn handle_unified_request(
    req: Request<Incoming>,
    tunnels: TunnelMap,
    pending_requests: PendingRequests,
    active_websockets: ActiveWebSockets,
    config: ServerConfig,
    challenge_store: ChallengeStore,
    ssl_manager: Arc<RwLock<SslManager>>,
    is_https: bool,
) -> Result<Response<ResponseBody>, BoxError> {
    let path = req.uri().path();
    let method = req.method();
    let is_websocket = is_websocket_upgrade(&req);

    info!("📥 {} request: {} {} (WebSocket: {})",
          if is_https { "HTTPS" } else { "HTTP" }, method, path, is_websocket);

    if path.starts_with("/.well-known/acme-challenge/") {
        info!("🔍 ACME challenge via {}", if is_https { "HTTPS" } else { "HTTP" });
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
            info!("🔌 Tunnel management WebSocket via {}", if is_https { "HTTPS" } else { "HTTP" });
            handle_tunnel_management_websocket(
                req, tunnels, pending_requests, active_websockets, config
            ).await
        } else {
            info!("🔌 Tunneled WebSocket via {}", if is_https { "HTTPS" } else { "HTTP" });
            handle_websocket_upgrade_request(
                req, tunnels, active_websockets, config
            ).await
        }
    }

    // === HTTP/HTTPS Differentiation ===

    if is_https {
        info!("🔒 Processing tunneled HTTP request via HTTPS");
        handle_tunnel_request(req, tunnels, pending_requests, config).await
    } else {
        if config.ssl.enabled {
            info!("🔄 Redirecting to HTTPS");
            let https_url = format!(
                "https://{}{}",
                config.server.domain,
                req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("")
            );

            Ok(Response::builder()
                .status(StatusCode::MOVED_PERMANENTLY)
                .header("Location", https_url)
                .body(boxed_body("Redirecting to HTTPS"))
                .unwrap())
        } else {
            info!("🌐 Processing tunneled HTTP request via HTTP (SSL disabled)");
            handle_tunnel_request(req, tunnels, pending_requests, config).await
        }
    }
}

pub async fn start_http_server(
    config: ServerConfig,
    tunnels: TunnelMap,
    pending_requests: PendingRequests,
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
            pending_requests: pending_requests.clone(),
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
    pending_requests: PendingRequests,
    active_websockets: ActiveWebSockets,
    ssl_manager: Arc<RwLock<SslManager>>,
    tls_config: Arc<RustlsConfig>,
) -> Result<(), BoxError> {
    let tls_acceptor = TlsAcceptor::from(tls_config);
    let addr: std::net::SocketAddr = config.https_addr().parse()?;
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    info!("✅ HTTPS server listening on https://{}", config.https_addr());

    loop {
        let (stream, _) = listener.accept().await?;
        let tls_acceptor = tls_acceptor.clone();
        let tunnels = tunnels.clone();
        let pending_requests = pending_requests.clone();
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
                        pending_requests,
                        active_websockets,
                        config:config.clone(),
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
                    let response = json!({"error": format!("Failed to get certificate info: {}", e)});
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

fn calculate_websocket_accept_key(ws_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(ws_key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"); // WebSocket magic string
    let hash = hasher.finalize();
    base64::engine::general_purpose::STANDARD.encode(&hash)
}

async fn handle_tunnel_management_websocket(
    req: Request<Incoming>,
    tunnels: TunnelMap,
    pending_requests: PendingRequests,
    active_websockets: ActiveWebSockets,
    config: ServerConfig,
) -> Result<Response<ResponseBody>, BoxError> {
    // This is the HTTP upgrade handler for tunnel management
    // It's called when exposeme-client connects to /tunnel-ws

    info!("🔌 Tunnel management WebSocket upgrade request");

    // Extract WebSocket key for response
    let ws_key = req.headers()
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
        // tokio::time::sleep(Duration::from_millis(100)).await;
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                info!("✅ Tunnel management WebSocket upgrade successful");
                if let Err(e) = handle_tunnel_management_connection(
                    upgraded,
                    tunnels,
                    pending_requests,
                    active_websockets,
                    config,
                ).await {
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
    pending_requests: PendingRequests,
    active_websockets: ActiveWebSockets,
    config: ServerConfig,
) -> Result<(), BoxError> {
    // Convert upgraded connection to WebSocket
    let ws_stream = WebSocketStream::from_raw_socket(
        TokioIo::new(upgraded),
        Role::Server,
        Some(WebSocketConfig::default()),
    ).await;

    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    // Create channel for outgoing messages
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    // Spawn task to handle outgoing messages
    let outgoing_task = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            if let Ok(json) = message.to_json() {
                if let Err(e) = ws_sender.send(WsMessage::Text(json.into())).await {
                    error!("Failed to send WS message to client: {}", e);
                    break;
                }
            }
        }
    });

    let mut tunnel_id: Option<String> = None;

    while let Some(message) = ws_receiver.next().await {
        match message {
            Ok(WsMessage::Text(text)) => {
                if let Ok(msg) = Message::from_json(&text.to_string()) {
                    match msg {
                        Message::Auth { token, tunnel_id: requested_tunnel_id } => {
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
                                        message: format!("Tunnel ID '{}' is already in use", requested_tunnel_id),
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

                        Message::HttpResponse { id, status, headers, body } => {
                            // Handle HTTP response from tunnel client
                            let response_sender = {
                                let mut pending = pending_requests.write().await;
                                pending.remove(&id)
                            };

                            if let Some(sender) = response_sender {
                                if let Err(e) = sender.send((status, headers, body)) {
                                    error!("Failed to send HTTP response: {}", e);
                                }
                            }
                        }

                        Message::WebSocketUpgradeResponse { connection_id, status, headers: _ } => {
                            info!("📡 WebSocket upgrade response: {} (status: {})", connection_id, status);
                            // Nothing to do here as we've already upgraded incoming connection.
                        }

                        Message::WebSocketData { connection_id, data } => {
                            // Handle WebSocket data from tunnel client
                            if let Some(connection) = active_websockets.read().await.get(&connection_id) {
                                debug!("📡 Received data for {} (age: {}, {} bytes)", connection_id, connection.age_info(), data.len());
                                if let Some(ws_tx) = &connection.ws_tx {
                                    match base64::engine::general_purpose::STANDARD.decode(&data) {
                                        Ok(binary_data) => {
                                            let ws_message = if let Ok(text) = String::from_utf8(binary_data.clone()) {
                                                WsMessage::Text(text.into())
                                            } else {
                                                WsMessage::Binary(binary_data.into())
                                            };

                                            if let Err(e) = ws_tx.send(ws_message) {
                                                error!("Failed to forward WebSocket data to client {}: {}", connection_id, e);
                                                // active_websockets.write().await.remove(&connection_id);
                                            }
                                        }
                                        Err(e) => {
                                            error!("Failed to decode WebSocket data for {}: {}", connection_id, e);
                                        }
                                    }
                                }
                            } else {
                                warn!("Received data for unknown WebSocket connection: {}", connection_id);
                            }
                        }

                        Message::WebSocketClose { connection_id, code, reason } => {
                            // Handle WebSocket close from tunnel client
                            if let Some(connection) = active_websockets.write().await.remove(&connection_id) {
                                info!("📡 Close for {}: code={:?}, reason={:?}, final_status={}", connection_id, code, reason, connection.status_summary());                                if let Some(ws_tx) = &connection.ws_tx {
                                    let close_frame = if let Some(code) = code {
                                        Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
                                            code: code.into(),
                                            reason: reason.unwrap_or_default().into(),
                                        })
                                    } else {
                                        None
                                    };

                                    if let Err(e) = ws_tx.send(WsMessage::Close(close_frame)) {
                                        error!("Failed to send close frame for {}: {:?}", connection_id, e);
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
        shutdown_tunnel(tunnels, active_websockets, tunnel_id).await;
    }

    outgoing_task.abort();
    Ok(())
}

async fn shutdown_tunnel(tunnels: TunnelMap, active_websockets: ActiveWebSockets, tunnel_id: String) {
    {
        let mut tunnels_guard = tunnels.write().await;
        tunnels_guard.remove(&tunnel_id);
        info!("ExposeME client disconnected. Tunnel '{}' removed", tunnel_id);
    }
    let websocket_connections_to_cleanup = {
        let websockets = active_websockets.read().await;
        websockets.iter()
            .filter(|(_, conn)| conn.tunnel_id == tunnel_id)
            .map(|(id, _)| id.clone())
            .collect::<Vec<_>>()
    };
    if !websocket_connections_to_cleanup.is_empty() {
        info!("🧹 Cleaning up {} WebSocket connections", websocket_connections_to_cleanup.len());
        for connection_id in websocket_connections_to_cleanup {
            if let Some(connection) = active_websockets.write().await.remove(&connection_id) {
                info!("🗑️  Cleaned up WebSocket connection: {}", connection_id);
                // Close the browser WebSocket connection gracefully
                if let Some(ws_tx) = &connection.ws_tx {
                    let close_msg = WsMessage::Close(Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
                        code: 1001u16.into(), // Going away
                        reason: "ExposeME client disconnected".into(),
                    }));
                    if let Err(e) = ws_tx.send(close_msg) {
                        warn!("Failed to close browser WebSocket {}: {}", connection_id, e);
                    }
                }
            }
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

    info!("🔌 WebSocket upgrade for tunnel '{}': {} {}", tunnel_id, method, forwarded_path);

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

    info!("🔌 Processing WebSocket upgrade for connection {}", connection_id);

    // Calculate WebSocket accept key
    let ws_key = req.headers()
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
            WebSocketConnection::new(tunnel_id.clone())
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
        error!("Failed to send WebSocket upgrade to tunnel '{}': {}", tunnel_id, e);
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
        // Wait a moment for the response to be sent
        // tokio::time::sleep(Duration::from_millis(300)).await;
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
                ).await {
                    error!("WebSocket proxy error: {}", e);
                }
            },
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
    info!("🔌 Starting WebSocket proxy for connection {}", connection_id);

    // Create channels for communication with tunnel client
    let (ws_tx, mut ws_rx) = mpsc::unbounded_channel::<WsMessage>();

    // Update the stored connection with ws_tx
    {
        let mut websockets = active_websockets.write().await;
        if let Some(connection) = websockets.get_mut(&connection_id) {
            connection.ws_tx = Some(ws_tx);
        }
        else {
            return Err(format!("WebSocket proxy for connection {} not found", connection_id).into());
        }
    }

    // Convert to WebSocket
    let ws_stream = WebSocketStream::from_raw_socket(
        TokioIo::new(upgraded),
        Role::Server,
        Some(WebSocketConfig::default()),
    ).await;

    let (mut original_sink, mut original_stream) = ws_stream.split();

    let connection_status = {
        let websockets = active_websockets.read().await;
        websockets.get(&connection_id)
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
                    if let Err(e) = send_to_tunnel(&connection_id_clone, message, &active_websockets_clone, &tunnels_clone).await {
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
                    if let Err(e) = send_to_tunnel(&connection_id_clone, message, &active_websockets_clone, &tunnels_clone).await {
                        error!("Failed to send WebSocket binary: {}", e);
                    }
                }
                Ok(WsMessage::Close(close_frame)) => {
                    let (code, reason) = if let Some(frame) = close_frame {
                        (Some(frame.code.into()), Some(frame.reason.to_string()))
                    } else {
                        (None, None)
                    };

                    info!("WebSocket connection {} closed by server with code={:?}, reason={:?}", connection_id_clone, code, reason);

                    let message = Message::WebSocketClose {
                        connection_id: connection_id_clone.clone(),
                        code,
                        reason,
                    };

                    // Send close to tunnel client
                    if let Err(e) = send_to_tunnel(&connection_id_clone, message, &active_websockets_clone, &tunnels_clone).await {
                        error!("Failed to send close message: {}", e);
                    }
                    break;
                }
                Err(e) => {
                    error!("Original WebSocket error for {}: {}", connection_id_clone, e);
                    break;
                }
                _ => {} // Handle Ping/Pong
            }
        }

        // Cleanup on task end
        // active_websockets_clone.write().await.remove(&connection_id_clone);
        info!("🔌 Original-to-tunnel task ended for {}", connection_id_clone);
    });

    // Forward messages FROM tunnel client TO original client
    let connection_id_clone = connection_id.clone();
    let tunnel_to_original_task = tokio::spawn(async move {
        while let Some(ws_message) = ws_rx.recv().await {
            if original_sink.send(ws_message).await.is_err() {
                error!("Failed to send to original WebSocket client for {}", connection_id_clone);
                break;
            }
        }

        info!("🔌 Tunnel-to-original task ended for {}", connection_id_clone);
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

    info!("🔌 WebSocket proxy connection {} fully closed", connection_id);
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
        websockets.get(connection_id)
            .map(|conn| conn.tunnel_id.clone())
            .ok_or("Connection not found")?
    };

    // Send to correct tunnel
    {
        let tunnels_guard = tunnels.read().await;
        let tunnel_sender = tunnels_guard.get(&tunnel_id).ok_or("Tunnel not found")?;
        tunnel_sender.send(message).map_err(|e| format!("Failed to send: {}", e))?;
    }

    Ok(())
}

async fn handle_tunnel_request(
    req: Request<Incoming>,
    tunnels: TunnelMap,
    pending_requests: PendingRequests,
    config: ServerConfig,
) -> Result<Response<ResponseBody>, BoxError> {
    let method = req.method().clone();

    // Extract tunnel ID and forwarded path based on routing mode
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

    info!(
        "Request for tunnel '{}' ({}): {} {}",
        tunnel_id,
        match config.server.routing_mode {
            RoutingMode::Path => "path",
            RoutingMode::Subdomain => "subdomain",
            RoutingMode::Both => "both",
        },
        method,
        forwarded_path
    );

    // Check if tunnel exists
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

    // Generate request ID
    let request_id = uuid::Uuid::new_v4().to_string();

    // Extract headers before consuming request body
    let headers_ref = req.headers();

    // Extract headers
    let mut headers = HashMap::new();
    for (name, value) in headers_ref {
        headers.insert(name.to_string(), value.to_str().unwrap_or("").to_string());
    }

    // Extract body
    let body_bytes = req.into_body().collect().await?.to_bytes();
    let body_b64 = base64::engine::general_purpose::STANDARD.encode(&body_bytes);

    // Create HTTP request message
    let http_request = Message::HttpRequest {
        id: request_id.clone(),
        method: method.to_string(),
        path: forwarded_path,
        headers,
        body: body_b64,
    };

    // Create response channel
    let (response_tx, mut response_rx) = mpsc::unbounded_channel();

    // Store pending request
    {
        let mut pending = pending_requests.write().await;
        pending.insert(request_id.clone(), response_tx);
    }

    // Send request to client
    if let Err(e) = tunnel_sender.send(http_request) {
        error!("Failed to send request to tunnel '{}': {}", tunnel_id, e);
        return Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(boxed_body("Tunnel communication error"))
            .unwrap());
    }

    // Wait for response (with timeout from config)
    let response = tokio::time::timeout(
        Duration::from_secs(config.limits.request_timeout_secs),
        response_rx.recv(),
    )
        .await;

    // Clean up pending request
    {
        let mut pending = pending_requests.write().await;
        pending.remove(&request_id);
    }

    match response {
        Ok(Some((status, headers, body))) => {
            let mut response_builder = Response::builder().status(status);

            // Add headers
            for (name, value) in headers {
                response_builder = response_builder.header(name, value);
            }

            // Decode body
            let body_bytes = match base64::engine::general_purpose::STANDARD.decode(&body) {
                Ok(bytes) => bytes,
                Err(e) => {
                    error!("Failed to decode base64 body from client: {}", e);
                    return Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(boxed_body(
                            "Tunnel communication error: invalid data format",
                        ))
                        .unwrap());
                }
            };

            Ok(response_builder.body(boxed_body(body_bytes)).unwrap())
        }
        Ok(None) => {
            warn!("No response received for request {}", request_id);
            Ok(Response::builder()
                .status(StatusCode::GATEWAY_TIMEOUT)
                .body(boxed_body("No response from tunnel"))
                .unwrap())
        }
        Err(_) => {
            warn!("Timeout waiting for response to request {}", request_id);
            Ok(Response::builder()
                .status(StatusCode::GATEWAY_TIMEOUT)
                .body(boxed_body("Tunnel response timeout"))
                .unwrap())
        }
    }
}

fn extract_tunnel_id_from_request(
    req: &Request<Incoming>,
    config: &ServerConfig,
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    let query = req.uri().query().map_or(String::new(), |q| format!("?{}", q));
    let path = req.uri().path();

    // tunnel-id.domain.com/path
    if matches!(config.server.routing_mode, RoutingMode::Subdomain | RoutingMode::Both) {
        let base_domain = &config.server.domain;
        let host = req
            .headers()
            .get("host")
            .and_then(|h| h.to_str().ok())
            .ok_or("Missing Host header")?;
        let host_without_port = host.split(':').next().unwrap_or(host);

        if host_without_port != base_domain {
            if let Some(subdomain) = host_without_port.strip_suffix(&format!(".{}", base_domain))
            {
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
    let path_parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if path_parts.is_empty() || path_parts[0].is_empty() {
        if let RoutingMode::Path = config.server.routing_mode {
            Err("Tunnel ID required in path".into())
        }
        else {
            Err("Tunnel ID required in path or subdomain".into())
        }
    }
    else {
        let tunnel_id = path_parts[0].to_string();
        let forwarded_path = format!("/{}{}", path_parts[1..].join("/"), query);
        Ok((tunnel_id, forwarded_path))
    }
}
