// src/bin/server.rs
use base64::Engine;
use clap::Parser;
use exposeme::{ChallengeStore, Message, RoutingMode, ServerArgs, ServerConfig, SslManager, SslProvider};
use futures_util::{SinkExt, StreamExt};
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use hyper::{body::Incoming, Request, Response, StatusCode};
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use rustls::ServerConfig as RustlsConfig;
use std::collections::HashMap;
use std::convert::Infallible;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::{RwLock, mpsc};
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::{accept_async, tungstenite::Message as WsMessage};
use tracing::{error, info, warn};
use serde_json::json;
use tower::Service;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ResponseBody = BoxBody<bytes::Bytes, BoxError>;

type TunnelMap = Arc<RwLock<HashMap<String, mpsc::UnboundedSender<Message>>>>;
type PendingRequests =
Arc<RwLock<HashMap<String, mpsc::UnboundedSender<(u16, HashMap<String, String>, String)>>>>;

fn boxed_body(text: impl Into<bytes::Bytes>) -> BoxBody<bytes::Bytes, Box<dyn std::error::Error + Send + Sync>> {
    Full::new(text.into())
        .map_err(|e: Infallible| -> Box<dyn std::error::Error + Send + Sync> {
            Box::new(e)
        })
        .boxed()
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    // Set up crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring CryptoProvider");
    
    // Parse CLI arguments
    let args = ServerArgs::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(if args.verbose {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        })
        .init();

    // Generate config if requested
    if args.generate_config {
        ServerConfig::generate_default_file(&args.config)?;
        return Ok(());
    }

    // Load configuration
    let config = ServerConfig::load(&args)?;
    info!("Loaded configuration from {:?}", args.config);
    info!("HTTP server: {}", config.http_addr());
    if config.ssl.enabled {
        info!("HTTPS server: {}", config.https_addr());
        info!("Domain: {}", config.server.domain);
        info!("SSL provider: {:?}", config.ssl.provider);
    }
    info!("WebSocket server: {}", config.ws_addr());
    info!("Auth tokens: {} configured", config.auth.tokens.len());

    // Initialize SSL
    let ssl_manager = Arc::new(RwLock::new(SslManager::new(config.clone())));
    let challenge_store = ssl_manager.read().await.get_challenge_store();

    info!("Starting ExposeME Server...");

    // Shared state
    let tunnels: TunnelMap = Arc::new(RwLock::new(HashMap::new()));
    let pending_requests: PendingRequests = Arc::new(RwLock::new(HashMap::new()));

    // Clone for servers
    let tunnels_http = tunnels.clone();
    let pending_requests_http = pending_requests.clone();
    let config_http = config.clone();
    let challenge_store_http = challenge_store.clone();
    let ssl_manager_http = ssl_manager.clone();

    // Start HTTP server (for redirects and ACME challenges)
    let http_handle = tokio::spawn(async move {
        if let Err(e) = start_http_server(
            config_http,
            tunnels_http,
            pending_requests_http,
            challenge_store_http,
            ssl_manager_http,
        ).await {
            error!("❌ HTTP server error: {}", e);
        }
    });

    // Wait a moment for HTTP server to start
    wait_for_http_server_ready(&config).await?;

    ssl_manager.write().await.initialize().await?;

    // Start HTTPS server (if SSL enabled)
    let https_handle = if config.ssl.enabled {
        let tunnels_https = tunnels.clone();
        let pending_requests_https = pending_requests.clone();
        let config_https = config.clone();
        let ssl_config_for_https = ssl_manager.read().await.get_rustls_config().unwrap();

        Some(tokio::spawn(async move {
            start_https_server(
                config_https,
                tunnels_https,
                pending_requests_https,
                ssl_config_for_https,
            )
                .await;
        }))
    } else {
        None
    };

    // Start WebSocket server
    let tunnels_ws = tunnels.clone();
    let pending_requests_ws = pending_requests.clone();
    let config_ws = config.clone();
    let ssl_config_for_ws = if config.ssl.enabled {
        ssl_manager.read().await.get_rustls_config()
    } else {
        None
    };

    let ws_handle = tokio::spawn(async move {
        if let Some(tls_config) = ssl_config_for_ws {
            // Start WSS (secure WebSocket)
            start_secure_websocket_server(config_ws, tunnels_ws, pending_requests_ws, tls_config)
                .await;
        } else {
            // Start WS (regular WebSocket)
            start_regular_websocket_server(config_ws, tunnels_ws, pending_requests_ws).await;
        }
    });

    let renew_handle = if config.ssl.enabled && config.ssl.provider != SslProvider::Manual {
        Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
            loop {
                interval.tick().await;
                info!("🔍 Daily certificate renewal check for {}", config.server.domain);
                let mut manager = ssl_manager.write().await;
                match manager.get_certificate_info() {
                    Ok(info) => {
                        if let Some(days_until_expiry) = info.days_until_expiry {
                            info!("📅 Certificate for {} expires in {} days", config.server.domain, days_until_expiry);
                            if info.needs_renewal {
                                if let Err(e) = manager.force_renewal().await {
                                    error!("Failed to renew certificate: {}", e);
                                }
                            }
                        }
                    },
                    Err(e) => {
                        error!("Failed to get certificate info: {}", e);
                    },
                }
            }
        }))
    } else {
        None
    };

    // Wait for all servers
    match https_handle {
        Some(https_handle) => {
            match renew_handle {
                Some(renew_handle) => {
                    tokio::select! {
                        _ = http_handle => info!("HTTP server terminated"),
                        _ = https_handle => info!("HTTPS server terminated"),
                        _ = ws_handle => info!("WebSocket server terminated"),
                        _ = renew_handle => info!("Renewal task terminated"),
                    }
                },
                None => {
                    tokio::select! {
                        _ = http_handle => info!("HTTP server terminated"),
                        _ = https_handle => info!("HTTPS server terminated"),
                        _ = ws_handle => info!("WebSocket server terminated"),
                    }
                },
            }
        }
        None => {
            tokio::select! {
                _ = http_handle => info!("HTTP server terminated"),
                _ = ws_handle => info!("WebSocket server terminated"),
            }
        }
    }

    info!("🛑 ExposeME server shutting down");
    Ok(())
}

// Service implementation for HTTP handling
#[derive(Clone)]
struct HttpService {
    tunnels: TunnelMap,
    pending_requests: PendingRequests,
    config: ServerConfig,
    challenge_store: ChallengeStore,
    ssl_manager: Arc<RwLock<SslManager>>,
}

impl Service<Request<Incoming>> for HttpService {
    type Response = Response<ResponseBody>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        let tunnels = self.tunnels.clone();
        let pending_requests = self.pending_requests.clone();
        let config = self.config.clone();
        let challenge_store = self.challenge_store.clone();
        let ssl_manager = self.ssl_manager.clone();

        Box::pin(async move {
            handle_http_request(req, tunnels, pending_requests, config, challenge_store, ssl_manager).await
        })
    }
}

async fn start_http_server(
    config: ServerConfig,
    tunnels: TunnelMap,
    pending_requests: PendingRequests,
    challenge_store: ChallengeStore,
    ssl_manager: Arc<RwLock<SslManager>>,
) -> Result<(), BoxError> {
    let addr: std::net::SocketAddr = config.http_addr().parse()?;
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    info!("✅ HTTP server listening on http://{}", config.http_addr());

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);

        let service = HttpService {
            tunnels: tunnels.clone(),
            pending_requests: pending_requests.clone(),
            config: config.clone(),
            challenge_store: challenge_store.clone(),
            ssl_manager: ssl_manager.clone(),
        };

        tokio::spawn(async move {
            if let Err(err) = Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(io, TowerToHyperService::new(service))
                .await
            {
                error!("Failed to serve connection: {}", err);
            }
        });
    }
}

async fn handle_http_request(
    req: Request<Incoming>,
    tunnels: TunnelMap,
    pending_requests: PendingRequests,
    config: ServerConfig,
    challenge_store: ChallengeStore,
    ssl_manager: Arc<RwLock<SslManager>>,
) -> Result<Response<ResponseBody>, BoxError> {
    let path = req.uri().path();

    // Handle ACME challenges
    if path.starts_with("/.well-known/acme-challenge/") {
        return handle_acme_challenge(req, challenge_store).await;
    }

    if path == "/api/health" {
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(boxed_body("OK"))
            .unwrap());
    }

    // If HTTPS is enabled, redirect HTTP to HTTPS
    if config.ssl.enabled {
        if path.starts_with("/api/certificates/") {
            return handle_certificate_api(req, ssl_manager, config).await;
        }

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
        // Handle normal HTTP requests (when HTTPS is disabled)
        handle_tunnel_request(req, tunnels, pending_requests, config).await
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
                        .body(boxed_body("Tunnel communication error: invalid data format"))
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

async fn wait_for_http_server_ready(
    config: &ServerConfig,
) -> Result<(), BoxError> {
    let test_url = format!(
        "http://127.0.0.1:{}/.well-known/acme-challenge/readiness-test",
        config.server.http_port
    );

    info!("Waiting for HTTP server to be ready...");

    for attempt in 1..=10 {
        match reqwest::get(&test_url).await {
            Ok(response) => {
                info!(
                    "✅ HTTP server is ready (attempt {}, status: {})",
                    attempt,
                    response.status()
                );
                return Ok(());
            }
            Err(e) => {
                if attempt < 10 {
                    info!("⏳ HTTP server not ready yet (attempt {}): {}", attempt, e);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                } else {
                    return Err(
                        format!("HTTP server failed to start after 10 attempts: {}", e).into(),
                    );
                }
            }
        }
    }

    Ok(())
}

async fn start_https_server(
    config: ServerConfig,
    tunnels: TunnelMap,
    pending_requests: PendingRequests,
    tls_config: Arc<RustlsConfig>,
) {
    let tls_acceptor = TlsAcceptor::from(tls_config);
    let addr: std::net::SocketAddr = config.https_addr().parse().unwrap();
    let tcp_listener = tokio::net::TcpListener::bind(&addr).await.unwrap();
    info!(
        "✅ HTTPS server listening on https://{}",
        config.https_addr()
    );

    loop {
        match tcp_listener.accept().await {
            Ok((stream, _)) => {
                let tls_acceptor = tls_acceptor.clone();
                let tunnels = tunnels.clone();
                let pending_requests = pending_requests.clone();
                let config = config.clone();

                tokio::spawn(async move {
                    match tls_acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let io = TokioIo::new(tls_stream);
                            let service = HttpsService {
                                tunnels,
                                pending_requests,
                                config,
                            };

                            if let Err(e) = Builder::new(hyper_util::rt::TokioExecutor::new())
                                .serve_connection(io, TowerToHyperService::new(service))
                                .await
                            {
                                error!("HTTPS connection error: {}", e);
                            }
                        }
                        Err(e) => {
                            error!("TLS handshake error: {}", e);
                        }
                    }
                });
            }
            Err(e) => {
                error!("TCP accept error: {}", e);
            }
        }
    }
}

// Service implementation for HTTPS handling
#[derive(Clone)]
struct HttpsService {
    tunnels: TunnelMap,
    pending_requests: PendingRequests,
    config: ServerConfig,
}

impl Service<Request<Incoming>> for HttpsService {
    type Response = Response<ResponseBody>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        let tunnels = self.tunnels.clone();
        let pending_requests = self.pending_requests.clone();
        let config = self.config.clone();

        Box::pin(async move {
            handle_tunnel_request(req, tunnels, pending_requests, config).await
        })
    }
}

async fn handle_websocket_connection<S>(
    stream: S,
    tunnels: TunnelMap,
    pending_requests: PendingRequests,
    config: ServerConfig,
) -> Result<(), BoxError>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let ws_stream = accept_async(stream).await?;
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    // Create channel for outgoing messages
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    // Spawn task to handle outgoing messages
    let outgoing_task = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            if let Ok(json) = message.to_json() {
                if ws_sender.send(WsMessage::Text(json.into())).await.is_err() {
                    break;
                }
            }
        }
    });

    let mut tunnel_id: Option<String> = None;

    // Handle incoming messages
    while let Some(message) = ws_receiver.next().await {
        match message {
            Ok(WsMessage::Text(text)) => {
                if let Ok(msg) = Message::from_json(&text.to_string()) {
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
                                    error!("Failed to send tunnel ID validation error to client: {}", err);
                                    break;
                                }
                                tokio::time::sleep(Duration::from_millis(500)).await;
                                break;
                            }

                            // Token validation using config
                            if !config.auth.tokens.contains(&token) {
                                let error_msg = Message::AuthError {
                                    error: "invalid_token".to_string(),
                                    message: "Invalid authentication token".to_string(),
                                };
                                if let Err(err) = tx.send(error_msg) {
                                    error!("Failed to send auth error to client: {}", err);
                                    break;
                                }
                                tokio::time::sleep(Duration::from_millis(500)).await;
                                break;
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
                                        error!(
                                            "Failed to send tunnel_taken error to client: {}",
                                            err
                                        );
                                        break;
                                    }
                                    tokio::time::sleep(Duration::from_millis(500)).await;
                                    break;
                                }
                            }

                            // Check max tunnels limit
                            {
                                let tunnels_guard = tunnels.read().await;
                                if tunnels_guard.len() >= config.limits.max_tunnels {
                                    let error_msg = Message::AuthError {
                                        error: "max_tunnels_reached".to_string(),
                                        message: format!(
                                            "Maximum number of tunnels ({}) reached",
                                            config.limits.max_tunnels
                                        ),
                                    };
                                    if let Err(err) = tx.send(error_msg) {
                                        error!(
                                            "Failed to send max_tunnels error to client: {}",
                                            err
                                        );
                                        break;
                                    }
                                    tokio::time::sleep(Duration::from_millis(500)).await;
                                    break;
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
                                error!("Failed to send auth success to client: {}", err);
                                break;
                            }
                            info!("Tunnel '{}' registered successfully", requested_tunnel_id);
                        }

                        Message::HttpResponse {
                            id,
                            status,
                            headers,
                            body,
                        } => {
                            // Find pending request and send response
                            let response_sender = {
                                let mut pending = pending_requests.write().await;
                                pending.remove(&id)
                            };

                            if let Some(sender) = response_sender {
                                let _ = sender.send((status, headers, body));
                            }
                        }

                        _ => {
                            warn!("Unexpected message type from client");
                        }
                    }
                }
            }
            Ok(WsMessage::Close(_)) => {
                info!("WebSocket connection closed");
                break;
            }
            Err(e) => {
                error!("WebSocket error: {}", e);
                break;
            }
            _ => {}
        }
    }

    // Clean up tunnel on disconnect
    if let Some(tunnel_id) = tunnel_id {
        let mut tunnels_guard = tunnels.write().await;
        tunnels_guard.remove(&tunnel_id);
        info!("Tunnel '{}' removed", tunnel_id);
    }

    // Wait for outgoing task to finish
    outgoing_task.abort();

    Ok(())
}

async fn start_regular_websocket_server(
    config: ServerConfig,
    tunnels: TunnelMap,
    pending_requests: PendingRequests,
) {
    let listener = tokio::net::TcpListener::bind(&config.ws_addr())
        .await
        .unwrap();
    info!(
        "✅ WebSocket server (WS) listening on ws://{}",
        config.ws_addr()
    );

    while let Ok((stream, addr)) = listener.accept().await {
        info!("New WebSocket connection from: {}", addr);

        let tunnels = tunnels.clone();
        let pending_requests = pending_requests.clone();
        let config = config.clone();

        tokio::spawn(async move {
            if let Err(e) =
                handle_websocket_connection(stream, tunnels, pending_requests, config).await
            {
                error!("WebSocket connection error: {}", e);
            }
        });
    }
}

async fn start_secure_websocket_server(
    config: ServerConfig,
    tunnels: TunnelMap,
    pending_requests: PendingRequests,
    tls_config: Arc<rustls::ServerConfig>,
) {
    let tls_acceptor = TlsAcceptor::from(tls_config);
    let listener = tokio::net::TcpListener::bind(&config.ws_addr())
        .await
        .unwrap();
    info!(
        "✅ WebSocket server (WSS) listening on wss://{}",
        config.ws_addr()
    );

    while let Ok((stream, addr)) = listener.accept().await {
        info!("New secure WebSocket connection from: {}", addr);

        let tls_acceptor = tls_acceptor.clone();
        let tunnels = tunnels.clone();
        let pending_requests = pending_requests.clone();
        let config = config.clone();

        tokio::spawn(async move {
            match tls_acceptor.accept(stream).await {
                Ok(tls_stream) => {
                    if let Err(e) =
                        handle_websocket_connection(tls_stream, tunnels, pending_requests, config)
                            .await
                    {
                        error!("Secure WebSocket connection error: {}", e);
                    }
                }
                Err(e) => {
                    error!("TLS handshake error for WebSocket: {}", e);
                }
            }
        });
    }
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

fn extract_tunnel_id_from_request(
    req: &Request<Incoming>,
    config: &ServerConfig,
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    let uri = req.uri();
    let path = uri.path();

    // Get Host header
    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .ok_or("Missing Host header")?;

    // Remove port if present
    let host_without_port = host.split(':').next().unwrap_or(host);

    match config.server.routing_mode {
        RoutingMode::Path => {
            // Original logic: /tunnel-id/path
            let path_parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            if path_parts.is_empty() || path_parts[0].is_empty() {
                return Err("Tunnel ID required in path".into());
            }

            let tunnel_id = path_parts[0].to_string();
            let forwarded_path = format!(
                "/{}{}",
                path_parts[1..].join("/"),
                uri.query().map_or(String::new(), |q| format!("?{}", q))
            );

            Ok((tunnel_id, forwarded_path))
        }

        RoutingMode::Subdomain => {
            // New logic: tunnel-id.domain.com/path
            let base_domain = &config.server.domain;

            if host_without_port == base_domain {
                return Err("No tunnel specified in subdomain".into());
            }

            // Extract tunnel_id from subdomain
            let tunnel_id = if let Some(subdomain) = host_without_port.strip_suffix(&format!(".{}", base_domain)) {
                subdomain.to_string()
            } else {
                return Err("Invalid subdomain format".into());
            };

            // For subdomain mode, forward the full path
            let forwarded_path = format!(
                "{}{}",
                path,
                uri.query().map_or(String::new(), |q| format!("?{}", q))
            );

            Ok((tunnel_id, forwarded_path))
        }

        RoutingMode::Both => {
            // Try subdomain first, then path
            let base_domain = &config.server.domain;

            // Check if it's a subdomain request
            if host_without_port != base_domain {
                if let Some(subdomain) = host_without_port.strip_suffix(&format!(".{}", base_domain)) {
                    let tunnel_id = subdomain.to_string();
                    let forwarded_path = format!(
                        "{}{}",
                        path,
                        uri.query().map_or(String::new(), |q| format!("?{}", q))
                    );
                    return Ok((tunnel_id, forwarded_path));
                }
            }

            // Fall back to path-based routing
            let path_parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
            if path_parts.is_empty() || path_parts[0].is_empty() {
                return Err("Tunnel ID required in path or subdomain".into());
            }

            let tunnel_id = path_parts[0].to_string();
            let forwarded_path = format!(
                "/{}{}",
                path_parts[1..].join("/"),
                uri.query().map_or(String::new(), |q| format!("?{}", q))
            );

            Ok((tunnel_id, forwarded_path))
        }
    }
}
