// src/bin/client.rs
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use bytes::Bytes;

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use reqwest::Client as HttpClient;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use base64::Engine;
use tokio::signal;
use tokio::sync::{mpsc, RwLock};
use tokio::time::timeout;
use tokio_tungstenite::Connector;
use rustls::ClientConfig as RustlsClientConfig;

use tracing::{debug, error, info, warn};

use exposeme::{initialize_tracing, ClientArgs, ClientConfig, Message};
use exposeme::insecure_cert::InsecureCertVerifier;

pub type OutgoingRequests = Arc<RwLock<HashMap<String, OutgoingRequest>>>;

#[derive(Debug)]
pub struct OutgoingRequest {
    id: String,
    created_at: std::time::Instant,
    body_tx: Option<mpsc::Sender<Result<Bytes, std::io::Error>>>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring CryptoProvider");

    // Handle Ctrl+C gracefully
    tokio::spawn(async {
        signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
        info!("🛑 Received Ctrl+C, shutting down...");
        std::process::exit(0);
    });

    // Parse CLI arguments
    let args = ClientArgs::parse();

    initialize_tracing(args.verbose);

    // Generate config if requested
    if args.generate_config {
        ClientConfig::generate_default_file(&args.config)?;
        return Ok(());
    }

    // Load configuration
    let config = ClientConfig::load(&args)?;
    info!("Loaded configuration from {:?}", args.config);
    info!("Server: {}", config.client.server_url);
    info!("Tunnel ID: {}", config.client.tunnel_id);
    info!("Local target: {}", config.client.local_target);

    info!("Starting ExposeME Client...");

    // Main client loop with reconnection
    loop {
        match run_client(&config).await {
            Ok(_) => {
                info!("Client disconnected normally");
                break;
            }
            Err(e) => {
                error!("Client error: {}", e);

                if config.client.auto_reconnect {
                    info!(
                        "Reconnecting in {} seconds...",
                        config.client.reconnect_delay_secs
                    );
                    tokio::time::sleep(Duration::from_secs(config.client.reconnect_delay_secs))
                        .await;
                    continue;
                } else {
                    break;
                }
            }
        }
    }

    Ok(())
}

// WebSocket connection management
#[derive(Debug, Clone)]
struct ActiveWebSocketConnection {
    connection_id: String,
    // Channel for sending data to local WebSocket service
    local_tx: mpsc::UnboundedSender<Vec<u8>>,
    // Channel for sending data back to server
    to_server_tx: mpsc::UnboundedSender<Message>,
    created_at: std::time::Instant,
    last_activity: Arc<RwLock<std::time::Instant>>,
}

impl ActiveWebSocketConnection {
    fn new(
        connection_id: String,
        local_tx: mpsc::UnboundedSender<Vec<u8>>,
        to_server_tx: mpsc::UnboundedSender<Message>,
    ) -> Self {
        let now = std::time::Instant::now();
        Self {
            connection_id,
            local_tx,
            to_server_tx,
            created_at: now,
            last_activity: Arc::new(RwLock::new(now)),
        }
    }

    // Use connection_id for structured logging
    fn log_info(&self, message: &str) {
        info!("🔌 WebSocket {}: {}", self.connection_id, message);
    }

    fn log_debug(&self, message: &str) {
        debug!("🔌 WebSocket {}: {}", self.connection_id, message);
    }

    fn log_error(&self, message: &str) {
        error!("❌ WebSocket {}: {}", self.connection_id, message);
    }

    fn log_warn(&self, message: &str) {
        warn!("⚠️  WebSocket {}: {}", self.connection_id, message);
    }

    // Use created_at for connection monitoring
    fn connection_age(&self) -> Duration {
        self.created_at.elapsed()
    }

    // Update last activity timestamp
    async fn update_activity(&self) {
        *self.last_activity.write().await = std::time::Instant::now();
    }

    async fn is_idle(&self, max_idle_duration: Duration) -> bool {
        let last_activity = *self.last_activity.read().await;
        last_activity.elapsed() > max_idle_duration
    }

    // Get idle time (time since last activity)
    async fn idle_time(&self) -> Duration {
        let last_activity = *self.last_activity.read().await;
        last_activity.elapsed()
    }

    async fn status_summary(&self) -> String {
        let idle = self.idle_time().await;
        let idle_info = if idle.as_secs() < 60 {
            format!("idle: {}s", idle.as_secs())
        } else {
            format!("idle: {}m", idle.as_secs() / 60)
        };

        format!(
            "Connection {} (age: {}, {}, channels: server={}, local={})",
            self.connection_id,
            self.age_info(),
            idle_info,
            if self.to_server_tx.is_closed() { "closed" } else { "open" },
            if self.local_tx.is_closed() { "closed" } else { "open" }
        )
    }

    fn age_info(&self) -> String {
        let age = self.connection_age();
        if age.as_secs() < 60 {
            format!("{}s", age.as_secs())
        } else if age.as_secs() < 3600 {
            format!("{}m", age.as_secs() / 60)
        } else {
            format!("{}h{}m", age.as_secs() / 3600, (age.as_secs() % 3600) / 60)
        }
    }

    // Use to_server_tx for reliable message sending with error handling
    async fn send_to_server(&self, message: Message) -> Result<(), String> {
        self.update_activity().await;
        self.to_server_tx
            .send(message)
            .map_err(|e| {
                let error_msg = format!("Failed to send message to server: {}", e);
                self.log_error(&error_msg);
                error_msg
            })
    }

    // Use local_tx for reliable data forwarding
    async fn send_to_local(&self, data: Vec<u8>) -> Result<(), String> {
        self.update_activity().await;
        self.local_tx
            .send(data)
            .map_err(|e| {
                let error_msg = format!("Failed to send data to local WebSocket: {}", e);
                self.log_error(&error_msg);
                error_msg
            })
    }
}

type ActiveWebSockets = Arc<RwLock<HashMap<String, ActiveWebSocketConnection>>>;

async fn run_client(config: &ClientConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Connect to WebSocket server
    let (ws_stream, _) = if config.client.insecure && config.client.server_url.starts_with("wss://") {
        // For self-signed certificates, use insecure connection
        warn!("⚠️  Using insecure connection (skipping TLS verification)");
        warn!("⚠️  This should only be used for development with self-signed certificates");

        // Create insecure TLS config that accepts any certificate
        let tls_config = RustlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier))
            .with_no_client_auth();

        let connector = Connector::Rustls(Arc::new(tls_config));
        tokio_tungstenite::connect_async_tls_with_config(
            &config.client.server_url,
            None,
            false,
            Some(connector),
        ).await?
    } else {
        // Normal secure connection
        connect_async(&config.client.server_url).await?
    };
    info!("Connected to WebSocket server");

    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    // Send authentication
    let auth_message = Message::Auth {
        token: config.client.auth_token.clone(),
        tunnel_id: config.client.tunnel_id.clone(),
    };

    let auth_json = auth_message.to_json()?;
    ws_sender.send(WsMessage::Text(auth_json.into())).await?;
    info!(
        "Sent authentication for tunnel '{}'",
        config.client.tunnel_id
    );

    // Create HTTP client for forwarding requests
    let http_client = HttpClient::new();

    // Store active WebSocket connections and outgoing HTTP requests
    let active_websockets: ActiveWebSockets = Arc::new(RwLock::new(HashMap::new()));
    let outgoing_requests: OutgoingRequests = Arc::new(RwLock::new(HashMap::new()));

    // Create channel for sending messages back to server
    let (to_server_tx, mut to_server_rx) = mpsc::unbounded_channel::<Message>();

    // Spawn task to handle outgoing messages to server
    tokio::spawn(async move {
        while let Some(message) = to_server_rx.recv().await {
            if let Ok(json) = message.to_json() {
                if let Err(e) = ws_sender.send(WsMessage::Text(json.into())).await {
                    error!("Failed to send message to server: {}", e);
                    break;
                }
            }
        }
    });

    // Add periodic cleanup task for WebSocket connections
    let cleanup_websockets = active_websockets.clone();
    let cleanup_interval = Duration::from_secs(config.client.websocket_cleanup_interval_secs);
    let max_connection_idle = Duration::from_secs(config.client.websocket_max_idle_secs);
    let cleanup_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(cleanup_interval);

        loop {
            interval.tick().await;

            let cleaned = cleanup_expired_connections(
                cleanup_websockets.clone(),
                max_connection_idle
            ).await;

            // Log current connection count
            let current_count = cleanup_websockets.read().await.len();
            if current_count > 0 || cleaned > 0 {
                info!(
                    "🔌 WebSocket status: {} active connections, {} cleaned up (max_idle: {}s, check_interval: {}s)",
                    current_count,
                    cleaned,
                    max_connection_idle.as_secs(),
                    cleanup_interval.as_secs()
                );
            }
        }
    });

    // Handle incoming WebSocket messages
    while let Some(message) = ws_receiver.next().await {
        match message {
            Ok(WsMessage::Text(text)) => {
                if let Ok(msg) = Message::from_json(&text.to_string()) {
                    match msg {
                        Message::AuthSuccess {
                            tunnel_id,
                            public_url,
                        } => {
                            info!("✅ Tunnel '{}' established!", tunnel_id);
                            info!("🌐 Public URL: {}", public_url);
                            info!("🔄 Forwarding to: {}", config.client.local_target);
                        }

                        Message::AuthError { error, message } => {
                            error!("❌ Authentication failed: {} - {}", error, message);
                            return Err(format!("Auth error: {}", message).into());
                        }

                        // New streaming protocol handlers
                        Message::HttpRequestStart { id, method, path, headers, initial_data } => {
                            debug!("📥 Received streaming request start: {} {}", method, path);

                            // Spawn parallel task for each HTTP request
                            let http_client = http_client.clone();
                            let local_target = config.client.local_target.clone();
                            let to_server_tx = to_server_tx.clone();
                            let outgoing_requests = outgoing_requests.clone();

                            tokio::spawn(async move {
                                handle_http_request_streaming(
                                    &http_client,
                                    &local_target,
                                    &to_server_tx,
                                    &outgoing_requests,
                                    id,
                                    method,
                                    path,
                                    headers,
                                    initial_data,
                                ).await;
                            });
                        }

                        Message::DataChunk { id, data, is_final } => {
                            handle_data_chunk(&outgoing_requests, id, data, is_final).await;
                        }

                        // Legacy protocol handlers (for backward compatibility)
                        Message::HttpRequest {
                            id,
                            method,
                            path,
                            headers,
                            body,
                        } => {
                            debug!("📥 Received legacy request: {} {}", method, path);

                            // Spawn parallel task for each HTTP request
                            let http_client = http_client.clone();
                            let local_target = config.client.local_target.clone();
                            let to_server_tx = to_server_tx.clone();

                            tokio::spawn(async move {
                                handle_http_request_legacy(
                                    &http_client,
                                    &local_target,
                                    &to_server_tx,
                                    id,
                                    method,
                                    path,
                                    headers,
                                    body,
                                ).await;
                            });
                        }

                        Message::WebSocketUpgrade { connection_id, method, path, headers } => {
                            info!("🔌 Received WebSocket upgrade: {} {}", method, path);

                            let local_target = config.client.local_target.clone();
                            let to_server_tx = to_server_tx.clone();
                            let active_websockets = active_websockets.clone();
                            let config = config.clone();

                            tokio::spawn(async move {
                                handle_websocket_upgrade(
                                    &local_target,
                                    &to_server_tx,
                                    active_websockets,
                                    connection_id,
                                    method,
                                    path,
                                    headers,
                                    &config,
                                ).await;
                            });
                        }
                        Message::WebSocketData { connection_id, data } => {
                            handle_websocket_data(active_websockets.clone(), connection_id, data).await;
                        }
                        Message::WebSocketClose { connection_id, code, reason } => {
                            handle_websocket_close(active_websockets.clone(), connection_id, code, reason).await;
                        }
                        Message::Error { message } => {
                            error!("Server error: {}", message);
                        }
                        _ => {
                            warn!("Unexpected message type from server");
                        }
                    }
                }
            }

            Ok(WsMessage::Close(_)) => {
                info!("WebSocket connection closed by server");
                break;
            }

            Err(e) => {
                error!("WebSocket error: {}", e);
                break;
            }

            _ => {}
        }
    }

    // Cleanup on client disconnect
    cleanup_task.abort();

    // Clean up all WebSocket connections on shutdown
    {
        let websockets = active_websockets.read().await;
        let connection_count = websockets.len();
        if connection_count > 0 {
            info!("🔌 Cleaning up {} WebSocket connections on shutdown", connection_count);
            for (_id, connection) in websockets.iter() {
                connection.log_info("Shutting down due to client disconnect");
            }
        }
    }

    info!("Client connection ended");
    Ok(())
}

// Handle streaming HTTP requests
async fn handle_http_request_streaming(
    http_client: &HttpClient,
    local_target: &str,
    to_server_tx: &mpsc::UnboundedSender<Message>,
    outgoing_requests: &OutgoingRequests,
    id: String,
    method: String,
    path: String,
    headers: HashMap<String, String>,
    initial_data: Vec<u8>,
) {
    info!("📥 Processing streaming HTTP request: {} {}", method, path);

    // Create streaming body channel
    let (body_tx, body_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(32);

    // Send initial data if present
    if !initial_data.is_empty() {
        let _ = body_tx.send(Ok(initial_data.into())).await;
    }

    // Register request for incoming chunks
    outgoing_requests.write().await.insert(id.clone(), OutgoingRequest {
        id: id.clone(),
        created_at: std::time::Instant::now(),
        body_tx: Some(body_tx.clone()),
    });

    // Create request
    let url = format!("{}{}", local_target, path);
    let mut request = create_request_builder(http_client, &method, &url, &headers);

    if ["POST", "PUT", "PATCH"].contains(&method.as_str()) {
        let body_stream = tokio_stream::wrappers::ReceiverStream::new(body_rx);
        request = request.body(reqwest::Body::wrap_stream(body_stream));
    } else {
        drop(body_tx); // Close body for GET requests
    }

    // Send request and stream response
    match request.send().await {
        Ok(response) => {
            stream_response_to_server(to_server_tx, id, response).await;
        }
        Err(e) => {
            send_error_response(to_server_tx, id, e.to_string()).await;
        }
    }
}

async fn handle_data_chunk(
    outgoing_requests: &OutgoingRequests,
    id: String,
    data: Vec<u8>,
    is_final: bool,
) {
    let body_tx = {
        let requests = outgoing_requests.read().await;
        requests.get(&id).and_then(|r| r.body_tx.clone())
    };

    if let Some(tx) = body_tx {
        if !data.is_empty() {
            let _ = tx.send(Ok(data.into())).await;
        }

        if is_final {
            drop(tx); // Close the stream
            outgoing_requests.write().await.remove(&id);
        }
    }
}

async fn stream_response_to_server(
    to_server_tx: &mpsc::UnboundedSender<Message>,
    id: String,
    response: reqwest::Response,
) {
    let status = response.status().as_u16();
    let headers = extract_response_headers(&response);

    // Check if we should stream this response
    let should_stream = is_streaming_response(&response);

    if !should_stream && response.content_length().unwrap_or(0) < 256 * 1024 {
        // Small response - collect and send in one message
        match response.bytes().await {
            Ok(bytes) => {
                to_server_tx.send(Message::HttpResponseStart {
                    id: id.clone(),
                    status,
                    headers,
                    initial_data: bytes.to_vec(),
                }).ok();

                to_server_tx.send(Message::DataChunk {
                    id,
                    data: vec![],
                    is_final: true,
                }).ok();
            }
            Err(e) => {
                send_error_response(to_server_tx, id, e.to_string()).await;
            }
        }
    } else {
        // Stream the response
        to_server_tx.send(Message::HttpResponseStart {
            id: id.clone(),
            status,
            headers,
            initial_data: vec![],
        }).ok();

        let mut stream = response.bytes_stream();
        while let Some(result) = stream.next().await {
            match result {
                Ok(chunk) => {
                    if to_server_tx.send(Message::DataChunk {
                        id: id.clone(),
                        data: chunk.to_vec(),
                        is_final: false,
                    }).is_err() {
                        break;
                    }
                }
                Err(e) => {
                    error!("Response stream error: {}", e);
                    break;
                }
            }
        }

        // Send final chunk
        to_server_tx.send(Message::DataChunk {
            id,
            data: vec![],
            is_final: true,
        }).ok();
    }
}

fn is_streaming_response(response: &reqwest::Response) -> bool {
    // Check for streaming indicators
    if let Some(content_type) = response.headers().get("content-type") {
        if let Ok(ct) = content_type.to_str() {
            if ct.contains("text/event-stream") || ct.contains("application/octet-stream") {
                return true;
            }
        }
    }

    // Check for chunked encoding
    if let Some(encoding) = response.headers().get("transfer-encoding") {
        if let Ok(te) = encoding.to_str() {
            if te.contains("chunked") {
                return true;
            }
        }
    }

    // Large or unknown size
    response.content_length().map(|len| len > 512 * 1024).unwrap_or(true)
}

// Legacy HTTP request handling (for backward compatibility)
async fn handle_http_request_legacy(
    http_client: &HttpClient,
    local_target: &str,
    to_server_tx: &mpsc::UnboundedSender<Message>,
    id: String,
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: String,
) {
    info!("📥 Processing legacy HTTP request: {} {}", method, path);

    // Forward request to local service
    let response = forward_request(
        http_client,
        local_target,
        &method,
        &path,
        headers,
        &body,
    ).await;

    let response_message = match response {
        Ok((status, headers, body)) => {
            debug!("📤 Sending legacy HTTP response: {}", status);
            Message::HttpResponse {
                id,
                status,
                headers,
                body,
            }
        }
        Err(e) => {
            error!("❌ Failed to forward legacy HTTP request: {}", e);
            Message::HttpResponse {
                id,
                status: 502,
                headers: HashMap::new(),
                body: base64::engine::general_purpose::STANDARD
                    .encode("Bad Gateway"),
            }
        }
    };

    // Send response back through channel
    if let Err(e) = to_server_tx.send(response_message) {
        error!("Failed to send legacy HTTP response through channel: {}", e);
    }
}

async fn forward_request(
    client: &HttpClient,
    base_url: &str,
    method: &str,
    path: &str,
    headers: HashMap<String, String>,
    body: &str,
) -> Result<(u16, HashMap<String, String>, String), Box<dyn std::error::Error>> {
    // Construct full URL
    let url = format!("{}{}", base_url, path);

    // Decode body from base64
    let body_bytes = match base64::engine::general_purpose::STANDARD.decode(body) {
        Ok(bytes) => bytes,
        Err(err) => return Err(err.into()),
    };

    // Create request
    let mut request_builder = create_request_builder(client, method, &url, &headers);

    // Add body for methods that support it
    if ["POST", "PUT", "PATCH"].contains(&method) {
        request_builder = request_builder.body(body_bytes);
    }

    // Send request
    let response = request_builder.send().await?;

    // Extract response details
    let status = response.status().as_u16();
    let response_headers = extract_response_headers(&response);

    // Get response body
    let response_body = response.bytes().await?;
    let response_body_b64 = base64::engine::general_purpose::STANDARD.encode(&response_body);

    Ok((status, response_headers, response_body_b64))
}

fn create_request_builder(
    client: &HttpClient,
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
) -> reqwest::RequestBuilder {
    let mut request_builder = match method {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        "PATCH" => client.patch(url),
        "HEAD" => client.head(url),
        _ => client.get(url), // Default to GET for unsupported methods
    };

    // Add headers
    for (name, value) in headers {
        // Skip headers that reqwest handles automatically
        if !["host", "content-length", "connection", "user-agent"]
            .contains(&name.to_lowercase().as_str())
        {
            request_builder = request_builder.header(name, value);
        }
    }

    request_builder
}

fn extract_response_headers(response: &reqwest::Response) -> HashMap<String, String> {
    let mut response_headers = HashMap::new();
    for (name, value) in response.headers() {
        response_headers.insert(name.to_string(), value.to_str().unwrap_or("").to_string());
    }
    response_headers
}

async fn send_error_response(
    to_server_tx: &mpsc::UnboundedSender<Message>,
    id: String,
    error: String,
) {
    let error_response = Message::HttpResponseStart {
        id: id.clone(),
        status: 502,
        headers: HashMap::new(),
        initial_data: error.into_bytes(),
    };

    to_server_tx.send(error_response).ok();

    to_server_tx.send(Message::DataChunk {
        id,
        data: vec![],
        is_final: true,
    }).ok();
}

// Handle WebSocket upgrade requests
async fn handle_websocket_upgrade(
    local_target: &str,
    to_server_tx: &mpsc::UnboundedSender<Message>,
    active_websockets: ActiveWebSockets,
    connection_id: String,
    method: String,
    path: String,
    headers: HashMap<String, String>,
    config: &ClientConfig,
) {
    info!("🔌 Processing WebSocket upgrade for connection {}", connection_id);
    info!("📋 Request: {} {} (headers: {})", method, path, headers.len());

    // Construct WebSocket URL for local service
    let ws_url = if local_target.starts_with("http://") {
        local_target.replace("http://", "ws://") + &path
    } else if local_target.starts_with("https://") {
        local_target.replace("https://", "wss://") + &path
    } else {
        format!("ws://{}{}", local_target, path)
    };

    info!("🔗 Connecting to local WebSocket: {}", ws_url);
    let connect_timeout = Duration::from_secs(config.client.websocket_connection_timeout_secs);
    let connect_result = timeout(connect_timeout, connect_async(&ws_url)).await;

    match connect_result {
        Ok(Ok((local_ws, response))) => {
            info!("✅ Connected to local WebSocket service for {}", connection_id);

            // Extract response headers
            let mut response_headers = HashMap::new();
            for (name, value) in response.headers() {
                response_headers.insert(
                    name.to_string(),
                    value.to_str().unwrap_or("").to_string()
                );
            }

            // Send successful upgrade response
            let upgrade_response = Message::WebSocketUpgradeResponse {
                connection_id: connection_id.clone(),
                status: response.status().as_u16(),
                headers: response_headers,
            };

            if let Err(e) = to_server_tx.send(upgrade_response) {
                error!("Failed to send WebSocket upgrade response for {}: {}", connection_id, e);
                return;
            }

            // Split WebSocket for bidirectional communication
            let (mut local_sink, mut local_stream) = local_ws.split();

            // Create channel for sending data to local WebSocket
            let (local_tx, mut local_rx) = mpsc::unbounded_channel::<Vec<u8>>();

            let connection = ActiveWebSocketConnection::new(
                connection_id.clone(),
                local_tx,
                to_server_tx.clone(),
            );
            let connection_clone = connection.clone();

            connection.log_info("WebSocket connection established");

            // Store the connection
            {
                let mut websockets = active_websockets.write().await;
                websockets.insert(connection_id.clone(), connection);
            }

            let active_websockets_clone = active_websockets.clone();
            let connection_id_clone = connection_id.clone();

            // Forward FROM local service TO server
            let local_to_server_task = {
                let connection = connection_clone.clone();
                let connection_id = connection_id_clone.clone();

                tokio::spawn(async move {
                    connection.log_info("Started local-to-server forwarding task");

                    while let Some(msg) = local_stream.next().await {
                        match msg {
                            Ok(WsMessage::Text(text)) => {
                                connection.log_debug(&format!("📤 Forwarding text to server: {} chars", text.len()));
                                let text_string = text.to_string();
                                let data = base64::engine::general_purpose::STANDARD.encode(text_string.as_bytes());
                                let message = Message::WebSocketData {
                                    connection_id: connection.connection_id.clone(),
                                    data,
                                };

                                // Use the stored to_server_tx from connection
                                if connection.send_to_server(message).await.is_err() {
                                    connection.log_error("Failed to send text message to server, terminating");
                                    break;
                                }
                            }
                            Ok(WsMessage::Binary(bytes)) => {
                                connection.log_info(&format!("📤 Forwarding binary to server: {} bytes", bytes.len()));
                                let bytes_vec = bytes.to_vec();
                                let data = base64::engine::general_purpose::STANDARD.encode(&bytes_vec);
                                let message = Message::WebSocketData {
                                    connection_id: connection.connection_id.clone(),
                                    data,
                                };

                                // Use the stored to_server_tx from connection
                                if connection.send_to_server(message).await.is_err() {
                                    connection.log_error("Failed to send binary message to server, terminating");
                                    break;
                                }
                            }
                            Ok(WsMessage::Close(close_frame)) => {
                                let (code, reason) = if let Some(frame) = close_frame {
                                    (Some(frame.code.into()), Some(frame.reason.to_string()))
                                } else {
                                    (None, None)
                                };

                                connection.log_info(&format!("Local WebSocket closed: code={:?}, reason={:?}", code, reason));

                                let message = Message::WebSocketClose {
                                    connection_id: connection.connection_id.clone(),
                                    code,
                                    reason,
                                };
                                let _ = connection.send_to_server(message).await;
                                break;
                            }
                            Err(e) => {
                                connection.log_error(&format!("Local WebSocket error: {}", e));
                                break;
                            }
                            _ => {}
                        }
                    }

                    // Cleanup on task end with connection age info
                    let final_status = {
                        let websockets = active_websockets_clone.read().await;
                        if let Some(conn) = websockets.get(&connection_id) {
                            conn.status_summary().await
                        } else {
                            format!("Connection {} (already cleaned up)", connection_id)
                        }
                    };

                    active_websockets_clone.write().await.remove(&connection_id);
                    info!("🔌 Local-to-server task ended: {}", final_status);
                })
            };

            // Forward FROM server TO local service
            let server_to_local_task = {
                let connection = connection_clone.clone();

                tokio::spawn(async move {
                    connection.log_info("Started server-to-local forwarding task");

                    while let Some(data) = local_rx.recv().await {
                        let ws_message = if let Ok(text) = String::from_utf8(data.clone()) {
                            WsMessage::Text(text.into())
                        } else {
                            WsMessage::Binary(data.into())
                        };

                        if local_sink.send(ws_message).await.is_err() {
                            connection.log_error("Failed to send to local WebSocket, terminating");
                            break;
                        }
                    }

                    connection.log_info(&format!("Server-to-local task ended ({})", connection.status_summary().await));
                })
            };

            // Connection monitoring task
            let monitoring_task = {
                let active_websockets = active_websockets.clone();
                let connection_id = connection_id.clone();
                let monitoring_interval = Duration::from_secs(config.client.websocket_monitoring_interval_secs);
                let max_idle = Duration::from_secs(config.client.websocket_max_idle_secs);

                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(monitoring_interval); // Check every 30 seconds

                    loop {
                        interval.tick().await;

                        let should_cleanup = {
                            let websockets = active_websockets.read().await;
                            if let Some(connection) = websockets.get(&connection_id) {
                                if connection.is_idle(max_idle).await {
                                    connection.log_warn(&format!("Connection timeout detected ({})", connection.status_summary().await));
                                    true
                                } else {
                                    // Log periodic status
                                    connection.log_info(&format!("Health check: {}", connection.status_summary().await));
                                    false
                                }
                            } else {
                                // Connection already cleaned up
                                true
                            }
                        };

                        if should_cleanup {
                            break;
                        }
                    }

                    info!("🔌 Monitoring task ended for {}", connection_id);
                })
            };

            // Wait for any task to complete
            tokio::select! {
                _ = local_to_server_task => {
                    info!("Local-to-server task completed for {}", connection_id);
                }
                _ = server_to_local_task => {
                    info!("Server-to-local task completed for {}", connection_id);
                }
                _ = monitoring_task => {
                    info!("Monitoring task completed for {}", connection_id);
                }
            }

            // Final cleanup
            {
                let mut websockets = active_websockets.write().await;
                if let Some(connection) = websockets.remove(&connection_id) {
                    connection.log_info(&format!("Final cleanup: {}", connection.status_summary().await));
                }
            }

            info!("🔌 WebSocket connection {} fully closed", connection_id);
        }
        Ok(Err(e)) => {
            error!("❌ Failed to connect to local WebSocket service {}: {}", connection_id, e);
            send_websocket_error_response(to_server_tx, connection_id, 502, "Connection failed").await;
        }
        Err(_) => {
            error!("❌ Connection timeout for WebSocket {}", connection_id);
            send_websocket_error_response(to_server_tx, connection_id, 504, "Connection timeout").await;
        }
    }
}

async fn send_websocket_error_response(
    to_server_tx: &mpsc::UnboundedSender<Message>,
    connection_id: String,
    status: u16,
    reason: &str,
) {
    let mut headers = HashMap::new();
    headers.insert("X-Error-Reason".to_string(), reason.to_string());

    let error_response = Message::WebSocketUpgradeResponse {
        connection_id,
        status,
        headers,
    };

    if let Err(e) = to_server_tx.send(error_response) {
        error!("Failed to send WebSocket error response: {}", e);
    }
}

// Handle WebSocket data from server (forward to local service)
async fn handle_websocket_data(
    active_websockets: ActiveWebSockets,
    connection_id: String,
    data: String,
) {
    if let Some(connection) = active_websockets.read().await.get(&connection_id) {
        connection.update_activity().await;
        // Decode base64 data
        match base64::engine::general_purpose::STANDARD.decode(&data) {
            Ok(binary_data) => {
                let data_size = binary_data.len();

                // Use connection method for proper error handling and logging
                if connection.send_to_local(binary_data).await.is_ok() {
                    connection.log_debug(&format!("Forwarded {} bytes to local WebSocket", data_size));
                } else {
                    // Connection method already logged the error
                    // Remove dead connection
                    active_websockets.write().await.remove(&connection_id);
                    connection.log_error("Failed to forward data to local WebSocket");
                }
            }
            Err(e) => {
                if let Some(connection) = active_websockets.read().await.get(&connection_id) {
                    connection.log_error(&format!("Failed to decode WebSocket data: {}", e));
                }
            }
        }
    } else {
        warn!("Received data for unknown WebSocket connection: {}", connection_id);
    }
}

// Handle WebSocket close
async fn handle_websocket_close(
    active_websockets: ActiveWebSockets,
    connection_id: String,
    code: Option<u16>,
    reason: Option<String>,
) {
    if let Some(connection) = active_websockets.write().await.remove(&connection_id) {
        connection.log_info(&format!(
            "WebSocket closed by server: code={:?}, reason={:?}, final_status={}",
            code, reason, connection.status_summary().await
        ));
    } else {
        warn!("Attempted to close unknown WebSocket connection: {}", connection_id);
    }
}

async fn cleanup_expired_connections(
    active_websockets: ActiveWebSockets,
    max_idle_time: Duration,
) -> usize {
    let mut cleanup_count = 0;
    let mut to_remove = Vec::new();

    {
        let websockets = active_websockets.read().await;
        for (id, connection) in websockets.iter() {
            if connection.is_idle(max_idle_time).await {
                connection.log_warn(&format!(
                    "Marking for cleanup: {} (idle: {}s, max_idle: {}s)",
                    connection.status_summary().await,
                    connection.idle_time().await.as_secs(),
                    max_idle_time.as_secs()
                ));
                to_remove.push(id.clone());
            }
        }
    }

    {
        let mut websockets = active_websockets.write().await;
        for id in to_remove {
            if let Some(connection) = websockets.remove(&id) {
                connection.log_info(&format!("Cleaned up idle connection (max_idle: {}s)", max_idle_time.as_secs()));
                cleanup_count += 1;
            }
        }
    }

    if cleanup_count > 0 {
        info!("🧹 Cleaned up {} idle WebSocket connections (max_idle: {}s)", cleanup_count, max_idle_time.as_secs());
    }

    cleanup_count
}