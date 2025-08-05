// src/bin/client.rs
use bytes::Bytes;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use reqwest::Client as HttpClient;
use rustls::ClientConfig as RustlsClientConfig;
use tokio::signal;
use tokio::sync::{RwLock, mpsc};
use tokio::time::timeout;
use tokio_tungstenite::Connector;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use tracing::{debug, error, info, warn};

use exposeme::insecure_cert::InsecureCertVerifier;
use exposeme::{ClientArgs, ClientConfig, Message, initialize_tracing};

type OutgoingRequests = Arc<RwLock<HashMap<String, mpsc::Sender<Result<Bytes, std::io::Error>>>>>;
type ActiveWebSockets = Arc<RwLock<HashMap<String, ActiveWebSocketConnection>>>;

#[derive(Debug, Clone)]
struct ActiveWebSocketConnection {
    connection_id: String,
    local_tx: mpsc::UnboundedSender<Vec<u8>>,
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

    async fn update_activity(&self) {
        *self.last_activity.write().await = std::time::Instant::now();
    }

    async fn is_idle(&self, max_idle: Duration) -> bool {
        self.last_activity.read().await.elapsed() > max_idle
    }

    async fn send_to_server(&self, message: Message) -> Result<(), String> {
        self.update_activity().await;
        self.to_server_tx
            .send(message)
            .map_err(|e| format!("Server send failed: {}", e))
    }

    async fn send_to_local(&self, data: Vec<u8>) -> Result<(), String> {
        self.update_activity().await;
        self.local_tx
            .send(data)
            .map_err(|e| format!("Local send failed: {}", e))
    }

    fn age_str(&self) -> String {
        let secs = self.created_at.elapsed().as_secs();
        if secs < 60 {
            format!("{}s", secs)
        } else if secs < 3600 {
            format!("{}m", secs / 60)
        } else {
            format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring CryptoProvider");

    tokio::spawn(async {
        signal::ctrl_c()
            .await
            .expect("Failed to install Ctrl+C handler");
        info!("🛑 Received Ctrl+C, shutting down...");
        std::process::exit(0);
    });

    let args = ClientArgs::parse();
    initialize_tracing(args.verbose);

    if args.generate_config {
        ClientConfig::generate_default_file(&args.config)?;
        return Ok(());
    }

    let config = ClientConfig::load(&args)?;
    info!("Loaded config from {:?}", args.config);
    info!(
        "Server: {} | Tunnel: {} | Target: {}",
        config.client.server_url, config.client.tunnel_id, config.client.local_target
    );

    loop {
        match run_client(&config).await {
            Ok(_) => {
                info!("Client disconnected normally");
                break;
            }
            Err(e) => {
                error!("Client error: {}", e);
                if !config.client.auto_reconnect {
                    break;
                }
                info!("Reconnecting in {}s...", config.client.reconnect_delay_secs);
                tokio::time::sleep(Duration::from_secs(config.client.reconnect_delay_secs)).await;
            }
        }
    }
    Ok(())
}

async fn run_client(config: &ClientConfig) -> Result<(), Box<dyn std::error::Error>> {
    let (ws_stream, _) = if config.client.insecure && config.client.server_url.starts_with("wss://")
    {
        warn!("⚠️  Using insecure connection (development only)");
        let tls_config = RustlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier))
            .with_no_client_auth();
        tokio_tungstenite::connect_async_tls_with_config(
            &config.client.server_url,
            None,
            false,
            Some(Connector::Rustls(Arc::new(tls_config))),
        )
        .await?
    } else {
        connect_async(&config.client.server_url).await?
    };

    info!("Connected to WebSocket server");
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    // Authentication
    ws_sender
        .send(WsMessage::Text(
            Message::Auth {
                token: config.client.auth_token.clone(),
                tunnel_id: config.client.tunnel_id.clone(),
            }
            .to_json()?
            .into(),
        ))
        .await?;
    info!(
        "Sent authentication for tunnel '{}'",
        config.client.tunnel_id
    );

    let http_client = HttpClient::new();
    let active_websockets: ActiveWebSockets = Arc::new(RwLock::new(HashMap::new()));
    let outgoing_requests: OutgoingRequests = Arc::new(RwLock::new(HashMap::new()));
    let (to_server_tx, mut to_server_rx) = mpsc::unbounded_channel::<Message>();

    // Outgoing message handler
    tokio::spawn(async move {
        while let Some(message) = to_server_rx.recv().await {
            if let Ok(json) = message.to_json() {
                if ws_sender.send(WsMessage::Text(json.into())).await.is_err() {
                    break;
                }
            }
        }
    });

    // Cleanup task
    let cleanup_websockets = active_websockets.clone();
    let cleanup_interval = Duration::from_secs(config.client.websocket_cleanup_interval_secs);
    let max_idle = Duration::from_secs(config.client.websocket_max_idle_secs);
    let _cleanup_task = tokio::spawn(async move {
        let mut interval = tokio::time::interval(cleanup_interval);
        loop {
            interval.tick().await;
            let mut to_remove = Vec::new();
            {
                let websockets = cleanup_websockets.read().await;
                for (id, conn) in websockets.iter() {
                    if conn.is_idle(max_idle).await {
                        to_remove.push(id.clone());
                    }
                }
            }
            if !to_remove.is_empty() {
                let mut websockets = cleanup_websockets.write().await;
                for id in &to_remove {
                    websockets.remove(id);
                }
                info!(
                    "🧹 Cleaned up {} idle WebSocket connections",
                    to_remove.len()
                );
            }
        }
    });

    // Main message processing loop
    while let Some(message) = ws_receiver.next().await {
        if let Ok(WsMessage::Text(text)) = message {
            debug!("📨 Received message: {} bytes", text.len());
            if let Ok(msg) = Message::from_json(&text.to_string()) {
                match msg {
                    Message::AuthSuccess {
                        tunnel_id,
                        public_url,
                    } => {
                        info!(
                            "✅ Tunnel '{}' established! Public: {}",
                            tunnel_id, public_url
                        );
                        info!("🔄 Forwarding to: {}", config.client.local_target);
                    }
                    Message::AuthError { error, message } => {
                        error!("❌ Auth failed: {} - {}", error, message);
                        return Err(format!("Auth error: {}", message).into());
                    }
                    Message::HttpRequestStart {
                        id,
                        method,
                        path,
                        headers,
                        initial_data,
                        is_complete,
                    } => {
                        info!(
                            "📥 HTTP {} {} (id: {}, complete: {:?}, {} bytes)",
                            method,
                            path,
                            id,
                            is_complete,
                            initial_data.len()
                        );
                        handle_http_request(
                            id,
                            method,
                            path,
                            headers,
                            initial_data,
                            is_complete,
                            &http_client,
                            &config.client.local_target,
                            &to_server_tx,
                            &outgoing_requests,
                        )
                        .await;
                    }
                    Message::DataChunk { id, data, is_final } => {
                        debug!(
                            "📥 DataChunk: {} bytes, final={} (id: {})",
                            data.len(),
                            is_final,
                            id
                        );
                        handle_data_chunk(&outgoing_requests, id, data, is_final).await;
                    }
                    Message::WebSocketUpgrade {
                        connection_id,
                        method,
                        path,
                        headers,
                    } => {
                        debug!(
                            "📥 WebSocket upgrade: {} {} (conn: {})",
                            method, path, connection_id
                        );
                        let local_target = config.client.local_target.clone();
                        let to_server_tx = to_server_tx.clone();
                        let active_websockets = active_websockets.clone();
                        let config = config.clone();
                        tokio::spawn(async move {
                            handle_websocket_upgrade(
                                local_target,
                                to_server_tx,
                                active_websockets,
                                connection_id,
                                method,
                                path,
                                headers,
                                config,
                            )
                            .await;
                        });
                    }
                    Message::WebSocketData {
                        connection_id,
                        data,
                    } => {
                        debug!(
                            "📥 WebSocket data: {} ({} bytes)",
                            connection_id,
                            data.len()
                        );
                        if let Some(conn) = active_websockets.read().await.get(&connection_id) {
                            if let Ok(binary_data) =
                                base64::engine::general_purpose::STANDARD.decode(&data)
                            {
                                let _ = conn.send_to_local(binary_data).await;
                            }
                        }
                    }
                    Message::WebSocketClose { connection_id, .. } => {
                        active_websockets.write().await.remove(&connection_id);
                        info!("🔌 WebSocket {} closed", connection_id);
                    }
                    Message::Error { message } => error!("Server error: {}", message),
                    _ => warn!("Unexpected message type"),
                }
            }
        } else if matches!(message, Ok(WsMessage::Close(_))) {
            info!("WebSocket closed by server");
            break;
        } else if let Err(e) = message {
            error!("WebSocket error: {}", e);
            break;
        }
    }

    info!("Client connection ended");
    Ok(())
}

async fn handle_http_request(
    id: String,
    method: String,
    path: String,
    headers: HashMap<String, String>,
    initial_data: Vec<u8>,
    is_complete: Option<bool>,
    http_client: &HttpClient,
    local_target: &str,
    to_server_tx: &mpsc::UnboundedSender<Message>,
    outgoing_requests: &OutgoingRequests,
) {
    let url = format!("{}{}", local_target, path);
    let to_server_tx = to_server_tx.clone();
    let id_clone = id.clone();
    let http_client = http_client.clone();

    // Check if this is likely an SSE request
    let is_sse_request = headers
        .get("accept")
        .map(|accept| accept.contains("text/event-stream"))
        .unwrap_or(false);

    if is_complete == Some(true) && !is_sse_request {
        // Complete request (non-SSE)
        debug!("📦 Processing complete request: {} {}", method, path);
        let mut request = create_request(&http_client, &method, &url, &headers);
        if !initial_data.is_empty() {
            request = request.body(initial_data);
        }

        tokio::spawn(async move {
            match request.send().await {
                Ok(response) => {
                    debug!("✅ Complete request succeeded: {} {}", method, path);
                    stream_response(&to_server_tx, id_clone, response).await;
                }
                Err(e) => {
                    error!("❌ Complete request failed: {} {}: {}", method, path, e);
                    send_error_response(&to_server_tx, id_clone, e.to_string()).await;
                }
            }
        });
    } else {
        // Streaming request (or SSE)
        let request_type = if is_sse_request { "SSE" } else { "streaming" };
        debug!(
            "📥 Processing {} request: {} {}",
            request_type, method, path
        );

        let (body_tx, body_rx) = mpsc::channel(32);
        if !initial_data.is_empty() {
            debug!("📦 Sending initial data: {} bytes", initial_data.len());
            let _ = body_tx.send(Ok(initial_data.into())).await;
        }

        outgoing_requests
            .write()
            .await
            .insert(id.clone(), body_tx.clone());
        debug!("✅ Registered {} request: {}", request_type, id);

        tokio::spawn(async move {
            let mut request = create_request(&http_client, &method, &url, &headers);
            if ["POST", "PUT", "PATCH"].contains(&method.as_str()) {
                request = request.body(reqwest::Body::wrap_stream(
                    tokio_stream::wrappers::ReceiverStream::new(body_rx),
                ));
            }
            drop(body_tx);

            match request.send().await {
                Ok(response) => {
                    debug!("✅ {} request succeeded: {} {}", request_type, method, path);
                    stream_response(&to_server_tx, id_clone, response).await;
                }
                Err(e) => {
                    error!(
                        "❌ {} request failed: {} {}: {}",
                        request_type, method, path, e
                    );
                    send_error_response(&to_server_tx, id_clone, e.to_string()).await;
                }
            }
        });
    }
}

async fn handle_data_chunk(requests: &OutgoingRequests, id: String, data: Vec<u8>, is_final: bool) {
    if let Some(tx) = requests.read().await.get(&id).cloned() {
        if !data.is_empty() {
            let _ = tx.send(Ok(data.into())).await;
        }
        if is_final {
            requests.write().await.remove(&id);
            debug!("✅ Streaming request completed: {}", id);
        }
    } else {
        warn!("❌ Received DataChunk for unknown request: {}", id);
    }
}

async fn stream_response(
    to_server_tx: &mpsc::UnboundedSender<Message>,
    id: String,
    response: reqwest::Response,
) {
    let status = response.status().as_u16();
    let headers: HashMap<String, String> = response
        .headers()
        .iter()
        .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    // Check for SSE, chunked encoding, or large responses
    let should_stream = response
        .headers()
        .get("content-type")
        .and_then(|h| h.to_str().ok())
        .map(|ct| ct.contains("text/event-stream"))
        .unwrap_or(false)
        || response
            .headers()
            .get("transfer-encoding")
            .and_then(|h| h.to_str().ok())
            .map(|te| te.contains("chunked"))
            .unwrap_or(false)
        || response
            .content_length()
            .map(|len| len > 256 * 1024)
            .unwrap_or(true);

    debug!(
        "📤 Response {}: {} (streaming: {})",
        id, status, should_stream
    );

    if !should_stream {
        // Complete response
        debug!("📦 Processing as complete response: {}", id);
        if let Ok(bytes) = response.bytes().await {
            debug!(
                "📤 Sending complete response: {} ({} bytes)",
                id,
                bytes.len()
            );
            let _ = to_server_tx.send(Message::HttpResponseStart {
                id,
                status,
                headers,
                initial_data: bytes.to_vec(),
                is_complete: Some(true),
            });
        }
    } else {
        // Streaming response (including SSE)
        debug!("🔄 Processing as streaming response: {}", id);
        let _ = to_server_tx.send(Message::HttpResponseStart {
            id: id.clone(),
            status,
            headers,
            initial_data: vec![],
            is_complete: Some(false),
        });

        let mut stream = response.bytes_stream();
        let mut chunk_count = 0;
        while let Some(Ok(chunk)) = stream.next().await {
            chunk_count += 1;
            if chunk_count % 10 == 0 {
                debug!(
                    "📤 Streaming chunk #{} ({} bytes) for {}",
                    chunk_count,
                    chunk.len(),
                    id
                );
            }
            let _ = to_server_tx.send(Message::DataChunk {
                id: id.clone(),
                data: chunk.to_vec(),
                is_final: false,
            });
        }
        debug!("✅ Streaming completed: {} ({} chunks)", id, chunk_count);
        let _ = to_server_tx.send(Message::DataChunk {
            id,
            data: vec![],
            is_final: true,
        });
    }
}

async fn send_error_response(
    to_server_tx: &mpsc::UnboundedSender<Message>,
    id: String,
    error: String,
) {
    let _ = to_server_tx.send(Message::HttpResponseStart {
        id,
        status: 502,
        headers: HashMap::new(),
        initial_data: error.into_bytes(),
        is_complete: Some(true),
    });
}

fn create_request(
    client: &HttpClient,
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
) -> reqwest::RequestBuilder {
    let mut request = match method {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        "PATCH" => client.patch(url),
        "HEAD" => client.head(url),
        _ => client.get(url),
    };

    for (name, value) in headers {
        if !["host", "content-length", "connection", "user-agent"]
            .contains(&name.to_lowercase().as_str())
        {
            request = request.header(name, value);
        }
    }
    request
}

async fn handle_websocket_upgrade(
    local_target: String,
    to_server_tx: mpsc::UnboundedSender<Message>,
    active_websockets: ActiveWebSockets,
    connection_id: String,
    _method: String,
    path: String,
    _headers: HashMap<String, String>,
    config: ClientConfig,
) {
    let ws_url = local_target
        .replace("http://", "ws://")
        .replace("https://", "wss://")
        + &path;
    debug!("🔗 Connecting to local WebSocket: {}", ws_url);
    let connect_timeout = Duration::from_secs(config.client.websocket_connection_timeout_secs);

    match timeout(connect_timeout, connect_async(&ws_url)).await {
        Ok(Ok((local_ws, response))) => {
            debug!("✅ Connected to local WebSocket: {}", connection_id);

            // Send upgrade response
            let response_headers: HashMap<String, String> = response
                .headers()
                .iter()
                .map(|(n, v)| (n.to_string(), v.to_str().unwrap_or("").to_string()))
                .collect();

            let _ = to_server_tx.send(Message::WebSocketUpgradeResponse {
                connection_id: connection_id.clone(),
                status: response.status().as_u16(),
                headers: response_headers,
            });

            let (mut local_sink, mut local_stream) = local_ws.split();
            let (local_tx, mut local_rx) = mpsc::unbounded_channel();
            let connection = ActiveWebSocketConnection::new(
                connection_id.clone(),
                local_tx,
                to_server_tx.clone(),
            );

            // Store connection
            active_websockets
                .write()
                .await
                .insert(connection_id.clone(), connection.clone());
            info!(
                "🔌 WebSocket {} established (age: {})",
                connection_id,
                connection.age_str()
            );

            let connection_clone = connection.clone();
            let active_websockets_clone = active_websockets.clone();
            let connection_id_clone = connection_id.clone();
            let connection_id_clone2 = connection_id.clone();

            // Local to server task
            let local_to_server = tokio::spawn(async move {
                debug!(
                    "🔌 WebSocket {}: Started local-to-server task",
                    connection_id_clone
                );
                while let Some(Ok(msg)) = local_stream.next().await {
                    let message = match msg {
                        WsMessage::Text(text) => {
                            debug!(
                                "🔌 WebSocket {}: Forwarding text ({} chars)",
                                connection_id_clone,
                                text.len()
                            );
                            Message::WebSocketData {
                                connection_id: connection_clone.connection_id.clone(),
                                data: base64::engine::general_purpose::STANDARD
                                    .encode(text.as_bytes()),
                            }
                        }
                        WsMessage::Binary(bytes) => {
                            debug!(
                                "🔌 WebSocket {}: Forwarding binary ({} bytes)",
                                connection_id_clone,
                                bytes.len()
                            );
                            Message::WebSocketData {
                                connection_id: connection_clone.connection_id.clone(),
                                data: base64::engine::general_purpose::STANDARD.encode(&bytes),
                            }
                        }
                        WsMessage::Close(frame) => {
                            let (code, reason) = frame
                                .map(|f| (Some(f.code.into()), Some(f.reason.to_string())))
                                .unwrap_or((None, None));
                            info!(
                                "🔌 WebSocket {}: Local close code={:?}",
                                connection_id_clone, code
                            );
                            Message::WebSocketClose {
                                connection_id: connection_clone.connection_id.clone(),
                                code,
                                reason,
                            }
                        }
                        _ => continue,
                    };
                    if connection_clone.send_to_server(message).await.is_err() {
                        break;
                    }
                }
                active_websockets_clone
                    .write()
                    .await
                    .remove(&connection_id_clone);
                debug!(
                    "🔌 WebSocket {}: Local-to-server task ended",
                    connection_id_clone
                );
            });

            // Server to local task
            let server_to_local = tokio::spawn(async move {
                debug!(
                    "🔌 WebSocket {}: Started server-to-local task",
                    connection_id_clone2
                );
                while let Some(data) = local_rx.recv().await {
                    let ws_message = if let Ok(text) = String::from_utf8(data.clone()) {
                        WsMessage::Text(text.into())
                    } else {
                        WsMessage::Binary(data.into())
                    };
                    if local_sink.send(ws_message).await.is_err() {
                        break;
                    }
                }
                debug!(
                    "🔌 WebSocket {}: Server-to-local task ended",
                    connection_id_clone2
                );
            });

            tokio::select! { _ = local_to_server => {}, _ = server_to_local => {} }
            active_websockets.write().await.remove(&connection_id);
            info!("🔌 WebSocket {} closed", connection_id);
        }
        Ok(Err(e)) => {
            error!(
                "❌ Failed to connect to local WebSocket {}: {}",
                connection_id, e
            );
            let _ = to_server_tx.send(Message::WebSocketUpgradeResponse {
                connection_id,
                status: 502,
                headers: HashMap::new(),
            });
        }
        Err(_) => {
            error!("❌ Connection timeout for WebSocket {}", connection_id);
            let _ = to_server_tx.send(Message::WebSocketUpgradeResponse {
                connection_id,
                status: 504,
                headers: HashMap::new(),
            });
        }
    }
}
