// src/bin/client.rs
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use reqwest::Client as HttpClient;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage, MaybeTlsStream, WebSocketStream};
use base64::Engine;
use tokio::signal;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};

use exposeme::{ClientArgs, ClientConfig, Message};

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
#[derive(Debug)]
struct ActiveWebSocketConnection {
    connection_id: String,
    local_ws: WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>,
    to_server_tx: mpsc::UnboundedSender<Message>,
}

type ActiveWebSockets = Arc<RwLock<HashMap<String, ActiveWebSocketConnection>>>;

async fn run_client(config: &ClientConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Connect to WebSocket server
    let (ws_stream, _) = connect_async(&config.client.server_url).await?;
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

    // Store active WebSocket connections
    let active_websockets: ActiveWebSockets = Arc::new(RwLock::new(HashMap::new()));

    // Create channel for sending messages back to server
    let (to_server_tx, mut to_server_rx) = mpsc::unbounded_channel::<Message>();

    // Spawn task to handle outgoing messages to server
    // let ws_sender_clone = ws_sender.clone();
    tokio::spawn(async move {
        // let mut ws_sender = ws_sender_clone;
        while let Some(message) = to_server_rx.recv().await {
            if let Ok(json) = message.to_json() {
                if let Err(e) = ws_sender.send(WsMessage::Text(json.into())).await {
                    error!("Failed to send message to server: {}", e);
                    break;
                }
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

                        Message::HttpRequest {
                            id,
                            method,
                            path,
                            headers,
                            body,
                        } => {
                            info!("📥 Received request: {} {}", method, path);

                            // Spawn parallel task for each HTTP request
                            let http_client = http_client.clone();
                            let local_target = config.client.local_target.clone();
                            let to_server_tx = to_server_tx.clone();

                            tokio::spawn(async move {
                                handle_http_request_parallel(
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

                            tokio::spawn(async move {
                                handle_websocket_upgrade(
                                    &local_target,
                                    &to_server_tx,
                                    active_websockets,
                                    connection_id,
                                    method,
                                    path,
                                    headers,
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

    info!("Client connection ended");
    Ok(())
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
) {
    info!("🔌 Processing WebSocket upgrade for connection {}", connection_id);

    // Construct WebSocket URL for local service
    let ws_url = if local_target.starts_with("http://") {
        local_target.replace("http://", "ws://") + &path
    } else if local_target.starts_with("https://") {
        local_target.replace("https://", "wss://") + &path
    } else {
        format!("ws://{}{}", local_target, path)
    };

    info!("🔗 Connecting to local WebSocket: {}", ws_url);

    // Attempt to connect to local WebSocket service
    match connect_async(&ws_url).await {
        Ok((local_ws, response)) => {
            info!("✅ Connected to local WebSocket service");

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
                error!("Failed to send WebSocket upgrade response: {}", e);
                return;
            }

            // Store active connection
            let (local_read, local_write) = local_ws.split();

            // TODO: Set up bidirectional data forwarding
            // This requires more complex handling than shown here
            info!("🔄 WebSocket connection established, setting up data forwarding");

        }
        Err(e) => {
            error!("❌ Failed to connect to local WebSocket service: {}", e);

            // Send error response
            let error_response = Message::WebSocketUpgradeResponse {
                connection_id: connection_id.clone(),
                status: 502,
                headers: HashMap::new(),
            };

            if let Err(e) = to_server_tx.send(error_response) {
                error!("Failed to send WebSocket error response: {}", e);
            }
        }
    }
}

// Parallel HTTP request handling
async fn handle_http_request_parallel(
    http_client: &HttpClient,
    local_target: &str,
    to_server_tx: &mpsc::UnboundedSender<Message>,
    id: String,
    method: String,
    path: String,
    headers: HashMap<String, String>,
    body: String,
) {
    info!("📥 Processing HTTP request (parallel): {} {}", method, path);

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
            info!("📤 Sending HTTP response (parallel): {}", status);
            Message::HttpResponse {
                id,
                status,
                headers,
                body,
            }
        }
        Err(e) => {
            error!("❌ Failed to forward HTTP request (parallel): {}", e);
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
        error!("Failed to send HTTP response through channel: {}", e);
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
    let mut request_builder = match method {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        "PATCH" => client.patch(&url),
        "HEAD" => client.head(&url),
        _ => return Err(format!("Unsupported HTTP method: {}", method).into()),
    };

    // Add headers
    for (name, value) in headers {
        // Skip headers that reqwest handles automatically
        if !["host", "content-length", "connection", "user-agent"]
            .contains(&name.to_lowercase().as_str())
        {
            request_builder = request_builder.header(&name, &value);
        }
    }

    // Add body for methods that support it
    if ["POST", "PUT", "PATCH"].contains(&method) {
        request_builder = request_builder.body(body_bytes);
    }

    // Send request
    let response = request_builder.send().await?;

    // Extract response details
    let status = response.status().as_u16();

    // Extract response headers
    let mut response_headers = HashMap::new();
    for (name, value) in response.headers() {
        response_headers.insert(name.to_string(), value.to_str().unwrap_or("").to_string());
    }

    // Get response body
    let response_body = response.bytes().await?;
    let response_body_b64 = base64::engine::general_purpose::STANDARD.encode(&response_body);

    Ok((status, response_headers, response_body_b64))
}

// NEW: Handle WebSocket data from server (forward to local service)
async fn handle_websocket_data(
    active_websockets: ActiveWebSockets,
    connection_id: String,
    data: String,
) {
    if let Some(connection) = active_websockets.write().await.get_mut(&connection_id) {
        // Decode base64 data
        match base64::engine::general_purpose::STANDARD.decode(&data) {
            Ok(binary_data) => {
                // Forward to local WebSocket service
                // TODO: Implement data forwarding
                info!("📤 Forwarding {} bytes to local WebSocket", binary_data.len());
            }
            Err(e) => {
                error!("Failed to decode WebSocket data: {}", e);
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
    info!("🔌 Closing WebSocket connection: {} (code: {:?}, reason: {:?})", 
          connection_id, code, reason);

    if let Some(_connection) = active_websockets.write().await.remove(&connection_id) {
        info!("✅ WebSocket connection {} cleaned up", connection_id);
        // TODO: Properly close local WebSocket connection
    } else {
        warn!("Attempted to close unknown WebSocket connection: {}", connection_id);
    }
}
