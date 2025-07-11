// src/bin/server.rs
use clap::Parser;
use exposeme::{initialize_tracing, ServerArgs, ServerConfig, SslManager, SslProvider};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock};
use tracing::{error, info};
use exposeme::svc::{BoxError, TunnelMap, PendingRequests, ActiveWebSockets, start_http_server, start_https_server};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    // Set up crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring CryptoProvider");

    // Parse CLI arguments
    let args = ServerArgs::parse();

    initialize_tracing(args.verbose);

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
        info!("Staging: {}", config.ssl.staging);
        info!("DNS provider: {:?}", config.ssl.dns_provider);
    }
    info!("WebSocket server: {}", config.tunnel_ws_url());
    info!("Auth tokens: {} configured", config.auth.tokens.len());

    // Initialize SSL
    let ssl_manager = Arc::new(RwLock::new(SslManager::new(config.clone())));
    let challenge_store = ssl_manager.read().await.get_challenge_store();

    info!("Starting ExposeME Server...");

    // Shared state
    let tunnels: TunnelMap = Arc::new(RwLock::new(HashMap::new()));
    let pending_requests: PendingRequests = Arc::new(RwLock::new(HashMap::new()));
    let active_websockets: ActiveWebSockets = Arc::new(RwLock::new(HashMap::new()));

    // Clone for servers
    let tunnels_http = tunnels.clone();
    let pending_requests_http = pending_requests.clone();
    let active_websockets_http = active_websockets.clone();
    let config_http = config.clone();
    let challenge_store_http = challenge_store.clone();
    let ssl_manager_http = ssl_manager.clone();

    // Start HTTP server (for redirects and ACME challenges)
    let http_handle = tokio::spawn(async move {
        if let Err(e) = start_http_server(
            config_http,
            tunnels_http,
            pending_requests_http,
            active_websockets_http,
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
        let active_websockets_https = active_websockets.clone();
        let config_https = config.clone();
        let ssl_config_for_https = ssl_manager.read().await.get_rustls_config().unwrap();
        let ssl_manager_https = ssl_manager.clone();

        Some(tokio::spawn(async move {
            if let Err(e) = start_https_server(
                config_https,
                tunnels_https,
                pending_requests_https,
                active_websockets_https,
                ssl_manager_https,
                ssl_config_for_https,
            ).await {
                error!("❌ HTTPS server error: {}", e);
            }
        }))
    } else {
        None
    };

    let renew_handle = if config.ssl.enabled && config.ssl.provider != SslProvider::Manual {
        Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
            loop {
                interval.tick().await;
                info!(
                    "🔍 Daily certificate renewal check for {}",
                    config.server.domain
                );
                let mut manager = ssl_manager.write().await;
                match manager.get_certificate_info() {
                    Ok(info) => {
                        if let Some(days_until_expiry) = info.days_until_expiry {
                            info!(
                                "📅 Certificate for {} expires in {} days",
                                config.server.domain, days_until_expiry
                            );
                            if info.needs_renewal {
                                if let Err(e) = manager.force_renewal().await {
                                    error!("Failed to renew certificate: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to get certificate info: {}", e);
                    }
                }
            }
        }))
    } else {
        None
    };

    // Wait for all servers
    match https_handle {
        Some(https_handle) => match renew_handle {
            Some(renew_handle) => {
                tokio::select! {
                    _ = http_handle => info!("HTTP server terminated"),
                    _ = https_handle => info!("HTTPS server terminated"),
                    _ = renew_handle => info!("Renewal task terminated"),
                }
            }
            None => {
                tokio::select! {
                    _ = http_handle => info!("HTTP server terminated"),
                    _ = https_handle => info!("HTTPS server terminated"),
                }
            }
        },
        None => {
            tokio::select! {
                _ = http_handle => info!("HTTP server terminated"),
            }
        }
    }

    info!("🛑 ExposeME server shutting down");
    Ok(())
}

async fn wait_for_http_server_ready(config: &ServerConfig) -> Result<(), BoxError> {
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

// async fn handle_websocket_connection<S>(
//     stream: S,
//     tunnels: TunnelMap,
//     pending_requests: PendingRequests,
//     active_websockets: ActiveWebSockets,
//
//     config: ServerConfig,
// ) -> Result<(), BoxError>
// where
//     S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
// {
//     let ws_stream = accept_async(stream).await?;
//     let (mut ws_sender, mut ws_receiver) = ws_stream.split();
//
//     // Create channel for outgoing messages
//     let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
//
//     // Spawn task to handle outgoing messages
//     let outgoing_task = tokio::spawn(async move {
//         while let Some(message) = rx.recv().await {
//             if let Ok(json) = message.to_json() {
//                 if ws_sender.send(WsMessage::Text(json.into())).await.is_err() {
//                     break;
//                 }
//             }
//         }
//     });
//
//     let mut tunnel_id: Option<String> = None;
//
//     // Handle incoming messages
//     while let Some(message) = ws_receiver.next().await {
//         match message {
//             Ok(WsMessage::Text(text)) => {
//                 if let Ok(msg) = Message::from_json(&text.to_string()) {
//                     match msg {
//                         Message::Auth {
//                             token,
//                             tunnel_id: requested_tunnel_id,
//                         } => {
//                             info!("Auth request for tunnel '{}'", requested_tunnel_id);
//
//                             // Validate tunnel ID
//                             if let Err(e) = config.validate_tunnel_id(&requested_tunnel_id) {
//                                 let error_msg = Message::AuthError {
//                                     error: "invalid_tunnel_id".to_string(),
//                                     message: format!("Invalid tunnel ID: {}", e),
//                                 };
//                                 if let Err(err) = tx.send(error_msg) {
//                                     error!(
//                                         "Failed to send tunnel ID validation error to client: {}",
//                                         err
//                                     );
//                                     break;
//                                 }
//                                 tokio::time::sleep(Duration::from_millis(500)).await;
//                                 break;
//                             }
//
//                             // Token validation using config
//                             if !config.auth.tokens.contains(&token) {
//                                 let error_msg = Message::AuthError {
//                                     error: "invalid_token".to_string(),
//                                     message: "Invalid authentication token".to_string(),
//                                 };
//                                 if let Err(err) = tx.send(error_msg) {
//                                     error!("Failed to send auth error to client: {}", err);
//                                     break;
//                                 }
//                                 tokio::time::sleep(Duration::from_millis(500)).await;
//                                 break;
//                             }
//
//                             // Check if tunnel_id is already taken
//                             {
//                                 let tunnels_guard = tunnels.read().await;
//                                 if tunnels_guard.contains_key(&requested_tunnel_id) {
//                                     let error_msg = Message::AuthError {
//                                         error: "tunnel_id_taken".to_string(),
//                                         message: format!(
//                                             "Tunnel ID '{}' is already in use",
//                                             requested_tunnel_id
//                                         ),
//                                     };
//                                     if let Err(err) = tx.send(error_msg) {
//                                         error!(
//                                             "Failed to send tunnel_taken error to client: {}",
//                                             err
//                                         );
//                                         break;
//                                     }
//                                     tokio::time::sleep(Duration::from_millis(500)).await;
//                                     break;
//                                 }
//                             }
//
//                             // Check max tunnels limit
//                             {
//                                 let tunnels_guard = tunnels.read().await;
//                                 if tunnels_guard.len() >= config.limits.max_tunnels {
//                                     let error_msg = Message::AuthError {
//                                         error: "max_tunnels_reached".to_string(),
//                                         message: format!(
//                                             "Maximum number of tunnels ({}) reached",
//                                             config.limits.max_tunnels
//                                         ),
//                                     };
//                                     if let Err(err) = tx.send(error_msg) {
//                                         error!(
//                                             "Failed to send max_tunnels error to client: {}",
//                                             err
//                                         );
//                                         break;
//                                     }
//                                     tokio::time::sleep(Duration::from_millis(500)).await;
//                                     break;
//                                 }
//                             }
//
//                             // Register tunnel
//                             {
//                                 let mut tunnels_guard = tunnels.write().await;
//                                 tunnels_guard.insert(requested_tunnel_id.clone(), tx.clone());
//                             }
//
//                             tunnel_id = Some(requested_tunnel_id.clone());
//
//                             let success_msg = Message::AuthSuccess {
//                                 tunnel_id: requested_tunnel_id.clone(),
//                                 public_url: config.get_public_url(&requested_tunnel_id),
//                             };
//
//                             if let Err(err) = tx.send(success_msg) {
//                                 error!("Failed to send auth success to client: {}", err);
//                                 break;
//                             }
//                             info!("Tunnel '{}' registered successfully", requested_tunnel_id);
//                         }
//
//                         Message::HttpResponse {
//                             id,
//                             status,
//                             headers,
//                             body,
//                         } => {
//                             // Find pending request and send response
//                             let response_sender = {
//                                 let mut pending = pending_requests.write().await;
//                                 pending.remove(&id)
//                             };
//
//                             if let Some(sender) = response_sender {
//                                 let _ = sender.send((status, headers, body));
//                             }
//                         }
//
//                         Message::WebSocketUpgradeResponse { connection_id, status, headers: _ } => {
//                             info!("📡 Received WebSocket upgrade response: {} (status: {})", connection_id, status);
//
//                             // For now, just log the response - the upgrade is already handled
//                             if status == 101 {
//                                 info!("✅ WebSocket upgrade successful for {}", connection_id);
//                             } else {
//                                 warn!("❌ WebSocket upgrade failed for {}: status {}", connection_id, status);
//                                 // Clean up failed connection
//                                 active_websockets.write().await.remove(&connection_id);
//                             }
//                         }
//
//                         Message::WebSocketData { connection_id, data } => {
//                             if let Some(connection) = active_websockets.read().await.get(&connection_id) {
//                                 debug!("📡 Received data for {} (age: {}, {} bytes)", connection_id, connection.age_info(), data.len());
//                                 if let Some(ws_tx) = &connection.ws_tx {
//                                     match base64::engine::general_purpose::STANDARD.decode(&data) {
//                                         Ok(binary_data) => {
//                                             let ws_message = if let Ok(text) = String::from_utf8(binary_data.clone()) {
//                                                 WsMessage::Text(text.into())
//                                             } else {
//                                                 WsMessage::Binary(binary_data.into())
//                                             };
//
//                                             if let Err(e) = ws_tx.send(ws_message) {
//                                                 error!("Failed to forward WebSocket data to client {}: {}", connection_id, e);
//                                                 // active_websockets.write().await.remove(&connection_id);
//                                             }
//                                         }
//                                         Err(e) => {
//                                             error!("Failed to decode WebSocket data for {}: {}", connection_id, e);
//                                         }
//                                     }
//                                 }
//                             } else {
//                                 warn!("Received data for unknown WebSocket connection: {}", connection_id);
//                             }
//                         }
//
//                         Message::WebSocketClose { connection_id, code, reason } => {
//                             if let Some(connection) = active_websockets.write().await.remove(&connection_id) {
//                                 info!("📡 Close for {}: code={:?}, reason={:?}, final_status={}", connection_id, code, reason, connection.status_summary());                                if let Some(ws_tx) = &connection.ws_tx {
//                                     let close_frame = if let Some(code) = code {
//                                         Some(tokio_tungstenite::tungstenite::protocol::CloseFrame {
//                                             code: code.into(),
//                                             reason: reason.unwrap_or_default().into(),
//                                         })
//                                     } else {
//                                         None
//                                     };
//
//                                     let _ = ws_tx.send(WsMessage::Close(close_frame));
//                                 }
//                                 info!("✅ Cleaned up WebSocket connection {}", connection_id);
//                             }
//                         }
//
//                         _ => {
//                             warn!("Unexpected message type from client");
//                         }
//                     }
//                 }
//             }
//             Ok(WsMessage::Close(_)) => {
//                 info!("WebSocket connection closed");
//                 break;
//             }
//             Err(e) => {
//                 error!("WebSocket error: {}", e);
//                 break;
//             }
//             _ => {}
//         }
//     }
//
//     // Clean up tunnel on disconnect
//     if let Some(tunnel_id) = tunnel_id {
//         shutdown_tunnel(tunnels, active_websockets, tunnel_id).await;
//     }
//
//     // Wait for outgoing task to finish
//     outgoing_task.abort();
//
//     Ok(())
// }
//

