// src/svc/tunnel_mgmt.rs - Tunnel client connection management

use crate::Message;
use crate::svc::types::*;
use crate::svc::{BoxError, ServiceContext};
use futures_util::stream::{SplitSink, SplitStream};
use futures_util::{SinkExt, StreamExt};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio::time::interval;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message as WsMessage};
use tracing::{debug, error, info, trace, warn};

/// Handle a tunnel management connection from an exposeme-client
pub async fn handle_tunnel_management_connection(
    upgraded: Upgraded,
    context: ServiceContext,
) -> Result<(), BoxError> {
    // Convert upgraded connection to WebSocket
    let ws_stream = WebSocketStream::from_raw_socket(
        TokioIo::new(upgraded),
        Role::Server,
        Some(WebSocketConfig::default()),
    )
    .await;

    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    debug!("🔍 Waiting for authentication message...");

    let tunnel_id =
        match wait_for_authentication(&mut ws_receiver, &mut ws_sender, &context).await? {
            Some(info) => info,
            None => {
                info!("❌ Authentication failed or connection closed");
                return Ok(());
            }
        };

    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    // Register tunnel
    let tunnel_connection = Arc::new(TunnelConnection::new(tx, tunnel_id.clone()));

    {
        let mut tunnels_guard = context.tunnels.write().await;
        tunnels_guard.insert(tunnel_id.clone(), tunnel_connection);
    }
    debug!("✅ Authentication successful for tunnel '{}'", tunnel_id);

    // Record tunnel connection in metrics
    if let Some(metrics) = &context.metrics {
        metrics.tunnel_connected(&tunnel_id);
    }

    // Create channel for ping requests from ping task to main loop
    let (ping_tx, mut ping_rx) = mpsc::unbounded_channel::<()>();
    let ping_handle = start_ping_task(
        tunnel_id.clone(),
        context.tunnels.clone(),
        context.clone(),
        ping_tx,
    );

    let mut message_count = 0;
    loop {
        tokio::select! {
            // Handle ping requests from ping task
            _ = ping_rx.recv() => {
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let ping_payload = timestamp.to_be_bytes().to_vec();

                if let Err(e) = ws_sender.send(WsMessage::Ping(ping_payload.into())).await {
                    error!("❌ Failed to send ping to tunnel '{}': {}", tunnel_id, e);
                    if let Some(metrics) = &context.metrics {
                        metrics.record_error(Some(&tunnel_id));
                    }
                    break;
                }

                // Record ping sent time for timeout detection
                if let Some(connection) = context.tunnels.read().await.get(&tunnel_id) {
                    connection.record_ping_sent().await;
                }
                debug!("📡 Sent native WebSocket ping to tunnel '{}'", tunnel_id);
            }

            // Handle outgoing messages to client
            message = rx.recv() => {
                let Some(message) = message else {
                    break;
                };
                match message.to_bincode() {
                    Ok(bytes) => {
                        if let Err(e) = ws_sender.send(WsMessage::Binary(bytes.into())).await {
                            error!("Failed to send WS message to client: {}", e);
                            if let Some(metrics) = &context.metrics {
                                metrics.record_error(Some(&tunnel_id));
                            }
                            break;
                        }
                    }
                    Err(e) => {
                        error!("Failed to serialize message to bincode: {}", e);
                        if let Some(metrics) = &context.metrics {
                            metrics.record_error(Some(&tunnel_id));
                        }
                    }
                }
            }

            // Handle incoming WebSocket messages
            message = ws_receiver.next() => {
                let Some(message) = message else {
                    break;
                };
                message_count += 1;
                trace!("🔍 Server: Received WebSocket message #{}", message_count);

                if let Some(connection) = context.tunnels.read().await.get(&tunnel_id) {
                    connection.update_activity().await;
                }

                match message {
                    Ok(WsMessage::Binary(bytes)) => {
                        trace!("🔍 Server: Processing binary message #{} ({} bytes)", message_count, bytes.len());

                        match Message::from_bincode(&bytes) {
                            Ok(msg) => {
                                trace!("🔍 Server: Successfully parsed message #{}: {:?}", message_count, std::mem::discriminant(&msg));

                                match msg {
                                    Message::HttpResponseStart {
                                        id,
                                        status,
                                        headers,
                                        initial_data,
                                        is_complete,
                                    } => {
                                        handle_http_response_start(
                                            id, status, headers, initial_data, is_complete, &context
                                        ).await;
                                    }

                                    Message::DataChunk { id, data, is_final } => {
                                        handle_data_chunk(id, data, is_final, &context).await;
                                    }

                                    Message::WebSocketUpgradeResponse {
                                        connection_id,
                                        status,
                                        headers: _,
                                    } => {
                                        debug!(
                                            "📡 WebSocket upgrade response: {} (status: {})",
                                            connection_id, status
                                        );
                                        // Nothing to do here as we've already upgraded incoming connection.
                                    }

                                    Message::WebSocketData {
                                        connection_id,
                                        data,
                                    } => {
                                        handle_websocket_data(connection_id, data, &context).await;
                                    }

                                    Message::WebSocketClose {
                                        connection_id,
                                        code,
                                        reason,
                                    } => {
                                        handle_websocket_close(connection_id, code, reason, &context).await;
                                    }


                                    _ => {
                                        warn!("Unexpected message type from tunnel client");
                                    }
                                }
                            }
                            Err(e) => {
                                error!("❌ Failed to parse bincode message: {}", e);
                                if let Some(metrics) = &context.metrics {
                                    metrics.record_error(Some(&tunnel_id));
                                }
                            }
                        }
                    }
                    Ok(WsMessage::Text(text)) => {
                        error!("❌ Received unexpected text message (protocol requires binary): {} chars", text.len());
                        error!("❌ Please ensure both client and server are using the same protocol version");
                        if let Some(metrics) = &context.metrics {
                            metrics.record_error(Some(&tunnel_id));
                        }
                    }
                    Ok(WsMessage::Pong(_)) => {
                        debug!("🏓 Received native WebSocket pong from tunnel '{}'", tunnel_id);
                        // Update activity to mark connection as alive
                        if let Some(connection) = context.tunnels.read().await.get(&tunnel_id) {
                            connection.update_activity().await;
                        }
                    }
                    Ok(WsMessage::Close(_)) => {
                        info!("Tunnel management WebSocket closed");
                        break;
                    }
                    Err(e) => {
                        error!("Tunnel management WebSocket error: {}", e);
                        if let Some(metrics) = &context.metrics {
                            metrics.record_error(Some(&tunnel_id));
                        }
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    // Clean up tunnel on disconnect
    info!("📤 Sending WebSocket close frame to client");
    let close_frame = tokio_tungstenite::tungstenite::protocol::CloseFrame {
        code: CloseCode::Away,
        reason: "Server shutting down".into(),
    };
    let _ = ws_sender.send(WsMessage::Close(Some(close_frame))).await;
    let _ = ws_sender.close().await;
    info!("✅ WebSocket closed gracefully");

    shutdown_tunnel(context.clone(), tunnel_id.clone()).await;
    ping_handle.abort();

    Ok(())
}

fn start_ping_task(
    tunnel_id: String,
    tunnels: TunnelMap,
    context: ServiceContext,
    ping_tx: mpsc::UnboundedSender<()>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(30));
        interval.tick().await; // Skip first tick

        loop {
            interval.tick().await;

            let connection = {
                let tunnels_guard = tunnels.read().await;
                tunnels_guard.get(&tunnel_id).cloned()
            };

            match connection {
                Some(conn) => {
                    // Check if connection is stale
                    if conn.is_stale().await {
                        warn!("🔄 Tunnel '{}' is stale, removing immediately", tunnel_id);
                        shutdown_tunnel(context.clone(), tunnel_id.clone()).await;
                        break;
                    }

                    // Request main loop to send a ping
                    if ping_tx.send(()).is_err() {
                        warn!(
                            "❌ Failed to request ping for tunnel '{}', main loop closed",
                            tunnel_id
                        );
                        break;
                    }
                }
                None => {
                    debug!("🔄 Tunnel '{}' no longer exists, stopping ping", tunnel_id);
                    break;
                }
            }
        }

        info!("💔 Ping task ended for tunnel '{}'", tunnel_id);
    })
}

async fn wait_for_authentication(
    ws_receiver: &mut SplitStream<WebSocketStream<TokioIo<Upgraded>>>,
    ws_sender: &mut SplitSink<WebSocketStream<TokioIo<Upgraded>>, WsMessage>,
    context: &ServiceContext,
) -> Result<Option<String>, BoxError> {
    // Wait for auth message with timeout
    let auth_timeout = Duration::from_secs(30);

    match tokio::time::timeout(auth_timeout, ws_receiver.next()).await {
        Ok(Some(Ok(WsMessage::Binary(bytes)))) => {
            match Message::from_bincode(&bytes) {
                Ok(Message::Auth {
                    token,
                    tunnel_id,
                    version,
                }) => {
                    info!("Auth request for tunnel '{}'", tunnel_id);

                    // Validate tunnel ID
                    if let Err(e) = context.config.validate_tunnel_id(&tunnel_id) {
                        let error_msg = WsMessage::Binary(
                            Message::AuthError {
                                error: "invalid_tunnel_id".to_string(),
                                message: format!("Invalid tunnel ID: {}", e),
                            }
                            .to_bincode()?
                            .into(),
                        );
                        ws_sender.send(error_msg).await?;
                        return Ok(None);
                    }

                    // Token validation
                    if !context.config.auth.tokens.contains(&token) {
                        let error_msg = WsMessage::Binary(
                            Message::AuthError {
                                error: "invalid_token".to_string(),
                                message: "Invalid authentication token".to_string(),
                            }
                            .to_bincode()?
                            .into(),
                        );
                        ws_sender.send(error_msg).await?;
                        return Ok(None);
                    }

                    // Check if tunnel_id is already taken
                    {
                        let tunnels_guard = context.tunnels.read().await;
                        if tunnels_guard.contains_key(&tunnel_id) {
                            let error_msg = WsMessage::Binary(
                                Message::AuthError {
                                    error: "tunnel_id_taken".to_string(),
                                    message: format!("Tunnel ID '{}' is already in use", tunnel_id),
                                }
                                .to_bincode()?
                                .into(),
                            );
                            ws_sender.send(error_msg).await?;
                            return Ok(None);
                        }
                    }

                    let our_version = env!("CARGO_PKG_VERSION").to_string();
                    let compatible = our_version
                        .split('.')
                        .zip(version.split('.'))
                        .take(2)
                        .all(|(a, b)| a == b);
                    if !compatible {
                        let error_msg = WsMessage::Binary(
                            Message::AuthError {
                                error: "incompatible_versions".to_string(),
                                message: format!(
                                    "Client version '{}' is incompatible with server version '{}'",
                                    version, our_version,
                                ),
                            }
                            .to_bincode()?
                            .into(),
                        );
                        ws_sender.send(error_msg).await?;
                        return Ok(None);
                    }

                    let success_msg = WsMessage::Binary(
                        Message::AuthSuccess {
                            tunnel_id: tunnel_id.clone(),
                            public_url: context.config.get_public_url(&tunnel_id),
                        }
                        .to_bincode()?
                        .into(),
                    );
                    ws_sender.send(success_msg).await?;

                    Ok(Some(tunnel_id))
                }
                Ok(_) => {
                    warn!("Expected authentication message, got different message type");
                    Ok(None)
                }
                Err(e) => {
                    error!("Failed to parse authentication message: {}", e);
                    Ok(None)
                }
            }
        }
        Ok(Some(Ok(WsMessage::Close(_)))) => {
            info!("WebSocket closed before authentication");
            Ok(None)
        }
        Ok(Some(Err(e))) => {
            error!("WebSocket error during authentication: {}", e);
            Ok(None)
        }
        Ok(None) => {
            info!("WebSocket stream ended before authentication");
            Ok(None)
        }
        Err(_) => {
            warn!("Authentication timeout after {}s", auth_timeout.as_secs());
            Ok(None)
        }
        _ => {
            warn!("Unexpected message type during authentication");
            Ok(None)
        }
    }
}

/// Handle HTTP response start message
async fn handle_http_response_start(
    id: String,
    status: u16,
    headers: std::collections::HashMap<String, String>,
    initial_data: Vec<u8>,
    is_complete: bool,
    context: &ServiceContext,
) {
    debug!(
        "📥 Response: {} (id: {}, complete: {:?}, {} bytes)",
        status,
        id,
        is_complete,
        initial_data.len()
    );

    if let Some(request) = context.active_requests.read().await.get(&id) {
        if is_complete == true {
            let complete_event = ResponseEvent::Complete {
                status,
                headers,
                body: initial_data,
            };

            match request.response_tx.send(complete_event).await {
                Ok(_) => debug!("✅ Complete response queued for {}", id),
                Err(e) => error!("❌ Failed to queue complete response for {}: {}", id, e),
            }
        } else {
            let stream_start = ResponseEvent::StreamStart {
                status,
                headers,
                initial_data,
            };

            match request.response_tx.send(stream_start).await {
                Ok(_) => debug!("✅ Stream started for {}", id),
                Err(e) => {
                    error!("❌ Failed to start stream for {}: {}", id, e);
                    context.active_requests.write().await.remove(&id);
                }
            }
        }
    }
}

/// Handle data chunk message
async fn handle_data_chunk(id: String, data: Vec<u8>, is_final: bool, context: &ServiceContext) {
    debug!(
        "📥 DataChunk: {} bytes, final={} (id: {})",
        data.len(),
        is_final,
        id
    );

    if let Some(request) = context.active_requests.read().await.get(&id) {
        if !data.is_empty() {
            let _ = request
                .response_tx
                .send(ResponseEvent::StreamChunk(data.into()))
                .await;
        }

        if is_final {
            let _ = request.response_tx.send(ResponseEvent::StreamEnd).await;
            debug!("✅ Stream ended for {}", id);
        }
    } else {
        warn!("❌ Received DataChunk for unknown request: {}", id);
    }
}

/// Handle WebSocket data from tunnel client - Binary data, no base64 needed
async fn handle_websocket_data(connection_id: String, data: Vec<u8>, context: &ServiceContext) {
    // Handle WebSocket data from tunnel client
    if let Some(connection) = context.active_websockets.read().await.get(&connection_id) {
        debug!(
            "📡 Received data for {} (age: {}, {} bytes)",
            connection_id,
            connection.age_info(),
            data.len()
        );
        
        // Record WebSocket traffic (tunnel -> server -> client)
        if let Some(metrics) = &context.metrics {
            metrics.record_websocket_traffic(&connection.tunnel_id, 0, data.len() as u64);
        }
        if let Some(ws_tx) = &connection.ws_tx {
            let ws_message = if let Ok(text) = String::from_utf8(data.clone()) {
                WsMessage::Text(text.into())
            } else {
                WsMessage::Binary(data.into())
            };

            if let Err(e) = ws_tx.send(ws_message) {
                error!(
                    "Failed to forward WebSocket data to client {}: {}",
                    connection_id, e
                );
            }
        }
    } else {
        warn!(
            "Received data for unknown WebSocket connection: {}",
            connection_id
        );
    }
}

/// Handle WebSocket close from tunnel client
async fn handle_websocket_close(
    connection_id: String,
    code: Option<u16>,
    reason: Option<String>,
    context: &ServiceContext,
) {
    // Handle WebSocket close from tunnel client
    if let Some(connection) = context
        .active_websockets
        .write()
        .await
        .remove(&connection_id)
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
                error!("Failed to send close frame for {}: {:?}", connection_id, e);
            };
        }
        info!("✅ Cleaned up WebSocket connection {}", connection_id);
    }
}

/// Clean up all resources associated with a tunnel when it disconnects
pub async fn shutdown_tunnel(context: ServiceContext, tunnel_id: String) -> bool {
    let result = {
        let mut tunnels_guard = context.tunnels.write().await;
        if tunnels_guard.remove(&tunnel_id).is_some() {
            info!(
                "ExposeME client disconnected. Tunnel '{}' removed",
                tunnel_id
            );
            true
        } else {false}
    };

    if result {
        // Clean up active requests for this tunnel
        let requests_to_cleanup = {
            let requests = context.active_requests.read().await;
            requests
                .iter()
                .filter(|(_, req)| req.tunnel_id == tunnel_id)
                .map(|(id, _)| id.clone())
                .collect::<Vec<_>>()
        };

        for request_id in requests_to_cleanup {
            if let Some(request) = context.active_requests.write().await.remove(&request_id) {
                request.client_disconnected.store(true, Ordering::Relaxed);
                let _ = request
                    .response_tx
                    .send(ResponseEvent::Error("Tunnel disconnected".to_string()))
                    .await;
            }
        }

        // Clean up WebSocket connections for this tunnel
        let websocket_connections_to_cleanup = {
            let websockets = context.active_websockets.read().await;
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
                if let Some(connection) = context
                    .active_websockets
                    .write()
                    .await
                    .remove(&connection_id)
                {
                    debug!("🗑️  Cleaned up WebSocket connection: {}", connection_id);

                    // Record WebSocket disconnection in metrics
                    if let Some(metrics) = &context.metrics {
                        metrics.websocket_disconnected(&tunnel_id);
                    }

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

        // Record disconnection in metrics
        if result {
            if let Some(metrics) = &context.metrics {
                metrics.tunnel_disconnected(&tunnel_id);
            }
        }


    }

    result
}
