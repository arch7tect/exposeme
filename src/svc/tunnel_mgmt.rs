// src/svc/tunnel_mgmt.rs - Tunnel client connection management

use crate::svc::{BoxError, ServiceContext};
use crate::svc::types::*;
use crate::Message;
use base64::Engine;
use futures_util::{SinkExt, StreamExt};
use hyper::upgrade::Upgraded;
use hyper_util::rt::TokioIo;
use std::sync::atomic::Ordering;
use tokio::sync::mpsc;
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
        trace!("🔍 Server: Received WebSocket message #{}", message_count);

        match message {
            Ok(WsMessage::Text(text)) => {
                trace!("🔍 Server: Processing text message #{} ({} chars)", message_count, text.len());

                if let Ok(msg) = Message::from_json(&text.to_string()) {
                    trace!("🔍 Server: Successfully parsed message #{}: {:?}", message_count, std::mem::discriminant(&msg));

                    match msg {
                        Message::Auth {
                            token,
                            tunnel_id: requested_tunnel_id,
                            version,
                        } => {
                            if let Err(e) = handle_auth_message(
                                token,
                                requested_tunnel_id,
                                version,
                                &tx,
                                &context,
                                &mut tunnel_id,
                            ).await {
                                error!("Auth handling failed: {}", e);
                                break;
                            }
                        }

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
        shutdown_tunnel(context, tunnel_id).await;
    }

    outgoing_task.abort();
    Ok(())
}

/// Handle authentication message from tunnel client
async fn handle_auth_message(
    token: String,
    requested_tunnel_id: String,
    version: String,
    tx: &mpsc::UnboundedSender<Message>,
    context: &ServiceContext,
    tunnel_id: &mut Option<String>,
) -> Result<(), BoxError> {
    info!("Auth request for tunnel '{}'", requested_tunnel_id);

    // Validate tunnel ID
    if let Err(e) = context.config.validate_tunnel_id(&requested_tunnel_id) {
        let error_msg = Message::AuthError {
            error: "invalid_tunnel_id".to_string(),
            message: format!("Invalid tunnel ID: {}", e),
        };
        tx.send(error_msg)?;
        return Ok(());
    }

    // Token validation
    if !context.config.auth.tokens.contains(&token) {
        let error_msg = Message::AuthError {
            error: "invalid_token".to_string(),
            message: "Invalid authentication token".to_string(),
        };
        tx.send(error_msg)?;
        return Ok(());
    }

    // Check if tunnel_id is already taken
    {
        let tunnels_guard = context.tunnels.read().await;
        if tunnels_guard.contains_key(&requested_tunnel_id) {
            let error_msg = Message::AuthError {
                error: "tunnel_id_taken".to_string(),
                message: format!(
                    "Tunnel ID '{}' is already in use",
                    requested_tunnel_id
                ),
            };
            tx.send(error_msg)?;
            return Ok(());
        }
    }

    let our_version = env!("CARGO_PKG_VERSION").to_string();
    let compatible = our_version.split('.').zip(version.split('.')).take(2).all(|(a, b)| a == b);
    if !compatible {
        let error_msg = Message::AuthError {
            error: "incompatible_versions".to_string(),
            message: format!(
                "Client version '{}' is incompatible with server version '{}'",
                version, our_version,
            ),
        };
        tx.send(error_msg)?;
        return Ok(());
    }

    // Register tunnel
    {
        let mut tunnels_guard = context.tunnels.write().await;
        tunnels_guard.insert(requested_tunnel_id.clone(), tx.clone());
    }

    *tunnel_id = Some(requested_tunnel_id.clone());

    let success_msg = Message::AuthSuccess {
        tunnel_id: requested_tunnel_id.clone(),
        public_url: context.config.get_public_url(&requested_tunnel_id),
    };

    tx.send(success_msg)?;
    info!("Tunnel '{}' registered successfully", requested_tunnel_id);
    Ok(())
}

/// Handle HTTP response start message
async fn handle_http_response_start(
    id: String,
    status: u16,
    headers: std::collections::HashMap<String, String>,
    initial_data: Vec<u8>,
    is_complete: Option<bool>,
    context: &ServiceContext,
) {
    debug!("📥 Response: {} (id: {}, complete: {:?}, {} bytes)",
           status, id, is_complete, initial_data.len());

    if let Some(request) = context.active_requests.read().await.get(&id) {
        if is_complete == Some(true) {
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
async fn handle_data_chunk(
    id: String,
    data: Vec<u8>,
    is_final: bool,
    context: &ServiceContext,
) {
    debug!("📥 DataChunk: {} bytes, final={} (id: {})", data.len(), is_final, id);

    if let Some(request) = context.active_requests.read().await.get(&id) {
        if !data.is_empty() {
            let _ = request.response_tx.send(
                ResponseEvent::StreamChunk(data.into())
            ).await;
        }

        if is_final {
            let _ = request.response_tx.send(ResponseEvent::StreamEnd).await;
            debug!("✅ Stream ended for {}", id);
        }
    } else {
        warn!("❌ Received DataChunk for unknown request: {}", id);
    }
}

/// Handle WebSocket data from tunnel client
async fn handle_websocket_data(
    connection_id: String,
    data: String,
    context: &ServiceContext,
) {
    // Handle WebSocket data from tunnel client
    if let Some(connection) = context.active_websockets.read().await.get(&connection_id) {
        debug!(
            "📡 Received data for {} (age: {}, {} bytes)",
            connection_id,
            connection.age_info(),
            data.len()
        );
        if let Some(ws_tx) = &connection.ws_tx {
            match base64::engine::general_purpose::STANDARD.decode(&data) {
                Ok(binary_data) => {
                    let ws_message = if let Ok(text) = String::from_utf8(binary_data.clone()) {
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

/// Handle WebSocket close from tunnel client
async fn handle_websocket_close(
    connection_id: String,
    code: Option<u16>,
    reason: Option<String>,
    context: &ServiceContext,
) {
    // Handle WebSocket close from tunnel client
    if let Some(connection) = context.active_websockets.write().await.remove(&connection_id) {
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

/// Clean up all resources associated with a tunnel when it disconnects
pub async fn shutdown_tunnel(context: ServiceContext, tunnel_id: String) {
    {
        let mut tunnels_guard = context.tunnels.write().await;
        tunnels_guard.remove(&tunnel_id);
        info!(
            "ExposeME client disconnected. Tunnel '{}' removed",
            tunnel_id
        );
    }

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
            if let Some(connection) = context.active_websockets.write().await.remove(&connection_id) {
                debug!("🗑️  Cleaned up WebSocket connection: {}", connection_id);
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