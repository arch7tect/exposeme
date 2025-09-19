// src/svc/handlers/websocket.rs - WebSocket upgrade and proxy handling

use crate::svc::{BoxError, ServiceContext};
use crate::svc::types::*;
use crate::svc::utils::{boxed_body, calculate_websocket_accept_key, extract_headers, extract_tunnel_id_from_request};
use crate::svc::tunnel_mgmt::handle_tunnel_management_connection;
use crate::Message;
use futures_util::{SinkExt, StreamExt};
use hyper::{Request, Response, StatusCode, body::Incoming};
use hyper_util::rt::TokioIo;
use tokio::sync::mpsc;
use tokio_tungstenite::tungstenite::protocol::{Role, WebSocketConfig};
use tokio_tungstenite::{WebSocketStream, tungstenite::Message as WsMessage};
use tracing::{debug, error, info, warn};

/// Handle tunnel management WebSocket upgrades (exposeme-client connections)
pub async fn handle_tunnel_management_websocket(
    req: Request<Incoming>,
    context: ServiceContext,
) -> Result<Response<ResponseBody>, BoxError> {
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
                if let Err(e) = handle_tunnel_management_connection(upgraded, context).await {
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

/// Handle WebSocket upgrade requests from browsers (to be proxied through tunnels)
pub async fn handle_websocket_upgrade_request(
    req: Request<Incoming>,
    context: ServiceContext,
) -> Result<Response<ResponseBody>, BoxError> {
    let method = req.method().clone();

    // Extract tunnel ID and forwarded path
    let (tunnel_id, forwarded_path) = match extract_tunnel_id_from_request(&req, &context.config) {
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
    let tunnel_sender = context.tunnels.read().await.get(&tunnel_id).map(|conn| conn.sender.clone());
    let tunnel_sender = match tunnel_sender {
        Some(sender) => sender,
        None => {
            warn!("Tunnel '{}' not found for WebSocket upgrade", tunnel_id);
            if let Some(metrics) = &context.metrics {
                metrics.record_error(Some(&tunnel_id));
            }
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(boxed_body("Tunnel not available"))
                .unwrap());
        }
    };

    // Generate connection ID
    let connection_id = uuid::Uuid::new_v4().to_string();

    // Extract headers for forwarding
    let headers = extract_headers(&req);

    debug!(
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
        let mut websockets = context.active_websockets.write().await;
        websockets.insert(
            connection_id.clone(),
            WebSocketConnection::new(tunnel_id.clone()),
        );
    }

    // Note: WebSocket connection will be recorded in metrics only after successful proxy establishment

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
        context.active_websockets.write().await.remove(&connection_id);
        return Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(boxed_body("Tunnel communication error"))
            .unwrap());
    }

    // Start WebSocket proxy task
    let connection_id_clone = connection_id.clone();
    let context_clone = context.clone();
    tokio::spawn(async move {
        // Get the upgraded connection
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                // Handle upgraded connection
                if let Err(e) = handle_websocket_proxy_connection(
                    upgraded,
                    connection_id_clone.clone(),
                    context_clone.clone(),
                )
                    .await
                {
                    error!("WebSocket proxy error: {}", e);
                    // Clean up connection on proxy error
                    context_clone.active_websockets.write().await.remove(&connection_id_clone);
                }
            }
            Err(e) => {
                error!("Failed to upgrade connection: {}", e);
                // Clean up connection on upgrade failure
                context_clone.active_websockets.write().await.remove(&connection_id_clone);
            }
        }
    });

    debug!("✅ WebSocket upgrade response sent for {}", connection_id);
    Ok(response)
}

/// Handle the upgraded WebSocket connection and proxy messages bidirectionally
async fn handle_websocket_proxy_connection(
    upgraded: hyper::upgrade::Upgraded,
    connection_id: String,
    context: ServiceContext,
) -> Result<(), BoxError> {
    debug!("🔌 Starting WebSocket proxy for connection {}", connection_id);

    // Create channels for communication with tunnel client
    let (ws_tx, mut ws_rx) = mpsc::unbounded_channel::<WsMessage>();

    // Update the stored connection with ws_tx
    {
        let mut websockets = context.active_websockets.write().await;
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
        let websockets = context.active_websockets.read().await;
        websockets
            .get(&connection_id)
            .map(|conn| conn.status_summary())
            .unwrap_or_else(|| "unknown".to_string())
    };
    info!("🔌 WebSocket proxy established: {}", connection_status);

    // Record WebSocket connection in metrics now that proxy is successfully established
    let tunnel_id_for_metrics = {
        let websockets = context.active_websockets.read().await;
        websockets.get(&connection_id).map(|conn| conn.tunnel_id.clone())
    };
    if let (Some(metrics), Some(tunnel_id)) = (&context.metrics, tunnel_id_for_metrics) {
        metrics.websocket_connected(&tunnel_id);
    }

    // Forward messages FROM original client TO tunnel client
    let connection_id_clone = connection_id.clone();
    let context_clone = context.clone();

    let original_to_tunnel_task = tokio::spawn(async move {
        while let Some(msg) = original_stream.next().await {
            match msg {
                Ok(WsMessage::Text(text)) => {
                    let data = text.as_bytes().to_vec();
                    let message = Message::WebSocketData {
                        connection_id: connection_id_clone.clone(),
                        data: data.clone(),
                    };

                    // Record WebSocket traffic (client -> server -> tunnel)
                    if let Some(metrics) = &context_clone.metrics {
                        if let Some(tunnel_id) = context_clone.active_websockets.read().await
                            .get(&connection_id_clone).map(|conn| conn.tunnel_id.clone()) {
                            metrics.record_websocket_traffic(&tunnel_id, data.len() as u64, 0);
                        }
                    }

                    // Send to tunnel client
                    if let Err(e) = send_to_tunnel(
                        &connection_id_clone,
                        message,
                        &context_clone,
                    )
                        .await
                    {
                        error!("Failed to send WebSocket text: {}", e);
                    }
                }
                Ok(WsMessage::Binary(bytes)) => {
                    let data = bytes.to_vec();
                    let message = Message::WebSocketData {
                        connection_id: connection_id_clone.clone(),
                        data: data.clone(),
                    };

                    // Record WebSocket traffic (client -> server -> tunnel)
                    if let Some(metrics) = &context_clone.metrics {
                        if let Some(tunnel_id) = context_clone.active_websockets.read().await
                            .get(&connection_id_clone).map(|conn| conn.tunnel_id.clone()) {
                            metrics.record_websocket_traffic(&tunnel_id, data.len() as u64, 0);
                        }
                    }

                    // Send to tunnel client
                    if let Err(e) = send_to_tunnel(
                        &connection_id_clone,
                        message,
                        &context_clone,
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
                        &context_clone,
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
    let tunnel_id = {
        let mut websockets = context.active_websockets.write().await;
        let tunnel_id = websockets.get(&connection_id).map(|conn| conn.tunnel_id.clone());
        websockets.remove(&connection_id);
        tunnel_id
    };

    // Record WebSocket disconnection in metrics
    if let (Some(metrics), Some(tunnel_id)) = (&context.metrics, tunnel_id) {
        metrics.websocket_disconnected(&tunnel_id);
    }

    info!(
        "🔌 WebSocket proxy connection {} fully closed",
        connection_id
    );
    Ok(())
}

/// Send a message to the appropriate tunnel client
pub async fn send_to_tunnel(
    connection_id: &str,
    message: Message,
    context: &ServiceContext,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Get tunnel_id from connection
    let tunnel_id = {
        let websockets = context.active_websockets.read().await;
        match websockets.get(connection_id) {
            Some(conn) => conn.tunnel_id.clone(),
            None => {
                // Connection already cleaned up, this is normal during shutdown
                debug!("Connection {} already cleaned up, ignoring message", connection_id);
                return Ok(());
            }
        }
    };

    // Send to correct tunnel
    {
        let tunnels_guard = context.tunnels.read().await;
        match tunnels_guard.get(&tunnel_id).map(|conn| conn.sender.clone()) {
            Some(tunnel_sender) => {
                if let Err(e) = tunnel_sender.send(message) {
                    if let Some(metrics) = &context.metrics {
                        metrics.record_error(Some(&tunnel_id));
                    }
                    return Err(format!("Failed to send: {}", e).into());
                }
            }
            None => {
                // Tunnel disconnected
                debug!("Tunnel {} disconnected, ignoring message for connection {}", tunnel_id, connection_id);
                if let Some(metrics) = &context.metrics {
                    metrics.record_error(Some(&tunnel_id));
                }
                return Ok(());
            }
        }
    }

    Ok(())
}