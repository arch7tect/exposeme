
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
    info!("Tunnel management WebSocket upgrade requested.");

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

    let response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Accept", accept_key)
        .body(boxed_body(""))
        .unwrap();

    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                info!("Tunnel management WebSocket upgrade succeeded.");
                if let Err(e) = handle_tunnel_management_connection(upgraded, context).await {
                    error!(error = %e, "Tunnel management WebSocket connection error.");
                }
            }
            Err(e) => {
                error!(error = %e, "Tunnel management WebSocket connection error.");
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

    let (tunnel_id, forwarded_path) = match extract_tunnel_id_from_request(&req, &context.config) {
        Ok(result) => result,
        Err(e) => {
            warn!(
                error = %e,
                "Invalid WebSocket upgrade request."
            );
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(boxed_body(format!("Invalid WebSocket request: {}", e)))
                .unwrap());
        }
    };

    info!(
        tunnel_id,
        method = %method,
        path = %forwarded_path,
        "WebSocket upgrade request received."
    );

    let tunnel_sender = context.tunnels.read().await.get(&tunnel_id).map(|conn| conn.sender.clone());
    let tunnel_sender = match tunnel_sender {
        Some(sender) => sender,
        None => {
            warn!(
                tunnel_id,
                "Tunnel not found for WebSocket upgrade."
            );
            context.metrics.record_error(Some(&tunnel_id));
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(boxed_body("Tunnel not available"))
                .unwrap());
        }
    };

    let connection_id = uuid::Uuid::new_v4().to_string();

    let headers = extract_headers(&req);

    debug!(
        connection_id,
        "Processing WebSocket upgrade."
    );

    let ws_key = req
        .headers()
        .get("sec-websocket-key")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let accept_key = calculate_websocket_accept_key(ws_key);

    let response = Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("Connection", "Upgrade")
        .header("Upgrade", "websocket")
        .header("Sec-WebSocket-Accept", accept_key)
        .body(boxed_body(""))
        .unwrap();

    {
        let mut websockets = context.active_websockets.write().await;
        websockets.insert(
            connection_id.clone(),
            WebSocketConnection::new(tunnel_id.clone()),
        );
    }

    // Note: WebSocket connection will be recorded in metrics only after successful proxy establishment

    let upgrade_message = Message::WebSocketUpgrade {
        connection_id: connection_id.clone(),
        method: method.to_string(),
        path: forwarded_path,
        headers,
    };

    if let Err(e) = tunnel_sender.send(upgrade_message) {
        error!(
            tunnel_id,
            error = %e,
            "Failed to send WebSocket upgrade to tunnel."
        );
        context.active_websockets.write().await.remove(&connection_id);
        return Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(boxed_body("Tunnel communication error"))
            .unwrap());
    }

    let connection_id_clone = connection_id.clone();
    let context_clone = context.clone();
    tokio::spawn(async move {
        match hyper::upgrade::on(req).await {
            Ok(upgraded) => {
                if let Err(e) = handle_websocket_proxy_connection(
                    upgraded,
                    connection_id_clone.clone(),
                    context_clone.clone(),
                )
                    .await
                {
                    error!(error = %e, "WebSocket proxy error.");
                    context_clone.active_websockets.write().await.remove(&connection_id_clone);
                }
            }
            Err(e) => {
                error!(error = %e, "WebSocket upgrade failed.");
                context_clone.active_websockets.write().await.remove(&connection_id_clone);
            }
        }
    });

    debug!(
        connection_id,
        "WebSocket upgrade response sent."
    );
    Ok(response)
}

/// Handle the upgraded WebSocket connection and proxy messages bidirectionally
async fn handle_websocket_proxy_connection(
    upgraded: hyper::upgrade::Upgraded,
    connection_id: String,
    context: ServiceContext,
) -> Result<(), BoxError> {
    debug!(
        connection_id,
        "WebSocket proxy started."
    );

    let (ws_tx, mut ws_rx) = mpsc::unbounded_channel::<WsMessage>();

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
    info!(
        connection_status,
        "WebSocket proxy established."
    );

    // Record WebSocket connection in metrics now that proxy is successfully established
    let tunnel_id_for_metrics = {
        let websockets = context.active_websockets.read().await;
        websockets.get(&connection_id).map(|conn| conn.tunnel_id.clone())
    };
    if let Some(tunnel_id) = tunnel_id_for_metrics {
        context.metrics.websocket_connected(&tunnel_id);
    }

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
                    if let Some(tunnel_id) = context_clone.active_websockets.read().await
                        .get(&connection_id_clone).map(|conn| conn.tunnel_id.clone()) {
                        context_clone.metrics.record_websocket_traffic(&tunnel_id, data.len() as u64, 0);
                    }

                    if let Err(e) = send_to_tunnel(
                        &connection_id_clone,
                        message,
                        &context_clone,
                    )
                        .await
                    {
                        error!(error = %e, "Failed to send text frame through proxy.");
                    }
                }
                Ok(WsMessage::Binary(bytes)) => {
                    let data = bytes.to_vec();
                    let message = Message::WebSocketData {
                        connection_id: connection_id_clone.clone(),
                        data: data.clone(),
                    };

                    // Record WebSocket traffic (client -> server -> tunnel)
                    if let Some(tunnel_id) = context_clone.active_websockets.read().await
                        .get(&connection_id_clone).map(|conn| conn.tunnel_id.clone()) {
                        context_clone.metrics.record_websocket_traffic(&tunnel_id, data.len() as u64, 0);
                    }

                    if let Err(e) = send_to_tunnel(
                        &connection_id_clone,
                        message,
                        &context_clone,
                    )
                        .await
                    {
                        error!(error = %e, "Failed to send binary frame through proxy.");
                    }
                }
                Ok(WsMessage::Close(close_frame)) => {
                    let (code, reason) = if let Some(frame) = close_frame {
                        (Some(frame.code.into()), Some(frame.reason.to_string()))
                    } else {
                        (None, None)
                    };

                    info!(
                        connection_id = %connection_id_clone,
                        code = ?code,
                        reason = ?reason,
                        "WebSocket proxy close received."
                    );

                    let message = Message::WebSocketClose {
                        connection_id: connection_id_clone.clone(),
                        code,
                        reason,
                    };

                    if let Err(e) = send_to_tunnel(
                        &connection_id_clone,
                        message,
                        &context_clone,
                    )
                        .await
                    {
                        error!(error = %e, "Failed to send proxy close message.");
                    }
                    break;
                }
                Err(e) => {
                    error!(
                        connection_id = %connection_id_clone,
                        error = %e,
                        "Original WebSocket error in proxy."
                    );
                    break;
                }
                _ => {} // Handle Ping/Pong
            }
        }

        info!(
            connection_id = %connection_id_clone,
            "Proxy forwarding from original to tunnel completed."
        );
    });

    let connection_id_clone = connection_id.clone();
    let tunnel_to_original_task = tokio::spawn(async move {
        while let Some(ws_message) = ws_rx.recv().await {
            if original_sink.send(ws_message).await.is_err() {
                error!(
                    connection_id = %connection_id_clone,
                    "Failed to send to original WebSocket client."
                );
                break;
            }
        }

        info!(
            connection_id = %connection_id_clone,
            "Proxy forwarding from tunnel to original completed."
        );
    });

    tokio::select! {
        _ = original_to_tunnel_task => {
            info!(
                connection_id,
                "Original WebSocket client disconnected."
            );
        }
        _ = tunnel_to_original_task => {
            info!(
                connection_id,
                "Tunnel client disconnected."
            );
        }
    }

    let tunnel_id = {
        let mut websockets = context.active_websockets.write().await;
        let tunnel_id = websockets.get(&connection_id).map(|conn| conn.tunnel_id.clone());
        websockets.remove(&connection_id);
        tunnel_id
    };

    // Record WebSocket disconnection in metrics
    if let Some(tunnel_id) = tunnel_id {
        context.metrics.websocket_disconnected(&tunnel_id);
    }

    info!(
        connection_id,
        "WebSocket proxy fully closed."
    );
    Ok(())
}

/// Send a message to the appropriate tunnel client
pub async fn send_to_tunnel(
    connection_id: &str,
    message: Message,
    context: &ServiceContext,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let tunnel_id = {
        let websockets = context.active_websockets.read().await;
        match websockets.get(connection_id) {
            Some(conn) => conn.tunnel_id.clone(),
            None => {
                debug!(
                    connection_id,
                    "WebSocket proxy connection missing."
                );
                return Ok(());
            }
        }
    };

    {
        let tunnels_guard = context.tunnels.read().await;
        match tunnels_guard.get(&tunnel_id).map(|conn| conn.sender.clone()) {
            Some(tunnel_sender) => {
                if let Err(e) = tunnel_sender.send(message) {
                    context.metrics.record_error(Some(&tunnel_id));
                    return Err(format!("Failed to send: {}", e).into());
                }
            }
            None => {
                debug!(
                    tunnel_id,
                    connection_id,
                    "Tunnel missing for proxy connection."
                );
                context.metrics.record_error(Some(&tunnel_id));
                return Ok(());
            }
        }
    }

    Ok(())
}
