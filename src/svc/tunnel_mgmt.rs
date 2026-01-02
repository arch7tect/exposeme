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
use tokio_util::sync::CancellationToken;
use tracing::{debug, error, info, trace, warn};

pub async fn handle_tunnel_management_connection(
    upgraded: Upgraded,
    context: ServiceContext,
) -> Result<(), BoxError> {
    let ws_stream = WebSocketStream::from_raw_socket(
        TokioIo::new(upgraded),
        Role::Server,
        Some(WebSocketConfig::default()),
    )
    .await;

    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    debug!("Waiting for tunnel authentication message.");

    let tunnel_id =
        match wait_for_authentication(&mut ws_receiver, &mut ws_sender, &context).await? {
            Some(info) => info,
            None => {
                info!("Tunnel authentication failed or connection closed.");
                return Ok(());
            }
        };

    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();
    let tunnel_connection = Arc::new(TunnelConnection::new(tx, tunnel_id.clone()));

    {
        let mut tunnels_guard = context.tunnels.write().await;
        tunnels_guard.insert(tunnel_id.clone(), tunnel_connection);
    }
    debug!(
        tunnel_id,
        "Tunnel authentication succeeded."
    );

    context.metrics.tunnel_connected(&tunnel_id);

    let _cleanup_guard = guard!(tunnel_id, context => {
        shutdown_tunnel(context, tunnel_id).await;
    });

    let (ping_tx, mut ping_rx) = mpsc::unbounded_channel::<()>();
    let cancel_token = CancellationToken::new();
    let ping_handle = start_ping_task(
        tunnel_id.clone(),
        context.tunnels.clone(),
        ping_tx,
        cancel_token.clone(),
    );

    let mut message_count = 0;
    loop {
        tokio::select! {
            _ = cancel_token.cancelled() => {
                info!(
                    tunnel_id,
                    "Ping task cancelled due to stale connection."
                );
                break;
            }

            _ = ping_rx.recv() => {
                let timestamp = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
                let ping_payload = timestamp.to_be_bytes().to_vec();

                if let Err(e) = ws_sender.send(WsMessage::Ping(ping_payload.into())).await {
                    error!(
                        tunnel_id,
                        error = %e,
                        "Failed to send ping to tunnel client."
                    );
                    context.metrics.record_error(Some(&tunnel_id));
                    break;
                }

                if let Some(connection) = context.tunnels.read().await.get(&tunnel_id) {
                    connection.record_ping_sent().await;
                }
                debug!(
                    tunnel_id,
                    "Ping sent to tunnel client."
                );
            }

            message = rx.recv() => {
                let Some(message) = message else {
                    break;
                };
                match message.to_bincode() {
                    Ok(bytes) => {
                        if let Err(e) = ws_sender.send(WsMessage::Binary(bytes.into())).await {
                            error!(
                                error = %e,
                                "Failed to send tunnel WebSocket message."
                            );
                            context.metrics.record_error(Some(&tunnel_id));
                            break;
                        }
                    }
                    Err(e) => {
                        error!(
                            error = %e,
                            "Failed to serialize tunnel message."
                        );
                        context.metrics.record_error(Some(&tunnel_id));
                    }
                }
            }

            message = ws_receiver.next() => {
                let Some(message) = message else {
                    break;
                };
                message_count += 1;
                trace!(
                    message_count,
                    "Tunnel WebSocket message received."
                );

                if let Some(connection) = context.tunnels.read().await.get(&tunnel_id) {
                    connection.update_activity().await;
                }

                match message {
                    Ok(WsMessage::Binary(bytes)) => {
                        trace!(
                            message_count,
                            bytes = bytes.len(),
                            "Binary tunnel WebSocket message received."
                        );

                        match Message::from_bincode(&bytes) {
                            Ok(msg) => {
                                trace!(
                                    message_count,
                                    "Tunnel WebSocket message parsed."
                                );

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
                                            connection_id,
                                            status,
                                            "Tunnel WebSocket upgrade response received."
                                        );
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
                                        warn!("Unexpected message from tunnel client.");
                                    }
                                }
                            }
                            Err(e) => {
                                error!(
                                    error = %e,
                                    "Failed to parse tunnel message."
                                );
                                context.metrics.record_error(Some(&tunnel_id));
                            }
                        }
                    }
                    Ok(WsMessage::Text(text)) => {
                        error!(
                            chars = text.len(),
                            "Unexpected text message received from tunnel client."
                        );
                        context.metrics.record_error(Some(&tunnel_id));
                    }
                    Ok(WsMessage::Pong(_)) => {
                        debug!(
                            tunnel_id,
                            "Pong received from tunnel client."
                        );
                        if let Some(connection) = context.tunnels.read().await.get(&tunnel_id) {
                            connection.update_activity().await;
                        }
                    }
                    Ok(WsMessage::Close(_)) => {
                        info!("Tunnel WebSocket closed.");
                        break;
                    }
                    Err(e) => {
                        error!(
                            error = %e,
                            "Tunnel WebSocket error."
                        );
                        context.metrics.record_error(Some(&tunnel_id));
                        break;
                    }
                    _ => {}
                }
            }
        }
    }

    info!("Sending close frame to tunnel client.");
    let close_frame = tokio_tungstenite::tungstenite::protocol::CloseFrame {
        code: CloseCode::Away,
        reason: "Server shutting down".into(),
    };
    let _ = ws_sender.send(WsMessage::Close(Some(close_frame))).await;
    let _ = ws_sender.close().await;
    info!("Tunnel WebSocket closed cleanly.");

    ping_handle.abort();
    drop(_cleanup_guard);

    Ok(())
}

fn start_ping_task(
    tunnel_id: String,
    tunnels: TunnelMap,
    ping_tx: mpsc::UnboundedSender<()>,
    cancel_token: CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = interval(Duration::from_secs(30));
        interval.tick().await;

        loop {
            interval.tick().await;

            let connection = {
                let tunnels_guard = tunnels.read().await;
                tunnels_guard.get(&tunnel_id).cloned()
            };

            match connection {
                Some(conn) => {
                    if conn.is_stale().await {
                        warn!(
                            tunnel_id,
                            "Tunnel marked stale by ping task."
                        );
                        cancel_token.cancel();
                        break;
                    }

                    if ping_tx.send(()).is_err() {
                        debug!(
                            tunnel_id,
                            "Ping task stopped; main loop closed."
                        );
                        break;
                    }
                }
                None => {
                    debug!(
                        tunnel_id,
                        "Tunnel missing; stopping ping task."
                    );
                    break;
                }
            }
        }

        info!(
            tunnel_id,
            "Ping task ended."
        );
    })
}

async fn wait_for_authentication(
    ws_receiver: &mut SplitStream<WebSocketStream<TokioIo<Upgraded>>>,
    ws_sender: &mut SplitSink<WebSocketStream<TokioIo<Upgraded>>, WsMessage>,
    context: &ServiceContext,
) -> Result<Option<String>, BoxError> {
    let auth_timeout = Duration::from_secs(30);

    match tokio::time::timeout(auth_timeout, ws_receiver.next()).await {
        Ok(Some(Ok(WsMessage::Binary(bytes)))) => {
            match Message::from_bincode(&bytes) {
                Ok(Message::Auth {
                    token,
                    tunnel_id,
                    version,
                }) => {
                    info!(
                        tunnel_id,
                        version,
                        "Tunnel authentication request received."
                    );

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
                    warn!("Unexpected message during tunnel authentication.");
                    Ok(None)
                }
                Err(e) => {
                    error!(
                        error = %e,
                        "Failed to parse tunnel authentication message."
                    );
                    Ok(None)
                }
            }
        }
        Ok(Some(Ok(WsMessage::Close(_)))) => {
            info!("Tunnel WebSocket closed before authentication.");
            Ok(None)
        }
        Ok(Some(Err(e))) => {
            error!(error = %e, "Tunnel WebSocket error during authentication.");
            Ok(None)
        }
        Ok(None) => {
            info!("Tunnel WebSocket ended before authentication.");
            Ok(None)
        }
        Err(_) => {
            warn!(
                seconds = auth_timeout.as_secs(),
                "Tunnel authentication timed out."
            );
            Ok(None)
        }
        _ => {
            warn!("Unexpected message during tunnel authentication.");
            Ok(None)
        }
    }
}

async fn handle_http_response_start(
    id: String,
    status: u16,
    headers: std::collections::HashMap<String, String>,
    initial_data: Vec<u8>,
    is_complete: bool,
    context: &ServiceContext,
) {
    debug!(
        status,
        id,
        complete = is_complete,
        bytes = initial_data.len(),
        "Tunnel response started."
    );

    if let Some(request) = context.active_requests.read().await.get(&id) {
        if is_complete {
            let complete_event = ResponseEvent::Complete {
                status,
                headers,
                body: initial_data,
            };

            match request.response_tx.send(complete_event).await {
                Ok(_) => debug!(id, "Tunnel response queued."),
                Err(e) => error!(
                    id,
                    error = %e,
                    "Failed to queue tunnel response."
                ),
            }
        } else {
            let stream_start = ResponseEvent::StreamStart {
                status,
                headers,
                initial_data,
            };

            match request.response_tx.send(stream_start).await {
                Ok(_) => debug!(id, "Tunnel streaming task started."),
                Err(e) => {
                    error!(
                        id,
                        error = %e,
                        "Failed to start tunnel streaming task."
                    );
                    context.active_requests.write().await.remove(&id);
                }
            }
        }
    }
}

async fn handle_data_chunk(id: String, data: Vec<u8>, is_final: bool, context: &ServiceContext) {
    debug!(
        bytes = data.len(),
        final_chunk = is_final,
        id,
        "Tunnel data chunk received."
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
            debug!(id, "Tunnel streaming task ended.");
        }
    } else {
        warn!(
            id,
            "Data chunk received for unknown request."
        );
    }
}

async fn handle_websocket_data(connection_id: String, data: Vec<u8>, context: &ServiceContext) {
    if let Some(connection) = context.active_websockets.read().await.get(&connection_id) {
        debug!(
            connection_id,
            age = %connection.age_info(),
            bytes = data.len(),
            "Tunnel WebSocket data received."
        );

        context.metrics.record_websocket_traffic(&connection.tunnel_id, 0, data.len() as u64);
        if let Some(ws_tx) = &connection.ws_tx {
            let ws_message = if let Ok(text) = String::from_utf8(data.clone()) {
                WsMessage::Text(text.into())
            } else {
                WsMessage::Binary(data.into())
            };

            if let Err(e) = ws_tx.send(ws_message) {
                error!(
                    connection_id,
                    error = %e,
                    "Failed to forward tunnel WebSocket data."
                );
            }
        }
    } else {
        warn!(
            connection_id,
            "Tunnel WebSocket connection not found."
        );
    }
}

async fn handle_websocket_close(
    connection_id: String,
    code: Option<u16>,
    reason: Option<String>,
    context: &ServiceContext,
) {
    if let Some(connection) = context
        .active_websockets
        .write()
        .await
        .remove(&connection_id)
    {
        info!(
            connection_id,
            code = ?code,
            reason = ?reason,
            final_status = %connection.status_summary(),
            "Tunnel WebSocket close received."
        );
        if let Some(ws_tx) = &connection.ws_tx {
            let close_frame = code.map(|code| tokio_tungstenite::tungstenite::protocol::CloseFrame {
                    code: code.into(),
                    reason: reason.unwrap_or_default().into(),
                });

            if let Err(e) = ws_tx.send(WsMessage::Close(close_frame)) {
                error!(
                    connection_id,
                    error = ?e,
                    "Failed to send tunnel close frame."
                );
            };
        }
        info!(
            connection_id,
            "Tunnel WebSocket connection cleaned."
        );
    }
}

pub async fn shutdown_tunnel(context: ServiceContext, tunnel_id: String) -> bool {
    let tunnel_existed = {
        let mut tunnels_guard = context.tunnels.write().await;
        if tunnels_guard.remove(&tunnel_id).is_some() {
            info!(
                tunnel_id,
                "Tunnel client disconnected."
            );
            true
        } else {false}
    };

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
            count = websocket_connections_to_cleanup.len(),
            "Tunnel WebSocket cleanup started."
        );
        for connection_id in websocket_connections_to_cleanup {
            if let Some(connection) = context
                .active_websockets
                .write()
                .await
                .remove(&connection_id)
            {
                debug!(
                    connection_id,
                    "Tunnel WebSocket connection marked for cleanup."
                );

                context.metrics.websocket_disconnected(&tunnel_id);

                if let Some(ws_tx) = &connection.ws_tx {
                    let close_msg = WsMessage::Close(Some(
                        tokio_tungstenite::tungstenite::protocol::CloseFrame {
                            code: 1001u16.into(),
                            reason: "ExposeME client disconnected".into(),
                        },
                    ));
                    if let Err(e) = ws_tx.send(close_msg) {
                        warn!(
                            connection_id,
                            error = %e,
                            "Failed to send close frame during tunnel WebSocket cleanup."
                        );
                    }
                }
            }
        }
    }

    context.metrics.tunnel_disconnected(&tunnel_id);

    tunnel_existed
}
