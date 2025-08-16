// src/client/websocket_handler.rs - WebSocket upgrade and data handling
use std::collections::HashMap;
use std::time::Duration;
use futures_util::{SinkExt, StreamExt};
use tokio::sync::{mpsc};
use tokio::time::timeout;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use tracing::{debug, error, info, trace, warn};

use crate::{ClientConfig, Message};
use super::connection::{ActiveWebSocketConnection, ActiveWebSockets};

pub struct WebSocketHandler {
    local_target: String,
    to_server_tx: mpsc::UnboundedSender<Message>,
    active_websockets: ActiveWebSockets,
    config: ClientConfig,
}

impl WebSocketHandler {
    pub fn new(
        local_target: String,
        to_server_tx: mpsc::UnboundedSender<Message>,
        active_websockets: ActiveWebSockets,
        config: ClientConfig,
    ) -> Self {
        Self {
            local_target,
            to_server_tx,
            active_websockets,
            config,
        }
    }

    pub async fn handle_upgrade(
        &self,
        connection_id: String,
        method: String,
        path: String,
        headers: HashMap<String, String>,
    ) {
        info!("📥 Received WebSocketUpgrade: {} {} (connection: {})", method, path, connection_id);

        let local_target = self.local_target.clone();
        let to_server_tx = self.to_server_tx.clone();
        let active_websockets = self.active_websockets.clone();
        let config = self.config.clone();

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

    pub async fn handle_data(&self, connection_id: String, data: Vec<u8>) {
        debug!("📥 Received WebSocketData: {} ({} bytes)", connection_id, data.len());
        handle_websocket_data(self.active_websockets.clone(), connection_id, data).await;
    }

    pub async fn handle_close(&self, connection_id: String, code: Option<u16>, reason: Option<String>) {
        debug!("📥 Received WebSocketClose: {} (code: {:?}, reason: {:?})", connection_id, code, reason);
        handle_websocket_close(self.active_websockets.clone(), connection_id, code, reason).await;
    }
}

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

    let ws_url = if local_target.starts_with("http://") {
        local_target.replace("http://", "ws://") + &path
    } else if local_target.starts_with("https://") {
        local_target.replace("https://", "wss://") + &path
    } else {
        format!("ws://{}{}", local_target, path)
    };

    debug!("🔗 Connecting to local WebSocket: {}", ws_url);
    let connect_timeout = Duration::from_secs(config.client.websocket_connection_timeout_secs);
    let connect_result = timeout(connect_timeout, connect_async(&ws_url)).await;

    match connect_result {
        Ok(Ok((local_ws, response))) => {
            debug!("✅ Connected to local WebSocket service for {}", connection_id);

            let mut response_headers = HashMap::new();
            for (name, value) in response.headers() {
                response_headers.insert(
                    name.to_string(),
                    value.to_str().unwrap_or("").to_string()
                );
            }

            let upgrade_response = Message::WebSocketUpgradeResponse {
                connection_id: connection_id.clone(),
                status: response.status().as_u16(),
                headers: response_headers,
            };

            if let Err(e) = to_server_tx.send(upgrade_response) {
                error!("Failed to send WebSocket upgrade response for {}: {}", connection_id, e);
                return;
            }

            let (mut local_sink, mut local_stream) = local_ws.split();
            let (local_tx, mut local_rx) = mpsc::unbounded_channel::<Vec<u8>>();

            let connection = ActiveWebSocketConnection::new(
                connection_id.clone(),
                local_tx,
                to_server_tx.clone(),
            );
            let connection_clone = connection.clone();

            info!("🔌 WebSocket {}: WebSocket connection established", connection.connection_id);

            {
                let mut websockets = active_websockets.write().await;
                websockets.insert(connection_id.clone(), connection);
            }

            // Connection monitoring task
            let monitoring_task = {
                let active_websockets = active_websockets.clone();
                let connection_id = connection_id.clone();
                let monitoring_interval = Duration::from_secs(config.client.websocket_monitoring_interval_secs);
                let max_idle = Duration::from_secs(config.client.websocket_max_idle_secs);

                tokio::spawn(async move {
                    let mut interval = tokio::time::interval(monitoring_interval);

                    loop {
                        interval.tick().await;

                        let should_cleanup = {
                            let websockets = active_websockets.read().await;
                            if let Some(connection) = websockets.get(&connection_id) {
                                if connection.is_idle(max_idle).await {
                                    warn!("⚠️  WebSocket {}: Connection timeout detected ({})", connection.connection_id, connection.status_summary().await);
                                    true
                                } else {
                                    // Log periodic status
                                    info!("🔌 WebSocket {}: Health check: {}", connection.connection_id, connection.status_summary().await);
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

            let active_websockets_clone = active_websockets.clone();
            let connection_id_clone = connection_id.clone();

            // Forward FROM local service TO server
            let local_to_server_task = {
                let connection = connection_clone.clone();
                let connection_id = connection_id_clone.clone();

                tokio::spawn(async move {
                    info!("🔌 WebSocket {}: Started local-to-server forwarding task", connection.connection_id);

                    while let Some(msg) = local_stream.next().await {
                        match msg {
                            Ok(WsMessage::Text(text)) => {
                                trace!("🔌 WebSocket {}: 📤 Forwarding text to server: {} chars", connection.connection_id, text.len());
                                let message = Message::WebSocketData {
                                    connection_id: connection.connection_id.clone(),
                                    data: text.as_bytes().to_vec(),
                                };

                                if connection.send_to_server(message).await.is_err() {
                                    error!("❌ WebSocket {}: Failed to send text message to server, terminating", connection.connection_id);
                                    break;
                                }
                            }
                            Ok(WsMessage::Binary(bytes)) => {
                                trace!("🔌 WebSocket {}: 📤 Forwarding binary to server: {} bytes", connection.connection_id, bytes.len());
                                let message = Message::WebSocketData {
                                    connection_id: connection.connection_id.clone(),
                                    data: bytes.to_vec(),
                                };

                                if connection.send_to_server(message).await.is_err() {
                                    error!("❌ WebSocket {}: Failed to send binary message to server, terminating", connection.connection_id);
                                    break;
                                }
                            }
                            Ok(WsMessage::Close(close_frame)) => {
                                let (code, reason) = if let Some(frame) = close_frame {
                                    (Some(frame.code.into()), Some(frame.reason.to_string()))
                                } else {
                                    (None, None)
                                };

                                info!("🔌 WebSocket {}: Local WebSocket closed: code={:?}, reason={:?}", connection.connection_id, code, reason);

                                let message = Message::WebSocketClose {
                                    connection_id: connection.connection_id.clone(),
                                    code,
                                    reason,
                                };
                                let _ = connection.send_to_server(message).await;
                                break;
                            }
                            Err(e) => {
                                error!("❌ WebSocket {}: Local WebSocket error: {}", connection.connection_id, e);
                                break;
                            }
                            _ => {}
                        }
                    }

                    let final_status = {
                        let websockets = active_websockets_clone.read().await;
                        if let Some(conn) = websockets.get(&connection_id) {
                            conn.status_summary().await
                        } else {
                            format!("Connection {} (already cleaned up)", connection_id)
                        }
                    };

                    active_websockets_clone.write().await.remove(&connection_id);
                    debug!("🔌 Local-to-server task ended: {}", final_status);
                })
            };

            // Forward FROM server TO local service
            let server_to_local_task = {
                let connection = connection_clone.clone();

                tokio::spawn(async move {
                    info!("🔌 WebSocket {}: Started server-to-local forwarding task", connection.connection_id);

                    while let Some(data) = local_rx.recv().await {
                        let ws_message = if let Ok(text) = String::from_utf8(data.clone()) {
                            WsMessage::Text(text.into())
                        } else {
                            WsMessage::Binary(data.into())
                        };

                        if local_sink.send(ws_message).await.is_err() {
                            error!("❌ WebSocket {}: Failed to send to local WebSocket, terminating", connection.connection_id);
                            break;
                        }
                    }

                    info!("🔌 WebSocket {}: Server-to-local task ended ({})", connection.connection_id, connection.status_summary().await);
                })
            };

            // Wait for any task to complete
            tokio::select! {
                _ = monitoring_task => {
                    info!("Monitoring task completed for {}", connection_id);
                }
                _ = local_to_server_task => {
                    info!("Local-to-server task completed for {}", connection_id);
                }
                _ = server_to_local_task => {
                    info!("Server-to-local task completed for {}", connection_id);
                }
            }

            {
                let mut websockets = active_websockets.write().await;
                if let Some(connection) = websockets.remove(&connection_id) {
                    info!("🔌 WebSocket {}: Final cleanup: {}", connection.connection_id, connection.status_summary().await);
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

async fn handle_websocket_data(
    active_websockets: ActiveWebSockets,
    connection_id: String,
    data: Vec<u8>, // No longer base64 string - raw bytes
) {
    if let Some(connection) = active_websockets.read().await.get(&connection_id) {
        connection.update_activity().await;
        let data_size = data.len();

        // No more base64 decoding - data is already raw bytes
        if connection.send_to_local(data).await.is_ok() {
            debug!("🔌 WebSocket {}: Forwarded {} bytes to local WebSocket", connection.connection_id, data_size);
        } else {
            active_websockets.write().await.remove(&connection_id);
            error!("❌ WebSocket {}: Failed to forward data to local WebSocket", connection.connection_id);
        }
    } else {
        warn!("Received data for unknown WebSocket connection: {}", connection_id);
    }
}

async fn handle_websocket_close(
    active_websockets: ActiveWebSockets,
    connection_id: String,
    code: Option<u16>,
    reason: Option<String>,
) {
    if let Some(connection) = active_websockets.write().await.remove(&connection_id) {
        info!(
            "🔌 WebSocket {}: WebSocket closed by server: code={:?}, reason={:?}, final_status={}",
            connection.connection_id, code, reason, connection.status_summary().await
        );
    } else {
        warn!("Attempted to close unknown WebSocket connection: {}", connection_id);
    }
}