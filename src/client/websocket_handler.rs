use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
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
    shutdown_flag: Arc<AtomicBool>,
}

impl WebSocketHandler {
    pub fn new(
        local_target: String,
        to_server_tx: mpsc::UnboundedSender<Message>,
        active_websockets: ActiveWebSockets,
        config: ClientConfig,
        shutdown_flag: Arc<AtomicBool>,
    ) -> Self {
        Self {
            local_target,
            to_server_tx,
            active_websockets,
            config,
            shutdown_flag,
        }
    }

    pub async fn handle_upgrade(
        &self,
        connection_id: String,
        method: String,
        path: String,
        headers: HashMap<String, String>,
    ) {
        info!(
            method,
            path,
            connection_id = %connection_id,
            "WebSocket upgrade request received."
        );

        let local_target = self.local_target.clone();
        let to_server_tx = self.to_server_tx.clone();
        let active_websockets = self.active_websockets.clone();
        let config = self.config.clone();
        let shutdown_flag = self.shutdown_flag.clone();

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
                shutdown_flag
            ).await;
        });
    }

    pub async fn handle_data(&self, connection_id: String, data: Vec<u8>) {
        debug!(
            connection_id = %connection_id,
            bytes = data.len(),
            "WebSocket data received for a client connection."
        );
        handle_websocket_data(self.active_websockets.clone(), connection_id, data).await;
    }

    pub async fn handle_close(&self, connection_id: String, code: Option<u16>, reason: Option<String>) {
        debug!(
            connection_id = %connection_id,
            code = ?code,
            reason = ?reason,
            "WebSocket close frame received from server."
        );
        handle_websocket_close(self.active_websockets.clone(), connection_id, code, reason).await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn handle_websocket_upgrade(
    local_target: &str,
    to_server_tx: &mpsc::UnboundedSender<Message>,
    active_websockets: ActiveWebSockets,
    connection_id: String,
    method: String,
    path: String,
    headers: HashMap<String, String>,
    config: &ClientConfig,
    shutdown_flag: Arc<AtomicBool>,
) {
    info!(
        connection_id = %connection_id,
        "WebSocket upgrade processing started."
    );
    info!(
        method,
        path,
        headers = headers.len(),
        "WebSocket upgrade request details logged."
    );

    let ws_url = if local_target.starts_with("http://") {
        local_target.replace("http://", "ws://") + &path
    } else if local_target.starts_with("https://") {
        local_target.replace("https://", "wss://") + &path
    } else {
        format!("ws://{}{}", local_target, path)
    };

    debug!(
        url = %ws_url,
        "Connecting to local WebSocket service."
    );
    let connect_timeout = Duration::from_secs(config.client.websocket_connection_timeout_secs);
    let connect_result = timeout(connect_timeout, connect_async(&ws_url)).await;

    match connect_result {
        Ok(Ok((local_ws, response))) => {
            debug!(
                connection_id = %connection_id,
                "Connected to local WebSocket service."
            );

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
                error!(
                    connection_id = %connection_id,
                    error = %e,
                    "Failed to send WebSocket upgrade response."
                );
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

            info!(
                connection_id = %connection.connection_id,
                "Client WebSocket connection established to local target."
            );

            {
                let mut websockets = active_websockets.write().await;
                websockets.insert(connection_id.clone(), connection);
            }

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
                                let status = connection.status_summary().await;
                                if connection.is_idle(max_idle).await {
                                    warn!(
                                        connection_id = %connection.connection_id,
                                        status = %status,
                                        "WebSocket monitor detected idle timeout."
                                    );
                                    true
                                } else {
                                    debug!(
                                        connection_id = %connection.connection_id,
                                        status = %status,
                                        "WebSocket health check recorded."
                                    );
                                    false
                                }
                            } else {
                                true
                            }
                        };

                        if should_cleanup {
                            break;
                        }
                    }

                    info!(
                        connection_id = %connection_id,
                        "WebSocket monitor task ended."
                    );
                })
            };

            let active_websockets_clone = active_websockets.clone();
            let connection_id_clone = connection_id.clone();

            let local_to_server_task = {
                let connection = connection_clone.clone();
                let connection_id = connection_id_clone.clone();

                tokio::spawn(async move {
                    debug!(
                        connection_id = %connection.connection_id,
                        "Local-to-server WebSocket forwarding started."
                    );

                    while let Some(msg) = local_stream.next().await {
                        if shutdown_flag.load(Ordering::Relaxed) {
                            debug!(
                                connection_id = %connection.connection_id,
                                "Local-to-server forwarding stopped due to shutdown."
                            );
                            break;
                        }
                        match msg {
                            Ok(WsMessage::Text(text)) => {
                                trace!(
                                    connection_id = %connection.connection_id,
                                    chars = text.len(),
                                    "Text frame forwarded to server."
                                );
                                let message = Message::WebSocketData {
                                    connection_id: connection.connection_id.clone(),
                                    data: text.as_bytes().to_vec(),
                                };

                                if connection.send_to_server(message).await.is_err() {
                                    error!(
                                        connection_id = %connection.connection_id,
                                        "Failed to forward text frame to server."
                                    );
                                    break;
                                }
                            }
                            Ok(WsMessage::Binary(bytes)) => {
                                trace!(
                                    connection_id = %connection.connection_id,
                                    bytes = bytes.len(),
                                    "Binary frame forwarded to server."
                                );
                                let message = Message::WebSocketData {
                                    connection_id: connection.connection_id.clone(),
                                    data: bytes.to_vec(),
                                };

                                if connection.send_to_server(message).await.is_err() {
                                    error!(
                                        connection_id = %connection.connection_id,
                                        "Failed to forward binary frame to server."
                                    );
                                    break;
                                }
                            }
                            Ok(WsMessage::Close(close_frame)) => {
                                let (code, reason) = if let Some(frame) = close_frame {
                                    (Some(frame.code.into()), Some(frame.reason.to_string()))
                                } else {
                                    (None, None)
                                };

                                info!(
                                    connection_id = %connection.connection_id,
                                    code = ?code,
                                    reason = ?reason,
                                    "Local WebSocket closed."
                                );

                                let message = Message::WebSocketClose {
                                    connection_id: connection.connection_id.clone(),
                                    code,
                                    reason,
                                };
                                let _ = connection.send_to_server(message).await;
                                break;
                            }
                            Err(e) => {
                                error!(
                                    connection_id = %connection.connection_id,
                                    error = %e,
                                    "Local WebSocket error."
                                );
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
                    debug!(
                        status = %final_status,
                        "Local-to-server forwarding task ended."
                    );
                })
            };

            let server_to_local_task = {
                let connection = connection_clone.clone();

                tokio::spawn(async move {
                    debug!(
                        connection_id = %connection.connection_id,
                        "Server-to-local WebSocket forwarding started."
                    );

                    while let Some(data) = local_rx.recv().await {
                        let ws_message = if let Ok(text) = String::from_utf8(data.clone()) {
                            WsMessage::Text(text.into())
                        } else {
                            WsMessage::Binary(data.into())
                        };

                        if local_sink.send(ws_message).await.is_err() {
                            error!(
                                connection_id = %connection.connection_id,
                                "Failed to forward frame to local WebSocket."
                            );
                            break;
                        }
                    }

                    let status = connection.status_summary().await;
                    info!(
                        connection_id = %connection.connection_id,
                        status = %status,
                        "Server-to-local forwarding task ended."
                    );
                })
            };

            tokio::select! {
                _ = monitoring_task => {
                    info!(
                        connection_id = %connection_id,
                        "WebSocket monitor task completed."
                    );
                }
                _ = local_to_server_task => {
                    info!(
                        connection_id = %connection_id,
                        "Local-to-server forwarding task completed."
                    );
                }
                _ = server_to_local_task => {
                    info!(
                        connection_id = %connection_id,
                        "Server-to-local forwarding task completed."
                    );
                }
            }

            {
                let mut websockets = active_websockets.write().await;
                if let Some(connection) = websockets.remove(&connection_id) {
                    let status = connection.status_summary().await;
                    info!(
                        connection_id = %connection.connection_id,
                        status = %status,
                        "Final WebSocket cleanup completed for the client connection."
                    );
                }
            }

            info!(
                connection_id = %connection_id,
                "WebSocket closed."
            );
        }
        Ok(Err(e)) => {
            error!(
                connection_id = %connection_id,
                error = %e,
                "Failed to connect to local WebSocket service."
            );
            send_websocket_error_response(to_server_tx, connection_id, 502, "Connection failed").await;
        }
        Err(_) => {
            error!(
                connection_id = %connection_id,
                "Local WebSocket connection timed out."
            );
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
        error!(
            error = %e,
            "Failed to send WebSocket error response to server."
        );
    }
}

async fn handle_websocket_data(
    active_websockets: ActiveWebSockets,
    connection_id: String,
    data: Vec<u8>,
) {
    if let Some(connection) = active_websockets.read().await.get(&connection_id) {
        connection.update_activity().await;
        let data_size = data.len();

        if connection.send_to_local(data).await.is_ok() {
            debug!(
                connection_id = %connection.connection_id,
                bytes = data_size,
                "Frame forwarded to local WebSocket."
            );
        } else {
            active_websockets.write().await.remove(&connection_id);
            error!(
                connection_id = %connection.connection_id,
                "Failed to forward frame to local WebSocket."
            );
        }
    } else {
        warn!(
            connection_id = %connection_id,
            "WebSocket message for unknown connection."
        );
    }
}

async fn handle_websocket_close(
    active_websockets: ActiveWebSockets,
    connection_id: String,
    code: Option<u16>,
    reason: Option<String>,
) {
    if let Some(connection) = active_websockets.write().await.remove(&connection_id) {
        let status = connection.status_summary().await;
        info!(
            connection_id = %connection.connection_id,
            code = ?code,
            reason = ?reason,
            status = %status,
            "Server closed WebSocket connection."
        );
    } else {
        debug!(
            connection_id = %connection_id,
            "Ignored WebSocket close for unknown client connection."
        );
    }
}
