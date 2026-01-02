use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use futures_util::{SinkExt, StreamExt};
use reqwest::Client as HttpClient;
use tokio::sync::{mpsc, RwLock};
use tokio_util::sync::CancellationToken;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use tokio_tungstenite::Connector;
use rustls::ClientConfig as RustlsClientConfig;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tracing::{debug, error, info, trace, warn};

use crate::{ClientConfig, Message};
use crate::insecure_cert::InsecureCertVerifier;

pub mod connection;
pub mod http_handler;
pub mod websocket_handler;

pub use connection::{ActiveWebSocketConnection, ActiveWebSockets};
use http_handler::{HttpHandler, OutgoingRequests};
use websocket_handler::WebSocketHandler;

pub struct ExposeMeClient {
    config: ClientConfig,
    http_client: HttpClient,
}

impl ExposeMeClient {
    pub fn new(config: ClientConfig) -> Self {
        Self {
            config,
            http_client: HttpClient::new(),
        }
    }

    pub fn config(&self) -> &ClientConfig {
        &self.config
    }

    pub async fn run(&mut self, shutdown_token: CancellationToken) -> Result<(), Box<dyn std::error::Error>> {
        let (ws_stream, _) = if self.config.client.insecure && self.config.client.server_url.starts_with("wss://") {
            warn!("Client running with insecure TLS verification.");
            warn!("Insecure TLS warning logged.");

            let tls_config = RustlsClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(InsecureCertVerifier))
                .with_no_client_auth();

            let connector = Connector::Rustls(Arc::new(tls_config));
            tokio_tungstenite::connect_async_tls_with_config(
                &self.config.client.server_url,
                None,
                false,
                Some(connector),
            ).await?
        } else {
            connect_async(&self.config.client.server_url).await?
        };

        info!("WebSocket connected to server.");

        let (mut ws_sender, mut ws_receiver) = ws_stream.split();

        let auth_message = Message::Auth {
            token: self.config.client.auth_token.clone(),
            tunnel_id: self.config.client.tunnel_id.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        };

        let auth_bytes = auth_message.to_bytes();
        ws_sender.send(WsMessage::Binary(auth_bytes.into())).await?;
        info!(
            tunnel_id = %self.config.client.tunnel_id,
            "Client authentication sent to server."
        );

        let active_websockets: ActiveWebSockets = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let outgoing_requests: OutgoingRequests = Arc::new(RwLock::new(std::collections::HashMap::new()));

        let shutdown_flag = Arc::new(AtomicBool::new(false));
        let outgoing_shutdown_flag = shutdown_flag.clone();

        let (to_server_tx, mut to_server_rx) = mpsc::unbounded_channel::<Message>();

        let http_handler = HttpHandler::new(
            self.http_client.clone(),
            self.config.client.local_target.clone(),
            to_server_tx.clone(),
            outgoing_requests.clone(),
        );

        let websocket_handler = WebSocketHandler::new(
            self.config.client.local_target.clone(),
            to_server_tx.clone(),
            active_websockets.clone(),
            self.config.clone(),
            shutdown_flag.clone(),
        );

        let ws_sender_shared = Arc::new(tokio::sync::Mutex::new(ws_sender));
        let ws_sender_for_task = ws_sender_shared.clone();

        let _outgoing_handle = tokio::spawn(async move {
            debug!("Outgoing message handler started.");
            let mut message_count = 0;

            while let Some(message) = to_server_rx.recv().await {
                message_count += 1;

                let bytes = message.to_bytes();
                trace!(
                    message_count,
                    bytes = bytes.len(),
                    "Outgoing message encoded and sent."
                );
                let mut sender = ws_sender_for_task.lock().await;
                if outgoing_shutdown_flag.load(Ordering::Relaxed) {
                    debug!("Outgoing handler stopped due to shutdown.");
                    break;
                }
                match sender.send(WsMessage::Binary(bytes.into())).await {
                    Ok(_) => {
                        trace!(
                            message_count,
                            "Outgoing message sent successfully."
                        );
                    }
                    Err(e) => {
                        match e {
                            tokio_tungstenite::tungstenite::Error::ConnectionClosed |
                            tokio_tungstenite::tungstenite::Error::AlreadyClosed => {
                                debug!("Outgoing handler stopped; WebSocket closed.");
                                break;
                            }
                            tokio_tungstenite::tungstenite::Error::Protocol(_) => {
                                debug!("Outgoing handler stopped; WebSocket protocol error.");
                                break;
                            }
                            tokio_tungstenite::tungstenite::Error::Io(_) => {
                                debug!("Outgoing handler stopped; WebSocket I/O error.");
                                break;
                            }
                            _ => {
                                error!(error = %e, "Failed to send outgoing message.");
                                break;
                            }
                        }
                    }
                }
            }

            debug!(
                sent = message_count,
                "Outgoing message handler completed."
            );
        });

        let mut cleanup_task = self.start_cleanup_task(active_websockets.clone()).await;

        let mut need_reconnect = false;

        loop {
            tokio::select! {
                _ = shutdown_token.cancelled() => {
                    info!("Client shutdown requested.");
                    shutdown_flag.store(true, Ordering::Relaxed);
                    {
                        let mut sender = ws_sender_shared.lock().await;
                        let _ = sender.close().await;
                    }

                    break;
                }

                message = ws_receiver.next() => {
                    match message {
                        Some(Ok(WsMessage::Binary(bytes))) => {
                            debug!(
                                bytes = bytes.len(),
                                "WebSocket message bytes received (raw length logged)."
                            );
                            trace!(
                                payload_hex = %bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<String>>().join(" "),
                                "WebSocket message bytes logged in hex for debugging."
                            );
                            match Message::from_bytes(&bytes) {
                                Ok(msg) => {
                                    if let Err(e) = self.handle_message(msg, &http_handler, &websocket_handler).await {
                                        error!(error = %e, "Failed to handle incoming server message.");
                                    }
                                }
                                Err(e) => {
                                    error!(error = %e, "Failed to parse incoming server message.");
                                }
                            }
                        }
                        Some(Ok(WsMessage::Text(text))) => {
                            error!(
                                chars = text.len(),
                                "Unexpected text message received (binary expected)."
                            );
                            break;
                        }
                        Some(Ok(WsMessage::Close(frame))) => {
                            if let Some(frame) = frame {
                                info!(
                                    code = ?frame.code,
                                    reason = %frame.reason,
                                    "WebSocket closed."
                                );

                                if frame.code == CloseCode::Away {
                                    info!("Server shutdown detected on WebSocket.");
                                    shutdown_flag.store(true, Ordering::Relaxed);
                                    drop(to_server_tx);
                                } else {
                                    need_reconnect = true;
                                }
                                let mut sender = ws_sender_shared.lock().await;
                                let close_response = WsMessage::Close(Some(
                                    tokio_tungstenite::tungstenite::protocol::CloseFrame {
                                        code: frame.code,
                                        reason: "Acknowledged".into(),
                                    }
                                ));
                                let _ = sender.send(close_response).await;
                                let _ = sender.close().await;
                            } else {
                                info!("WebSocket closed.");
                                need_reconnect = true;
                            }
                            break;
                        }
                        Some(Err(e)) => {
                            match e {
                                tokio_tungstenite::tungstenite::Error::Io(io_err) => {
                                    match io_err.kind() {
                                        std::io::ErrorKind::UnexpectedEof => {
                                            info!("WebSocket closed by peer (EOF).");
                                        }
                                        std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::ConnectionReset => {
                                            info!("WebSocket closed by peer (abort/reset).");
                                        }
                                        _ => {
                                            error!(
                                                error = %io_err,
                                                "WebSocket I/O error."
                                            );
                                        }
                                    }
                                    need_reconnect = true;
                                }
                                tokio_tungstenite::tungstenite::Error::ConnectionClosed => {
                                    info!("WebSocket closed.");
                                }
                                _ => {
                                    error!(error = %e, "WebSocket error.");
                                    need_reconnect = true;
                                }
                            }
                            break;
                        }
                        None => {
                            info!("WebSocket stream ended.");
                            shutdown_flag.store(true, Ordering::Relaxed);
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        info!("Client cleanup started.");

        let cleanup_timeout = Duration::from_secs(5);
        let cleanup_start = tokio::time::Instant::now();

        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                debug!("Cleanup grace period ended before task completion.");
                cleanup_task.abort();
            }
            result = &mut cleanup_task => {
                debug!(result = ?result, "Client cleanup finished naturally.");
            }
        }

        let cleanup_result = tokio::select! {
            _ = tokio::time::sleep(cleanup_timeout) => {
                warn!(
                    timeout = ?cleanup_timeout,
                    "Cleanup timed out; forcing shutdown."
                );
                false
            }
            _ = async {
                let mut websockets = active_websockets.write().await;
                let connection_count = websockets.len();
                if connection_count > 0 {
                    info!(
                        count = connection_count,
                        "WebSocket connections scheduled for cleanup."
                    );

                    for (_id, connection) in websockets.iter() {
                        info!(
                            connection_id = %connection.connection_id,
                            "WebSocket close sent during cleanup."
                        );

                        let close_msg = Message::WebSocketClose {
                            connection_id: connection.connection_id.clone(),
                            code: Some(1000),
                            reason: Some("Client shutting down".to_string()),
                        };

                        let _ = connection.to_server_tx.send(close_msg);
                    }

                    websockets.clear();
                }
            } => {
                true
            }
        };
        
        let cleanup_elapsed = cleanup_start.elapsed();
        if cleanup_result {
            info!(
                duration = ?cleanup_elapsed,
                "Client cleanup completed."
            );
        } else {
            info!(
                duration = ?cleanup_elapsed,
                "Client cleanup forced due to timeout."
            );
        }

        info!("Client connection ended.");
        if need_reconnect && !shutdown_flag.load(Ordering::Relaxed) {
            Err("Network error".into())
        } else {
            Ok(())
        }
    }

    async fn handle_message(
        &self,
        msg: Message,
        http_handler: &HttpHandler,
        websocket_handler: &WebSocketHandler,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match msg {
            Message::AuthSuccess { tunnel_id, public_url } => {
                info!(
                    tunnel_id,
                    public_url,
                    target = %self.config.client.local_target,
                    "Client authentication succeeded."
                );
            }

            Message::AuthError { error, message } => {
                return Err(format!("Auth error: {} (code: {})", message, error).into());
            }

            Message::HttpRequestStart { id, method, path, headers, initial_data, is_complete } => {
                http_handler.handle_request_start(id, method, path, headers, initial_data, is_complete).await;
            }

            Message::DataChunk { id, data, is_final } => {
                http_handler.handle_data_chunk(id, data, is_final).await;
            }

            Message::WebSocketUpgrade { connection_id, method, path, headers } => {
                websocket_handler.handle_upgrade(connection_id, method, path, headers).await;
            }

            Message::WebSocketData { connection_id, data } => {
                websocket_handler.handle_data(connection_id, data).await;
            }

            Message::WebSocketClose { connection_id, code, reason } => {
                websocket_handler.handle_close(connection_id, code, reason).await;
            }

            Message::Error { message } => {
                error!(message, "Server reported an error to client.");
            }

            _ => {
                warn!("Unexpected message received from server.");
            }
        }

        Ok(())
    }

    async fn start_cleanup_task(&self, active_websockets: ActiveWebSockets) -> tokio::task::JoinHandle<()> {
        let cleanup_interval = Duration::from_secs(self.config.client.websocket_cleanup_interval_secs);
        let max_connection_idle = Duration::from_secs(self.config.client.websocket_max_idle_secs);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(cleanup_interval);

            loop {
                interval.tick().await;

                let cleaned = connection::cleanup_expired_connections(
                    active_websockets.clone(),
                    max_connection_idle
                ).await;

                let current_count = active_websockets.read().await.len();
                if current_count > 0 || cleaned > 0 {
                    debug!(
                        active = current_count,
                        cleaned,
                        max_idle_secs = max_connection_idle.as_secs(),
                        check_interval_secs = cleanup_interval.as_secs(),
                        "WebSocket status reported."
                    );
                }
            }
        })
    }
}
