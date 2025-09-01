// src/client/mod.rs - Main client implementation
use std::sync::Arc;
use std::time::Duration;
use futures_util::{SinkExt, StreamExt};
use reqwest::Client as HttpClient;
use tokio::sync::{mpsc, RwLock, broadcast};
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use tokio_tungstenite::Connector;
use rustls::ClientConfig as RustlsClientConfig;
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

    pub async fn run(&mut self, mut shutdown_rx: broadcast::Receiver<()>) -> Result<(), Box<dyn std::error::Error>> {
        // Connect to WebSocket server
        let (ws_stream, _) = if self.config.client.insecure && self.config.client.server_url.starts_with("wss://") {
            warn!("⚠️  Using insecure connection (skipping TLS verification)");
            warn!("⚠️  This should only be used for development with self-signed certificates");

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

        info!("Connected to WebSocket server");

        let (mut ws_sender, mut ws_receiver) = ws_stream.split();

        // Send authentication
        let auth_message = Message::Auth {
            token: self.config.client.auth_token.clone(),
            tunnel_id: self.config.client.tunnel_id.clone(),
            version: env!("CARGO_PKG_VERSION").to_string(),
        };

        let auth_bytes = auth_message.to_bincode()?;
        ws_sender.send(WsMessage::Binary(auth_bytes.into())).await?;
        info!("Sent authentication for tunnel '{}'", self.config.client.tunnel_id);

        // Create shared state
        let active_websockets: ActiveWebSockets = Arc::new(RwLock::new(std::collections::HashMap::new()));
        let outgoing_requests: OutgoingRequests = Arc::new(RwLock::new(std::collections::HashMap::new()));

        // Create channel for sending messages back to server
        let (to_server_tx, mut to_server_rx) = mpsc::unbounded_channel::<Message>();

        // Create handlers
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
        );

        // Split WebSocket sender for shared access
        let ws_sender_shared = Arc::new(tokio::sync::Mutex::new(ws_sender));
        let ws_sender_for_task = ws_sender_shared.clone();

        // Spawn task to handle outgoing messages to server
        let _outgoing_handle = tokio::spawn(async move {
            debug!("🔍 Starting outgoing message handler task");
            let mut message_count = 0;

            while let Some(message) = to_server_rx.recv().await {
                message_count += 1;

                match message.to_bincode() {
                    Ok(bytes) => {
                        trace!("🔍 Sending message #{} ({} bytes)", message_count, bytes.len());
                        let mut sender = ws_sender_for_task.lock().await;
                        match sender.send(WsMessage::Binary(bytes.into())).await {
                            Ok(_) => {
                                trace!("✅ Message #{} sent successfully", message_count);
                            }
                            Err(e) => {
                                error!("❌ FAILED to send message #{}: {}", message_count, e);
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        error!("❌ Failed to serialize message #{}: {}", message_count, e);
                    }
                }
            }

            debug!("⚠️ Outgoing message handler ended (sent {} messages)", message_count);
        });

        // Start cleanup task
        let mut cleanup_task = self.start_cleanup_task(active_websockets.clone()).await;

        let mut need_reconnect = false;

        // Handle incoming WebSocket messages
        loop {
            tokio::select! {
                // Handle shutdown signal
                _ = shutdown_rx.recv() => {
                    info!("🔄 Client shutdown requested, closing WebSocket connection...");
                    
                    {
                        let mut sender = ws_sender_shared.lock().await;
                        let _ = sender.close().await;  // Send WebSocket close frame directly
                    }
                    
                    break;
                }
                
                // Handle WebSocket messages
                message = ws_receiver.next() => {
                    match message {
                        Some(Ok(WsMessage::Binary(bytes))) => {
                            debug!("📨 Raw WebSocket message received: {} bytes", bytes.len());
                            trace!("Bytes: {}", bytes.iter().map(|b| format!("{:02x}", b)).collect::<Vec<String>>().join(" "));
                            match Message::from_bincode(&bytes) {
                                Ok(msg) => {
                                    if let Err(e) = self.handle_message(msg, &http_handler, &websocket_handler).await {
                                        error!("Message handling error: {}", e);
                                    }
                                }
                                Err(e) => {
                                    error!("❌ Failed to parse WebSocket message: {}", e);
                                }
                            }
                        }
                        Some(Ok(WsMessage::Text(text))) => {
                            error!("❌ Received unexpected text message (protocol requires binary): {} chars", text.len());
                            error!("❌ Please ensure both client and server are using the same protocol version");
                            break;
                        }
                        Some(Ok(WsMessage::Close(_))) => {
                            info!("WebSocket connection closed by server");
                            break;
                        }
                        Some(Err(e)) => {
                            match e {
                                tokio_tungstenite::tungstenite::Error::Io(io_err) => {
                                    match io_err.kind() {
                                        std::io::ErrorKind::UnexpectedEof => {
                                            info!("WebSocket connection closed by peer (EOF)");
                                        }
                                        std::io::ErrorKind::ConnectionAborted | std::io::ErrorKind::ConnectionReset => {
                                            info!("WebSocket connection closed by peer (ABORT|RESET)");
                                        }
                                        _ => {
                                            error!("WebSocket IO error: {}", io_err);
                                            need_reconnect = true;
                                        }
                                    }
                                }
                                tokio_tungstenite::tungstenite::Error::ConnectionClosed => {
                                    info!("WebSocket connection closed");
                                }
                                _ => {
                                    error!("WebSocket error: {}", e);
                                    need_reconnect = true;
                                }
                            }
                            break;
                        }
                        None => {
                            info!("WebSocket stream ended");
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        // Graceful cleanup on client disconnect with timeout
        info!("🔄 Starting graceful cleanup...");
        
        let cleanup_timeout = Duration::from_secs(5);
        let cleanup_start = tokio::time::Instant::now();
        
        // Give cleanup task a chance to finish, then abort it
        tokio::select! {
            _ = tokio::time::sleep(Duration::from_millis(500)) => {
                debug!("Cleanup grace period completed, aborting task");
                cleanup_task.abort();
            }
            result = &mut cleanup_task => {
                debug!("Cleanup task completed naturally: {:?}", result);
            }
        }

        // Clean up all WebSocket connections on shutdown with timeout
        let cleanup_result = tokio::select! {
            _ = tokio::time::sleep(cleanup_timeout) => {
                warn!("⚠️ Cleanup timeout reached after {:?}, forcing shutdown", cleanup_timeout);
                false
            }
            _ = async {
                let mut websockets = active_websockets.write().await;
                let connection_count = websockets.len();
                if connection_count > 0 {
                    info!("🔌 Cleaning up {} WebSocket connections on shutdown", connection_count);
                    
                    // Close all active WebSocket connections gracefully
                    for (_id, connection) in websockets.iter() {
                        info!("🔌 Closing WebSocket connection: {}", connection.connection_id);
                        
                        // Send close message to server through tunnel
                        let close_msg = Message::WebSocketClose {
                            connection_id: connection.connection_id.clone(),
                            code: Some(1000), // Normal Closure
                            reason: Some("Client shutting down".to_string()),
                        };
                        
                        let _ = connection.to_server_tx.send(close_msg);
                    }
                    
                    // Clear all connections
                    websockets.clear();
                }
            } => {
                true
            }
        };
        
        let cleanup_elapsed = cleanup_start.elapsed();
        if cleanup_result {
            info!("✅ Graceful cleanup completed in {:?}", cleanup_elapsed);
        } else {
            info!("⚠️ Forced cleanup after {:?}", cleanup_elapsed);
        }

        info!("Client connection ended");
        if need_reconnect {Err("Network error".into())} else {Ok(())}
    }

    async fn handle_message(
        &self,
        msg: Message,
        http_handler: &HttpHandler,
        websocket_handler: &WebSocketHandler,
    ) -> Result<(), Box<dyn std::error::Error>> {
        match msg {
            Message::AuthSuccess { tunnel_id, public_url } => {
                info!("✅ Tunnel '{}' established!", tunnel_id);
                info!("🌐 Public URL: {}", public_url);
                info!("🔄 Forwarding to: {}", self.config.client.local_target);
            }

            Message::AuthError { error, message } => {
                error!("❌ Authentication failed: {} - {}", error, message);
                return Err(format!("Auth error: {}", message).into());
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
                error!("Server error: {}", message);
            }

            _ => {
                warn!("Unexpected message type from server");
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
                    info!(
                        "🔌 WebSocket status: {} active connections, {} cleaned up (max_idle: {}s, check_interval: {}s)",
                        current_count,
                        cleaned,
                        max_connection_idle.as_secs(),
                        cleanup_interval.as_secs()
                    );
                }
            }
        })
    }
}