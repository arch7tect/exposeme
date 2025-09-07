// src/svc/types.rs - Core types and data structures

use crate::{ChallengeStore, Message, SslManager};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::time::Duration;
use tokio::sync::{RwLock, mpsc};
use tokio::time::Instant;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use crate::ServerConfig;

pub type TunnelMap = Arc<RwLock<HashMap<String, Arc<TunnelConnection>>>>;
pub type ActiveRequests = Arc<RwLock<HashMap<String, ActiveRequest>>>;
pub type ActiveWebSockets = Arc<RwLock<HashMap<String, WebSocketConnection>>>;
pub type ResponseBody = BoxBody<Bytes, super::BoxError>;

// Type aliases for shared state
#[derive(Debug)]
pub struct TunnelConnection {
    pub sender: mpsc::UnboundedSender<Message>,
    pub last_activity: Arc<RwLock<Instant>>,
    pub last_ping_sent: Arc<RwLock<Option<Instant>>>,
    pub tunnel_id: String,
}

impl TunnelConnection {
    pub fn new(sender: mpsc::UnboundedSender<Message>, tunnel_id: String) -> Self {
        Self {
            sender,
            last_activity: Arc::new(RwLock::new(Instant::now())),
            last_ping_sent: Arc::new(RwLock::new(None)),
            tunnel_id,
        }
    }

    pub async fn update_activity(&self) {
        *self.last_activity.write().await = Instant::now();
    }

    pub async fn is_stale(&self) -> bool {
        let last_activity = *self.last_activity.read().await;
        let last_ping_sent = *self.last_ping_sent.read().await;
        
        // Check if connection is stale (no activity in 90s)
        let activity_stale = last_activity.elapsed() > Duration::from_secs(90);
        
        // Check if ping was sent but no pong received within 60s
        let ping_timeout = if let Some(ping_time) = last_ping_sent {
            ping_time.elapsed() > Duration::from_secs(60) && ping_time > last_activity
        } else {
            false
        };
        
        activity_stale || ping_timeout
    }

    pub async fn record_ping_sent(&self) {
        *self.last_ping_sent.write().await = Some(Instant::now());
    }
}

/// Represents an active HTTP request being processed through a tunnel
#[derive(Debug)]
pub struct ActiveRequest {
    pub tunnel_id: String,
    pub response_tx: mpsc::Sender<ResponseEvent>,
    pub client_disconnected: Arc<AtomicBool>,
}

/// Events that can occur during response processing
#[derive(Debug)]
pub enum ResponseEvent {
    Complete {
        status: u16,
        headers: HashMap<String, String>,
        body: Vec<u8>,
    },
    StreamStart {
        status: u16,
        headers: HashMap<String, String>,
        initial_data: Vec<u8>,
    },
    StreamChunk(Bytes),
    StreamEnd,
    Error(String),
}

/// Represents an active WebSocket connection through a tunnel
#[derive(Debug)]
pub struct WebSocketConnection {
    pub tunnel_id: String,
    pub created_at: std::time::Instant,
    pub ws_tx: Option<mpsc::UnboundedSender<WsMessage>>,
}

impl WebSocketConnection {
    pub fn new(tunnel_id: String) -> Self {
        Self {
            tunnel_id,
            created_at: std::time::Instant::now(),
            ws_tx: None,
        }
    }

    pub fn connection_age(&self) -> Duration {
        self.created_at.elapsed()
    }

    pub fn age_info(&self) -> String {
        let age = self.connection_age();
        if age.as_secs() < 60 {
            format!("{}s", age.as_secs())
        } else {
            format!("{}m", age.as_secs() / 60)
        }
    }

    pub fn status_summary(&self) -> String {
        format!(
            "tunnel: {}, age: {}, ws: {}",
            self.tunnel_id,
            self.age_info(),
            if self.ws_tx.is_some() {
                "active"
            } else {
                "upgrading"
            }
        )
    }
}

/// Context passed to unified service handlers
#[derive(Clone)]
pub struct ServiceContext {
    pub tunnels: TunnelMap,
    pub active_requests: ActiveRequests,
    pub active_websockets: ActiveWebSockets,
    pub config: ServerConfig,
    pub challenge_store: ChallengeStore,
    pub ssl_manager: Arc<RwLock<SslManager>>,
    pub is_https: bool,
}