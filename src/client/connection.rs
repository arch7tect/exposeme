// src/client/connection.rs - WebSocket connection management
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, RwLock};
use tracing::{error, info, warn};
use crate::Message;

pub type ActiveWebSockets = Arc<RwLock<HashMap<String, ActiveWebSocketConnection>>>;

#[derive(Debug, Clone)]
pub struct ActiveWebSocketConnection {
    pub connection_id: String,
    pub local_tx: mpsc::UnboundedSender<Vec<u8>>,
    pub to_server_tx: mpsc::UnboundedSender<Message>,
    created_at: std::time::Instant,
    last_activity: Arc<RwLock<std::time::Instant>>,
}

impl ActiveWebSocketConnection {
    pub fn new(
        connection_id: String,
        local_tx: mpsc::UnboundedSender<Vec<u8>>,
        to_server_tx: mpsc::UnboundedSender<Message>,
    ) -> Self {
        let now = std::time::Instant::now();
        Self {
            connection_id,
            local_tx,
            to_server_tx,
            created_at: now,
            last_activity: Arc::new(RwLock::new(now)),
        }
    }

    pub fn connection_age(&self) -> Duration {
        self.created_at.elapsed()
    }

    pub async fn update_activity(&self) {
        *self.last_activity.write().await = std::time::Instant::now();
    }

    pub async fn is_idle(&self, max_idle_duration: Duration) -> bool {
        let last_activity = *self.last_activity.read().await;
        last_activity.elapsed() > max_idle_duration
    }

    pub async fn idle_time(&self) -> Duration {
        let last_activity = *self.last_activity.read().await;
        last_activity.elapsed()
    }

    pub async fn status_summary(&self) -> String {
        let idle = self.idle_time().await;
        let idle_info = if idle.as_secs() < 60 {
            format!("idle: {}s", idle.as_secs())
        } else {
            format!("idle: {}m", idle.as_secs() / 60)
        };

        format!(
            "Connection {} (age: {}, {}, channels: server={}, local={})",
            self.connection_id,
            self.age_info(),
            idle_info,
            if self.to_server_tx.is_closed() { "closed" } else { "open" },
            if self.local_tx.is_closed() { "closed" } else { "open" }
        )
    }

    pub fn age_info(&self) -> String {
        let age = self.connection_age();
        if age.as_secs() < 60 {
            format!("{}s", age.as_secs())
        } else if age.as_secs() < 3600 {
            format!("{}m", age.as_secs() / 60)
        } else {
            format!("{}h{}m", age.as_secs() / 3600, (age.as_secs() % 3600) / 60)
        }
    }

    pub async fn send_to_server(&self, message: Message) -> Result<(), String> {
        self.update_activity().await;
        self.to_server_tx
            .send(message)
            .map_err(|e| {
                let error_msg = format!("Failed to send message to server: {}", e);
                error!("❌ WebSocket {}: {}", self.connection_id, error_msg);
                error_msg
            })
    }

    pub async fn send_to_local(&self, data: Vec<u8>) -> Result<(), String> {
        self.update_activity().await;
        self.local_tx
            .send(data)
            .map_err(|e| {
                let error_msg = format!("Failed to send data to local WebSocket: {}", e);
                error!("❌ WebSocket {}: {}", self.connection_id, error_msg);
                error_msg
            })
    }
}

pub async fn cleanup_expired_connections(
    active_websockets: ActiveWebSockets,
    max_idle_time: Duration,
) -> usize {
    let mut cleanup_count = 0;
    let mut to_remove = Vec::new();

    {
        let mut websockets = active_websockets.write().await;
        for (id, connection) in websockets.iter() {
            if connection.is_idle(max_idle_time).await {
                warn!(
                    "⚠️  WebSocket {}: Marking for cleanup: {} (idle: {}s, max_idle: {}s)",
                    connection.connection_id,
                    connection.status_summary().await,
                    connection.idle_time().await.as_secs(),
                    max_idle_time.as_secs()
                );
                to_remove.push(id.clone());
            }
        }

        for id in to_remove {
            if let Some(connection) = websockets.remove(&id) {
                info!("🔌 WebSocket {}: Cleaned up idle connection (max_idle: {}s)", connection.connection_id, max_idle_time.as_secs());
                cleanup_count += 1;
            }
        }
    }

    if cleanup_count > 0 {
        info!("🧹 Cleaned up {} idle WebSocket connections (max_idle: {}s)", cleanup_count, max_idle_time.as_secs());
    }

    cleanup_count
}