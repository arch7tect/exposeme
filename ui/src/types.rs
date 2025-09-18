use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub domain: String,
    pub ssl_enabled: bool,
    pub uptime_check: String,
    pub timestamp: DateTime<Utc>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerMetrics {
    pub active_tunnels: usize,
    pub total_requests: u64,
    pub total_bytes_in: u64,
    pub total_bytes_out: u64,
    pub websocket_connections: usize,
    pub uptime_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelMetrics {
    pub tunnel_id: String,
    pub last_activity: u64,
    pub requests_count: u64,
    pub bytes_in: u64,
    pub bytes_out: u64,
    pub websocket_connections: usize,
    pub websocket_bytes_in: u64,
    pub websocket_bytes_out: u64,
    pub error_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricsResponse {
    pub server: ServerMetrics,
    pub tunnels: Vec<TunnelMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertificateInfo {
    pub valid: bool,
    pub expires_at: Option<DateTime<Utc>>,
    pub issuer: Option<String>,
    pub subject: Option<String>,
    pub days_until_expiry: Option<i64>,
}