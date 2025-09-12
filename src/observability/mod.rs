use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Instant;
use serde::Serialize;

pub mod api;

#[derive(Default)]
pub struct MetricsCollector {
    server_metrics: Arc<ServerMetrics>,
    tunnel_metrics: Arc<RwLock<HashMap<String, TunnelMetrics>>>,
}

#[derive(Default, Serialize)]
pub struct ServerMetrics {
    #[serde(skip)]
    pub start_time: RwLock<Option<Instant>>,
    pub active_tunnels: AtomicU64,
    pub total_requests: AtomicU64,
    pub total_bytes_in: AtomicU64,
    pub total_bytes_out: AtomicU64,
    pub websocket_connections: AtomicU64,
    pub websocket_bytes_in: AtomicU64,
    pub websocket_bytes_out: AtomicU64,
    pub error_count: AtomicU64,
}

#[derive(Serialize)]
pub struct TunnelMetrics {
    pub tunnel_id: String,
    #[serde(skip)]
    pub created_at: Instant,
    pub last_activity: AtomicU64,
    pub requests_count: AtomicU64,
    pub bytes_in: AtomicU64,
    pub bytes_out: AtomicU64,
    pub websocket_connections: AtomicU64,
    pub websocket_bytes_in: AtomicU64,
    pub websocket_bytes_out: AtomicU64,
    pub error_count: AtomicU64,
}

impl MetricsCollector {
    pub fn new() -> Self { 
        Self::default() 
    }
    
    pub fn server_started(&self) {
        *self.server_metrics.start_time.write().unwrap() = Some(Instant::now());
    }
    
    pub fn tunnel_connected(&self, tunnel_id: &str) {
        self.server_metrics.active_tunnels.fetch_add(1, Ordering::Relaxed);
        
        let mut tunnels = self.tunnel_metrics.write().unwrap();
        tunnels.insert(tunnel_id.to_string(), TunnelMetrics {
            tunnel_id: tunnel_id.to_string(),
            created_at: Instant::now(),
            last_activity: AtomicU64::new(timestamp_now()),
            requests_count: AtomicU64::new(0),
            bytes_in: AtomicU64::new(0),
            bytes_out: AtomicU64::new(0),
            websocket_connections: AtomicU64::new(0),
            websocket_bytes_in: AtomicU64::new(0),
            websocket_bytes_out: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        });
    }
    
    pub fn tunnel_disconnected(&self, tunnel_id: &str) {
        if self.server_metrics.active_tunnels.load(Ordering::Relaxed) > 0 {
            self.server_metrics.active_tunnels.fetch_sub(1, Ordering::Relaxed);
        }
        self.tunnel_metrics.write().unwrap().remove(tunnel_id);
    }
    
    pub fn record_request(&self, tunnel_id: &str, bytes_in: u64, bytes_out: u64) {
        // Server totals
        self.server_metrics.total_requests.fetch_add(1, Ordering::Relaxed);
        self.server_metrics.total_bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
        self.server_metrics.total_bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
        
        // Tunnel specific
        if let Some(tunnel) = self.tunnel_metrics.read().unwrap().get(tunnel_id) {
            tunnel.requests_count.fetch_add(1, Ordering::Relaxed);
            tunnel.bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
            tunnel.bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
            tunnel.last_activity.store(timestamp_now(), Ordering::Relaxed);
        }
    }
    
    pub fn websocket_connected(&self, tunnel_id: &str) {
        self.server_metrics.websocket_connections.fetch_add(1, Ordering::Relaxed);
        if let Some(tunnel) = self.tunnel_metrics.read().unwrap().get(tunnel_id) {
            tunnel.websocket_connections.fetch_add(1, Ordering::Relaxed);
        }
    }
    
    pub fn websocket_disconnected(&self, tunnel_id: &str) {
        if self.server_metrics.websocket_connections.load(Ordering::Relaxed) > 0 {
            self.server_metrics.websocket_connections.fetch_sub(1, Ordering::Relaxed);
        }
        if let Some(tunnel) = self.tunnel_metrics.read().unwrap().get(tunnel_id) {
            if tunnel.websocket_connections.load(Ordering::Relaxed) > 0 {
                tunnel.websocket_connections.fetch_sub(1, Ordering::Relaxed);
            }
        }
    }
    
    pub fn record_websocket_traffic(&self, tunnel_id: &str, bytes_in: u64, bytes_out: u64) {
        // Server totals
        self.server_metrics.websocket_bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
        self.server_metrics.websocket_bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
        
        // Tunnel specific
        if let Some(tunnel) = self.tunnel_metrics.read().unwrap().get(tunnel_id) {
            tunnel.websocket_bytes_in.fetch_add(bytes_in, Ordering::Relaxed);
            tunnel.websocket_bytes_out.fetch_add(bytes_out, Ordering::Relaxed);
            tunnel.last_activity.store(timestamp_now(), Ordering::Relaxed);
        }
    }
    
    pub fn record_error(&self, tunnel_id: Option<&str>) {
        self.server_metrics.error_count.fetch_add(1, Ordering::Relaxed);
        if let Some(tunnel_id) = tunnel_id {
            if let Some(tunnel) = self.tunnel_metrics.read().unwrap().get(tunnel_id) {
                tunnel.error_count.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
    
    pub fn get_server_metrics(&self) -> &Arc<ServerMetrics> {
        &self.server_metrics
    }
    
    pub fn get_tunnel_metrics(&self) -> &Arc<RwLock<HashMap<String, TunnelMetrics>>> {
        &self.tunnel_metrics
    }
    
    pub fn get_uptime_seconds(&self) -> u64 {
        if let Some(start_time) = *self.server_metrics.start_time.read().unwrap() {
            start_time.elapsed().as_secs()
        } else {
            0
        }
    }
}

fn timestamp_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}