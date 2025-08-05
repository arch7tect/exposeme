// src/svc/mod.rs - Main module file with re-exports

pub mod types;
pub mod servers;
pub mod handlers;
pub mod tunnel_mgmt;
pub mod utils;

// Re-export commonly used types
pub use types::*;
pub use servers::{start_http_server, start_https_server};
pub use handlers::UnifiedService;

// Re-export error type for convenience
pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

// Re-export types from parent crate for convenience within svc module
pub use crate::{ChallengeStore, SslManager, ServerConfig, Message};