// src/lib.rs
pub mod protocol;
pub mod config;
mod ssl;
mod dns;
pub mod svc;
pub mod insecure_cert;
// pub mod async_defer;

use tracing_subscriber::EnvFilter;
pub use protocol::*;
pub use config::*;
pub use ssl::*;

pub fn initialize_tracing(verbose: bool) {
    let filter = if let Ok(filter) = std::env::var("RUST_LOG") {
        EnvFilter::new(filter)
    } else if verbose {
        EnvFilter::new("debug")
    } else {
        EnvFilter::new("info")
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();
}

