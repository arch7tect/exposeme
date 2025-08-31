// src/bin/client.rs - Main entry point
use clap::Parser;
use tokio::signal;
use tokio::sync::broadcast;
use tracing::{error, info};
use std::time::Duration;

use exposeme::{initialize_tracing, ClientArgs, ClientConfig};
use exposeme::client::ExposeMeClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Set up crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring CryptoProvider");

    // Shutdown signal handling
    let (shutdown_tx, _) = broadcast::channel::<()>(1);
    let shutdown_tx_clone = shutdown_tx.clone();

    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler");
            let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
                .expect("Failed to install SIGINT handler");
            
            tokio::select! {
                _ = sigterm.recv() => info!("🛑 Received SIGTERM, initiating graceful shutdown..."),
                _ = sigint.recv() => info!("🛑 Received SIGINT, initiating graceful shutdown..."),
            }
        }
        #[cfg(not(unix))]
        {
            signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
            info!("🛑 Received Ctrl+C, initiating graceful shutdown...");
        }
        
        let _ = shutdown_tx_clone.send(());
    });

    // Parse CLI arguments
    let args = ClientArgs::parse();
    initialize_tracing(args.verbose);

    // Generate config if requested
    if args.generate_config {
        ClientConfig::generate_default_file(&args.config)?;
        return Ok(());
    }

    // Load configuration
    let config = ClientConfig::load(&args)?;
    info!("Loaded configuration from {:?}", args.config);
    info!("Server: {}", config.client.server_url);
    info!("Tunnel ID: {}", config.client.tunnel_id);
    info!("Local target: {}", config.client.local_target);

    info!("Starting ExposeME Client (v {})...", env!("CARGO_PKG_VERSION"));

    // Create and run client
    let mut client = ExposeMeClient::new(config);

    // Main client loop with reconnection
    let mut shutdown_rx = shutdown_tx.subscribe();
    loop {
        tokio::select! {
            // Handle shutdown signal
            _ = shutdown_rx.recv() => {
                info!("🔄 Graceful shutdown initiated...");
                break;
            }
            // Run client
            result = client.run(shutdown_tx.subscribe()) => {
                match result {
                    Ok(_) => {
                        info!("Client disconnected normally");
                        break;
                    }
                    Err(e) => {
                        error!("Client error: {}", e);

                        if client.config().client.auto_reconnect {
                            info!(
                                "Reconnecting in {} seconds...",
                                client.config().client.reconnect_delay_secs
                            );
                            tokio::time::sleep(Duration::from_secs(client.config().client.reconnect_delay_secs))
                                .await;
                            continue;
                        } else {
                            break;
                        }
                    }
                }
            }
        }
    }

    Ok(())
}