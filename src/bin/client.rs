// src/bin/client.rs - Main entry point
use clap::Parser;
use tokio::signal;
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

    // Handle Ctrl+C gracefully
    tokio::spawn(async {
        signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
        info!("🛑 Received Ctrl+C, shutting down...");
        std::process::exit(0);
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

    info!("Starting ExposeME Client...");

    // Create and run client
    let mut client = ExposeMeClient::new(config);

    // Main client loop with reconnection
    loop {
        match client.run().await {
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

    Ok(())
}