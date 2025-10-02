// Main entry point
use clap::Parser;
use tokio::signal;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};
use std::time::Duration;

use exposeme::{initialize_tracing, ClientArgs, ClientConfig};
use exposeme::client::ExposeMeClient;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring CryptoProvider");

    let shutdown_token = CancellationToken::new();
    let shutdown_token_signal = shutdown_token.clone();

    tokio::spawn(async move {
        #[cfg(unix)]
        {
            let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
                .expect("Failed to install SIGTERM handler");
            let mut sigint = signal::unix::signal(signal::unix::SignalKind::interrupt())
                .expect("Failed to install SIGINT handler");

            tokio::select! {
                _ = sigterm.recv() => info!("Received SIGTERM, initiating graceful shutdown..."),
                _ = sigint.recv() => info!("Received SIGINT, initiating graceful shutdown..."),
            }
        }
        #[cfg(not(unix))]
        {
            signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
            info!("Received Ctrl+C, initiating graceful shutdown...");
        }

        shutdown_token_signal.cancel();
    });

    let args = ClientArgs::parse();
    initialize_tracing(args.verbose);

    if args.generate_config {
        ClientConfig::generate_default_file(&args.config)?;
        return Ok(());
    }

    let config = ClientConfig::load(&args)?;
    info!("Loaded configuration from {:?}", args.config);
    info!("Server: {}", config.client.server_url);
    info!("Tunnel ID: {}", config.client.tunnel_id);
    info!("Local target: {}", config.client.local_target);

    info!("Starting ExposeME Client (v {})...", env!("CARGO_PKG_VERSION"));

    let mut client = ExposeMeClient::new(config);

    loop {
        tokio::select! {
            _ = shutdown_token.cancelled() => {
                info!("Graceful shutdown initiated...");
                break;
            }
            result = client.run(shutdown_token.clone()) => {
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