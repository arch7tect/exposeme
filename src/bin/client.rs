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

    let args = ClientArgs::parse();
    initialize_tracing(args.verbose);
    let _log_span = tracing::info_span!(
        "exposeme",
        role = "client",
        version = env!("CARGO_PKG_VERSION")
    )
    .entered();

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
                _ = sigterm.recv() => info!(event = "shutdown.signal", signal = "SIGTERM", "Shutdown signal received."),
                _ = sigint.recv() => info!(event = "shutdown.signal", signal = "SIGINT", "Shutdown signal received."),
            }
        }
        #[cfg(not(unix))]
        {
            signal::ctrl_c().await.expect("Failed to install Ctrl+C handler");
            info!(event = "shutdown.signal", signal = "SIGINT", "Shutdown signal received.");
        }

        shutdown_token_signal.cancel();
    });

    if args.generate_config {
        ClientConfig::generate_default_file(&args.config)?;
        return Ok(());
    }

    let config = ClientConfig::load(&args)?;
    info!(event = "config.loaded", path = ?args.config, "Config loaded from path.");
    info!(event = "client.server.configured", url = %config.client.server_url, "Client server URL configured.");
    info!(event = "client.tunnel.configured", tunnel_id = %config.client.tunnel_id, "Client tunnel configured.");
    info!(event = "client.target.configured", target = %config.client.local_target, "Client local target configured.");
    info!(event = "client.start", version = env!("CARGO_PKG_VERSION"), "Client started.");

    let mut client = ExposeMeClient::new(config);

    loop {
        tokio::select! {
            _ = shutdown_token.cancelled() => {
                info!(event = "shutdown.start", "Graceful shutdown started.");
                break;
            }
            result = client.run(shutdown_token.clone()) => {
                match result {
                    Ok(_) => {
                        info!(event = "client.disconnect", clean = true, "Client disconnected cleanly.");
                        break;
                    }
                    Err(e) => {
                        error!(event = "client.error", error = %e, "Client run failed.");

                        if client.config().client.auto_reconnect {
                            info!(
                                event = "client.reconnect.scheduled",
                                delay_secs = client.config().client.reconnect_delay_secs,
                                "Client reconnect scheduled."
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
