use clap::Parser;
use exposeme::{initialize_tracing, ServerArgs, ServerConfig, SslManager, SslProvider, MetricsCollector};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;
use tokio::signal;
use tokio_util::sync::CancellationToken;
use tokio_tungstenite::{tungstenite::Message as WsMessage};
use tracing::{error, info, debug};
use exposeme::svc::{start_http_server, start_https_server, TunnelMap, ActiveRequests, ActiveWebSockets, BoxError};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring CryptoProvider");

    let args = ServerArgs::parse();

    initialize_tracing(args.verbose);

    if args.generate_config {
        ServerConfig::generate_default_file(&args.config)?;
        return Ok(());
    }

    let config = ServerConfig::load(&args)?;
    info!("Loaded configuration from {:?}", args.config);
    info!("HTTP server: {}", config.http_addr());
    if config.ssl.enabled {
        info!("HTTPS server: {}", config.https_addr());
        info!("Domain: {}", config.server.domain);
        info!("SSL provider: {:?}", config.ssl.provider);
        info!("Staging: {}", config.ssl.staging);
        info!("DNS provider: {:?}", config.ssl.dns_provider);
    }
    info!("WebSocket server: {}", config.tunnel_ws_url());
    info!("Auth tokens: {} configured", config.auth.tokens.len());

    let ssl_manager = Arc::new(RwLock::new(SslManager::new(config.clone())));
    let challenge_store = ssl_manager.read().await.get_challenge_store();

    info!("Starting ExposeME Server (v {})...", env!("CARGO_PKG_VERSION"));

    let tunnels: TunnelMap = Arc::new(RwLock::new(HashMap::new()));
    let active_requests: ActiveRequests = Arc::new(RwLock::new(HashMap::new()));
    let active_websockets: ActiveWebSockets = Arc::new(RwLock::new(HashMap::new()));

    let metrics = Arc::new(MetricsCollector::new());
    metrics.server_started();

    let shutdown_token = CancellationToken::new();
    let shutdown_token_signal = shutdown_token.clone();
    let shutdown_token_http = shutdown_token.clone();
    let shutdown_token_https = shutdown_token.clone();

    let signal_handle = tokio::spawn(async move {
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

    let tunnels_http = tunnels.clone();
    let active_requests_http = active_requests.clone();
    let active_websockets_http = active_websockets.clone();
    let config_http = config.clone();
    let challenge_store_http = challenge_store.clone();
    let ssl_manager_http = ssl_manager.clone();
    let metrics_http = metrics.clone();

    let http_handle = tokio::spawn(async move {
        if let Err(e) = start_http_server(
            config_http,
            tunnels_http,
            active_requests_http,
            active_websockets_http,
            challenge_store_http,
            ssl_manager_http,
            metrics_http,
            shutdown_token_http,
        ).await {
            error!("HTTP server error: {}", e);
        }
    });

    wait_for_http_server_ready(&config).await?;

    ssl_manager.write().await.initialize().await?;

    let https_handle = if config.ssl.enabled {
        let tunnels_https = tunnels.clone();
        let active_requests_https = active_requests.clone();
        let active_websockets_https = active_websockets.clone();
        let config_https = config.clone();
        let ssl_config_for_https = ssl_manager.read().await.get_rustls_config().unwrap();
        let ssl_manager_https = ssl_manager.clone();
        let metrics_https = metrics.clone();

        Some(tokio::spawn(async move {
            if let Err(e) = start_https_server(
                config_https,
                tunnels_https,
                active_requests_https,
                active_websockets_https,
                ssl_manager_https,
                ssl_config_for_https,
                metrics_https,
                shutdown_token_https,
            ).await {
                error!("HTTPS server error: {}", e);
            }
        }))
    } else {
        None
    };

    let renew_handle = if config.ssl.enabled && config.ssl.provider != SslProvider::Manual {
        Some(tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(24 * 60 * 60));
            loop {
                interval.tick().await;
                info!(
                    "Daily certificate renewal check for {}",
                    config.server.domain
                );
                let mut manager = ssl_manager.write().await;
                match manager.get_certificate_info().await {
                    Ok(info) => {
                        if let Some(days_until_expiry) = info.days_until_expiry {
                            info!(
                                "Certificate for {} expires in {} days",
                                config.server.domain, days_until_expiry
                            );
                            if info.needs_renewal {
                                if let Err(e) = manager.force_renewal().await {
                                    error!("Failed to renew certificate: {}", e);
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Failed to get certificate info: {}", e);
                    }
                }
            }
        }))
    } else {
        None
    };

    shutdown_token.cancelled().await;

    info!("Graceful shutdown initiated...");

    graceful_shutdown(tunnels, active_requests, active_websockets, Duration::from_secs(30)).await;

    signal_handle.abort();
    http_handle.abort();
    if let Some(handle) = https_handle {
        handle.abort();
    }
    if let Some(handle) = renew_handle {
        handle.abort();
    }

    info!("ExposeME server shutdown complete");
    Ok(())
}

async fn wait_for_http_server_ready(config: &ServerConfig) -> Result<(), BoxError> {
    let test_url = format!(
        "http://127.0.0.1:{}/api/health",
        config.server.http_port
    );

    info!("Waiting for HTTP server to be ready...");

    for attempt in 1..=10 {
        match reqwest::get(&test_url).await {
            Ok(response) => {
                info!(
                    "HTTP server is ready (attempt {}, status: {})",
                    attempt,
                    response.status()
                );
                return Ok(());
            }
            Err(e) => {
                if attempt < 10 {
                    info!("HTTP server not ready yet (attempt {}): {}", attempt, e);
                    tokio::time::sleep(Duration::from_millis(500)).await;
                } else {
                    return Err(
                        format!("HTTP server failed to start after 10 attempts: {}", e).into(),
                    );
                }
            }
        }
    }

    Ok(())
}

async fn graceful_shutdown(
    tunnels: TunnelMap,
    active_requests: ActiveRequests,
    active_websockets: ActiveWebSockets,
    timeout: Duration,
) {
    tokio::time::sleep(Duration::from_millis(500)).await;
    {
        let mut tunnels = tunnels.write().await;
        let tunnel_count = tunnels.len();
        info!("Dropping {} tunnel connections...", tunnel_count);
        tunnels.clear();
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;

    {
        let websockets = active_websockets.write().await;
        let ws_count = websockets.len();

        if ws_count > 0 {
            info!("Force closing {} WebSocket connections...", ws_count);

            for (_connection_id, connection) in websockets.iter() {
                if let Some(ws_tx) = &connection.ws_tx {
                    let close_msg = WsMessage::Close(Some(
                        tokio_tungstenite::tungstenite::protocol::CloseFrame {
                            code: 1001u16.into(),
                            reason: "Server shutting down".into(),
                        },
                    ));
                    let _ = ws_tx.send(close_msg);
                }
            }
            info!("Close frames sent to all WebSocket connections");
        }
    }
    tokio::time::sleep(Duration::from_millis(500)).await;

    let start = tokio::time::Instant::now();
    loop {
        let active_count = {
            let requests = active_requests.read().await;
            let websockets = active_websockets.read().await;
            requests.len() + websockets.len()
        };
        
        if active_count == 0 {
            info!("All active connections completed gracefully");
            break;
        }

        if start.elapsed() >= timeout {
            info!("Graceful shutdown timeout reached, forcing shutdown ({} active connections)", active_count);
            break;
        }

        debug!("Waiting for {} active connections to complete...", active_count);
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    
    info!("Graceful shutdown complete");
}