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
    let _log_span = tracing::info_span!(
        "exposeme",
        role = "server",
        version = env!("CARGO_PKG_VERSION")
    )
    .entered();

    if args.generate_config {
        ServerConfig::generate_default_file(&args.config)?;
        return Ok(());
    }

    let config = ServerConfig::load(&args)?;
    info!(event = "config.loaded", path = ?args.config, "Config loaded from path.");
    info!(event = "server.http.configured", addr = %config.http_addr(), "HTTP server configured.");
    if config.ssl.enabled {
        info!(event = "server.https.configured", addr = %config.https_addr(), "HTTPS server configured.");
        info!(event = "server.domain.configured", domain = %config.server.domain, "Server domain configured.");
        info!(event = "server.ssl.provider", provider = ?config.ssl.provider, "Server SSL provider configured.");
        info!(event = "server.ssl.staging", enabled = config.ssl.staging, "Server SSL staging mode configured.");
        info!(event = "server.ssl.dns_provider", provider = ?config.ssl.dns_provider, "Server SSL DNS provider configured.");
    }
    info!(event = "server.ws.configured", url = %config.tunnel_ws_url(), "WebSocket server configured.");
    info!(event = "auth.tokens.configured", count = config.auth.tokens.len(), "Authentication tokens configured.");

    let ssl_manager = Arc::new(RwLock::new(SslManager::new(config.clone())));
    let challenge_store = ssl_manager.read().await.get_challenge_store();

    info!(event = "server.start", version = env!("CARGO_PKG_VERSION"), "Server starting.");

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
            error!(event = "server.http.error", error = %e, "HTTP server error.");
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
                error!(event = "server.https.error", error = %e, "HTTPS server error.");
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
                    event = "ssl.renew.check",
                    domain = %config.server.domain,
                    "Checked whether certificates need renewal."
                );
                let mut manager = ssl_manager.write().await;
                match manager.get_certificate_info().await {
                    Ok(info) => {
                        if let Some(days_until_expiry) = info.days_until_expiry {
                            info!(
                                event = "ssl.certificate.expiry",
                                domain = %config.server.domain,
                                days_until_expiry,
                                "Certificate expiry checked for renewal decision."
                            );
                            if info.needs_renewal {
                                if let Err(e) = manager.force_renewal().await {
                                    error!(event = "ssl.renew.error", error = %e, "Certificate renewal failed.");
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!(event = "ssl.certificate.info_error", error = %e, "Failed to read certificate metadata.");
                    }
                }
            }
        }))
    } else {
        None
    };

    shutdown_token.cancelled().await;

    info!(event = "shutdown.start", "Graceful shutdown started.");

    graceful_shutdown(tunnels, active_requests, active_websockets, Duration::from_secs(30)).await;

    signal_handle.abort();
    http_handle.abort();
    if let Some(handle) = https_handle {
        handle.abort();
    }
    if let Some(handle) = renew_handle {
        handle.abort();
    }

    info!(event = "shutdown.complete", "Shutdown completed.");
    Ok(())
}

async fn wait_for_http_server_ready(config: &ServerConfig) -> Result<(), BoxError> {
    let test_url = format!(
        "http://127.0.0.1:{}/api/health",
        config.server.http_port
    );

    info!(event = "server.http.wait_ready", "Waiting for HTTP server readiness.");

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
                    info!(
                        event = "server.http.wait_retry",
                        attempt,
                        error = %e,
                        "HTTP server not ready; retrying."
                    );
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
        info!(
            event = "shutdown.tunnels.drop",
            count = tunnel_count,
            "Active tunnels dropped during shutdown."
        );
        tunnels.clear();
    }
    tokio::time::sleep(Duration::from_millis(1500)).await;

    {
        let websockets = active_websockets.write().await;
        let ws_count = websockets.len();

        if ws_count > 0 {
            info!(
                event = "shutdown.websockets.force_close",
                count = ws_count,
                "WebSocket connections force-closed during shutdown."
            );

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
            info!(event = "shutdown.websockets.close_sent", "WebSocket close frames sent during shutdown.");
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
            info!(event = "shutdown.connections.drained", "Active connections drained during shutdown.");
            break;
        }

        if start.elapsed() >= timeout {
            info!(
                event = "shutdown.timeout",
                active = active_count,
                "Graceful shutdown timed out; forcing exit."
            );
            break;
        }

        debug!(
            event = "shutdown.wait",
            active = active_count,
            "Waiting for active connections to complete."
        );
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    
    info!(event = "shutdown.done", "Graceful shutdown completed.");
}
