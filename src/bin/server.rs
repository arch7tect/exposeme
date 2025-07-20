// src/bin/server.rs
use clap::Parser;
use exposeme::{initialize_tracing, ServerArgs, ServerConfig, SslManager, SslProvider};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{RwLock};
use tracing::{error, info};
use exposeme::svc::{BoxError, TunnelMap, PendingRequests, ActiveWebSockets, start_http_server, start_https_server};

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    // Set up crypto provider
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install ring CryptoProvider");

    // Parse CLI arguments
    let args = ServerArgs::parse();

    initialize_tracing(args.verbose);

    // Generate config if requested
    if args.generate_config {
        ServerConfig::generate_default_file(&args.config)?;
        return Ok(());
    }

    // Load configuration
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

    // Initialize SSL
    let ssl_manager = Arc::new(RwLock::new(SslManager::new(config.clone())));
    let challenge_store = ssl_manager.read().await.get_challenge_store();

    info!("Starting ExposeME Server...");

    // Shared state
    let tunnels: TunnelMap = Arc::new(RwLock::new(HashMap::new()));
    let pending_requests: PendingRequests = Arc::new(RwLock::new(HashMap::new()));
    let active_websockets: ActiveWebSockets = Arc::new(RwLock::new(HashMap::new()));

    // Clone for servers
    let tunnels_http = tunnels.clone();
    let pending_requests_http = pending_requests.clone();
    let active_websockets_http = active_websockets.clone();
    let config_http = config.clone();
    let challenge_store_http = challenge_store.clone();
    let ssl_manager_http = ssl_manager.clone();

    // Start HTTP server (for redirects and ACME challenges)
    let http_handle = tokio::spawn(async move {
        if let Err(e) = start_http_server(
            config_http,
            tunnels_http,
            pending_requests_http,
            active_websockets_http,
            challenge_store_http,
            ssl_manager_http,
        ).await {
            error!("❌ HTTP server error: {}", e);
        }
    });

    // Wait a moment for HTTP server to start
    wait_for_http_server_ready(&config).await?;

    ssl_manager.write().await.initialize().await?;

    // Start HTTPS server (if SSL enabled)
    let https_handle = if config.ssl.enabled {
        let tunnels_https = tunnels.clone();
        let pending_requests_https = pending_requests.clone();
        let active_websockets_https = active_websockets.clone();
        let config_https = config.clone();
        let ssl_config_for_https = ssl_manager.read().await.get_rustls_config().unwrap();
        let ssl_manager_https = ssl_manager.clone();

        Some(tokio::spawn(async move {
            if let Err(e) = start_https_server(
                config_https,
                tunnels_https,
                pending_requests_https,
                active_websockets_https,
                ssl_manager_https,
                ssl_config_for_https,
            ).await {
                error!("❌ HTTPS server error: {}", e);
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
                    "🔍 Daily certificate renewal check for {}",
                    config.server.domain
                );
                let mut manager = ssl_manager.write().await;
                match manager.get_certificate_info() {
                    Ok(info) => {
                        if let Some(days_until_expiry) = info.days_until_expiry {
                            info!(
                                "📅 Certificate for {} expires in {} days",
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

    // Wait for all servers
    match https_handle {
        Some(https_handle) => match renew_handle {
            Some(renew_handle) => {
                tokio::select! {
                    _ = http_handle => info!("HTTP server terminated"),
                    _ = https_handle => info!("HTTPS server terminated"),
                    _ = renew_handle => info!("Renewal task terminated"),
                }
            }
            None => {
                tokio::select! {
                    _ = http_handle => info!("HTTP server terminated"),
                    _ = https_handle => info!("HTTPS server terminated"),
                }
            }
        },
        None => {
            tokio::select! {
                _ = http_handle => info!("HTTP server terminated"),
            }
        }
    }

    info!("🛑 ExposeME server shutting down");
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
                    "✅ HTTP server is ready (attempt {}, status: {})",
                    attempt,
                    response.status()
                );
                return Ok(());
            }
            Err(e) => {
                if attempt < 10 {
                    info!("⏳ HTTP server not ready yet (attempt {}): {}", attempt, e);
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
