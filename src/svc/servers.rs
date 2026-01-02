// HTTP/HTTPS server startup logic

use crate::svc::{BoxError, ServiceContext};
use crate::svc::handlers::UnifiedService;
use crate::svc::types::*;
use crate::{ChallengeStore, ServerConfig, SslManager, MetricsCollector};
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig as RustlsConfig;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio_util::sync::CancellationToken;
use tokio_rustls::TlsAcceptor;
use tower::ServiceBuilder;
use tower_http::compression::CompressionLayer;
use tracing::{error, info};

/// Start the HTTP server (handles redirects and ACME challenges)
#[allow(clippy::too_many_arguments)]
pub async fn start_http_server(
    config: ServerConfig,
    tunnels: TunnelMap,
    active_requests: ActiveRequests,
    active_websockets: ActiveWebSockets,
    challenge_store: ChallengeStore,
    ssl_manager: Arc<RwLock<SslManager>>,
    metrics: Arc<MetricsCollector>,
    shutdown_token: CancellationToken,
) -> Result<(), BoxError> {
    let addr: std::net::SocketAddr = config.http_addr().parse()?;
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    info!(
        event = "server.http.listen",
        addr = %config.http_addr(),
        "HTTP server listening."
    );

    loop {
        tokio::select! {
            _ = shutdown_token.cancelled() => {
                info!(event = "server.http.shutdown", "HTTP server shutting down.");
                break;
            }
            result = listener.accept() => {
                let (stream, _) = result?;
                let io = TokioIo::new(stream);

                let context = ServiceContext {
                    tunnels: tunnels.clone(),
                    active_requests: active_requests.clone(),
                    active_websockets: active_websockets.clone(),
                    config: config.clone(),
                    challenge_store: challenge_store.clone(),
                    ssl_manager: ssl_manager.clone(),
                    is_https: false,
                    metrics: metrics.clone(),
                };

                let service = ServiceBuilder::new()
                    .layer(CompressionLayer::new())
                    .service(UnifiedService::new(context));

                tokio::spawn(async move {
                    if let Err(err) = Builder::new(hyper_util::rt::TokioExecutor::new())
                        .serve_connection_with_upgrades(io, TowerToHyperService::new(service))
                        .await
                    {
                        error!(
                            event = "server.http.connection_error",
                            error = %err,
                            "HTTP connection handling failed."
                        );
                    }
                });
            }
        }
    }
    
    Ok(())
}

/// Start the HTTPS server (handles secure tunneled requests)
#[allow(clippy::too_many_arguments)]
pub async fn start_https_server(
    config: ServerConfig,
    tunnels: TunnelMap,
    active_requests: ActiveRequests,
    active_websockets: ActiveWebSockets,
    ssl_manager: Arc<RwLock<SslManager>>,
    tls_config: Arc<RustlsConfig>,
    metrics: Arc<MetricsCollector>,
    shutdown_token: CancellationToken,
) -> Result<(), BoxError> {
    let tls_acceptor = TlsAcceptor::from(tls_config);
    let addr: std::net::SocketAddr = config.https_addr().parse()?;
    let listener = tokio::net::TcpListener::bind(&addr).await?;

    info!(
        event = "server.https.listen",
        addr = %config.https_addr(),
        "HTTPS server listening."
    );

    loop {
        tokio::select! {
            _ = shutdown_token.cancelled() => {
                info!(event = "server.https.shutdown", "HTTPS server shutting down.");
                break;
            }
            result = listener.accept() => {
                let (stream, _) = result?;
                let tls_acceptor = tls_acceptor.clone();
                let ssl_manager = ssl_manager.clone();

                let context = ServiceContext {
                    tunnels: tunnels.clone(),
                    active_requests: active_requests.clone(),
                    active_websockets: active_websockets.clone(),
                    config: config.clone(),
                    challenge_store: Arc::new(RwLock::new(HashMap::new())),
                    ssl_manager,
                    is_https: true,
                    metrics: metrics.clone(),
                };

                tokio::spawn(async move {
                    match tls_acceptor.accept(stream).await {
                        Ok(tls_stream) => {
                            let io = TokioIo::new(tls_stream);
                            let service = ServiceBuilder::new()
                                .layer(CompressionLayer::new())
                                .service(UnifiedService::new(context));

                            if let Err(e) = Builder::new(hyper_util::rt::TokioExecutor::new())
                                .serve_connection_with_upgrades(io, TowerToHyperService::new(service))
                                .await
                            {
                                error!(
                                    event = "server.https.connection_error",
                                    error = %e,
                                    "HTTPS connection handling failed."
                                );
                            }
                        }
                        Err(e) => {
                            error!(
                                event = "server.https.tls_error",
                                error = %e,
                                "TLS handshake failed."
                            );
                        }
                    }
                });
            }
        }
    }
    
    Ok(())
}
