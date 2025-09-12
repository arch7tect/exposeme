// src/svc/handlers/mod.rs - Main request handler and routing

pub mod tunnel;
pub mod websocket;
pub mod acme;
pub mod api;

use crate::svc::{BoxError, ServiceContext};
use crate::svc::types::*;
use crate::svc::utils::{is_websocket_upgrade, boxed_body};
use hyper::{Request, Response, StatusCode, body::Incoming};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::Service;
use tracing::{debug, info};
use crate::svc::tunnel_mgmt::shutdown_tunnel;

/// Unified service that routes requests to appropriate handlers
#[derive(Clone)]
pub struct UnifiedService {
    context: ServiceContext,
}

impl UnifiedService {
    pub fn new(context: ServiceContext) -> Self {
        Self { context }
    }
}

impl Service<Request<Incoming>> for UnifiedService {
    type Response = Response<ResponseBody>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        let context = self.context.clone();
        Box::pin(async move { route_request(req, context).await })
    }
}

/// Main request routing logic
async fn route_request(
    req: Request<Incoming>,
    context: ServiceContext,
) -> Result<Response<ResponseBody>, BoxError> {
    let path = req.uri().path();
    let method = req.method();
    let is_websocket = is_websocket_upgrade(&req);

    info!(
        "📥 {} request: {} {} (WebSocket: {})",
        if context.is_https { "HTTPS" } else { "HTTP" },
        method,
        path,
        is_websocket
    );

    // ACME challenges
    if path.starts_with("/.well-known/acme-challenge/") {
        info!("🔍 ACME challenge via {}", if context.is_https { "HTTPS" } else { "HTTP" });
        return acme::handle_acme_challenge(req, context.challenge_store).await;
    }

    // Internal API and admin endpoints
    if path.starts_with("/api/") {
        if let Some(resp) = api::handle_api(&req, &context.ssl_manager, &context.config).await? {
            return Ok(resp);
        }
    }

    // Admin observability endpoints
    if path.starts_with("/admin/") && context.metrics.is_some() {
        // Simple authentication check
        let is_admin = if let Some(admin_token) = &context.config.auth.admin_token {
            req.headers().get("authorization")
                .and_then(|h| h.to_str().ok())
                .and_then(|h| h.strip_prefix("Bearer "))
                .map(|token| token == admin_token)
                .unwrap_or(false)
        } else {
            false
        };

        if !is_admin {
            return Ok(Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .body(boxed_body("Unauthorized: Admin token required"))
                .unwrap());
        }

        // Handle metrics endpoint
        if path == "/admin/metrics" {
            let metrics = context.metrics.as_ref().unwrap();
            let server_metrics = metrics.get_server_metrics();
            let tunnel_metrics = metrics.get_tunnel_metrics().read().unwrap();
            
            let uptime = metrics.get_uptime_seconds();
            
            let mut tunnels_data = Vec::new();
            for (tunnel_id, tunnel) in tunnel_metrics.iter() {
                tunnels_data.push(serde_json::json!({
                    "tunnel_id": tunnel_id,
                    "last_activity": tunnel.last_activity.load(std::sync::atomic::Ordering::Relaxed),
                    "requests_count": tunnel.requests_count.load(std::sync::atomic::Ordering::Relaxed),
                    "bytes_in": tunnel.bytes_in.load(std::sync::atomic::Ordering::Relaxed),
                    "bytes_out": tunnel.bytes_out.load(std::sync::atomic::Ordering::Relaxed),
                    "websocket_connections": tunnel.websocket_connections.load(std::sync::atomic::Ordering::Relaxed),
                    "websocket_bytes_in": tunnel.websocket_bytes_in.load(std::sync::atomic::Ordering::Relaxed),
                    "websocket_bytes_out": tunnel.websocket_bytes_out.load(std::sync::atomic::Ordering::Relaxed),
                    "error_count": tunnel.error_count.load(std::sync::atomic::Ordering::Relaxed)
                }));
            }

            let response_json = serde_json::json!({
                "server": {
                    "uptime_seconds": uptime,
                    "active_tunnels": server_metrics.active_tunnels.load(std::sync::atomic::Ordering::Relaxed),
                    "total_requests": server_metrics.total_requests.load(std::sync::atomic::Ordering::Relaxed),
                    "total_bytes_in": server_metrics.total_bytes_in.load(std::sync::atomic::Ordering::Relaxed),
                    "total_bytes_out": server_metrics.total_bytes_out.load(std::sync::atomic::Ordering::Relaxed),
                    "websocket_connections": server_metrics.websocket_connections.load(std::sync::atomic::Ordering::Relaxed),
                    "websocket_bytes_in": server_metrics.websocket_bytes_in.load(std::sync::atomic::Ordering::Relaxed),
                    "websocket_bytes_out": server_metrics.websocket_bytes_out.load(std::sync::atomic::Ordering::Relaxed),
                    "error_count": server_metrics.error_count.load(std::sync::atomic::Ordering::Relaxed)
                },
                "tunnels": tunnels_data
            });

            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(boxed_body(serde_json::to_string(&response_json).unwrap()))
                .unwrap());
        }

        // Handle tunnel deletion endpoint
        if path.starts_with("/admin/tunnels/") && method == "DELETE" {
            let tunnel_id = path.strip_prefix("/admin/tunnels/").unwrap_or("");
            if !tunnel_id.is_empty() {
                // Force disconnect the tunnel
                let result = shutdown_tunnel(context.clone(), tunnel_id.to_owned()).await;
                
                let response_json = if result {
                    serde_json::json!({
                        "success": true,
                        "message": format!("Tunnel '{}' has been disconnected", tunnel_id)
                    })
                } else {
                    serde_json::json!({
                        "success": false,
                        "message": format!("Tunnel '{}' not found or already disconnected", tunnel_id)
                    })
                };

                return Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/json")
                    .body(boxed_body(serde_json::to_string(&response_json).unwrap()))
                    .unwrap());
            }
        }

        // Handle SSL renewal endpoint
        if path == "/admin/ssl/renew" && method == "POST" {
            let result = {
                let mut ssl_manager = context.ssl_manager.write().await;
                ssl_manager.force_renewal().await
            };
            
            let response_json = match result {
                Ok(_) => serde_json::json!({
                    "success": true,
                    "message": "SSL certificate renewal initiated successfully"
                }),
                Err(e) => serde_json::json!({
                    "success": false,
                    "message": format!("SSL certificate renewal failed: {}", e)
                })
            };

            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(boxed_body(serde_json::to_string(&response_json).unwrap()))
                .unwrap());
        }
    }

    // WebSocket requests
    if is_websocket {
        return if path == context.config.server.tunnel_path {
            debug!("🔌 Tunnel management WebSocket via {}",
                  if context.is_https { "HTTPS" } else { "HTTP" });
            websocket::handle_tunnel_management_websocket(req, context).await
        } else {
            debug!("🔌 Tunneled WebSocket via {}",
                  if context.is_https { "HTTPS" } else { "HTTP" });
            websocket::handle_websocket_upgrade_request(req, context).await
        };
    }

    // HTTP/HTTPS differentiation
    if context.is_https {
        tunnel::handle_tunnel_request(req, context).await
    } else {
        if context.config.ssl.enabled {
            // Redirect to HTTPS
            let https_url = format!(
                "https://{}{}",
                context.config.server.domain,
                req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("")
            );

            Ok(Response::builder()
                .status(StatusCode::MOVED_PERMANENTLY)
                .header("Location", https_url)
                .body(boxed_body("Redirecting to HTTPS"))
                .unwrap())
        } else {
            debug!("🌐 Processing tunneled HTTP request via HTTP (SSL disabled)");
            tunnel::handle_tunnel_request(req, context).await
        }
    }
}