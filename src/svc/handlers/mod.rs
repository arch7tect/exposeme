// src/svc/handlers/mod.rs - Main request handler and routing

pub mod tunnel;
pub mod websocket;
pub mod acme;
pub mod api;
pub mod admin;

use crate::svc::{BoxError, ServiceContext};
use crate::svc::types::*;
use crate::svc::utils::{is_websocket_upgrade, boxed_body};
use hyper::{Request, Response, StatusCode, body::Incoming};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::Service;
use tracing::{debug, info};

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
        if let Some(response) = admin::handle_admin_request(&req, context.clone(), path).await? {
            return Ok(response);
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