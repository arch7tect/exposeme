pub mod tunnel;
pub mod websocket;
pub mod acme;
pub mod api;
pub mod admin;

use crate::svc::{BoxError, ServiceContext};
use crate::svc::types::*;
use crate::svc::utils::{is_websocket_upgrade, boxed_body};
use crate::ui_assets::UIAssets;
use hyper::{Request, Response, StatusCode, body::Incoming};
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use tower::Service;
use tracing::{debug, info};

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

async fn route_request(
    req: Request<Incoming>,
    context: ServiceContext,
) -> Result<Response<ResponseBody>, BoxError> {
    let path = req.uri().path();
    let method = req.method();
    let is_websocket = is_websocket_upgrade(&req);

    info!(
        scheme = if context.is_https { "https" } else { "http" },
        method = %method,
        path,
        websocket = is_websocket,
        "Incoming HTTP request received."
    );

    if path.starts_with("/.well-known/acme-challenge/") {
        info!(
            scheme = if context.is_https { "https" } else { "http" },
            "ACME challenge routed to handler."
        );
        return acme::handle_acme_challenge(req, context.challenge_store).await;
    }

    if path.starts_with("/api/") {
        if let Some(resp) = api::handle_api(&req, &context.ssl_manager, &context.config, Some(&context)).await? {
            return Ok(resp);
        }
    }

    if path.starts_with("/admin/") {
        if let Some(response) = admin::handle_admin_request(&req, context.clone(), path).await? {
            return Ok(response);
        }
    }

    if is_websocket {
        return if path == context.config.server.tunnel_path {
            debug!(
                scheme = if context.is_https { "https" } else { "http" },
                "Tunnel management WebSocket request routed."
            );
            websocket::handle_tunnel_management_websocket(req, context).await
        } else {
            debug!(
                scheme = if context.is_https { "https" } else { "http" },
                "Routed tunneled WebSocket request."
            );
            websocket::handle_websocket_upgrade_request(req, context).await
        };
    }

    if context.is_https && UIAssets::is_ui_asset(path) {
        let host = req.headers()
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or("");
        let host_without_port = host.split(':').next().unwrap_or(host);

        if host_without_port == context.config.server.domain {
            if let Some(response) = UIAssets::serve_asset(path) {
                debug!(path, "UI asset served.");
                return Ok(response);
            }
        }
    }

    if context.is_https {
        tunnel::handle_tunnel_request(req, context.clone()).await
    } else if context.config.ssl.enabled {
        let host = req.headers()
            .get("host")
            .and_then(|h| h.to_str().ok())
            .unwrap_or(&context.config.server.domain);

        let https_url = format!(
            "https://{}{}",
            host,
            req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("")
        );

        Ok(Response::builder()
            .status(StatusCode::MOVED_PERMANENTLY)
            .header("Location", https_url)
            .body(boxed_body("Redirecting to HTTPS"))
            .unwrap())
    } else {
        debug!("HTTP tunnel used without SSL.");
        tunnel::handle_tunnel_request(req, context).await
    }
}
