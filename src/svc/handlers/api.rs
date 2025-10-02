
use crate::svc::{BoxError, SslManager, ServiceContext};
use crate::svc::types::ResponseBody;
use crate::svc::utils::boxed_body;
use crate::{ServerConfig, SslProvider};
use hyper::{Request, Response, StatusCode, body::Incoming, body::Frame};
use http_body_util::BodyExt;
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;
use tokio::time::{interval, Duration};
use tokio_stream::{wrappers::IntervalStream, StreamExt};

/// Handle certificate management and metrics API requests
pub async fn handle_api(
    req: &Request<Incoming>,
    ssl_manager: &Arc<RwLock<SslManager>>,
    config: &ServerConfig,
    context: Option<&ServiceContext>,
) -> Result<Option<Response<ResponseBody>>, BoxError> {
    let path = req.uri().path();
    let method = req.method();

    match (method, path) {
        (&hyper::Method::GET, "/api/certificates") => {
            handle_certificate_status(ssl_manager, config).await.map(|resp| Some(resp))
        }

        (&hyper::Method::GET, "/api/certificates/info") => {
            handle_certificate_info(ssl_manager, config).await.map(|resp| Some(resp))
        }

        (&hyper::Method::GET, "/api/health") => {
            handle_extended_health_check(ssl_manager, config).await.map(|resp| Some(resp))
        }

        (&hyper::Method::GET, "/api/metrics") => {
            if let Some(ctx) = context {
                handle_metrics_endpoint(ctx).await.map(|resp| Some(resp))
            } else {
                Ok(Some(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(boxed_body("Metrics not available"))
                    .unwrap()))
            }
        }

        (&hyper::Method::GET, "/api/metrics/stream") => {
            if let Some(ctx) = context {
                handle_metrics_stream_endpoint(ctx.clone()).await.map(|resp| Some(resp))
            } else {
                Ok(Some(Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .body(boxed_body("Metrics not available"))
                    .unwrap()))
            }
        }

        _ => {
            Ok(None)
        }
    }
}

/// Get basic certificate status
async fn handle_certificate_status(
    ssl_manager: &Arc<RwLock<SslManager>>,
    config: &ServerConfig,
) -> Result<Response<ResponseBody>, BoxError> {
    let manager = ssl_manager.read().await;
    match manager.get_certificate_info().await {
        Ok(cert_info) => {
            let response = json!({
                "domain": cert_info.domain,
                "exists": cert_info.exists,
                "expiry_date": cert_info.expiry_date,
                "days_until_expiry": cert_info.days_until_expiry,
                "needs_renewal": cert_info.needs_renewal,
                "auto_renewal": config.ssl.provider != SslProvider::Manual,
                "wildcard": config.ssl.wildcard,
                "ssl_enabled": config.ssl.enabled,
                "provider": format!("{:?}", config.ssl.provider),
            });

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(boxed_body(response.to_string()))
                .unwrap())
        }
        Err(e) => {
            let response = json!({
                "error": format!("Failed to get certificate info: {}", e),
                "ssl_enabled": config.ssl.enabled,
                "provider": format!("{:?}", config.ssl.provider),
            });
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .header("Content-Type", "application/json")
                .body(boxed_body(response.to_string()))
                .unwrap())
        }
    }
}


/// Get detailed certificate information
async fn handle_certificate_info(
    ssl_manager: &Arc<RwLock<SslManager>>,
    config: &ServerConfig,
) -> Result<Response<ResponseBody>, BoxError> {
    let manager = ssl_manager.read().await;

    let cert_info = match manager.get_certificate_info().await {
        Ok(info) => Some(info),
        Err(_) => None,
    };

    let response = json!({
        "domain": config.server.domain,
        "ssl_config": {
            "enabled": config.ssl.enabled,
            "provider": format!("{:?}", config.ssl.provider),
            "staging": config.ssl.staging,
            "wildcard": config.ssl.wildcard,
            "email": config.ssl.email,
            "cert_cache_dir": config.ssl.cert_cache_dir,
            "auto_renewal": config.ssl.provider != SslProvider::Manual,
        },
        "certificate": cert_info.map(|info| json!({
            "exists": info.exists,
            "expiry_date": info.expiry_date,
            "days_until_expiry": info.days_until_expiry,
            "needs_renewal": info.needs_renewal,
        })),
        "dns_provider": config.ssl.dns_provider.as_ref().map(|dns| {
            let is_configured = !dns.config.is_null() || match dns.provider.as_str() {
                "cloudflare" => std::env::var("EXPOSEME_CLOUDFLARE_TOKEN").is_ok(),
                "digitalocean" => std::env::var("EXPOSEME_DIGITALOCEAN_TOKEN").is_ok(),
                "azure" => std::env::var("EXPOSEME_AZURE_CLIENT_ID").is_ok()
                          && std::env::var("EXPOSEME_AZURE_CLIENT_SECRET").is_ok()
                          && std::env::var("EXPOSEME_AZURE_TENANT_ID").is_ok()
                          && std::env::var("EXPOSEME_AZURE_SUBSCRIPTION_ID").is_ok()
                          && std::env::var("EXPOSEME_AZURE_RESOURCE_GROUP").is_ok(),
                "hetzner" => std::env::var("EXPOSEME_HETZNER_TOKEN").is_ok(),
                _ => false,
            };

            json!({
                "provider": dns.provider,
                "configured": is_configured,
            })
        }),
        "server_config": {
            "http_port": config.server.http_port,
            "https_port": config.server.https_port,
            "routing_mode": format!("{:?}", config.server.routing_mode),
        },
        "timestamp": chrono::Utc::now().to_rfc3339(),
    });

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(boxed_body(response.to_string()))
        .unwrap())
}

/// Extended health check with certificate information
async fn handle_extended_health_check(
    ssl_manager: &Arc<RwLock<SslManager>>,
    config: &ServerConfig,
) -> Result<Response<ResponseBody>, BoxError> {
    let manager = ssl_manager.read().await;

    let mut health_status = "healthy".to_string();
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    if config.ssl.enabled {
        match manager.get_certificate_info().await {
            Ok(cert_info) => {
                if !cert_info.exists {
                    health_status = "degraded".to_string();
                    warnings.push("SSL enabled but no certificate found".to_string());
                } else if cert_info.needs_renewal {
                    if cert_info.days_until_expiry.unwrap_or(0) < 7 {
                        health_status = "critical".to_string();
                        errors.push(format!(
                            "Certificate expires in {} days",
                            cert_info.days_until_expiry.unwrap_or(0)
                        ));
                    } else {
                        warnings.push(format!(
                            "Certificate needs renewal ({} days until expiry)",
                            cert_info.days_until_expiry.unwrap_or(0)
                        ));
                    }
                }
            }
            Err(e) => {
                health_status = "unhealthy".to_string();
                errors.push(format!("Failed to check certificate: {}", e));
            }
        }

        if config.ssl.wildcard && config.ssl.dns_provider.is_none() {
            health_status = "unhealthy".to_string();
            errors.push("Wildcard certificates enabled but no DNS provider configured".to_string());
        }
    }

    let status_code = match health_status.as_str() {
        "healthy" => StatusCode::OK,
        "degraded" => StatusCode::OK,
        "critical" => StatusCode::SERVICE_UNAVAILABLE,
        "unhealthy" => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::INTERNAL_SERVER_ERROR,
    };

    let response = json!({
        "status": health_status,
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "domain": config.server.domain,
        "ssl_enabled": config.ssl.enabled,
        "warnings": warnings,
        "errors": errors,
        "version": env!("CARGO_PKG_VERSION"),
        "uptime_check": "OK",
    });

    Ok(Response::builder()
        .status(status_code)
        .header("Content-Type", "application/json")
        .body(boxed_body(response.to_string()))
        .unwrap())
}

async fn handle_metrics_endpoint(context: &ServiceContext) -> Result<Response<ResponseBody>, BoxError> {
    if let Some(metrics) = &context.metrics {
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
    
    Ok(Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .body(boxed_body("Metrics not available"))
        .unwrap())
}

async fn handle_metrics_stream_endpoint(context: ServiceContext) -> Result<Response<ResponseBody>, BoxError> {
    if let Some(metrics) = &context.metrics {
        let metrics = metrics.clone();
        let interval = interval(Duration::from_secs(5));
        let stream = IntervalStream::new(interval)
            .map(move |_| {
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

                format!("data: {}\n\n", response_json)
            })
            .map(|data| Ok::<_, std::convert::Infallible>(Frame::data(bytes::Bytes::from(data))));

        let body = http_body_util::StreamBody::new(stream)
            .map_err(|e: std::convert::Infallible| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
            .boxed();

        return Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/event-stream")
            .header("Cache-Control", "no-cache")
            .header("Connection", "keep-alive") 
            .header("Access-Control-Allow-Origin", "*")
            .body(body)
            .unwrap());
    }
    
    Ok(Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .body(boxed_body("Metrics not available"))
        .unwrap())
}