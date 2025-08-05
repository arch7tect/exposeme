// src/svc/handlers/api.rs - Certificate and management API endpoints

use crate::svc::{BoxError, SslManager};
use crate::svc::types::ResponseBody;
use crate::svc::utils::boxed_body;
use crate::{ServerConfig, SslProvider};
use hyper::{Request, Response, StatusCode, body::Incoming};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::info;

/// Handle certificate management API requests
pub async fn handle_certificate_api(
    req: Request<Incoming>,
    ssl_manager: Arc<RwLock<SslManager>>,
    config: ServerConfig,
) -> Result<Response<ResponseBody>, BoxError> {
    let path = req.uri().path();
    let method = req.method();

    match (method, path) {
        // GET /api/certificates/status - Get certificate status
        (&hyper::Method::GET, "/api/certificates/status") => {
            handle_certificate_status(ssl_manager, config).await
        }

        // POST /api/certificates/renew - Force certificate renewal
        (&hyper::Method::POST, "/api/certificates/renew") => {
            handle_certificate_renewal(ssl_manager, config).await
        }

        // GET /api/certificates/info - Get detailed certificate information
        (&hyper::Method::GET, "/api/certificates/info") => {
            handle_certificate_info(ssl_manager, config).await
        }

        // GET /api/health - Extended health check with certificate info
        (&hyper::Method::GET, "/api/health") => {
            handle_extended_health_check(ssl_manager, config).await
        }

        _ => {
            let response = json!({"error": "Certificate API endpoint not found"});
            Ok(Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("Content-Type", "application/json")
                .body(boxed_body(response.to_string()))
                .unwrap())
        }
    }
}

/// Get basic certificate status
async fn handle_certificate_status(
    ssl_manager: Arc<RwLock<SslManager>>,
    config: ServerConfig,
) -> Result<Response<ResponseBody>, BoxError> {
    let manager = ssl_manager.read().await;
    match manager.get_certificate_info() {
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

/// Force certificate renewal
async fn handle_certificate_renewal(
    ssl_manager: Arc<RwLock<SslManager>>,
    config: ServerConfig,
) -> Result<Response<ResponseBody>, BoxError> {
    info!("🔄 Manual certificate renewal requested via API");

    // Check if renewal is supported for this provider
    if config.ssl.provider == SslProvider::Manual {
        let response = json!({
            "success": false,
            "error": "Manual renewal not supported for manual certificate provider",
            "domain": config.server.domain,
            "provider": "Manual"
        });

        return Ok(Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .header("Content-Type", "application/json")
            .body(boxed_body(response.to_string()))
            .unwrap());
    }

    let mut manager = ssl_manager.write().await;
    match manager.force_renewal().await {
        Ok(_) => {
            let response = json!({
                "success": true,
                "message": "Certificate renewed successfully",
                "domain": config.server.domain,
                "provider": format!("{:?}", config.ssl.provider),
                "timestamp": chrono::Utc::now().to_rfc3339(),
            });

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "application/json")
                .body(boxed_body(response.to_string()))
                .unwrap())
        }
        Err(e) => {
            let response = json!({
                "success": false,
                "error": format!("Certificate renewal failed: {}", e),
                "domain": config.server.domain,
                "provider": format!("{:?}", config.ssl.provider),
                "timestamp": chrono::Utc::now().to_rfc3339(),
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
    ssl_manager: Arc<RwLock<SslManager>>,
    config: ServerConfig,
) -> Result<Response<ResponseBody>, BoxError> {
    let manager = ssl_manager.read().await;

    let cert_info = match manager.get_certificate_info() {
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
        "dns_provider": config.ssl.dns_provider.as_ref().map(|dns| json!({
            "provider": dns.provider,
            "configured": !dns.config.is_null(),
        })),
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
    ssl_manager: Arc<RwLock<SslManager>>,
    config: ServerConfig,
) -> Result<Response<ResponseBody>, BoxError> {
    let manager = ssl_manager.read().await;

    let mut health_status = "healthy".to_string();
    let mut warnings = Vec::new();
    let mut errors = Vec::new();

    // Check SSL configuration
    if config.ssl.enabled {
        match manager.get_certificate_info() {
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

        // Check wildcard configuration
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