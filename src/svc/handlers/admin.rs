use crate::svc::{BoxError, ServiceContext};
use crate::svc::types::*;
use crate::svc::utils::boxed_body;
use crate::svc::tunnel_mgmt::shutdown_tunnel;
use hyper::{Request, Response, StatusCode, body::Incoming, body::Frame};
use http_body_util::BodyExt;

pub async fn handle_admin_request(
    req: &Request<Incoming>,
    context: ServiceContext,
    path: &str,
) -> Result<Option<Response<ResponseBody>>, BoxError> {
    let method = req.method();
    
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
        return Ok(Some(Response::builder()
            .status(StatusCode::UNAUTHORIZED)
            .body(boxed_body("Unauthorized: Admin token required"))
            .unwrap()));
    }

    // Handle metrics endpoint
    if path == "/admin/metrics" {
        return Ok(Some(handle_metrics_endpoint(&context).await?));
    }

    // Handle SSE metrics endpoint  
    if path == "/admin/metrics/stream" {
        return Ok(Some(handle_metrics_stream_endpoint(context).await?));
    }

    // Handle tunnel deletion endpoint
    if path.starts_with("/admin/tunnels/") && method == "DELETE" {
        let tunnel_id = path.strip_prefix("/admin/tunnels/").unwrap_or("");
        if !tunnel_id.is_empty() {
            return Ok(Some(handle_tunnel_deletion(context, tunnel_id).await?));
        }
    }

    // Handle SSL renewal endpoint
    if path == "/admin/ssl/renew" && method == "POST" {
        return Ok(Some(handle_ssl_renewal(context).await?));
    }

    Ok(None)
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
        use tokio_stream::{wrappers::IntervalStream, StreamExt};
        use tokio::time::{interval, Duration};
        
        let metrics = metrics.clone();
        let interval = interval(Duration::from_secs(1));
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

async fn handle_tunnel_deletion(context: ServiceContext, tunnel_id: &str) -> Result<Response<ResponseBody>, BoxError> {
    let result = shutdown_tunnel(context, tunnel_id.to_owned()).await;
    
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

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(boxed_body(serde_json::to_string(&response_json).unwrap()))
        .unwrap())
}

async fn handle_ssl_renewal(context: ServiceContext) -> Result<Response<ResponseBody>, BoxError> {
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

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(boxed_body(serde_json::to_string(&response_json).unwrap()))
        .unwrap())
}