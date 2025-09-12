use crate::svc::{BoxError, ServiceContext};
use crate::svc::types::*;
use crate::svc::utils::boxed_body;
use crate::svc::tunnel_mgmt::shutdown_tunnel;
use hyper::{Request, Response, StatusCode, body::Incoming};

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