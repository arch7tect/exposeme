// src/svc/utils.rs - Utility functions for service handlers

use crate::svc::types::*;
use crate::{RoutingMode, ServerConfig};
use base64::Engine;
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::{body::Incoming, Request};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::convert::Infallible;

/// Check if a request is a WebSocket upgrade
pub fn is_websocket_upgrade(req: &Request<Incoming>) -> bool {
    let connection_header = req
        .headers()
        .get("connection")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let upgrade_header = req
        .headers()
        .get("upgrade")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    connection_header.to_lowercase().contains("upgrade")
        && upgrade_header.to_lowercase() == "websocket"
}

/// Create a boxed body from text/bytes
pub fn boxed_body(text: impl Into<Bytes>) -> ResponseBody {
    Full::new(text.into())
        .map_err(|e: Infallible| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
        .boxed()
}

/// Extract headers from a request into a HashMap
pub fn extract_headers(req: &Request<Incoming>) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    for (name, value) in req.headers() {
        headers.insert(name.to_string(), value.to_str().unwrap_or("").to_string());
    }
    headers
}

/// Extract tunnel ID and forwarded path from request based on routing mode
pub fn extract_tunnel_id_from_request(
    req: &Request<Incoming>,
    config: &ServerConfig,
) -> Result<(String, String), Box<dyn std::error::Error + Send + Sync>> {
    let query = req
        .uri()
        .query()
        .map_or(String::new(), |q| format!("?{}", q));
    let path = req.uri().path();

    // tunnel-id.domain.com/path
    if matches!(
        config.server.routing_mode,
        RoutingMode::Subdomain | RoutingMode::Both
    ) {
        let base_domain = &config.server.domain;
        let host = req
            .headers()
            .get("host")
            .and_then(|h| h.to_str().ok())
            .ok_or("Missing Host header")?;
        let host_without_port = host.split(':').next().unwrap_or(host);

        if host_without_port != base_domain {
            if let Some(subdomain) = host_without_port.strip_suffix(&format!(".{}", base_domain)) {
                let tunnel_id = subdomain.to_string();
                let forwarded_path = format!("{}{}", path, query);
                return Ok((tunnel_id, forwarded_path));
            }
        }
        if let RoutingMode::Subdomain = config.server.routing_mode {
            return Err("Invalid subdomain format".into());
        }
    }

    // domain.com/tunnel-id/path
    let path_parts: Vec<&str> = path
        .trim_start_matches('/')
        .split('/')
        .filter(|s| !s.is_empty())
        .collect();
    if path_parts.is_empty() {
        return Err("Tunnel ID required in path or subdomain".into());
    }

    let tunnel_id = path_parts[0].to_string();
    let forwarded_path = if path_parts.len() > 1 {
        format!("/{}{}", path_parts[1..].join("/"), query)
    } else {
        format!("/{}", query)
    };

    Ok((tunnel_id, forwarded_path))
}

/// Calculate WebSocket accept key for upgrade handshake
const WS_MAGIC: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
pub fn calculate_websocket_accept_key(ws_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(ws_key.as_bytes());
    hasher.update(WS_MAGIC); // WebSocket magic string
    let hash = hasher.finalize();
    base64::engine::general_purpose::STANDARD.encode(hash)
}

#[cfg(test)]
mod tests {
    use super::calculate_websocket_accept_key;

    #[test]
    fn rfc6455_example() {
        // From RFC 6455 §1.3
        let key = "dGhlIHNhbXBsZSBub25jZQ==";
        let accept = calculate_websocket_accept_key(key);
        assert_eq!(accept.as_str(), "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");
    }
}
