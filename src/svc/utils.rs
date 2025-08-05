// src/svc/utils.rs - Utility functions for service handlers

use crate::svc::{BoxError};
use crate::svc::types::*;
use crate::{RoutingMode, ServerConfig};
use async_stream::stream;
use base64::Engine;
use bytes::Bytes;
use http_body_util::{Full, StreamBody, combinators::BoxBody, BodyExt};
use hyper::{Request, Response, body::Incoming, body::Frame};
use sha1::{Digest, Sha1};
use std::collections::HashMap;
use std::convert::Infallible;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn};

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
pub fn calculate_websocket_accept_key(ws_key: &str) -> String {
    let mut hasher = Sha1::new();
    hasher.update(ws_key.as_bytes());
    hasher.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"); // WebSocket magic string
    let hash = hasher.finalize();
    base64::engine::general_purpose::STANDARD.encode(&hash)
}

/// Build HTTP response from response events (handles both complete and streaming)
pub async fn build_response(
    request_id: String,
    mut response_rx: mpsc::Receiver<ResponseEvent>,
    active_requests: ActiveRequests,
) -> Result<Response<ResponseBody>, BoxError> {
    // Only match on the FIRST event to determine response type
    match response_rx.recv().await {
        Some(ResponseEvent::Complete { status, headers, body }) => {
            info!("✅ Complete response: {} ({} bytes)", status, body.len());
            active_requests.write().await.remove(&request_id);

            let mut builder = Response::builder().status(status);
            for (key, value) in headers {
                builder = builder.header(key, value);
            }

            Ok(builder.body(boxed_body(body))?)
        }

        Some(ResponseEvent::StreamStart { status, headers, initial_data }) => {
            info!("🔄 Streaming response: {} (initial: {} bytes)", status, initial_data.len());

            let mut builder = Response::builder().status(status);
            for (key, value) in headers {
                builder = builder.header(key, value);
            }

            // Handle streaming with Frame<Bytes>
            let body_stream = stream! {
                // Send initial data if present
                if !initial_data.is_empty() {
                    yield Ok(Frame::data(Bytes::from(initial_data)));
                }

                // Stream the rest - this handles StreamChunk and StreamEnd
                while let Some(event) = response_rx.recv().await {
                    match event {
                        ResponseEvent::StreamChunk(chunk) => {
                            yield Ok(Frame::data(chunk));
                        }
                        ResponseEvent::StreamEnd => break,
                        ResponseEvent::Error(e) => {
                            yield Err(e.into());
                            break;
                        }
                        _ => break, // Ignore other events in streaming context
                    }
                }
            };

            let body = BoxBody::new(StreamBody::new(body_stream));

            let active_requests_clone = active_requests.clone();
            let request_id_clone = request_id.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                active_requests_clone.write().await.remove(&request_id_clone);
            });

            Ok(builder.body(body)?)
        }

        Some(ResponseEvent::Error(e)) => {
            active_requests.write().await.remove(&request_id);
            Ok(Response::builder()
                .status(hyper::StatusCode::BAD_GATEWAY)
                .body(boxed_body(e))?)
        }

        Some(ResponseEvent::StreamChunk(_)) => {
            // This shouldn't happen as first event, but handle gracefully
            warn!("Received StreamChunk as first event for {}", request_id);
            active_requests.write().await.remove(&request_id);
            Ok(Response::builder()
                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                .body(boxed_body("Invalid response sequence"))?)
        }

        Some(ResponseEvent::StreamEnd) => {
            // This shouldn't happen as first event, but handle gracefully
            warn!("Received StreamEnd as first event for {}", request_id);
            active_requests.write().await.remove(&request_id);
            Ok(Response::builder()
                .status(hyper::StatusCode::INTERNAL_SERVER_ERROR)
                .body(boxed_body("Invalid response sequence"))?)
        }

        None => {
            active_requests.write().await.remove(&request_id);
            Ok(Response::builder()
                .status(hyper::StatusCode::GATEWAY_TIMEOUT)
                .body(boxed_body("No response from tunnel"))?)
        }
    }
}