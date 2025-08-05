// src/svc/handlers/tunnel.rs - HTTP tunnel request handling

use crate::svc::{BoxError, ServiceContext};
use crate::svc::types::*;
use crate::svc::utils::{boxed_body, extract_headers, extract_tunnel_id_from_request, build_response};
use crate::Message;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use hyper::{Request, Response, StatusCode, body::Incoming};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;
use tracing::{info, warn};

/// Handle HTTP requests that should be tunneled to clients
pub async fn handle_tunnel_request(
    req: Request<Incoming>,
    context: ServiceContext,
) -> Result<Response<ResponseBody>, BoxError> {
    let (tunnel_id, forwarded_path) = match extract_tunnel_id_from_request(&req, &context.config) {
        Ok(result) => result,
        Err(e) => {
            warn!("Failed to extract tunnel ID: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(boxed_body(format!("Invalid request: {}", e)))
                .unwrap());
        }
    };

    let request_id = uuid::Uuid::new_v4().to_string();

    // Get tunnel sender
    let tunnel_sender = {
        let tunnels_guard = context.tunnels.read().await;
        tunnels_guard.get(&tunnel_id).cloned()
    };

    let tunnel_sender = match tunnel_sender {
        Some(sender) => sender,
        None => {
            warn!("Tunnel '{}' not found", tunnel_id);
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(boxed_body("Tunnel not available"))
                .unwrap());
        }
    };

    // Detect if this should be a streaming request
    let is_streaming_request = is_streaming_request(&req);
    let method = req.method().clone();
    let headers = extract_headers(&req);

    // Create response channel
    let (response_tx, response_rx) = mpsc::channel(32);

    // Register request
    context.active_requests.write().await.insert(
        request_id.clone(),
        ActiveRequest {
            tunnel_id: tunnel_id.clone(),
            response_tx,
            client_disconnected: Arc::new(AtomicBool::new(false)),
        },
    );

    if is_streaming_request {
        // Handle as streaming request
        info!("🔄 Processing streaming request: {} {}", method, forwarded_path);

        // Send initial request without body
        let initial_request = Message::HttpRequestStart {
            id: request_id.clone(),
            method: method.to_string(),
            path: forwarded_path,
            headers,
            initial_data: vec![],
            is_complete: None, // Streaming
        };

        if tunnel_sender.send(initial_request).is_err() {
            context.active_requests.write().await.remove(&request_id);
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(boxed_body("Tunnel communication error"))
                .unwrap());
        }

        // Stream request body if present
        tokio::spawn(stream_request_body(
            req.into_body(),
            request_id.clone(),
            tunnel_sender,
            Arc::new(AtomicBool::new(false)),
        ));

    } else {
        // Handle as complete request
        let body_bytes = match req.into_body().collect().await {
            Ok(collected) => collected.to_bytes(),
            Err(_) => {
                context.active_requests.write().await.remove(&request_id);
                return Ok(Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(boxed_body("Failed to read request body"))
                    .unwrap());
            }
        };

        let complete_request = Message::HttpRequestStart {
            id: request_id.clone(),
            method: method.to_string(),
            path: forwarded_path,
            headers,
            initial_data: body_bytes.to_vec(),
            is_complete: Some(true),
        };

        if tunnel_sender.send(complete_request).is_err() {
            context.active_requests.write().await.remove(&request_id);
            return Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(boxed_body("Tunnel communication error"))
                .unwrap());
        }
    }

    // Build response (handles both complete and streaming)
    build_response(request_id, response_rx, context.active_requests).await
}

/// Helper to detect streaming requests
fn is_streaming_request(req: &Request<Incoming>) -> bool {
    // Check for SSE
    if req.headers().get("accept")
        .and_then(|h| h.to_str().ok())
        .map(|accept| accept.contains("text/event-stream"))
        .unwrap_or(false) {
        return true;
    }

    // Check for streaming content types
    if let Some(content_type) = req.headers().get("content-type")
        .and_then(|h| h.to_str().ok()) {
        if content_type.contains("application/octet-stream")
            || content_type.contains("multipart/") {
            return true;
        }
    }

    // Check for chunked encoding
    if req.headers().get("transfer-encoding")
        .and_then(|h| h.to_str().ok())
        .map(|te| te.contains("chunked"))
        .unwrap_or(false) {
        return true;
    }

    // Large content length
    if let Some(content_length) = req.headers().get("content-length")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok()) {
        if content_length > 1024 * 1024 { // > 1MB
            return true;
        }
    }

    false
}

/// Stream request body to tunnel client in chunks
async fn stream_request_body(
    body: Incoming,
    request_id: String,
    tunnel_sender: mpsc::UnboundedSender<Message>,
    client_disconnected: Arc<AtomicBool>,
) -> Result<(), BoxError> {
    let mut body_stream = body.into_data_stream();

    while let Some(result) = body_stream.next().await {
        if client_disconnected.load(Ordering::Relaxed) {
            break; // Client gone, stop processing
        }

        match result {
            Ok(chunk) => {
                if !chunk.is_empty() {
                    tunnel_sender.send(Message::DataChunk {
                        id: request_id.clone(),
                        data: chunk.to_vec(),
                        is_final: false,
                    })?;
                }
            }
            Err(e) => {
                tracing::error!("Body stream error: {}", e);
                break;
            }
        }
    }

    // Send final chunk
    tunnel_sender.send(Message::DataChunk {
        id: request_id,
        data: vec![],
        is_final: true,
    })?;

    Ok(())
}