// src/svc/handlers/tunnel.rs - HTTP tunnel request handling
// Enhanced SSE support for src/svc/handlers/tunnel.rs

use crate::svc::{BoxError, ServiceContext};
use crate::svc::types::*;
use crate::svc::utils::{boxed_body, extract_headers, extract_tunnel_id_from_request};
use crate::Message;
use futures_util::StreamExt;
use http_body_util::BodyExt;
use hyper::{Request, Response, StatusCode, body::Incoming};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

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

    // Enhanced SSE and streaming detection
    let is_streaming_request = is_enhanced_streaming_request(&req);
    let method = req.method().clone();
    let mut headers = extract_headers(&req);

    // Handle SSE reconnection - check for Last-Event-ID header
    if let Some(last_event_id) = req.headers().get("last-event-id")
        .and_then(|h| h.to_str().ok()) {
        debug!("🔄 SSE reconnection detected with Last-Event-ID: {}", last_event_id);
        headers.insert("Last-Event-ID".to_string(), last_event_id.to_string());
    }

    // Log request type for debugging
    let request_type = if is_sse_request(&req) {
        "SSE"
    } else if is_streaming_request {
        "streaming"
    } else {
        "regular"
    };

    info!("📥 {} request: {} {} (id: {})", request_type, method, forwarded_path, request_id);

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
        // Handle as streaming request (including SSE)
        debug!("🔄 Processing {} request: {} {}", request_type, method, forwarded_path);

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
    build_enhanced_response(request_id, response_rx, context.active_requests).await
}

/// Enhanced streaming detection that includes SSE-specific patterns
fn is_enhanced_streaming_request(req: &Request<Incoming>) -> bool {
    // Check for SSE first (most specific)
    if is_sse_request(req) {
        return true;
    }

    // Check for streaming content types
    if let Some(content_type) = req.headers().get("content-type")
        .and_then(|h| h.to_str().ok()) {
        if content_type.contains("application/octet-stream")
            || content_type.contains("multipart/")
            || content_type.contains("text/event-stream") {
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

/// Check if this is an SSE request
fn is_sse_request(req: &Request<Incoming>) -> bool {
    // Check Accept header for text/event-stream
    req.headers().get("accept")
        .and_then(|h| h.to_str().ok())
        .map(|accept| accept.contains("text/event-stream"))
        .unwrap_or(false)
        // Also check Cache-Control: no-cache (common SSE pattern)
        || req.headers().get("cache-control")
        .and_then(|h| h.to_str().ok())
        .map(|cc| cc.contains("no-cache"))
        .unwrap_or(false)
}

/// Enhanced response builder that adds SSE-specific headers when needed
async fn build_enhanced_response(
    request_id: String,
    mut response_rx: mpsc::Receiver<ResponseEvent>,
    active_requests: ActiveRequests,
) -> Result<Response<ResponseBody>, BoxError> {
    // Only match on the FIRST event to determine response type
    match response_rx.recv().await {
        Some(ResponseEvent::Complete { status, headers, body }) => {
            info!("✅ Complete response: {} ({} bytes)", status, body.len());
            active_requests.write().await.remove(&request_id);

            // Check if this is an SSE response that should have been streamed
            if headers.get("content-type")
                .map(|ct| ct.contains("text/event-stream"))
                .unwrap_or(false) {
                warn!("⚠️  SSE response received as complete - this may cause issues");
            }

            let mut builder = Response::builder().status(status);
            for (key, value) in headers {
                builder = builder.header(key, value);
            }

            Ok(builder.body(boxed_body(body))?)
        }

        Some(ResponseEvent::StreamStart { status, mut headers, initial_data }) => {
            let is_sse_response = headers.get("content-type")
                .map(|ct| ct.contains("text/event-stream"))
                .unwrap_or(false);

            let response_type = if is_sse_response { "SSE" } else { "streaming" };
            info!("🔄 {} response: {} (initial: {} bytes)", response_type, status, initial_data.len());

            // Add SSE-specific headers if this is an SSE response
            if is_sse_response {
                debug!("✨ Adding SSE-specific response headers");
                headers.insert("Cache-Control".to_string(), "no-cache".to_string());
                headers.insert("Connection".to_string(), "keep-alive".to_string());
                headers.insert("X-Accel-Buffering".to_string(), "no".to_string()); // Disable nginx buffering

                // Ensure UTF-8 encoding is specified
                if let Some(content_type) = headers.get_mut("content-type") {
                    if !content_type.contains("charset") {
                        *content_type = format!("{}; charset=utf-8", content_type);
                    }
                }
            }

            let mut builder = Response::builder().status(status);
            for (key, value) in headers {
                builder = builder.header(key, value);
            }

            // Handle streaming with Frame<Bytes>
            let body_stream = async_stream::stream! {
                // Send initial data if present
                if !initial_data.is_empty() {
                    yield Ok(hyper::body::Frame::data(bytes::Bytes::from(initial_data)));
                }

                // Stream the rest - this handles StreamChunk and StreamEnd
                while let Some(event) = response_rx.recv().await {
                    match event {
                        ResponseEvent::StreamChunk(chunk) => {
                            yield Ok(hyper::body::Frame::data(chunk));
                        }
                        ResponseEvent::StreamEnd => {
                            debug!("✅ {} stream ended", response_type);
                            break;
                        }
                        ResponseEvent::Error(e) => {
                            yield Err(e.into());
                            break;
                        }
                        _ => break, // Ignore other events in streaming context
                    }
                }
            };

            let body = http_body_util::combinators::BoxBody::new(
                http_body_util::StreamBody::new(body_stream)
            );

            let active_requests_clone = active_requests.clone();
            let request_id_clone = request_id.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                active_requests_clone.write().await.remove(&request_id_clone);
            });

            Ok(builder.body(body)?)
        }

        Some(ResponseEvent::Error(e)) => {
            active_requests.write().await.remove(&request_id);
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(boxed_body(e))?)
        }

        Some(ResponseEvent::StreamChunk(_)) => {
            // This shouldn't happen as first event, but handle gracefully
            warn!("Received StreamChunk as first event for {}", request_id);
            active_requests.write().await.remove(&request_id);
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(boxed_body("Invalid response sequence"))?)
        }

        Some(ResponseEvent::StreamEnd) => {
            // This shouldn't happen as first event, but handle gracefully
            warn!("Received StreamEnd as first event for {}", request_id);
            active_requests.write().await.remove(&request_id);
            Ok(Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(boxed_body("Invalid response sequence"))?)
        }

        None => {
            active_requests.write().await.remove(&request_id);
            Ok(Response::builder()
                .status(StatusCode::GATEWAY_TIMEOUT)
                .body(boxed_body("No response from tunnel"))?)
        }
    }
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
