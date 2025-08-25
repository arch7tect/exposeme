// src/streaming.rs - Simple unified streaming detection

use hyper::{Request, body::Incoming};

const STREAMING_SIZE_THRESHOLD: usize = 512 * 1024; // 512KB

/// Simple streaming detection for requests
pub fn is_streaming_request(req: &Request<Incoming>) -> bool {
    // SSE requests
    if req.headers().get("accept")
        .and_then(|h| h.to_str().ok())
        .map(|accept| accept.contains("text/event-stream"))
        .unwrap_or(false) {
        return true;
    }

    // Streaming content types
    if let Some(content_type) = req.headers().get("content-type").and_then(|h| h.to_str().ok()) {
        if content_type.contains("text/event-stream")
            || content_type.contains("application/octet-stream")
            || content_type.contains("multipart/") {
            return true;
        }
    }

    // Chunked encoding
    if req.headers().get("transfer-encoding")
        .and_then(|h| h.to_str().ok())
        .map(|te| te.contains("chunked"))
        .unwrap_or(false) {
        return true;
    }

    // Large content
    if let Some(content_length) = req.headers().get("content-length")
        .and_then(|h| h.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok()) {
        return content_length > STREAMING_SIZE_THRESHOLD;
    }

    false
}

/// Simple streaming detection for responses
pub fn is_streaming_response(response: &reqwest::Response) -> bool {
    // SSE responses
    if let Some(content_type) = response.headers().get("content-type") {
        if let Ok(ct) = content_type.to_str() {
            if ct.contains("text/event-stream")
                || ct.contains("application/octet-stream") {
                return true;
            }
        }
    }

    // Chunked encoding
    if let Some(encoding) = response.headers().get("transfer-encoding") {
        if let Ok(te) = encoding.to_str() {
            if te.contains("chunked") {
                return true;
            }
        }
    }

    // Large content
    response.content_length()
        .map(|len| len > STREAMING_SIZE_THRESHOLD as u64)
        .unwrap_or(true) // Unknown size = streaming
}

/// Check if this is an SSE request/response
pub fn is_sse(content_type: Option<&str>, accept: Option<&str>) -> bool {
    if let Some(ct) = content_type {
        if ct.contains("text/event-stream") {
            return true;
        }
    }
    if let Some(accept) = accept {
        if accept.contains("text/event-stream") {
            return true;
        }
    }
    false
}

/// Add required SSE headers
pub fn add_sse_headers(headers: &mut std::collections::HashMap<String, String>) {
    headers.insert("Cache-Control".to_string(), "no-cache".to_string());
    headers.insert("Connection".to_string(), "keep-alive".to_string());
    headers.insert("X-Accel-Buffering".to_string(), "no".to_string());

    // Ensure charset for SSE
    if let Some(content_type) = headers.get_mut("content-type") {
        if content_type.contains("text/event-stream") && !content_type.contains("charset") {
            *content_type = format!("{}; charset=utf-8", content_type);
        }
    }
}