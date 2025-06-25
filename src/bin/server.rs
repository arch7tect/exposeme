// src/bin/server.rs
use std::collections::HashMap;
use std::sync::Arc;

use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use tokio::sync::{mpsc, RwLock};
use tokio_tungstenite::{accept_async, tungstenite::Message as WsMessage};
use tracing::{error, info, warn};

use exposeme::Message;

type TunnelMap = Arc<RwLock<HashMap<String, mpsc::UnboundedSender<Message>>>>;
type PendingRequests = Arc<RwLock<HashMap<String, mpsc::UnboundedSender<(u16, HashMap<String, String>, String)>>>>;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize tracing
    tracing_subscriber::fmt::init();

    info!("Starting ExposeME Server...");

    // Shared state
    let tunnels: TunnelMap = Arc::new(RwLock::new(HashMap::new()));
    let pending_requests: PendingRequests = Arc::new(RwLock::new(HashMap::new()));

    // Clone for HTTP server
    let tunnels_http = tunnels.clone();
    let pending_requests_http = pending_requests.clone();

    // Start HTTP server
    let http_server = async {
        let make_svc = make_service_fn(move |_conn| {
            let tunnels = tunnels_http.clone();
            let pending_requests = pending_requests_http.clone();

            async move {
                Ok::<_, hyper::Error>(service_fn(move |req| {
                    handle_http_request(req, tunnels.clone(), pending_requests.clone())
                }))
            }
        });

        let addr = ([0, 0, 0, 0], 8080).into();
        let server = Server::bind(&addr).serve(make_svc);

        info!("HTTP server listening on http://localhost:8080");

        if let Err(e) = server.await {
            error!("HTTP server error: {}", e);
        }
    };

    // Start WebSocket server
    let ws_server = async {
        let listener = tokio::net::TcpListener::bind("0.0.0.0:8081").await?;
        info!("WebSocket server listening on ws://localhost:8081");

        while let Ok((stream, addr)) = listener.accept().await {
            info!("New WebSocket connection from: {}", addr);

            let tunnels = tunnels.clone();
            let pending_requests = pending_requests.clone();

            tokio::spawn(async move {
                if let Err(e) = handle_websocket_connection(stream, tunnels, pending_requests).await {
                    error!("WebSocket connection error: {}", e);
                }
            });
        }

        Ok::<(), Box<dyn std::error::Error>>(())
    };

    // Run both servers concurrently
    tokio::select! {
        _ = http_server => {},
        result = ws_server => {
            if let Err(e) = result {
                error!("WebSocket server error: {}", e);
            }
        }
    }

    Ok(())
}

async fn handle_http_request(
    req: Request<Body>,
    tunnels: TunnelMap,
    pending_requests: PendingRequests,
) -> Result<Response<Body>, hyper::Error> {
    let path = req.uri().path().to_string();
    let method = req.method().clone();

    // Parse tunnel_id from path: /{tunnel_id}/...
    let path_parts: Vec<&str> = path.trim_start_matches('/').split('/').collect();
    if path_parts.is_empty() {
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Body::from("Tunnel ID required"))
            .unwrap());
    }

    let tunnel_id = path_parts[0].to_string();
    let forwarded_path = format!("/{}", path_parts[1..].join("/"));

    info!("HTTP request for tunnel '{}': {} {}", tunnel_id, method, forwarded_path);

    // Check if tunnel exists
    let tunnel_sender = {
        let tunnels_guard = tunnels.read().await;
        tunnels_guard.get(&tunnel_id).cloned()
    };

    let tunnel_sender = match tunnel_sender {
        Some(sender) => sender,
        None => {
            warn!("Tunnel '{}' not found", tunnel_id);
            return Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .body(Body::from("Tunnel not available"))
                .unwrap());
        }
    };

    // Generate request ID
    let request_id = uuid::Uuid::new_v4().to_string();

    // Extract method and headers before consuming request body
    let headers_ref = req.headers();

    // Extract headers
    let mut headers = HashMap::new();
    for (name, value) in headers_ref {
        headers.insert(
            name.to_string(),
            value.to_str().unwrap_or("").to_string(),
        );
    }

    // Extract body
    let body_bytes = hyper::body::to_bytes(req.into_body()).await?;
    let body_b64 = base64::engine::general_purpose::STANDARD.encode(&body_bytes);

    // Create HTTP request message
    let http_request = Message::HttpRequest {
        id: request_id.clone(),
        method: method.to_string(),
        path: forwarded_path,
        headers,
        body: body_b64,
    };

    // Create response channel
    let (response_tx, mut response_rx) = mpsc::unbounded_channel();

    // Store pending request
    {
        let mut pending = pending_requests.write().await;
        pending.insert(request_id.clone(), response_tx);
    }

    // Send request to client
    if let Err(e) = tunnel_sender.send(http_request) {
        error!("Failed to send request to tunnel '{}': {}", tunnel_id, e);
        return Ok(Response::builder()
            .status(StatusCode::INTERNAL_SERVER_ERROR)
            .body(Body::from("Tunnel communication error"))
            .unwrap());
    }

    // Wait for response (with timeout)
    let response = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        response_rx.recv()
    ).await;

    // Clean up pending request
    {
        let mut pending = pending_requests.write().await;
        pending.remove(&request_id);
    }

    match response {
        Ok(Some((status, headers, body))) => {
            let mut response_builder = Response::builder().status(status);

            // Add headers
            for (name, value) in headers {
                response_builder = response_builder.header(name, value);
            }

            // Decode body
            let body_bytes = base64::engine::general_purpose::STANDARD
                .decode(&body)
                .unwrap_or_else(|_| body.into_bytes());

            Ok(response_builder.body(Body::from(body_bytes)).unwrap())
        }
        Ok(None) => {
            warn!("No response received for request {}", request_id);
            Ok(Response::builder()
                .status(StatusCode::GATEWAY_TIMEOUT)
                .body(Body::from("No response from tunnel"))
                .unwrap())
        }
        Err(_) => {
            warn!("Timeout waiting for response to request {}", request_id);
            Ok(Response::builder()
                .status(StatusCode::GATEWAY_TIMEOUT)
                .body(Body::from("Tunnel response timeout"))
                .unwrap())
        }
    }
}

async fn handle_websocket_connection(
    stream: tokio::net::TcpStream,
    tunnels: TunnelMap,
    pending_requests: PendingRequests,
) -> Result<(), Box<dyn std::error::Error>> {
    let ws_stream = accept_async(stream).await?;
    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    // Create channel for outgoing messages
    let (tx, mut rx) = mpsc::unbounded_channel::<Message>();

    // Spawn task to handle outgoing messages
    let outgoing_task = tokio::spawn(async move {
        while let Some(message) = rx.recv().await {
            if let Ok(json) = message.to_json() {
                if ws_sender.send(WsMessage::Text(json)).await.is_err() {
                    break;
                }
            }
        }
    });

    let mut tunnel_id: Option<String> = None;

    // Handle incoming messages
    while let Some(message) = ws_receiver.next().await {
        match message {
            Ok(WsMessage::Text(text)) => {
                if let Ok(msg) = Message::from_json(&text) {
                    match msg {
                        Message::Auth { token, tunnel_id: requested_tunnel_id } => {
                            info!("Auth request for tunnel '{}'", requested_tunnel_id);

                            // Simple token validation (hardcoded for MVP)
                            if token != "dev" {
                                let error_msg = Message::AuthError {
                                    error: "invalid_token".to_string(),
                                    message: "Invalid authentication token".to_string(),
                                };
                                tx.send(error_msg)?;
                                continue;
                            }

                            // Check if tunnel_id is already taken
                            {
                                let tunnels_guard = tunnels.read().await;
                                if tunnels_guard.contains_key(&requested_tunnel_id) {
                                    let error_msg = Message::AuthError {
                                        error: "tunnel_id_taken".to_string(),
                                        message: format!("Tunnel ID '{}' is already in use", requested_tunnel_id),
                                    };
                                    tx.send(error_msg)?;
                                    continue;
                                }
                            }

                            // Register tunnel
                            {
                                let mut tunnels_guard = tunnels.write().await;
                                tunnels_guard.insert(requested_tunnel_id.clone(), tx.clone());
                            }

                            tunnel_id = Some(requested_tunnel_id.clone());

                            let success_msg = Message::AuthSuccess {
                                tunnel_id: requested_tunnel_id.clone(),
                                public_url: format!("http://localhost:8080/{}", requested_tunnel_id),
                            };

                            tx.send(success_msg)?;
                            info!("Tunnel '{}' registered successfully", requested_tunnel_id);
                        }

                        Message::HttpResponse { id, status, headers, body } => {
                            // Find pending request and send response
                            let response_sender = {
                                let mut pending = pending_requests.write().await;
                                pending.remove(&id)
                            };

                            if let Some(sender) = response_sender {
                                let _ = sender.send((status, headers, body));
                            }
                        }

                        _ => {
                            warn!("Unexpected message type from client");
                        }
                    }
                }
            }
            Ok(WsMessage::Close(_)) => {
                info!("WebSocket connection closed");
                break;
            }
            Err(e) => {
                error!("WebSocket error: {}", e);
                break;
            }
            _ => {}
        }
    }

    // Clean up tunnel on disconnect
    if let Some(tunnel_id) = tunnel_id {
        let mut tunnels_guard = tunnels.write().await;
        tunnels_guard.remove(&tunnel_id);
        info!("Tunnel '{}' removed", tunnel_id);
    }

    // Wait for outgoing task to finish
    outgoing_task.abort();

    Ok(())
}

// Re-export base64 for convenience
use base64::Engine;
// Re-export futures for stream handling
use futures_util::{SinkExt, StreamExt};