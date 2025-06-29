// src/bin/client.rs
use std::collections::HashMap;
use std::time::Duration;

use clap::Parser;
use futures_util::{SinkExt, StreamExt};
use reqwest::Client as HttpClient;
use tokio_tungstenite::{connect_async, tungstenite::Message as WsMessage};
use base64::Engine;
use tracing::{error, info, warn};

use exposeme::{ClientArgs, ClientConfig, Message};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Parse CLI arguments
    let args = ClientArgs::parse();

    // Initialize tracing
    tracing_subscriber::fmt()
        .with_max_level(if args.verbose {
            tracing::Level::DEBUG
        } else {
            tracing::Level::INFO
        })
        .init();

    // Generate config if requested
    if args.generate_config {
        ClientConfig::generate_default_file(&args.config)?;
        return Ok(());
    }

    // Load configuration
    let config = ClientConfig::load(&args)?;
    info!("Loaded configuration from {:?}", args.config);
    info!("Server: {}", config.client.server_url);
    info!("Tunnel ID: {}", config.client.tunnel_id);
    info!("Local target: {}", config.client.local_target);

    info!("Starting ExposeME Client...");

    // Main client loop with reconnection
    loop {
        match run_client(&config).await {
            Ok(_) => {
                info!("Client disconnected normally");
                break;
            }
            Err(e) => {
                error!("Client error: {}", e);

                if config.client.auto_reconnect {
                    info!(
                        "Reconnecting in {} seconds...",
                        config.client.reconnect_delay_secs
                    );
                    tokio::time::sleep(Duration::from_secs(config.client.reconnect_delay_secs))
                        .await;
                    continue;
                } else {
                    break;
                }
            }
        }
    }

    Ok(())
}

async fn run_client(config: &ClientConfig) -> Result<(), Box<dyn std::error::Error>> {
    // Connect to WebSocket server
    let (ws_stream, _) = connect_async(&config.client.server_url).await?;
    info!("Connected to WebSocket server");

    let (mut ws_sender, mut ws_receiver) = ws_stream.split();

    // Send authentication
    let auth_message = Message::Auth {
        token: config.client.auth_token.clone(),
        tunnel_id: config.client.tunnel_id.clone(),
    };

    let auth_json = auth_message.to_json()?;
    ws_sender.send(WsMessage::Text(auth_json)).await?;
    info!(
        "Sent authentication for tunnel '{}'",
        config.client.tunnel_id
    );

    // Create HTTP client for forwarding requests
    let http_client = HttpClient::new();

    // Handle incoming WebSocket messages
    while let Some(message) = ws_receiver.next().await {
        match message {
            Ok(WsMessage::Text(text)) => {
                if let Ok(msg) = Message::from_json(&text) {
                    match msg {
                        Message::AuthSuccess {
                            tunnel_id,
                            public_url,
                        } => {
                            info!("✅ Tunnel '{}' established!", tunnel_id);
                            info!("🌐 Public URL: {}", public_url);
                            info!("🔄 Forwarding to: {}", config.client.local_target);
                        }

                        Message::AuthError { error, message } => {
                            error!("❌ Authentication failed: {} - {}", error, message);
                            return Err(format!("Auth error: {}", message).into());
                        }

                        Message::HttpRequest {
                            id,
                            method,
                            path,
                            headers,
                            body,
                        } => {
                            info!("📥 Received request: {} {}", method, path);

                            // Forward request to local service
                            let response = forward_request(
                                &http_client,
                                &config.client.local_target,
                                &method,
                                &path,
                                headers,
                                &body,
                            )
                            .await;

                            let response_message = match response {
                                Ok((status, headers, body)) => {
                                    info!("📤 Sending response: {}", status);
                                    Message::HttpResponse {
                                        id,
                                        status,
                                        headers,
                                        body,
                                    }
                                }
                                Err(e) => {
                                    error!("❌ Failed to forward request: {}", e);
                                    Message::HttpResponse {
                                        id,
                                        status: 502,
                                        headers: HashMap::new(),
                                        body: base64::engine::general_purpose::STANDARD
                                            .encode("Bad Gateway"),
                                    }
                                }
                            };

                            // Send response back
                            if let Ok(response_json) = response_message.to_json() {
                                if let Err(e) = ws_sender.send(WsMessage::Text(response_json)).await
                                {
                                    error!("Failed to send response: {}", e);
                                    break;
                                }
                            }
                        }

                        Message::Error { message } => {
                            error!("Server error: {}", message);
                        }

                        _ => {
                            warn!("Unexpected message type from server");
                        }
                    }
                }
            }

            Ok(WsMessage::Close(_)) => {
                info!("WebSocket connection closed by server");
                break;
            }

            Err(e) => {
                error!("WebSocket error: {}", e);
                break;
            }

            _ => {}
        }
    }

    info!("Client connection ended");
    Ok(())
}

async fn forward_request(
    client: &HttpClient,
    base_url: &str,
    method: &str,
    path: &str,
    headers: HashMap<String, String>,
    body: &str,
) -> Result<(u16, HashMap<String, String>, String), Box<dyn std::error::Error>> {
    // Construct full URL
    let url = format!("{}{}", base_url, path);

    // Decode body from base64
    let body_bytes = match base64::engine::general_purpose::STANDARD.decode(body) {
        Ok(bytes) => bytes,
        Err(err) => return Err(err.into()),
    };

    // Create request
    let mut request_builder = match method {
        "GET" => client.get(&url),
        "POST" => client.post(&url),
        "PUT" => client.put(&url),
        "DELETE" => client.delete(&url),
        "PATCH" => client.patch(&url),
        "HEAD" => client.head(&url),
        _ => return Err(format!("Unsupported HTTP method: {}", method).into()),
    };

    // Add headers
    for (name, value) in headers {
        // Skip headers that reqwest handles automatically
        if !["host", "content-length", "connection", "user-agent"]
            .contains(&name.to_lowercase().as_str())
        {
            request_builder = request_builder.header(&name, &value);
        }
    }

    // Add body for methods that support it
    if ["POST", "PUT", "PATCH"].contains(&method) {
        request_builder = request_builder.body(body_bytes);
    }

    // Send request
    let response = request_builder.send().await?;

    // Extract response details
    let status = response.status().as_u16();

    // Extract response headers
    let mut response_headers = HashMap::new();
    for (name, value) in response.headers() {
        response_headers.insert(name.to_string(), value.to_str().unwrap_or("").to_string());
    }

    // Get response body
    let response_body = response.bytes().await?;
    let response_body_b64 = base64::engine::general_purpose::STANDARD.encode(&response_body);

    Ok((status, response_headers, response_body_b64))
}

