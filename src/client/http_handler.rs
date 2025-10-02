use std::collections::HashMap;
use std::sync::Arc;
use bytes::Bytes;
use futures_util::StreamExt;
use reqwest::Client as HttpClient;
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info, trace, warn};
use crate::Message;
use crate::streaming::{is_sse, is_streaming_response};

pub type OutgoingRequests = Arc<RwLock<HashMap<String, OutgoingRequest>>>;

#[derive(Debug)]
pub struct OutgoingRequest {
    pub body_tx: Option<mpsc::Sender<Result<Bytes, std::io::Error>>>,
}

pub struct HttpHandler {
    http_client: HttpClient,
    local_target: String,
    to_server_tx: mpsc::UnboundedSender<Message>,
    outgoing_requests: OutgoingRequests,
}

impl HttpHandler {
    pub fn new(
        http_client: HttpClient,
        local_target: String,
        to_server_tx: mpsc::UnboundedSender<Message>,
        outgoing_requests: OutgoingRequests,
    ) -> Self {
        Self {
            http_client,
            local_target,
            to_server_tx,
            outgoing_requests,
        }
    }

    pub async fn handle_request_start(
        &self,
        id: String,
        method: String,
        path: String,
        headers: HashMap<String, String>,
        initial_data: Vec<u8>,
        is_complete: bool,
    ) {
        info!("Http request: {} {}", method, path);
        debug!("Received HttpRequestStart: {} {} (id: {}, complete: {})", method, path, id, is_complete);

        let http_client = self.http_client.clone();
        let local_target = self.local_target.clone();
        let to_server_tx = self.to_server_tx.clone();

        if is_complete == true {
            debug!("Processing complete request: {} {} ({} bytes)", method, path, initial_data.len());

            tokio::spawn(async move {
                let url = format!("{}{}", local_target, path);
                let mut request = create_request_builder(&http_client, &method, &url, &headers);

                if !initial_data.is_empty() {
                    request = request.body(initial_data);
                }

                match request.send().await {
                    Ok(response) => {
                        debug!("Complete request succeeded: {} {}", method, path);
                        stream_response_to_server(&to_server_tx, id, response).await;
                    }
                    Err(e) => {
                        error!("Complete request failed: {} {}: {}", method, path, e);
                        send_error_response(&to_server_tx, id, e.to_string()).await;
                    }
                }
            });
        } else {
            debug!("Processing streaming request start: {} {}", method, path);

            let (body_tx, body_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(32);

            if !initial_data.is_empty() {
                debug!("Sending initial data: {} bytes", initial_data.len());
                let _ = body_tx.send(Ok(initial_data.into())).await;
            }

            {
                self.outgoing_requests.write().await.insert(id.clone(), OutgoingRequest {
                    body_tx: Some(body_tx.clone()),
                });
                debug!("Registered streaming request: {}", id);
            }

            tokio::spawn(async move {
                let url = format!("{}{}", local_target, path);
                let mut request = create_request_builder(&http_client, &method, &url, &headers);

                if ["POST", "PUT", "PATCH"].contains(&method.as_str()) {
                    let body_stream = tokio_stream::wrappers::ReceiverStream::new(body_rx);
                    request = request.body(reqwest::Body::wrap_stream(body_stream));
                }

                drop(body_tx);

                match request.send().await {
                    Ok(response) => {
                        debug!("Streaming request succeeded: {} {}", method, path);
                        stream_response_to_server(&to_server_tx, id, response).await;
                    }
                    Err(e) => {
                        error!("Streaming request failed: {} {}: {}", method, path, e);
                        send_error_response(&to_server_tx, id, e.to_string()).await;
                    }
                }
            });
        }
    }

    pub async fn handle_data_chunk(&self, id: String, data: Vec<u8>, is_final: bool) {
        debug!("Received DataChunk: {} bytes, final={} (id: {})", data.len(), is_final, id);

        let body_tx = {
            let requests = self.outgoing_requests.read().await;
            requests.get(&id).and_then(|r| r.body_tx.clone())
        };

        let Some(tx) = body_tx else {
            warn!("Received DataChunk for unknown request ID: {} (this indicates HttpRequestStart was not received)", id);
            let requests = self.outgoing_requests.read().await;
            let active_ids: Vec<String> = requests.keys().cloned().collect();
            warn!("Active request IDs: {:?}", active_ids);
            return;
        };

        if !data.is_empty() {
            if let Err(e) = tx.send(Ok(data.into())).await {
                error!("Failed to send data: {}", e);
            }
        }

        if is_final {
            self.outgoing_requests.write().await.remove(&id);
            drop(tx);
        }
    }
}

fn create_request_builder(
    client: &HttpClient,
    method: &str,
    url: &str,
    headers: &HashMap<String, String>,
) -> reqwest::RequestBuilder {
    let mut request_builder = match method {
        "GET" => client.get(url),
        "POST" => client.post(url),
        "PUT" => client.put(url),
        "DELETE" => client.delete(url),
        "PATCH" => client.patch(url),
        "HEAD" => client.head(url),
        _ => client.get(url),
    };

    for (name, value) in headers {
        if !["host", "content-length", "connection", "user-agent"]
            .contains(&name.to_lowercase().as_str())
        {
            request_builder = request_builder.header(name, value);
        }
    }

    request_builder
}

async fn stream_response_to_server(
    to_server_tx: &mpsc::UnboundedSender<Message>,
    id: String,
    response: reqwest::Response,
) {
    trace!("ENTER stream_response_to_server for id: {}", id);

    let status = response.status().as_u16();
    let headers = extract_response_headers(&response);

    debug!("Preparing response: {} (id: {}, headers: {})", status, id, headers.len());

    let should_stream = is_streaming_response(&response);
    let is_sse_resp = is_sse(
        response.headers().get("content-type").and_then(|h| h.to_str().ok()),
        None
    );
    debug!("Should stream: {} (SSE: {})", should_stream, is_sse_resp);

    if to_server_tx.is_closed() {
        error!("WebSocket sender is CLOSED for {}", id);
        return;
    }

    if !should_stream {
        debug!("Processing as complete response for {}", id);

        match response.bytes().await {
            Ok(bytes) => {
                let response_msg = Message::HttpResponseStart {
                    id: id.clone(),
                    status,
                    headers,
                    initial_data: bytes.to_vec(),
                    is_complete: true,
                };

                match to_server_tx.send(response_msg) {
                    Ok(_) => {
                        trace!("Complete HttpResponseStart sent successfully for {}", id);
                    }
                    Err(e) => {
                        error!("FAILED to send HttpResponseStart for {}: {}", id, e);
                    }
                }
            }
            Err(e) => {
                error!("Failed to read response body for {}: {}", id, e);
                send_error_response(to_server_tx, id.to_owned(), e.to_string()).await;
            }
        }
    } else {
        debug!("Processing as streaming response for {}", id);

        let start_msg = Message::HttpResponseStart {
            id: id.clone(),
            status,
            headers,
            initial_data: vec![],
            is_complete: false,
        };

        if let Err(e) = to_server_tx.send(start_msg) {
            error!("Failed to send streaming response start for {}: {}", id, e);
            return;
        }

        let mut stream = response.bytes_stream();
        let mut total_bytes = 0;
        let mut chunk_count = 0;

        while let Some(result) = stream.next().await {
            match result {
                Ok(chunk) => {
                    total_bytes += chunk.len();
                    chunk_count += 1;

                    if chunk_count % 10 == 0 || chunk.len() > 1024 {
                        trace!("Sending chunk {} ({} bytes, {} total) for {}",
                              chunk_count, chunk.len(), total_bytes, id);
                    }

                    let chunk_msg = Message::DataChunk {
                        id: id.clone(),
                        data: chunk.to_vec(),
                        is_final: false,
                    };

                    if let Err(e) = to_server_tx.send(chunk_msg) {
                        error!("Failed to send data chunk for {}: {}", id, e);
                        break;
                    }
                }
                Err(e) => {
                    error!("Response stream error for {}: {}", id, e);
                    break;
                }
            }
        }

        trace!("Sending final chunk for {} ({} total bytes, {} chunks)", id, total_bytes, chunk_count);

        let final_msg = Message::DataChunk {
            id: id.clone(),
            data: vec![],
            is_final: true,
        };

        if let Err(e) = to_server_tx.send(final_msg) {
            error!("Failed to send final chunk for {}: {}", id, e);
        }

        debug!("Streaming completed for {}: {} bytes in {} chunks", id, total_bytes, chunk_count);
    }
    
    trace!("EXIT stream_response_to_server for id: {}", id);
}

async fn send_error_response(
    to_server_tx: &mpsc::UnboundedSender<Message>,
    id: String,
    error: String,
) {
    error!("Sending error response for {}: {}", id, error);

    let error_response = Message::HttpResponseStart {
        id: id.clone(),
        status: 502,
        headers: HashMap::new(),
        initial_data: error.into_bytes(),
        is_complete: true,
    };

    if let Err(e) = to_server_tx.send(error_response) {
        error!("Failed to send error response for {}: {}", id, e);
    } else {
        info!("Error response sent for {}", id);
    }
}

fn extract_response_headers(response: &reqwest::Response) -> HashMap<String, String> {
    let mut response_headers = HashMap::new();
    for (name, value) in response.headers() {
        response_headers.insert(name.to_string(), value.to_str().unwrap_or("").to_string());
    }
    response_headers
}