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
        info!(
            event = "client.http.request",
            method,
            path,
            request_id = %id,
            complete = is_complete,
            "HTTP request received from server."
        );
        debug!(
            event = "client.http.request.start",
            method,
            path,
            request_id = %id,
            complete = is_complete,
            "HTTP request start received from server."
        );

        let http_client = self.http_client.clone();
        let local_target = self.local_target.clone();
        let to_server_tx = self.to_server_tx.clone();

        if is_complete {
            debug!(
                event = "client.http.request.complete",
                method,
                path,
                bytes = initial_data.len(),
                "Handling HTTP request as complete payload."
            );

            tokio::spawn(async move {
                let url = format!("{}{}", local_target, path);
                let mut request = create_request_builder(&http_client, &method, &url, &headers);

                if !initial_data.is_empty() {
                    request = request.body(initial_data);
                }

                match request.send().await {
                    Ok(response) => {
                        debug!(
                            event = "client.http.request.complete_ok",
                            method,
                            path,
                            "Complete HTTP request succeeded."
                        );
                        stream_response_to_server(&to_server_tx, id, response).await;
                    }
                    Err(e) => {
                        error!(
                            event = "client.http.request.complete_error",
                            method,
                            path,
                            error = %e,
                            "Complete HTTP request failed."
                        );
                        send_error_response(&to_server_tx, id, e.to_string()).await;
                    }
                }
            });
        } else {
            debug!(
                event = "client.http.request.stream_start",
                method,
                path,
                "Streaming HTTP request started."
            );

            let (body_tx, body_rx) = mpsc::channel::<Result<Bytes, std::io::Error>>(32);

            if !initial_data.is_empty() {
                debug!(
                    event = "client.http.request.stream_initial",
                    bytes = initial_data.len(),
                    "Initial bytes sent for streaming HTTP request."
                );
                let _ = body_tx.send(Ok(initial_data.into())).await;
            }

            {
                self.outgoing_requests.write().await.insert(id.clone(), OutgoingRequest {
                    body_tx: Some(body_tx.clone()),
                });
                debug!(
                    event = "client.http.request.stream_registered",
                    request_id = %id,
                    "Streaming HTTP request registered."
                );
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
                        debug!(
                            event = "client.http.request.stream_ok",
                            method,
                            path,
                            "Streaming HTTP request succeeded."
                        );
                        stream_response_to_server(&to_server_tx, id, response).await;
                    }
                    Err(e) => {
                        error!(
                            event = "client.http.request.stream_error",
                            method,
                            path,
                            error = %e,
                            "Streaming HTTP request failed."
                        );
                        send_error_response(&to_server_tx, id, e.to_string()).await;
                    }
                }
            });
        }
    }

    pub async fn handle_data_chunk(&self, id: String, data: Vec<u8>, is_final: bool) {
        debug!(
            event = "client.http.data_chunk",
            bytes = data.len(),
            final_chunk = is_final,
            request_id = %id,
            "HTTP request body chunk received."
        );

        let body_tx = {
            let requests = self.outgoing_requests.read().await;
            requests.get(&id).and_then(|r| r.body_tx.clone())
        };

        let Some(tx) = body_tx else {
            warn!(
                event = "client.http.data_chunk.unknown",
                request_id = %id,
                "HTTP request body chunk received for unknown request."
            );
            let requests = self.outgoing_requests.read().await;
            let active_ids: Vec<String> = requests.keys().cloned().collect();
            warn!(
                event = "client.http.data_chunk.active",
                active_ids = ?active_ids,
                "Active HTTP request IDs listed for debugging."
            );
            return;
        };

        if !data.is_empty() {
            if let Err(e) = tx.send(Ok(data.into())).await {
                error!(
                    event = "client.http.data_chunk.send_error",
                    error = %e,
                    "Failed to forward HTTP request body chunk."
                );
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
    trace!(
        event = "client.http.response.stream.enter",
        request_id = %id,
        "Entered client HTTP response streaming handler."
    );

    let status = response.status().as_u16();
    let headers = extract_response_headers(&response);

    debug!(
        event = "client.http.response.prepare",
        status,
        request_id = %id,
        headers = headers.len(),
        "Preparing HTTP response for tunnel."
    );

    let should_stream = is_streaming_response(&response);
    let is_sse_resp = is_sse(
        response.headers().get("content-type").and_then(|h| h.to_str().ok()),
        None
    );
    debug!(
        event = "client.http.response.should_stream",
        stream = should_stream,
        sse = is_sse_resp,
        "Determined whether response should stream."
    );

    if to_server_tx.is_closed() {
        error!(
            event = "client.http.response.send_closed",
            request_id = %id,
            "WebSocket sender closed before response send."
        );
        return;
    }

    if !should_stream {
        debug!(
            event = "client.http.response.complete",
            request_id = %id,
            "Sending complete HTTP response."
        );

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
                        trace!(
                            event = "client.http.response.complete_sent",
                            request_id = %id,
                            "Complete HTTP response sent."
                        );
                    }
                    Err(e) => {
                        error!(
                            event = "client.http.response.complete_send_error",
                            request_id = %id,
                            error = %e,
                            "Failed to send complete HTTP response."
                        );
                    }
                }
            }
            Err(e) => {
                error!(
                    event = "client.http.response.read_error",
                    request_id = %id,
                    error = %e,
                    "Failed to read HTTP response body."
                );
                send_error_response(to_server_tx, id.to_owned(), e.to_string()).await;
            }
        }
    } else {
        debug!(
            event = "client.http.response.stream_start",
            request_id = %id,
            "Streaming HTTP response started."
        );

        let start_msg = Message::HttpResponseStart {
            id: id.clone(),
            status,
            headers,
            initial_data: vec![],
            is_complete: false,
        };

        if let Err(e) = to_server_tx.send(start_msg) {
            error!(
                event = "client.http.response.stream_send_error",
                request_id = %id,
                error = %e,
                "Failed to send streaming response start."
            );
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
                        trace!(
                            event = "client.http.response.chunk",
                            request_id = %id,
                            chunk = chunk_count,
                            bytes = chunk.len(),
                            total_bytes,
                            "HTTP response chunk forwarded."
                        );
                    }

                    let chunk_msg = Message::DataChunk {
                        id: id.clone(),
                        data: chunk.to_vec(),
                        is_final: false,
                    };

                    if let Err(e) = to_server_tx.send(chunk_msg) {
                        error!(
                            event = "client.http.response.chunk_send_error",
                            request_id = %id,
                            error = %e,
                            "Failed to forward HTTP response chunk."
                        );
                        break;
                    }
                }
                Err(e) => {
                    error!(
                        event = "client.http.response.stream_error",
                        request_id = %id,
                        error = %e,
                        "HTTP response stream error."
                    );
                    break;
                }
            }
        }

        trace!(
            event = "client.http.response.final_chunk",
            request_id = %id,
            total_bytes,
            chunks = chunk_count,
            "Final HTTP response chunk sent."
        );

        let final_msg = Message::DataChunk {
            id: id.clone(),
            data: vec![],
            is_final: true,
        };

        if let Err(e) = to_server_tx.send(final_msg) {
            error!(
                event = "client.http.response.final_chunk_error",
                request_id = %id,
                error = %e,
                "Failed to send final HTTP response chunk."
            );
        }

        debug!(
            event = "client.http.response.stream_done",
            request_id = %id,
            total_bytes,
            chunks = chunk_count,
            "HTTP response streaming completed."
        );
    }
    
    trace!(
        event = "client.http.response.stream.exit",
        request_id = %id,
        "Exited client HTTP response streaming handler."
    );
}

async fn send_error_response(
    to_server_tx: &mpsc::UnboundedSender<Message>,
    id: String,
    error: String,
) {
    error!(
        event = "client.http.response.error_send",
        request_id = %id,
        error = %error,
        "Sending HTTP error response to server."
    );

    let error_response = Message::HttpResponseStart {
        id: id.clone(),
        status: 502,
        headers: HashMap::new(),
        initial_data: error.into_bytes(),
        is_complete: true,
    };

    if let Err(e) = to_server_tx.send(error_response) {
        error!(
            event = "client.http.response.error_send_fail",
            request_id = %id,
            error = %e,
            "Failed to send HTTP error response."
        );
    } else {
        info!(
            event = "client.http.response.error_sent",
            request_id = %id,
            "HTTP error response sent."
        );
    }
}

fn extract_response_headers(response: &reqwest::Response) -> HashMap<String, String> {
    let mut response_headers = HashMap::new();
    for (name, value) in response.headers() {
        response_headers.insert(name.to_string(), value.to_str().unwrap_or("").to_string());
    }
    response_headers
}
