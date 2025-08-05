// examples/simple_sse_test.rs - Simple SSE test without Unicode

use std::time::Duration;
use hyper::{Request, Response, StatusCode, body::Incoming};
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use http_body_util::{Full, StreamBody, combinators::BoxBody, BodyExt};
use tower::Service;
use tokio::time::sleep;
use tokio::net::TcpListener;
use bytes::Bytes;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ResponseBody = BoxBody<Bytes, BoxError>;

#[derive(Clone)]
pub struct SimpleTestService;

impl Service<Request<Incoming>> for SimpleTestService {
    type Response = Response<ResponseBody>;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        Box::pin(async move { handle_request(req).await })
    }
}

async fn handle_request(req: Request<Incoming>) -> Result<Response<ResponseBody>, BoxError> {
    let path = req.uri().path();
    let accept = req.headers().get("accept").and_then(|h| h.to_str().ok()).unwrap_or("");

    println!("Request: {} {} Accept: {}", req.method(), path, accept);

    match path {
        "/" => Ok(serve_test_page()),
        "/sse" => serve_simple_sse().await,
        "/json" => Ok(serve_json_api()),
        "/json-nocache" => Ok(serve_json_nocache()),
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(boxed_body("Not Found"))
            .unwrap()),
    }
}

fn boxed_body<T: Into<Bytes>>(chunk: T) -> ResponseBody {
    Full::new(chunk.into())
        .map_err(|e: std::convert::Infallible| -> BoxError { Box::new(e) })
        .boxed()
}

fn serve_test_page() -> Response<ResponseBody> {
    let html = r#"<!DOCTYPE html>
<html>
<head>
    <title>Simple SSE Test</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        button { padding: 10px; margin: 5px; }
        .result { border: 1px solid #ccc; padding: 10px; margin: 10px 0; height: 150px; overflow-y: auto; }
        .status { padding: 5px; margin: 5px 0; }
        .ok { background: lightgreen; }
        .error { background: lightcoral; }
    </style>
</head>
<body>
    <h1>Simple SSE vs JSON Test</h1>
    
    <h3>Test SSE:</h3>
    <button onclick="testSSE()">Start SSE</button>
    <button onclick="stopSSE()">Stop SSE</button>
    <div id="sse-status" class="status">Ready</div>
    <div id="sse-result" class="result">SSE events will appear here...</div>
    
    <h3>Test JSON APIs:</h3>
    <button onclick="testJSON('/json')">Test Regular JSON</button>
    <button onclick="testJSON('/json-nocache')">Test JSON + no-cache</button>
    <div id="json-status" class="status">Ready</div>
    <div id="json-result" class="result">JSON results will appear here...</div>

    <script>
        let eventSource = null;
        
        function testSSE() {
            stopSSE();
            
            document.getElementById('sse-status').textContent = 'Connecting...';
            document.getElementById('sse-result').innerHTML = '';
            
            eventSource = new EventSource('/sse');
            
            eventSource.onopen = function() {
                document.getElementById('sse-status').textContent = 'Connected';
                document.getElementById('sse-status').className = 'status ok';
                addSSE('Connected to SSE');
            };
            
            eventSource.onmessage = function(e) {
                addSSE('Message: ' + e.data);
            };
            
            eventSource.onerror = function() {
                document.getElementById('sse-status').textContent = 'Error or Closed';
                document.getElementById('sse-status').className = 'status error';
                addSSE('Connection error or closed');
            };
        }
        
        function stopSSE() {
            if (eventSource) {
                eventSource.close();
                eventSource = null;
                document.getElementById('sse-status').textContent = 'Stopped';
                document.getElementById('sse-status').className = 'status';
            }
        }
        
        function addSSE(message) {
            const result = document.getElementById('sse-result');
            const time = new Date().toLocaleTimeString();
            result.innerHTML += '[' + time + '] ' + message + '\n';
            result.scrollTop = result.scrollHeight;
        }
        
        async function testJSON(endpoint) {
            const status = document.getElementById('json-status');
            const result = document.getElementById('json-result');
            
            status.textContent = 'Testing ' + endpoint + '...';
            
            try {
                const response = await fetch(endpoint);
                const text = await response.text();
                
                // Check if it looks like SSE format
                if (text.startsWith('data: ')) {
                    status.textContent = 'ERROR: Got SSE format!';
                    status.className = 'status error';
                    result.innerHTML += 'ERROR at ' + endpoint + ': Got SSE format: ' + text.substring(0, 50) + '...\n';
                } else {
                    // Try to parse as JSON
                    try {
                        const json = JSON.parse(text);
                        status.textContent = 'OK: Got JSON';
                        status.className = 'status ok';
                        result.innerHTML += 'OK at ' + endpoint + ': ' + JSON.stringify(json) + '\n';
                    } catch (e) {
                        status.textContent = 'ERROR: Invalid response';
                        status.className = 'status error';
                        result.innerHTML += 'ERROR at ' + endpoint + ': Invalid JSON: ' + text.substring(0, 50) + '...\n';
                    }
                }
            } catch (error) {
                status.textContent = 'ERROR: Request failed';
                status.className = 'status error';
                result.innerHTML += 'ERROR at ' + endpoint + ': ' + error.message + '\n';
            }
        }
    </script>
</body>
</html>"#;

    Response::builder()
        .header("Content-Type", "text/html; charset=utf-8")
        .body(boxed_body(html))
        .unwrap()
}

async fn serve_simple_sse() -> Result<Response<ResponseBody>, BoxError> {
    println!("Serving SSE stream");

    let stream = async_stream::stream! {
        for i in 1..=5 {
            let data = format!("data: Event {}\n\n", i);
            yield Ok::<_, BoxError>(hyper::body::Frame::data(Bytes::from(data)));
            sleep(Duration::from_secs(1)).await;
        }
        
        let data = "data: [DONE]\n\n";
        yield Ok::<_, BoxError>(hyper::body::Frame::data(Bytes::from(data)));
    };

    let body = BodyExt::boxed(StreamBody::new(stream));

    Ok(Response::builder()
        .header("Content-Type", "text/event-stream; charset=utf-8")
        .header("Cache-Control", "no-cache")
        .body(body)
        .unwrap())
}

fn serve_json_api() -> Response<ResponseBody> {
    println!("Serving regular JSON");

    let json = serde_json::json!({
        "type": "regular_json",
        "message": "Regular JSON API response",
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    Response::builder()
        .header("Content-Type", "application/json; charset=utf-8")
        .body(boxed_body(json.to_string()))
        .unwrap()
}

fn serve_json_nocache() -> Response<ResponseBody> {
    println!("Serving JSON with no-cache (should NOT be SSE!)");

    let json = serde_json::json!({
        "type": "json_with_nocache",
        "message": "JSON API with Cache-Control no-cache header",
        "note": "This should NOT be detected as SSE!",
        "timestamp": chrono::Utc::now().to_rfc3339()
    });

    Response::builder()
        .header("Content-Type", "application/json; charset=utf-8")
        .header("Cache-Control", "no-cache")  // KEY: This should NOT trigger SSE detection
        .body(boxed_body(json.to_string()))
        .unwrap()
}

#[tokio::main]
async fn main() -> Result<(), BoxError> {
    let addr = "127.0.0.1:3002";  // Different port to avoid conflicts
    let listener = TcpListener::bind(addr).await?;

    println!("Simple SSE Test Server running on http://{}", addr);
    println!("Open http://{} in your browser", addr);
    println!("");

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let service = TowerToHyperService::new(SimpleTestService);

        tokio::spawn(async move {
            if let Err(err) = Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(io, service)
                .await
            {
                println!("Connection error: {}", err);
            }
        });
    }
}