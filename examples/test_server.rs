// examples/test_server.rs
// Simple HTTP server for testing the tunnel
use hyper::{body::Incoming, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use http_body_util::{combinators::BoxBody, BodyExt, Full};
use std::convert::Infallible;
use tower::Service;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};

type BoxError = Box<dyn std::error::Error + Send + Sync>;
type ResponseBody = BoxBody<bytes::Bytes, BoxError>;

#[derive(Clone)]
struct TestService;

impl Service<Request<Incoming>> for TestService {
    type Response = Response<ResponseBody>;
    type Error = Infallible;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, _: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request<Incoming>) -> Self::Future {
        Box::pin(async move {
            Ok(handle_request(req).await)
        })
    }
}

async fn handle_request(req: Request<Incoming>) -> Response<ResponseBody> {
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let headers = req.headers().clone();

    println!("🔔 Received request:");
    println!("   Method: {}", method);
    println!("   Path: {}", path);

    // Print some headers
    for (name, value) in &headers {
        println!("   {}: {}", name, value.to_str().unwrap_or(""));
    }

    // Get body
    let body_bytes = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            println!("   Error reading body: {}", e);
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(bytes::Bytes::from("Bad Request"))
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>).boxed())
                .unwrap();
        }
    };

    let body_str = String::from_utf8_lossy(&body_bytes);

    if !body_str.is_empty() {
        println!("   Body: {}", body_str);
    }

    println!("   ---");

    // Create response based on path
    let response = match path.as_str() {
        "/webhook" => {
            // Simulate webhook response
            let response_body = r#"{"status": "ok", "message": "Webhook received!"}"#;
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(Full::new(bytes::Bytes::from(response_body))
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>).boxed())
                .unwrap()
        }
        "/health" => {
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/plain")
                .body(Full::new(bytes::Bytes::from("OK"))
                .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>).boxed())
                .unwrap()
        }
        _ => {
            let response_body = format!(
                r#"{{"path": "{}", "method": "{}", "body": "{}"}}"#,
                path, method, body_str
            );
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "application/json")
                .body(Full::new(bytes::Bytes::from(response_body))
                    .map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>).boxed())
                .unwrap()
        }
    };

    response
}

#[tokio::main]
async fn main() {
    println!("🚀 Starting test server...");

    let addr: std::net::SocketAddr = ([127, 0, 0, 1], 3300).into();
    let listener = tokio::net::TcpListener::bind(&addr).await.unwrap();

    println!("🚀 Test server running on http://localhost:3300");
    println!("   Try: curl http://localhost:3300/webhook -d 'test data'");
    println!("   Or:  curl http://localhost:3300/health");

    loop {
        let (stream, _) = listener.accept().await.unwrap();
        let io = TokioIo::new(stream);
        let service = TestService;

        tokio::spawn(async move {
            if let Err(err) = Builder::new(hyper_util::rt::TokioExecutor::new())
                .serve_connection(io, TowerToHyperService::new(service))
                .await
            {
                eprintln!("❌ Server error: {}", err);
            }
        });
    }
}