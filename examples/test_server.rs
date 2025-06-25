// examples/test_server.rs
// Simple HTTP server for testing the tunnel
use hyper::service::{make_service_fn, service_fn};
use hyper::{Body, Request, Response, Server, StatusCode};
use std::convert::Infallible;

async fn handle_request(req: Request<Body>) -> Result<Response<Body>, Infallible> {
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
    let body_bytes = match hyper::body::to_bytes(req.into_body()).await {
        Ok(bytes) => bytes,
        Err(e) => {
            println!("   Error reading body: {}", e);
            return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Bad Request"))
                .unwrap());
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
                .body(Body::from(response_body))
                .unwrap()
        }
        "/health" => {
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/plain")
                .body(Body::from("OK"))
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
                .body(Body::from(response_body))
                .unwrap()
        }
    };

    Ok(response)
}

#[tokio::main]
async fn main() {
    println!("🚀 Starting test server...");

    let make_svc = make_service_fn(|_conn| async {
        Ok::<_, Infallible>(service_fn(handle_request))
    });

    let addr = ([127, 0, 0, 1], 3300).into();

    println!("🚀 Test server running on http://localhost:3300");
    println!("   Try: curl http://localhost:3300/webhook -d 'test data'");
    println!("   Or:  curl http://localhost:3300/health");

    let server = Server::bind(&addr).serve(make_svc);

    if let Err(e) = server.await {
        eprintln!("❌ Server error: {}", e);
    }
}