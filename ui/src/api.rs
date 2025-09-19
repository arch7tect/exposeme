use leptos::prelude::*;
use wasm_bindgen::{prelude::*, JsCast};
use web_sys::{EventSource, MessageEvent};
use crate::types::*;

/// Fetch health data from the server
pub async fn fetch_health() -> Result<HealthResponse, String> {
    let window = web_sys::window().ok_or("No window object")?;
    let resp = wasm_bindgen_futures::JsFuture::from(
        window
            .fetch_with_str("/api/health")
    )
    .await
    .map_err(|e| format!("Fetch error: {:?}", e))?;
    
    let resp: web_sys::Response = resp.dyn_into().unwrap();
    let text = wasm_bindgen_futures::JsFuture::from(resp.text().unwrap())
        .await
        .map_err(|e| format!("Text error: {:?}", e))?;
    
    let json_str = text.as_string().unwrap();
    serde_json::from_str(&json_str)
        .map_err(|e| format!("JSON parse error: {:?}", e))
}

/// Fetch current metrics snapshot
pub async fn fetch_metrics() -> Result<MetricsResponse, String> {
    let window = web_sys::window().ok_or("No window object")?;
    let resp = wasm_bindgen_futures::JsFuture::from(
        window
            .fetch_with_str("/api/metrics")
    )
    .await
    .map_err(|e| format!("Fetch error: {:?}", e))?;
    
    let resp: web_sys::Response = resp.dyn_into().unwrap();
    let text = wasm_bindgen_futures::JsFuture::from(resp.text().unwrap())
        .await
        .map_err(|e| format!("Text error: {:?}", e))?;
    
    let json_str = text.as_string().unwrap();
    serde_json::from_str(&json_str)
        .map_err(|e| format!("JSON parse error: {:?}", e))
}

/// Create Server-Sent Events connection for live metrics
pub fn create_metrics_stream() -> Result<EventSource, String> {
    EventSource::new("/api/metrics/stream")
        .map_err(|e| format!("Failed to create EventSource: {:?}", e))
}


/// Set up an EventSource listener that forwards each decoded message to a
/// `leptos::Callback`. The callback is *owned* by the component that calls this
/// function, so it can be dropped (or cloned) at will.
///
/// The returned `Closure` is **not** forgotten – you are responsible for
/// calling `on_cleanup` (or otherwise dropping it) when you no longer need the
/// listener.
///
/// # Example
/// ```ignore
/// let es = EventSource::new("/api/metrics/stream").unwrap();
/// let cb = Callback::new(move |msg: MetricsResponse| {
///     // Update a signal with the metrics
///     set_metrics.set(Some(msg));
/// });
/// let listener = setup_sse_listener(&es, cb);
/// on_cleanup(move || {
///     // This automatically unregisters the JS handler and drops the Closure
///     drop(listener);
/// });
/// ```
pub fn setup_sse_listener(
    event_source: &EventSource,
    callback: Callback<MetricsResponse>,
) -> Closure<dyn Fn(MessageEvent)> {
    // Clone the callback into the closure that will be called from JS.
    // `Callback` is cheap to clone because it internally holds an Arc.
    let cb = callback.clone();

    // Build the actual JS closure.
    let closure = Closure::wrap(Box::new(move |event: MessageEvent| {
        // 1️⃣ Extract the raw string payload.
        let payload = match event.data().as_string() {
            Some(s) => s,
            None => {
                // If the server sent a Blob or something else we ignore it.
                // In a real app you might want to log this.
                web_sys::console::error_1(&"SSE: non‑string payload".into());
                return;
            }
        };

        // 2️⃣ Deserialize JSON → MetricsResponse.
        match serde_json::from_str::<MetricsResponse>(&payload) {
            Ok(metrics) => {
                // 3️⃣ Forward the data to the Leptos callback with error handling
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    cb.run(metrics);
                }));

                if result.is_err() {
                    web_sys::console::warn_1(&"SSE: callback failed (likely component disposed)".into());
                }
            }
            Err(err) => {
                // Log JSON errors – they are often a sign of a server bug.
                let msg = format!("SSE: failed to parse JSON – {err}");
                web_sys::console::error_1(&msg.into());
            }
        }
    }) as Box<dyn Fn(MessageEvent)>);

    // Register the handler with the EventSource.
    event_source.set_onmessage(Some(closure.as_ref().unchecked_ref()));

    // Return the Closure so the caller can keep it alive and later drop it.
    closure
}

/// Fetch certificate information
pub async fn fetch_certificates() -> Result<CertificateInfo, String> {
    let window = web_sys::window().ok_or("No window object")?;
    let resp = wasm_bindgen_futures::JsFuture::from(
        window
            .fetch_with_str("/api/certificates")
    )
    .await
    .map_err(|e| format!("Fetch error: {:?}", e))?;

    let resp: web_sys::Response = resp.dyn_into().unwrap();
    let text = wasm_bindgen_futures::JsFuture::from(resp.text().unwrap())
        .await
        .map_err(|e| format!("Text error: {:?}", e))?;

    let json_str = text.as_string().unwrap();
    serde_json::from_str(&json_str)
        .map_err(|e| format!("JSON parse error: {:?}", e))
}

/// Fetch detailed certificate information
pub async fn fetch_certificate_info() -> Result<CertificateInfo, String> {
    let window = web_sys::window().ok_or("No window object")?;
    let resp = wasm_bindgen_futures::JsFuture::from(
        window
            .fetch_with_str("/api/certificates/info")
    )
    .await
    .map_err(|e| format!("Fetch error: {:?}", e))?;

    let resp: web_sys::Response = resp.dyn_into().unwrap();
    let text = wasm_bindgen_futures::JsFuture::from(resp.text().unwrap())
        .await
        .map_err(|e| format!("Text error: {:?}", e))?;

    let json_str = text.as_string().unwrap();
    serde_json::from_str(&json_str)
        .map_err(|e| format!("JSON parse error: {:?}", e))
}

/// Force SSL certificate renewal using admin token
pub async fn renew_certificate_request(admin_token: &str) -> Result<(), String> {
    let window = web_sys::window().ok_or("No window object")?;

    // Create headers
    let headers = web_sys::Headers::new().map_err(|_| "Failed to create headers")?;
    headers.set("Authorization", &format!("Bearer {}", admin_token))
        .map_err(|_| "Failed to set Authorization header")?;

    // Create request init object
    let init = web_sys::RequestInit::new();
    init.set_method("POST");
    init.set_headers(&headers);

    let resp = wasm_bindgen_futures::JsFuture::from(
        window.fetch_with_str_and_init("/admin/ssl/renew", &init)
    )
    .await
    .map_err(|e| format!("Fetch error: {:?}", e))?;

    let resp: web_sys::Response = resp.dyn_into().unwrap();

    if !resp.ok() {
        let status = resp.status();
        let text = wasm_bindgen_futures::JsFuture::from(resp.text().unwrap())
            .await
            .map_err(|e| format!("Text error: {:?}", e))?;
        let error_text = text.as_string().unwrap_or_default();
        return Err(format!("HTTP {}: {}", status, error_text));
    }

    let text = wasm_bindgen_futures::JsFuture::from(resp.text().unwrap())
        .await
        .map_err(|e| format!("Text error: {:?}", e))?;

    let json_str = text.as_string().unwrap();
    let response: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| format!("JSON parse error: {:?}", e))?;

    // Check if the operation was successful
    if let Some(success) = response.get("success").and_then(|v| v.as_bool()) {
        if success {
            Ok(())
        } else {
            let message = response.get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown error");
            Err(message.to_string())
        }
    } else {
        Err("Invalid response format".to_string())
    }
}

/// Disconnect a tunnel using admin token
pub async fn disconnect_tunnel_request(tunnel_id: &str, admin_token: &str) -> Result<(), String> {
    let window = web_sys::window().ok_or("No window object")?;

    // Create headers
    let headers = web_sys::Headers::new().map_err(|_| "Failed to create headers")?;
    headers.set("Authorization", &format!("Bearer {}", admin_token))
        .map_err(|_| "Failed to set Authorization header")?;

    // Create request init object
    let init = web_sys::RequestInit::new();
    init.set_method("DELETE");
    init.set_headers(&headers);

    let url = format!("/admin/tunnels/{}", tunnel_id);

    let resp = wasm_bindgen_futures::JsFuture::from(
        window.fetch_with_str_and_init(&url, &init)
    )
    .await
    .map_err(|e| format!("Fetch error: {:?}", e))?;

    let resp: web_sys::Response = resp.dyn_into().unwrap();

    if !resp.ok() {
        let status = resp.status();
        let text = wasm_bindgen_futures::JsFuture::from(resp.text().unwrap())
            .await
            .map_err(|e| format!("Text error: {:?}", e))?;
        let error_text = text.as_string().unwrap_or_default();
        return Err(format!("HTTP {}: {}", status, error_text));
    }

    let text = wasm_bindgen_futures::JsFuture::from(resp.text().unwrap())
        .await
        .map_err(|e| format!("Text error: {:?}", e))?;

    let json_str = text.as_string().unwrap();
    let response: serde_json::Value = serde_json::from_str(&json_str)
        .map_err(|e| format!("JSON parse error: {:?}", e))?;

    // Check if the operation was successful
    if let Some(success) = response.get("success").and_then(|v| v.as_bool()) {
        if success {
            Ok(())
        } else {
            let message = response.get("message")
                .and_then(|v| v.as_str())
                .unwrap_or("Unknown error");
            Err(message.to_string())
        }
    } else {
        Err("Invalid response format".to_string())
    }
}