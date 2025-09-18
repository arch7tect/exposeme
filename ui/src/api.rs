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
                // 3️⃣ Forward the data to the Leptos callback.
                // The callback runs on the main JS thread, which is fine for UI
                // updates. If you need heavy work, spawn a local async task.
                cb.run(metrics);
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