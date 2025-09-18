// Remove unused import
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
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

/// Setup SSE listener with callback
pub fn setup_sse_listener<F>(event_source: &EventSource, callback: F) 
where 
    F: Fn(MetricsResponse) + 'static,
{
    let callback = Closure::wrap(Box::new(move |event: MessageEvent| {
        if let Some(data) = event.data().as_string() {
            if let Ok(metrics) = serde_json::from_str::<MetricsResponse>(&data) {
                callback(metrics);
            }
        }
    }) as Box<dyn Fn(_)>);

    event_source.set_onmessage(Some(callback.as_ref().unchecked_ref()));
    callback.forget(); // Keep the closure alive
}