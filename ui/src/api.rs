use wasm_bindgen::prelude::*;
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