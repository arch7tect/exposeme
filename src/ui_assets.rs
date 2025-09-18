// UI Assets - Embedded at compile time for single binary distribution

use hyper::{Response, StatusCode, header::{CONTENT_TYPE, CACHE_CONTROL}};
use crate::svc::types::ResponseBody;
use crate::svc::utils::boxed_body;

#[cfg(feature = "ui")]
use rust_embed::RustEmbed;

#[cfg(feature = "ui")]
#[derive(RustEmbed)]
#[folder = "ui/dist/"]
#[include = "*.html"]
#[include = "*.js"]
#[include = "*.css"]
#[include = "*.wasm"]
#[include = "*.ico"]
#[include = "*.png"]
#[include = "*.svg"]
pub struct UIAssets;


#[cfg(not(feature = "ui"))]
pub struct UIAssets;

impl UIAssets {
    /// Handle UI asset requests with optimized caching
    pub fn serve_asset(path: &str) -> Option<Response<ResponseBody>> {
        #[cfg(feature = "ui")]
        {
            println!("🎨 DEBUG: UI feature is ENABLED at runtime");

            // Remove leading slash for rust-embed lookup
            let file_path = path.trim_start_matches('/');

            // Special handling for root path and favicon
            let lookup_path = if path == "/" {
                "index.html"
            } else if path == "/favicon.ico" {
                // Try to find favicon, fallback to serving a minimal one
                if UIAssets::get("favicon.ico").is_none() {
                    return Some(Self::serve_default_favicon());
                }
                "favicon.ico"
            } else {
                file_path
            };

            if let Some(file) = UIAssets::get(lookup_path) {
                let mime_type = Self::get_mime_type(lookup_path);

                // Clone the data to avoid lifetime issues
                let file_data = file.data.to_vec();

                let response = Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, mime_type)
                    .header(CACHE_CONTROL, "no-cache, no-store, must-revalidate")
                    .header("Pragma", "no-cache")
                    .header("Expires", "0")
                    .body(boxed_body(file_data))
                    .unwrap();

                println!("🎨 DEBUG: Serving asset: {} -> {}", path, lookup_path);
                Some(response)
            } else {
                println!("❌ DEBUG: Asset not found: {} -> {}", path, lookup_path);
                None
            }
        }

        #[cfg(not(feature = "ui"))]
        {
            println!("❌ DEBUG: UI feature is DISABLED at runtime");

            // Fallback UI for when UI feature is disabled
            let content = match path {
                "/" | "/index.html" => {
                    br#"<!DOCTYPE html><html><head><title>ExposeME</title></head><body><h1>UI not available</h1><p>Build with <code>--features ui</code> to enable web interface.</p></body></html>"#
                },
                _ => {
                    return None;
                }
            };

            let response = Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "text/html; charset=utf-8")
                .header(CACHE_CONTROL, "no-cache, no-store, must-revalidate")
                .body(boxed_body(content.to_vec()))
                .unwrap();

            Some(response)
        }
    }

    /// Get MIME type for a file path
    fn get_mime_type(path: &str) -> &'static str {
        if path.ends_with(".html") {
            "text/html; charset=utf-8"
        } else if path.ends_with(".css") {
            "text/css"
        } else if path.ends_with(".js") {
            "application/javascript"
        } else if path.ends_with(".wasm") {
            "application/wasm"
        } else if path.ends_with(".ico") {
            "image/x-icon"
        } else if path.ends_with(".png") {
            "image/png"
        } else if path.ends_with(".svg") {
            "image/svg+xml"
        } else {
            "application/octet-stream"
        }
    }

    /// Serve a minimal default favicon when none exists
    fn serve_default_favicon() -> Response<ResponseBody> {
        // Minimal 16x16 transparent PNG favicon
        let favicon_data = vec![
            0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0x00, 0x00, 0x00, 0x0D,
            0x49, 0x48, 0x44, 0x52, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x10,
            0x08, 0x06, 0x00, 0x00, 0x00, 0x1F, 0xF3, 0xFF, 0x61, 0x00, 0x00, 0x00,
            0x0D, 0x49, 0x44, 0x41, 0x54, 0x38, 0x8D, 0x63, 0x60, 0x00, 0x02, 0x00,
            0x00, 0x05, 0x00, 0x01, 0x0D, 0x0A, 0x2D, 0xB4, 0x00, 0x00, 0x00, 0x00,
            0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82
        ];

        Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "image/png")
            .header(CACHE_CONTROL, "public, max-age=3600")
            .body(boxed_body(favicon_data))
            .unwrap()
    }
    
    /// Check if path is a UI asset
    pub fn is_ui_asset(path: &str) -> bool {
        #[cfg(feature = "ui")]
        {
            // Remove leading slash for rust-embed lookup
            let file_path = path.trim_start_matches('/');
            let lookup_path = if path == "/" { "index.html" } else { file_path };

            // Always serve favicon.ico (we have a fallback)
            if path == "/favicon.ico" {
                println!("✅ DEBUG: Favicon requested: {}", path);
                return true;
            }

            let result = UIAssets::get(lookup_path).is_some();

            // Debug logging to see what's happening
            if !result {
                println!("❌ DEBUG: Asset not found: {} -> {}", path, lookup_path);
                println!("📁 DEBUG: Available assets:");
                for file in UIAssets::iter() {
                    println!("   - {}", file.as_ref());
                }
            } else {
                println!("✅ DEBUG: Asset found: {} -> {}", path, lookup_path);
            }

            result
        }

        #[cfg(not(feature = "ui"))]
        {
            matches!(path, "/" | "/index.html" | "/favicon.ico")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ui_asset() {
        assert!(UIAssets::is_ui_asset("/"));
        assert!(UIAssets::is_ui_asset("/index.html"));
        assert!(!UIAssets::is_ui_asset("/api/health"));
        assert!(!UIAssets::is_ui_asset("/some-tunnel-id/path"));
    }

    #[test]
    fn test_serve_asset_returns_response() {
        let response = UIAssets::serve_asset("/");
        assert!(response.is_some());

        let response = UIAssets::serve_asset("/nonexistent");
        assert!(response.is_none());
    }
}