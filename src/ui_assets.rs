// UI Assets - Embedded at compile time for single binary distribution

use hyper::{Response, StatusCode, header::{CONTENT_TYPE, CACHE_CONTROL}};
use crate::svc::types::ResponseBody;
use crate::svc::utils::boxed_body;
use tracing::debug;
use rust_embed::RustEmbed;

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

impl UIAssets {
    /// Handle UI asset requests
    pub fn serve_asset(path: &str) -> Option<Response<ResponseBody>> {
        debug!(
            path,
            "UI asset requested."
        );

        let file_path = path.trim_start_matches('/');

        let lookup_path = if path == "/" {
            "index.html"
        } else if path == "/favicon.ico" {
            if UIAssets::get("favicon.ico").is_none() {
                return Some(Self::serve_default_favicon());
            }
            "favicon.ico"
        } else {
            file_path
        };

        if let Some(file) = UIAssets::get(lookup_path) {
            let mime_type = Self::get_mime_type(lookup_path);
            let file_data = file.data.to_vec();

            let response = Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, mime_type)
                .header(CACHE_CONTROL, "no-cache, no-store, must-revalidate")
                .header("Pragma", "no-cache")
                .header("Expires", "0")
                .body(boxed_body(file_data))
                .unwrap();

            debug!(
                path,
                lookup_path,
                "UI asset served."
            );
            Some(response)
        } else {
            debug!(
                path,
                lookup_path,
                "UI asset not found in embedded assets."
            );
            None
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
        let file_path = path.trim_start_matches('/');
        let lookup_path = if path == "/" { "index.html" } else { file_path };

        if path == "/favicon.ico" {
            debug!(
                path,
                "Favicon requested."
            );
            return true;
        }

        let result = UIAssets::get(lookup_path).is_some();

        if !result {
            debug!(
                path,
                lookup_path,
                "UI asset not found in embedded assets."
            );
            debug!("Listing available UI assets.");
            for file in UIAssets::iter() {
                debug!(
                    file = %file.as_ref(),
                    "UI asset listed in debug output."
                );
            }
        } else {
            debug!(
                path,
                lookup_path,
                "UI asset found in embedded assets."
            );
        }

        result
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
