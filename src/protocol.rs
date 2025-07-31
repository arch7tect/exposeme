// src/protocol.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Messages sent between client and server via WebSocket
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Message {
    // === AUTHENTICATION ===
    /// Client authentication request
    #[serde(rename = "auth")]
    Auth {
        token: String,
        tunnel_id: String,
    },

    /// Server authentication response (success)
    #[serde(rename = "auth_success")]
    AuthSuccess {
        tunnel_id: String,
        public_url: String,
    },

    /// Server authentication response (error)
    #[serde(rename = "auth_error")]
    AuthError {
        error: String,
        message: String,
    },

    // === HTTP STREAMING ===

    /// HTTP request start (server -> client)
    #[serde(rename = "http_request_start")]
    HttpRequestStart {
        id: String,
        method: String,
        path: String,
        headers: HashMap<String, String>,
        #[serde(with = "serde_bytes")]
        #[serde(skip_serializing_if = "Vec::is_empty")]
        initial_data: Vec<u8>, // Optional first chunk
    },

    /// HTTP response start (client -> server)  
    #[serde(rename = "http_response_start")]
    HttpResponseStart {
        id: String,
        status: u16,
        headers: HashMap<String, String>,
        #[serde(with = "serde_bytes")]
        #[serde(skip_serializing_if = "Vec::is_empty")]
        initial_data: Vec<u8>, // Optional first chunk
    },

    /// Data chunk (bidirectional)
    #[serde(rename = "data_chunk")]
    DataChunk {
        id: String,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>, // Binary data
        is_final: bool,
    },

    // === WEBSOCKET ===

    /// WebSocket upgrade request (server -> client)
    #[serde(rename = "websocket_upgrade")]
    WebSocketUpgrade {
        connection_id: String,
        method: String,
        path: String,
        headers: HashMap<String, String>,
    },

    /// WebSocket upgrade response (client -> server)
    #[serde(rename = "websocket_upgrade_response")]
    WebSocketUpgradeResponse {
        connection_id: String,
        status: u16,
        headers: HashMap<String, String>,
    },

    /// WebSocket data transfer (bidirectional)
    #[serde(rename = "websocket_data")]
    WebSocketData {
        connection_id: String,
        data: String, // Keep base64 for WebSocket compat
    },

    /// WebSocket connection close (bidirectional)
    #[serde(rename = "websocket_close")]
    WebSocketClose {
        connection_id: String,
        code: Option<u16>,
        reason: Option<String>,
    },

    // === ERROR ===

    /// Error message
    #[serde(rename = "error")]
    Error {
        message: String,
    },
}

impl Message {
    /// Serialize message to JSON string
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    /// Deserialize message from JSON string
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

/// Tunnel information
#[derive(Debug, Clone)]
pub struct TunnelInfo {
    pub tunnel_id: String,
    pub token: String,
    pub created_at: std::time::SystemTime,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_message_serialization() {
        let auth_msg = Message::Auth {
            token: "test-token".to_string(),
            tunnel_id: "my-tunnel".to_string(),
        };

        let json = auth_msg.to_json().unwrap();
        let parsed = Message::from_json(&json).unwrap();

        match parsed {
            Message::Auth { token, tunnel_id } => {
                assert_eq!(token, "test-token");
                assert_eq!(tunnel_id, "my-tunnel");
            }
            _ => panic!("Unexpected message type"),
        }
    }

    #[test]
    fn test_streaming_request_serialization() {
        let streaming_msg = Message::HttpRequestStart {
            id: "req-123".to_string(),
            method: "POST".to_string(),
            path: "/api/data".to_string(),
            headers: {
                let mut headers = HashMap::new();
                headers.insert("content-type".to_string(), "application/json".to_string());
                headers
            },
            initial_data: b"Hello".to_vec(),
        };

        let json = streaming_msg.to_json().unwrap();
        let parsed = Message::from_json(&json).unwrap();

        match parsed {
            Message::HttpRequestStart { id, method, path, headers, initial_data } => {
                assert_eq!(id, "req-123");
                assert_eq!(method, "POST");
                assert_eq!(path, "/api/data");
                assert_eq!(headers.get("content-type").unwrap(), "application/json");
                assert_eq!(initial_data, b"Hello".to_vec());
            }
            _ => panic!("Unexpected message type"),
        }
    }

    #[test]
    fn test_data_chunk_serialization() {
        let chunk_msg = Message::DataChunk {
            id: "req-123".to_string(),
            data: b"chunk data".to_vec(),
            is_final: false,
        };

        let json = chunk_msg.to_json().unwrap();
        let parsed = Message::from_json(&json).unwrap();

        match parsed {
            Message::DataChunk { id, data, is_final } => {
                assert_eq!(id, "req-123");
                assert_eq!(data, b"chunk data".to_vec());
                assert_eq!(is_final, false);
            }
            _ => panic!("Unexpected message type"),
        }
    }

    #[test]
    fn test_websocket_upgrade_serialization() {
        let upgrade_msg = Message::WebSocketUpgrade {
            connection_id: "ws-123".to_string(),
            method: "GET".to_string(),
            path: "/websocket".to_string(),
            headers: {
                let mut headers = HashMap::new();
                headers.insert("upgrade".to_string(), "websocket".to_string());
                headers.insert("connection".to_string(), "upgrade".to_string());
                headers
            },
        };

        let json = upgrade_msg.to_json().unwrap();
        let parsed = Message::from_json(&json).unwrap();

        match parsed {
            Message::WebSocketUpgrade { connection_id, method, path, headers } => {
                assert_eq!(connection_id, "ws-123");
                assert_eq!(method, "GET");
                assert_eq!(path, "/websocket");
                assert_eq!(headers.get("upgrade").unwrap(), "websocket");
            }
            _ => panic!("Unexpected message type"),
        }
    }
}