// src/protocol.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Messages sent between client and server via WebSocket
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Message {
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

    /// HTTP request forwarding (server -> client)
    #[serde(rename = "http_request")]
    HttpRequest {
        id: String,
        method: String,
        path: String,
        headers: HashMap<String, String>,
        body: String, // Base64 encoded for binary safety
    },

    /// HTTP response forwarding (client -> server)
    #[serde(rename = "http_response")]
    HttpResponse {
        id: String,
        status: u16,
        headers: HashMap<String, String>,
        body: String, // Base64 encoded for binary safety
    },

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
        data: String, // Base64 encoded binary data
    },

    /// WebSocket connection close (bidirectional)
    #[serde(rename = "websocket_close")]
    WebSocketClose {
        connection_id: String,
        code: Option<u16>,
        reason: Option<String>,
    },

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

    #[test]
    fn test_websocket_data_serialization() {
        let data_msg = Message::WebSocketData {
            connection_id: "ws-123".to_string(),
            data: "SGVsbG8gV29ybGQ=".to_string(), // "Hello World" in base64
        };

        let json = data_msg.to_json().unwrap();
        let parsed = Message::from_json(&json).unwrap();

        match parsed {
            Message::WebSocketData { connection_id, data } => {
                assert_eq!(connection_id, "ws-123");
                assert_eq!(data, "SGVsbG8gV29ybGQ=");
            }
            _ => panic!("Unexpected message type"),
        }
    }
}