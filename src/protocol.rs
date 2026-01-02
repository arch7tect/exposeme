use bitcode::{Decode, Encode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Messages sent between client and server via WebSocket binary frames
#[derive(Debug, Clone, Serialize, Deserialize, Encode, Decode, PartialEq)]
pub enum Message {
    /// Client authentication request
    Auth {
        token: String,
        tunnel_id: String,
        version: String,
    },

    /// Server authentication response (success)
    AuthSuccess {
        tunnel_id: String,
        public_url: String,
    },

    /// Server authentication response (error)
    AuthError {
        error: String,
        message: String,
    },

    /// HTTP request start (server -> client)
    HttpRequestStart {
        id: String,
        method: String,
        path: String,
        headers: HashMap<String, String>,
        initial_data: Vec<u8>,
        is_complete: bool,
    },

    /// HTTP response start (client -> server)
    HttpResponseStart {
        id: String,
        status: u16,
        headers: HashMap<String, String>,
        initial_data: Vec<u8>,
        is_complete: bool,
    },

    /// Data chunk (bidirectional)
    DataChunk {
        id: String,
        data: Vec<u8>,
        is_final: bool,
    },

    /// WebSocket upgrade request (server -> client)
    WebSocketUpgrade {
        connection_id: String,
        method: String,
        path: String,
        headers: HashMap<String, String>,
    },

    /// WebSocket upgrade response (client -> server)
    WebSocketUpgradeResponse {
        connection_id: String,
        status: u16,
        headers: HashMap<String, String>,
    },

    /// WebSocket data transfer (bidirectional)
    WebSocketData {
        connection_id: String,
        data: Vec<u8>,
    },

    /// WebSocket connection close (bidirectional)
    WebSocketClose {
        connection_id: String,
        code: Option<u16>,
        reason: Option<String>,
    },


    /// Error message
    Error {
        message: String,
    },
}

impl Message {
    /// Serialize message to bytes for WebSocket binary frames.
    pub fn to_bytes(&self) -> Vec<u8> {
        bitcode::encode(self)
    }

    /// Deserialize message from bytes from WebSocket binary frames.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bitcode::Error> {
        bitcode::decode(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::Message;
    use std::collections::HashMap;

    fn round_trip(message: Message) {
        let bytes = message.to_bytes();
        let decoded = Message::from_bytes(&bytes).expect("decode");
        assert_eq!(decoded, message);
    }

    #[test]
    fn message_round_trips() {
        let mut headers = HashMap::new();
        headers.insert("x-test".to_string(), "1".to_string());

        round_trip(Message::Auth {
            token: "token".to_string(),
            tunnel_id: "tunnel".to_string(),
            version: "1.5.0".to_string(),
        });
        round_trip(Message::AuthSuccess {
            tunnel_id: "tunnel".to_string(),
            public_url: "https://example.com".to_string(),
        });
        round_trip(Message::AuthError {
            error: "invalid_token".to_string(),
            message: "Invalid authentication token".to_string(),
        });
        round_trip(Message::HttpRequestStart {
            id: "req-1".to_string(),
            method: "GET".to_string(),
            path: "/".to_string(),
            headers: headers.clone(),
            initial_data: vec![],
            is_complete: true,
        });
        round_trip(Message::HttpResponseStart {
            id: "req-1".to_string(),
            status: 200,
            headers: headers.clone(),
            initial_data: b"ok".to_vec(),
            is_complete: true,
        });
        round_trip(Message::DataChunk {
            id: "req-1".to_string(),
            data: vec![0, 1, 2, 3, 4],
            is_final: false,
        });
        round_trip(Message::WebSocketUpgrade {
            connection_id: "conn-1".to_string(),
            method: "GET".to_string(),
            path: "/ws".to_string(),
            headers: headers.clone(),
        });
        round_trip(Message::WebSocketUpgradeResponse {
            connection_id: "conn-1".to_string(),
            status: 101,
            headers: headers.clone(),
        });
        round_trip(Message::WebSocketData {
            connection_id: "conn-1".to_string(),
            data: vec![9, 8, 7, 6],
        });
        round_trip(Message::WebSocketClose {
            connection_id: "conn-1".to_string(),
            code: Some(1000),
            reason: Some("bye".to_string()),
        });
        round_trip(Message::Error {
            message: "oops".to_string(),
        });
    }
}
