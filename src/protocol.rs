// src/protocol.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Messages sent between client and server via WebSocket binary frames
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Message {
    /// Client authentication request
    #[serde(rename = "auth")]
    Auth {
        token: String,
        tunnel_id: String,
        version: String,
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

    /// HTTP request start (server -> client)
    #[serde(rename = "http_request_start")]
    HttpRequestStart {
        id: String,
        method: String,
        path: String,
        headers: HashMap<String, String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        #[serde(default)]
        initial_data: Vec<u8>, // Binary data handled natively by bincode
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        is_complete: Option<bool>,
    },

    /// HTTP response start (client -> server)
    #[serde(rename = "http_response_start")]
    HttpResponseStart {
        id: String,
        status: u16,
        headers: HashMap<String, String>,
        #[serde(skip_serializing_if = "Vec::is_empty")]
        #[serde(default)]
        initial_data: Vec<u8>, // Binary data handled natively by bincode
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        is_complete: Option<bool>,
    },

    /// Data chunk (bidirectional)
    #[serde(rename = "data_chunk")]
    DataChunk {
        id: String,
        data: Vec<u8>, // Binary data handled natively by bincode
        is_final: bool,
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
        data: Vec<u8>, // Binary data handled natively by bincode
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
    /// Serialize message to bincode bytes
    pub fn to_bincode(&self) -> Result<Vec<u8>, bincode::Error> {
        bincode::serialize(self)
    }

    /// Deserialize message from bincode bytes
    pub fn from_bincode(bytes: &[u8]) -> Result<Self, bincode::Error> {
        bincode::deserialize(bytes)
    }

    /// Legacy JSON methods for temporary backward compatibility during migration
    /// TODO: Remove these after all clients and servers are upgraded
    #[deprecated(note = "Use to_bincode() instead - will be removed in next version")]
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string(self)
    }

    #[deprecated(note = "Use from_bincode() instead - will be removed in next version")]
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}