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
        #[serde(with = "serde_bytes")]
        #[serde(skip_serializing_if = "Vec::is_empty")]
        #[serde(default)]
        initial_data: Vec<u8>, // Optional first chunk
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
        #[serde(with = "serde_bytes")]
        #[serde(skip_serializing_if = "Vec::is_empty")]
        #[serde(default)]
        initial_data: Vec<u8>, // Optional first chunk
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(default)]
        is_complete: Option<bool>,
    },

    /// Data chunk (bidirectional)
    #[serde(rename = "data_chunk")]
    DataChunk {
        id: String,
        #[serde(with = "serde_bytes")]
        data: Vec<u8>, // Binary data
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
        #[serde(with = "serde_bytes")]
        data: Vec<u8>,
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