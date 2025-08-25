// src/protocol.rs
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Messages sent between client and server via WebSocket binary frames
#[derive(Debug, Clone, Serialize, Deserialize)]
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
        data: Vec<u8>, // Binary data handled natively by bincode
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
    /// Serialize message to bincode bytes for WebSocket Binary frames
    pub fn to_bincode(&self) -> Result<Vec<u8>, bincode::error::EncodeError> {
        bincode::serde::encode_to_vec(self, bincode::config::standard())
    }

    /// Deserialize message from bincode bytes from WebSocket Binary frames
    pub fn from_bincode(bytes: &[u8]) -> Result<Self, bincode::error::DecodeError> {
        bincode::serde::decode_from_slice(bytes, bincode::config::standard()).map(|(msg, _)| msg)
    }
}