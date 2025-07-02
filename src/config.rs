// src/config.rs
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub server: ServerSettings,
    pub ssl: SslSettings,
    pub auth: AuthSettings,
    pub limits: LimitSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerSettings {
    pub http_bind: String,
    pub http_port: u16,
    pub https_port: u16,
    pub ws_bind: String,
    pub ws_port: u16,
    pub domain: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslSettings {
    pub enabled: bool,
    pub provider: SslProvider,
    pub email: String,
    pub staging: bool,
    pub cert_cache_dir: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum SslProvider {
    LetsEncrypt,
    Manual,
    SelfSigned,
}

impl Default for SslProvider {
    fn default() -> Self {
        SslProvider::LetsEncrypt
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthSettings {
    pub tokens: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LimitSettings {
    pub max_tunnels: usize,
    pub request_timeout_secs: u64,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            server: ServerSettings {
                http_bind: "0.0.0.0".to_string(),
                http_port: 80,
                https_port: 443,
                ws_bind: "0.0.0.0".to_string(),
                ws_port: 8081,
                domain: "localhost".to_string(),
            },
            ssl: SslSettings {
                enabled: false,
                provider: SslProvider::LetsEncrypt,
                email: "admin@example.com".to_string(),
                staging: true,
                cert_cache_dir: "/tmp/exposeme-certs".to_string(),
            },
            auth: AuthSettings {
                tokens: vec!["dev".to_string()],
            },
            limits: LimitSettings {
                max_tunnels: 50,
                request_timeout_secs: 30,
            },
        }
    }
}

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub client: ClientSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientSettings {
    pub server_url: String,
    pub auth_token: String,
    pub tunnel_id: String,
    pub local_target: String,
    pub auto_reconnect: bool,
    pub reconnect_delay_secs: u64,
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            client: ClientSettings {
                server_url: "ws://localhost:8081".to_string(),
                auth_token: "dev".to_string(),
                tunnel_id: "test".to_string(),
                local_target: "http://localhost:3300".to_string(),
                auto_reconnect: true,
                reconnect_delay_secs: 5,
            },
        }
    }
}

/// Server CLI Arguments
#[derive(Parser, Debug)]
#[command(name = "exposeme-server")]
#[command(about = "ExposeME tunneling server")]
pub struct ServerArgs {
    /// Configuration file path
    #[arg(short, long, default_value = "server.toml")]
    pub config: PathBuf,

    /// HTTP bind address
    #[arg(long)]
    pub http_bind: Option<String>,

    /// HTTP port
    #[arg(long)]
    pub http_port: Option<u16>,

    /// HTTPS port
    #[arg(long)]
    pub https_port: Option<u16>,

    /// WebSocket bind address  
    #[arg(long)]
    pub ws_bind: Option<String>,

    /// WebSocket port
    #[arg(long)]
    pub ws_port: Option<u16>,

    /// Domain name for certificates
    #[arg(long)]
    pub domain: Option<String>,

    /// Enable HTTPS with Let's Encrypt
    #[arg(long)]
    pub enable_https: bool,

    /// Disable HTTPS (HTTP only mode)
    #[arg(long)]
    pub disable_https: bool,

    /// Let's Encrypt email
    #[arg(long)]
    pub email: Option<String>,

    /// Use Let's Encrypt staging environment
    #[arg(long)]
    pub staging: bool,

    /// Generate default config file and exit
    #[arg(long)]
    pub generate_config: bool,

    /// Verbose logging
    #[arg(short, long)]
    pub verbose: bool,
}

/// Client CLI Arguments
#[derive(Parser, Debug)]
#[command(name = "exposeme-client")]
#[command(about = "ExposeME tunneling client")]
pub struct ClientArgs {
    /// Configuration file path
    #[arg(short, long, default_value = "client.toml")]
    pub config: PathBuf,

    /// Server WebSocket URL
    #[arg(short, long)]
    pub server_url: Option<String>,

    /// Authentication token
    #[arg(short, long)]
    pub token: Option<String>,

    /// Tunnel ID
    #[arg(short = 'T', long)]
    pub tunnel_id: Option<String>,

    /// Local target URL
    #[arg(short, long)]
    pub local_target: Option<String>,

    /// Generate default config file and exit
    #[arg(long)]
    pub generate_config: bool,

    /// Verbose logging
    #[arg(short, long)]
    pub verbose: bool,
}

impl ServerConfig {
    /// Load configuration from file and CLI args
    pub fn load(args: &ServerArgs) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let mut config = if args.config.exists() {
            let content = fs::read_to_string(&args.config)?;
            toml::from_str(&content)?
        } else {
            tracing::info!("Config file {:?} not found, using defaults", args.config);
            Self::default()
        };

        // Override with CLI arguments
        if let Some(bind) = &args.http_bind {
            config.server.http_bind = bind.clone();
        }
        if let Some(port) = args.http_port {
            config.server.http_port = port;
        }
        if let Some(port) = args.https_port {
            config.server.https_port = port;
        }
        if let Some(bind) = &args.ws_bind {
            config.server.ws_bind = bind.clone();
        }
        if let Some(port) = args.ws_port {
            config.server.ws_port = port;
        }
        if let Some(domain) = &args.domain {
            config.server.domain = domain.clone();
        }
        if let Some(email) = &args.email {
            config.ssl.email = email.clone();
        }
        if args.enable_https {
            config.ssl.enabled = true;
        }
        if args.disable_https {
            config.ssl.enabled = false;
        }
        if args.staging {
            config.ssl.staging = true;
        }

        Ok(config)
    }

    /// Generate default config file
    pub fn generate_default_file(path: &PathBuf) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config = Self::default();
        let content = toml::to_string_pretty(&config)?;
        fs::write(path, content)?;
        println!("Generated default server config: {:?}", path);
        Ok(())
    }

    /// Get HTTP server address
    pub fn http_addr(&self) -> String {
        format!("{}:{}", self.server.http_bind, self.server.http_port)
    }

    /// Get HTTPS server address
    pub fn https_addr(&self) -> String {
        format!("{}:{}", self.server.http_bind, self.server.https_port)
    }

    /// Get WebSocket server address  
    pub fn ws_addr(&self) -> String {
        format!("{}:{}", self.server.ws_bind, self.server.ws_port)
    }

    /// Get public URL base
    pub fn public_url_base(&self) -> String {
        if self.ssl.enabled {
            if self.server.https_port == 443 {
                format!("https://{}", self.server.domain)
            } else {
                format!("https://{}:{}", self.server.domain, self.server.https_port)
            }
        } else {
            if self.server.http_port == 80 {
                format!("http://{}", self.server.domain)
            } else {
                format!("http://{}:{}", self.server.domain, self.server.http_port)
            }
        }
    }
}

impl ClientConfig {
    /// Load configuration from file and CLI args
    pub fn load(args: &ClientArgs) -> Result<Self, Box<dyn std::error::Error>> {
        let mut config = if args.config.exists() {
            let content = fs::read_to_string(&args.config)?;
            toml::from_str(&content)?
        } else {
            tracing::info!("Config file {:?} not found, using defaults", args.config);
            Self::default()
        };

        // Override with CLI arguments
        if let Some(url) = &args.server_url {
            config.client.server_url = url.clone();
        }
        if let Some(token) = &args.token {
            config.client.auth_token = token.clone();
        }
        if let Some(tunnel_id) = &args.tunnel_id {
            config.client.tunnel_id = tunnel_id.clone();
        }
        if let Some(target) = &args.local_target {
            config.client.local_target = target.clone();
        }

        Ok(config)
    }

    /// Generate default config file
    pub fn generate_default_file(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let config = Self::default();
        let content = toml::to_string_pretty(&config)?;
        fs::write(path, content)?;
        println!("Generated default client config: {:?}", path);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_server_config_default() {
        let config = ServerConfig::default();
        assert_eq!(config.server.http_port, 8888);
        assert_eq!(config.server.ws_port, 8081);
        assert_eq!(config.auth.tokens.len(), 1);
        assert_eq!(config.auth.tokens[0], "dev");
    }

    #[test]
    fn test_client_config_default() {
        let config = ClientConfig::default();
        assert_eq!(config.client.tunnel_id, "test");
        assert_eq!(config.client.auth_token, "dev");
        assert!(config.client.auto_reconnect);
    }
}