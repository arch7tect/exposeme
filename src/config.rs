// src/config.rs - обновленная конфигурация

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
    pub routing_mode: RoutingMode, // Новое поле
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoutingMode {
    Path,      // /tunnel-id/path
    Subdomain, // tunnel-id.domain.com/path  
    Both,      // поддержка обоих
}

impl Default for RoutingMode {
    fn default() -> Self {
        RoutingMode::Path
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SslSettings {
    pub enabled: bool,
    pub provider: SslProvider,
    pub email: String,
    pub staging: bool,
    pub cert_cache_dir: String,
    pub wildcard: bool,                    // Add this field
    pub dns_provider: Option<DnsProviderConfig>, // Add this field
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProviderConfig {
    pub provider: String, // "digitalocean", "cloudflare", etc.
    pub config: serde_json::Value, // провайдер-специфичная конфигурация
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
                routing_mode: RoutingMode::Path,
            },
            ssl: SslSettings {
                enabled: false,
                provider: SslProvider::LetsEncrypt,
                email: "admin@example.com".to_string(),
                staging: true,
                cert_cache_dir: "/tmp/exposeme-certs".to_string(),
                wildcard: false,
                dns_provider: None,
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

/// Client configuration (без изменений)
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

// CLI аргументы остаются теми же...
#[derive(Parser, Debug)]
#[command(name = "exposeme-server")]
#[command(about = "ExposeME tunneling server")]
pub struct ServerArgs {
    #[arg(short, long, default_value = "server.toml")]
    pub config: PathBuf,
    #[arg(long)]
    pub http_bind: Option<String>,
    #[arg(long)]
    pub http_port: Option<u16>,
    #[arg(long)]
    pub https_port: Option<u16>,
    #[arg(long)]
    pub ws_bind: Option<String>,
    #[arg(long)]
    pub ws_port: Option<u16>,
    #[arg(long)]
    pub domain: Option<String>,
    #[arg(long)]
    pub enable_https: bool,
    #[arg(long)]
    pub disable_https: bool,
    #[arg(long)]
    pub email: Option<String>,
    #[arg(long)]
    pub staging: bool,
    #[arg(long)]
    pub generate_config: bool,
    #[arg(short, long)]
    pub verbose: bool,
    // Новые опции
    #[arg(long)]
    pub wildcard: bool,
    #[arg(long)]
    pub routing_mode: Option<String>,
}

#[derive(Parser, Debug)]
#[command(name = "exposeme-client")]
#[command(about = "ExposeME tunneling client")]
pub struct ClientArgs {
    #[arg(short, long, default_value = "client.toml")]
    pub config: PathBuf,
    #[arg(short, long)]
    pub server_url: Option<String>,
    #[arg(short, long)]
    pub token: Option<String>,
    #[arg(short = 'T', long)]
    pub tunnel_id: Option<String>,
    #[arg(short, long)]
    pub local_target: Option<String>,
    #[arg(long)]
    pub generate_config: bool,
    #[arg(short, long)]
    pub verbose: bool,
}

impl ServerConfig {
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
        if args.wildcard {
            config.ssl.wildcard = true;
        }
        if let Some(mode) = &args.routing_mode {
            config.server.routing_mode = match mode.as_str() {
                "path" => RoutingMode::Path,
                "subdomain" => RoutingMode::Subdomain,
                "both" => RoutingMode::Both,
                _ => return Err(format!("Invalid routing mode: {}", mode).into()),
            };
        }

        Ok(config)
    }

    pub fn generate_default_file(path: &PathBuf) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let config = Self::default();
        let content = toml::to_string_pretty(&config)?;
        fs::write(path, content)?;
        tracing::info!("Generated default server config: {:?}", path);
        Ok(())
    }

    pub fn http_addr(&self) -> String {
        format!("{}:{}", self.server.http_bind, self.server.http_port)
    }

    pub fn https_addr(&self) -> String {
        format!("{}:{}", self.server.http_bind, self.server.https_port)
    }

    pub fn ws_addr(&self) -> String {
        format!("{}:{}", self.server.ws_bind, self.server.ws_port)
    }

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

    /// Получить публичный URL для туннеля
    pub fn get_public_url(&self, tunnel_id: &str) -> String {
        match self.server.routing_mode {
            RoutingMode::Subdomain => {
                if self.ssl.enabled {
                    if self.server.https_port == 443 {
                        format!("https://{}.{}", tunnel_id, self.server.domain)
                    } else {
                        format!("https://{}.{}:{}", tunnel_id, self.server.domain, self.server.https_port)
                    }
                } else {
                    if self.server.http_port == 80 {
                        format!("http://{}.{}", tunnel_id, self.server.domain)
                    } else {
                        format!("http://{}.{}:{}", tunnel_id, self.server.domain, self.server.http_port)
                    }
                }
            },
            RoutingMode::Path => {
                format!("{}/{}", self.public_url_base(), tunnel_id)
            },
            RoutingMode::Both => {
                // Возвращаем поддомен как основной
                if self.ssl.enabled {
                    if self.server.https_port == 443 {
                        format!("https://{}.{}", tunnel_id, self.server.domain)
                    } else {
                        format!("https://{}.{}:{}", tunnel_id, self.server.domain, self.server.https_port)
                    }
                } else {
                    if self.server.http_port == 80 {
                        format!("http://{}.{}", tunnel_id, self.server.domain)
                    } else {
                        format!("http://{}.{}:{}", tunnel_id, self.server.domain, self.server.http_port)
                    }
                }
            }
        }
    }
}

impl ClientConfig {
    pub fn load(args: &ClientArgs) -> Result<Self, Box<dyn std::error::Error>> {
        let mut config = if args.config.exists() {
            let content = fs::read_to_string(&args.config)?;
            toml::from_str(&content)?
        } else {
            tracing::info!("Config file {:?} not found, using defaults", args.config);
            Self::default()
        };

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

    pub fn generate_default_file(path: &PathBuf) -> Result<(), Box<dyn std::error::Error>> {
        let config = Self::default();
        let content = toml::to_string_pretty(&config)?;
        fs::write(path, content)?;
        tracing::info!("Generated default client config: {:?}", path);
        Ok(())
    }
}