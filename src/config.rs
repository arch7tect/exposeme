// src/config.rs
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

/// Server configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerConfig {
    pub server: ServerSettings,
    pub ssl: SslSettings,
    pub auth: AuthSettings,
    pub limits: LimitSettings,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            server: ServerSettings::default(),
            ssl: SslSettings {
                enabled: false,
                provider: SslProvider::LetsEncrypt,
                email: "admin@example.com".to_string(),
                staging: true,
                cert_cache_dir: "/etc/exposeme/certs".to_string(),
                wildcard: false, // Set to true for subdomain support
                dns_provider: None, // Required for wildcard certificates
            },
            auth: AuthSettings {
                tokens: vec!["dev".to_string()],
            },
            limits: LimitSettings {
                max_tunnels: 50,
                request_timeout_secs: 120,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ServerSettings {
    pub http_bind: String,
    pub http_port: u16,
    pub https_port: u16,
    pub tunnel_path: String,
    pub domain: String,
    pub routing_mode: RoutingMode,
}

impl Default for ServerSettings {
    fn default() -> Self {
        Self {
            http_bind: "0.0.0.0".to_string(),
            http_port: 80,
            https_port: 443,
            tunnel_path: "/tunnel-ws".to_string(),  // ← This is what was missing!
            domain: "localhost".to_string(),
            routing_mode: RoutingMode::Path,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RoutingMode {
    Path,      // /tunnel-id/path
    Subdomain, // tunnel-id.domain.com/path
    Both,      
}

impl Default for RoutingMode {
    fn default() -> Self {
        RoutingMode::Path
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(default)]
pub struct SslSettings {
    pub enabled: bool,
    pub provider: SslProvider,
    pub email: String,
    pub staging: bool,
    pub cert_cache_dir: String,
    pub wildcard: bool,
    pub dns_provider: Option<DnsProviderConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsProviderConfig {
    pub provider: String, // "digitalocean", "azure", etc.
    pub config: serde_json::Value, 
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

/// Client configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClientConfig {
    pub client: ClientSettings,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ClientSettings {
    pub server_url: String,
    pub auth_token: String,
    pub tunnel_id: String,
    pub local_target: String,
    pub auto_reconnect: bool,
    pub reconnect_delay_secs: u64,
    pub websocket_cleanup_interval_secs: u64,
    pub websocket_connection_timeout_secs: u64,
    pub websocket_max_idle_secs: u64,
    pub websocket_monitoring_interval_secs: u64,
    pub insecure: bool,
}

impl Default for ClientSettings {
    fn default() -> Self {
        Self {
            server_url: "ws://localhost:8081".to_string(),
            auth_token: "dev".to_string(),
            tunnel_id: "test".to_string(),
            local_target: "http://localhost:3300".to_string(),
            auto_reconnect: true,
            reconnect_delay_secs: 5,
            websocket_cleanup_interval_secs: 60,
            websocket_connection_timeout_secs: 10,
            websocket_max_idle_secs: 600,
            websocket_monitoring_interval_secs: 30,
            insecure: false,
        }
    }
}

impl Default for ClientConfig {
    fn default() -> Self {
        Self {
            client: ClientSettings::default(),
        }
    }
}

#[derive(Parser, Debug)]
#[command(name = "exposeme-server")]
#[command(about = "ExposeME tunneling server - expose local services through WebSocket tunnels")]
#[command(long_about = "A secure HTTP tunneling server that forwards requests to connected clients via WebSocket connections. Supports automatic SSL certificates, multiple routing modes, and DNS providers.")]
pub struct ServerArgs {
    #[arg(short, long, default_value = "server.toml", help = "Path to TOML configuration file")]
    pub config: PathBuf,
    #[arg(long, help = "HTTP server bind address (overrides config)")]
    pub http_bind: Option<String>,
    #[arg(long, help = "HTTP port for redirects and ACME challenges (overrides config)")]
    pub http_port: Option<u16>,
    #[arg(long, help = "HTTPS port for secure connections (overrides config)")]
    pub https_port: Option<u16>,
    #[arg(long, help = "WebSocket upgrade path for tunnel connections (overrides config)")]
    pub tunnel_path: Option<String>,
    #[arg(long, help = "Server domain name for SSL certificates (overrides config)")]
    pub domain: Option<String>,
    #[arg(long, help = "Force enable HTTPS (overrides config)")]
    pub enable_https: bool,
    #[arg(long, help = "Force disable HTTPS, run HTTP only (overrides config)")]
    pub disable_https: bool,
    #[arg(long, help = "Contact email for Let's Encrypt certificates (overrides config)")]
    pub email: Option<String>,
    #[arg(long, help = "Use Let's Encrypt staging environment for testing (overrides config)")]
    pub staging: bool,
    #[arg(long, help = "Generate default configuration file and exit")]
    pub generate_config: bool,
    #[arg(short, long, help = "Enable verbose debug logging")]
    pub verbose: bool,
    #[arg(long, help = "Enable wildcard SSL certificates for subdomain routing (overrides config)")]
    pub wildcard: bool,
    #[arg(long, help = "Routing mode: 'path', 'subdomain', or 'both' (overrides config)")]
    pub routing_mode: Option<String>,
    #[arg(long, help = "HTTP request timeout in seconds (overrides config)")]
    pub request_timeout: Option<u64>,
}

#[derive(Parser, Debug)]
#[command(name = "exposeme-client")]
#[command(about = "ExposeME tunneling client - connect local services to ExposeME server")]
#[command(long_about = "A client that creates secure tunnels by connecting to an ExposeME server via WebSocket. Forwards HTTP and WebSocket requests from the server to your local services.")]
pub struct ClientArgs {
    #[arg(short, long, default_value = "client.toml", help = "Path to TOML configuration file")]
    pub config: PathBuf,
    #[arg(short, long, help = "WebSocket server URL (e.g. wss://example.com/tunnel-ws)")]
    pub server_url: Option<String>,
    #[arg(short, long, help = "Authentication token for server access")]
    pub token: Option<String>,
    #[arg(short = 'T', long, help = "Unique tunnel identifier (alphanumeric, hyphens allowed)")]
    pub tunnel_id: Option<String>,
    #[arg(short, long, help = "Local service URL to forward requests to (e.g. http://localhost:3000)")]
    pub local_target: Option<String>,
    #[arg(long, help = "Generate default configuration file and exit")]
    pub generate_config: bool,
    #[arg(short, long, help = "Enable verbose debug logging")]
    pub verbose: bool,
    #[arg(long, help = "Skip TLS certificate verification (INSECURE: development only)")]
    pub insecure: bool,
    #[arg(long, help = "Enable automatic reconnection on disconnect")]
    pub auto_reconnect: Option<bool>,
    #[arg(long, help = "Disable automatic reconnection on disconnect")]
    pub no_auto_reconnect: bool,
    #[arg(long, help = "Delay in seconds before reconnection attempts")]
    pub reconnect_delay_secs: Option<u64>,
    #[arg(long, help = "WebSocket cleanup check interval in seconds")]
    pub websocket_cleanup_interval: Option<u64>,
    #[arg(long, help = "WebSocket connection timeout in seconds")]
    pub websocket_connection_timeout: Option<u64>,
    #[arg(long, help = "WebSocket maximum idle time before cleanup in seconds")]
    pub websocket_max_idle: Option<u64>,
    #[arg(long, help = "WebSocket connection monitoring interval in seconds")]
    pub websocket_monitoring_interval: Option<u64>,
}

impl ServerConfig {
    pub fn validate_tunnel_id(&self, tunnel_id: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Basic validation for all modes
        if tunnel_id.is_empty() {
            return Err("Tunnel ID cannot be empty".into());
        }

        if tunnel_id.len() > 63 {
            return Err("Tunnel ID too long (max 63 characters)".into());
        }

        // Additional validation for subdomain routing
        match self.server.routing_mode {
            RoutingMode::Subdomain | RoutingMode::Both => {
                // RFC 1123 hostname validation
                if !tunnel_id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
                    return Err("Tunnel ID contains invalid characters for subdomain (only alphanumeric and hyphen allowed)".into());
                }

                if tunnel_id.starts_with('-') || tunnel_id.ends_with('-') {
                    return Err("Tunnel ID cannot start or end with hyphen".into());
                }

                // Reserved subdomains
                let reserved = ["www", "mail", "ftp", "localhost", "api", "admin", "root"];
                if reserved.contains(&tunnel_id) {
                    return Err("Tunnel ID is reserved".into());
                }
            }
            _ => {}
        }

        Ok(())
    }

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
        if let Some(tunnel_path) = &args.tunnel_path {
            config.server.tunnel_path = tunnel_path.clone();
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
        if let Some(timeout) = args.request_timeout {
            config.limits.request_timeout_secs = timeout;
        }

        // Environment variable overrides
        if let Ok(domain) = std::env::var("EXPOSEME_DOMAIN") {
            config.server.domain = domain;
            tracing::info!("Domain set from EXPOSEME_DOMAIN environment variable");
        }

        if let Ok(http_bind) = std::env::var("EXPOSEME_HTTP_BIND") {
            config.server.http_bind = http_bind;
        }

        if let Ok(http_port) = std::env::var("EXPOSEME_HTTP_PORT") {
            if let Ok(port) = http_port.parse::<u16>() {
                config.server.http_port = port;
            }
        }

        if let Ok(https_port) = std::env::var("EXPOSEME_HTTPS_PORT") {
            if let Ok(port) = https_port.parse::<u16>() {
                config.server.https_port = port;
            }
        }

        if let Ok(tunnel_path) = std::env::var("EXPOSEME_TUNNEL_PATH") {
            config.server.tunnel_path = tunnel_path;
        }

        // SSL settings
        if let Ok(email) = std::env::var("EXPOSEME_EMAIL") {
            config.ssl.email = email;
            tracing::info!("Email set from EXPOSEME_EMAIL environment variable");
        }

        if let Ok(staging) = std::env::var("EXPOSEME_STAGING") {
            config.ssl.staging = staging.parse().unwrap_or(false);
            tracing::info!("Staging set from EXPOSEME_STAGING environment variable");
        }

        if let Ok(wildcard) = std::env::var("EXPOSEME_WILDCARD") {
            config.ssl.wildcard = wildcard.parse().unwrap_or(false);
            tracing::info!("Wildcard certificates enabled from EXPOSEME_WILDCARD");
        }

        // Routing mode environment variable
        if let Ok(routing_mode) = std::env::var("EXPOSEME_ROUTING_MODE") {
            config.server.routing_mode = match routing_mode.as_str() {
                "path" => RoutingMode::Path,
                "subdomain" => RoutingMode::Subdomain,
                "both" => RoutingMode::Both,
                _ => {
                    tracing::warn!("Invalid EXPOSEME_ROUTING_MODE: {}, using default", routing_mode);
                    RoutingMode::Path
                }
            };
            tracing::info!("Routing mode set to {:?} from EXPOSEME_ROUTING_MODE", config.server.routing_mode);
        }

        // DNS Provider configuration - only set provider name from environment
        if let Ok(dns_provider) = std::env::var("EXPOSEME_DNS_PROVIDER") {
            config.ssl.dns_provider = Some(DnsProviderConfig {
                provider: dns_provider.clone(),
                config: serde_json::Value::Null, // Empty config - providers will use env vars
            });
            tracing::info!("DNS provider set to '{}' from EXPOSEME_DNS_PROVIDER", dns_provider);
            tracing::info!("DNS provider will be configured from its specific environment variables");
        }

        // Authentication tokens from environment
        if let Ok(token) = std::env::var("EXPOSEME_AUTH_TOKEN") {
            config.auth.tokens = vec![token];
            tracing::info!("Authentication token set from EXPOSEME_AUTH_TOKEN");
        }

        // Request timeout from environment
        if let Ok(timeout) = std::env::var("EXPOSEME_REQUEST_TIMEOUT") {
            if let Ok(secs) = timeout.parse::<u64>() {
                config.limits.request_timeout_secs = secs;
                tracing::info!("Request timeout set to {} seconds from EXPOSEME_REQUEST_TIMEOUT", secs);
            } else {
                tracing::warn!("Invalid EXPOSEME_REQUEST_TIMEOUT value: {}", timeout);
            }
        }

        // Automatic configuration for subdomain routing
        if matches!(config.server.routing_mode, RoutingMode::Subdomain | RoutingMode::Both) {
            if config.ssl.enabled && !config.ssl.wildcard {
                tracing::warn!("Subdomain routing with SSL requires wildcard certificates");
                tracing::warn!("Setting wildcard = true automatically");
                config.ssl.wildcard = true;
            }

            if config.ssl.wildcard && config.ssl.dns_provider.is_none() {
                return Err("Wildcard certificates require DNS provider configuration".into());
            }
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

    pub fn tunnel_url(&self) -> String {
        format!("{}{}", self.public_url_base(), self.server.tunnel_path)
    }

    pub fn tunnel_ws_url(&self) -> String {
        let base = if self.ssl.enabled {
            format!("wss://{}", self.server.domain)
        } else {
            format!("ws://{}", self.server.domain)
        };
        format!("{}{}", base, self.server.tunnel_path)
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
        // Check if all required params are provided via CLI to skip config file requirement
        let can_skip_config = args.server_url.is_some() && 
                              args.token.is_some() && 
                              args.tunnel_id.is_some() && 
                              args.local_target.is_some();

        let mut config = if args.config.exists() {
            let content = fs::read_to_string(&args.config)?;
            toml::from_str(&content)?
        } else if can_skip_config {
            tracing::info!("All required parameters provided via CLI, skipping config file");
            Self::default()
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
        if args.insecure {
            config.client.insecure = true;
        }
        if let Some(auto_reconnect) = args.auto_reconnect {
            config.client.auto_reconnect = auto_reconnect;
        }
        if args.no_auto_reconnect {
            config.client.auto_reconnect = false;
        }
        if let Some(delay) = args.reconnect_delay_secs {
            config.client.reconnect_delay_secs = delay;
        }
        if let Some(interval) = args.websocket_cleanup_interval {
            config.client.websocket_cleanup_interval_secs = interval;
        }
        if let Some(timeout) = args.websocket_connection_timeout {
            config.client.websocket_connection_timeout_secs = timeout;
        }
        if let Some(max_idle) = args.websocket_max_idle {
            config.client.websocket_max_idle_secs = max_idle;
        }
        if let Some(monitoring) = args.websocket_monitoring_interval {
            config.client.websocket_monitoring_interval_secs = monitoring;
        }

        // Validate that all required fields are set
        if config.client.server_url.is_empty() {
            return Err("server_url is required (use --server-url or set in config file)".into());
        }
        if config.client.auth_token.is_empty() {
            return Err("auth_token is required (use --token or set in config file)".into());
        }
        if config.client.tunnel_id.is_empty() {
            return Err("tunnel_id is required (use --tunnel-id or set in config file)".into());
        }
        if config.client.local_target.is_empty() {
            return Err("local_target is required (use --local-target or set in config file)".into());
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