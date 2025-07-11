# ExposeME

A fast, secure HTTP tunneling solution written in Rust that exposes local services to the internet through WebSocket connections.

## Introduction

ExposeME is a simple tool that lets you share your local development server with the outside world. Whether you're building a web app on your laptop or testing a local API, ExposeME creates a secure tunnel so others can access your work from anywhere on the internet.

**What does it do?**
- Turn `http://localhost:3000` into `https://myapp.yourdomain.com`
- Share your local development work with clients, teammates, or testing tools
- Receive webhooks from external services directly to your development machine
- Test real-time features like WebSocket connections through a secure tunnel

**How does it work?**
You run ExposeME on a server (like a VPS) with your own domain name. Then you run a small client program on your development machine that connects to your server. When someone visits your public URL, the request gets forwarded through the secure tunnel to your local application.

**Why use your own server?**
- **Full control**: Your own domain, your own SSL certificates, no rate limits
- **Privacy**: Your traffic doesn't go through third-party services
- **Reliability**: No dependency on external tunnel services
- **Cost-effective**: Use any cheap VPS instead of paid tunnel subscriptions
- **Professional**: Use your own domain for demos and client previews

**Perfect for:**
- Sharing development work with clients and teammates
- Testing webhooks from payment processors, GitHub, etc.
- Demonstrating mobile app backends
- Remote development and testing
- Getting SSL certificates for local development

## Architecture

ExposeME creates secure HTTP tunnels to expose local services:

- **Single HTTP/HTTPS Server**: One server handles both regular HTTP/HTTPS requests and WebSocket upgrades on the same ports (80/443)
- **Tunnel Setup**: Client connects to server via WebSocket upgrade on `/tunnel-ws` to establish a persistent tunnel
- **Request Forwarding**: When users visit your public URL, the server forwards their HTTP requests through the existing WebSocket tunnel to your local service
- **Flow**: Internet User → Server (HTTP) → WebSocket Tunnel → Client → Local Service → Response back

### Connection Types
- **HTTP mode**: Client connects to `ws://your-domain.com/tunnel-ws`
- **HTTPS mode**: Client connects to `wss://your-domain.com/tunnel-ws`
- **Custom path**: Configurable via `tunnel_path` setting

## Authentication & Security

ExposeME uses **token-based authentication** to control access. Configure your server with one or more tokens, and clients must provide a valid token to create tunnels.

**Security features:**
- **Token authentication**: Only clients with valid tokens can create tunnels
- **Tunnel isolation**: Each tunnel has a unique ID and operates independently
- **Transport encryption**: All tunnel communication is encrypted when SSL is enabled
- **Private URLs**: Tunnel URLs are only known to those who create them

```bash
# Generate a secure token
openssl rand -base64 32
# Use this as your EXPOSEME_AUTH_TOKEN
```

## Routing Modes

ExposeME supports three routing modes:

### 1. Path-based Routing (default)
```
https://your-domain.com/tunnel-id/path
```
*Uses single-domain certificates with HTTP challenges (no DNS provider needed)*

### 2. Subdomain Routing
```
https://tunnel-id.your-domain.com/path
```
*Requires wildcard certificates with DNS challenges (DNS provider required)*

### 3. Both (recommended)
Supports both routing methods simultaneously
*Requires wildcard certificates with DNS challenges (DNS provider required)*

## Certificate Management

To use HTTPS (the secure "lock" icon in browsers), your server needs an SSL certificate. ExposeME gives you three ways to get one:

### 1. Automatic Let's Encrypt (recommended)
Let's Encrypt provides free SSL certificates that ExposeME can get and renew automatically. Perfect for most users.

- **Simple setup**: Works with just your domain name and email
- **Completely free**: No cost, ever
- **Auto-renewal**: New certificates every 90 days, handled automatically
- **Two modes**: Regular certificates (easy) or wildcard certificates (requires DNS setup)

### 2. Bring Your Own Certificate
Already have an SSL certificate from another provider? Just drop the files in the right folder and ExposeME will use them.

- **Full control**: Use certificates from any provider (Cloudflare, Namecheap, etc.)
- **Your responsibility**: You handle renewals and configuration
- **Any provider**: Works with commercial SSL providers

**File naming:** Place your certificate files in the cache directory with these exact names:
- **Regular certificate**: `your-domain-com.pem` and `your-domain-com.key`
- **Wildcard certificate**: `wildcard-your-domain-com.pem` and `wildcard-your-domain-com.key`
- **Example**: For `example.com` → `example-com.pem` and `example-com.key`

**Cache directory:** By default `/etc/exposeme/certs`, but configurable via `cert_cache_dir` setting.

### 3. Self-Signed Certificate (development only)
ExposeME can create its own certificate for local development. Browsers will show warnings, but it works for testing.

- **Development only**: Don't use this for real websites
- **No setup required**: Works immediately, no domain or DNS needed
- **Browser warnings**: Visitors will see "not secure" warnings

## Quick Start

### Server Setup with Docker Compose

1. **Create environment file:**

```bash
# .env
DIGITALOCEAN_TOKEN=your_digitalocean_api_token
# OR for Azure
AZURE_SUBSCRIPTION_ID=your_azure_subscription_id
AZURE_RESOURCE_GROUP=your_resource_group
AZURE_CLIENT_ID=your_client_id
AZURE_CLIENT_SECRET=your_client_secret
AZURE_TENANT_ID=your_tenant_id
# OR for Hetzner
HETZNER_TOKEN=your_hetzner_api_token

EXPOSEME_AUTH_TOKEN=your_secure_auth_token
```

2. **Create Docker Compose configuration:**

```yaml
# docker-compose.yml
services:
  exposeme-server:
    image: arch7tect/exposeme-server:latest
    container_name: exposeme-server
    restart: unless-stopped

    ports:
      - "80:80"       # HTTP (ACME challenges + redirects + WebSocket upgrades)
      - "443:443"     # HTTPS (secure requests + WebSocket upgrades)

    volumes:
      - ./config/server.toml:/etc/exposeme/server.toml:ro
      - ./exposeme-certs:/etc/exposeme/certs:rw

    environment:
      # Domain configuration
      - EXPOSEME_DOMAIN=your-domain.com
      - EXPOSEME_EMAIL=admin@your-domain.com
      
      # SSL configuration
      - EXPOSEME_STAGING=false
      - EXPOSEME_WILDCARD=true
      - EXPOSEME_ROUTING_MODE=both
      
      # DNS Provider - Required ONLY for wildcard certificates (subdomain routing):
      # For DigitalOcean:
      - EXPOSEME_DNS_PROVIDER=digitalocean
      - EXPOSEME_DIGITALOCEAN_TOKEN=${DIGITALOCEAN_TOKEN}
      
      # For Azure:
      # - EXPOSEME_DNS_PROVIDER=azure
      # - EXPOSEME_AZURE_SUBSCRIPTION_ID=${AZURE_SUBSCRIPTION_ID}
      # - EXPOSEME_AZURE_RESOURCE_GROUP=${AZURE_RESOURCE_GROUP}
      # - EXPOSEME_AZURE_CLIENT_ID=${AZURE_CLIENT_ID}
      # - EXPOSEME_AZURE_CLIENT_SECRET=${AZURE_CLIENT_SECRET}
      # - EXPOSEME_AZURE_TENANT_ID=${AZURE_TENANT_ID}

      # For Hetzner:
      # - EXPOSEME_DNS_PROVIDER=hetzner
      # - EXPOSEME_HETZNER_TOKEN=${HETZNER_TOKEN}
      
      # Authentication
      - EXPOSEME_AUTH_TOKEN=${EXPOSEME_AUTH_TOKEN}
      
      # Logging
      - RUST_LOG=info

    env_file:
      - .env

    security_opt:
      - no-new-privileges:true

    deploy:
      resources:
        limits:
          memory: 1G
          cpus: '1.0'

    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:80/api/health"]
      interval: 30s
      timeout: 10s
      retries: 5
      start_period: 120s
```

3. **Create server configuration:**

```toml
# config/server.toml
[server]
http_bind = "0.0.0.0"
http_port = 80
https_port = 443
tunnel_path = "/tunnel-ws"  # WebSocket upgrade path (configurable)
domain = "your-domain.com"
routing_mode = "both"  # "path", "subdomain", or "both"

[ssl]
enabled = true
provider = "letsencrypt"
email = "admin@your-domain.com"
staging = false
cert_cache_dir = "/etc/exposeme/certs"
wildcard = true  # Required for subdomain routing

# DNS provider required ONLY for wildcard certificates:
[ssl.dns_provider]
provider = "digitalocean"  # or "azure" or "hetzner"

# DigitalOcean specific config (can be overridden by env vars):
[ssl.dns_provider.config]
api_token = "your-do-token-will-be-set-via-env"
timeout_seconds = 30

# Azure specific config (uncomment if using Azure):
# [ssl.dns_provider.config]
# subscription_id = "your-subscription-id"
# resource_group = "your-resource-group"
# client_id = "your-client-id"
# client_secret = "your-client-secret"
# tenant_id = "your-tenant-id"
# timeout_seconds = 30

# Hetzner specific config (uncomment if using Hetzner):
# [ssl.dns_provider.config]
# api_token = "your-hetzner-token-will-be-set-via-env"
# timeout_seconds = 30

[auth]
tokens = ["dev"]  # Will be overridden by environment

[limits]
max_tunnels = 100
request_timeout_secs = 30
```

4. **Start the server:**

```bash
docker-compose up -d
```

### Client Setup

1. **Create client configuration:**

```toml
# client.toml
[client]
server_url = "wss://your-domain.com/tunnel-ws"  # Uses WebSocket upgrade on HTTPS
auth_token = "your_secure_auth_token"
tunnel_id = "my-app"
local_target = "http://host.docker.internal:3000"
auto_reconnect = true
reconnect_delay_secs = 5
insecure = false  # Set to true for self-signed certificates (development only)
```

2. **Run the client:**

```bash
docker run -it --rm \
  -v ./client.toml:/etc/exposeme/client.toml \
  arch7tect/exposeme-client:latest
```

3. **Access your service:**
   - Subdomain: `https://my-app.your-domain.com/`
   - Path-based: `https://your-domain.com/my-app/`

## DNS Provider Setup

**DNS providers are only required for automatic Let's Encrypt wildcard certificates** (subdomain routing). For path-based routing with single-domain certificates, ExposeME uses HTTP-01 challenges and no DNS provider configuration is needed. Wildcard certificates require DNS-01 challenges which need a DNS provider.

If you're using manual certificates or self-signed certificates, DNS providers are not needed regardless of routing mode.

### DigitalOcean

**Required for wildcard certificates only**

1. **Create API token** at https://cloud.digitalocean.com/account/api/tokens
2. **Add your domain** to DigitalOcean Domains
3. **Set environment variables:**
   ```bash
   EXPOSEME_DNS_PROVIDER=digitalocean
   EXPOSEME_DIGITALOCEAN_TOKEN=your_do_token
   ```

### Hetzner DNS

**Required for wildcard certificates only**

1. **Create API token** at https://dns.hetzner.com/ (Console → API tokens)
2. **Add your domain** to Hetzner DNS
3. **Set environment variables:**
   ```bash
   EXPOSEME_DNS_PROVIDER=hetzner
   EXPOSEME_HETZNER_TOKEN=your_hetzner_token
   ```

### Azure DNS

**Required for wildcard certificates only**

1. **Create a Service Principal** with DNS Zone Contributor role:
   ```bash
   # Create service principal
   az ad sp create-for-rbac --name "exposeme-dns" \
     --role "DNS Zone Contributor" \
     --scopes "/subscriptions/YOUR_SUBSCRIPTION_ID/resourceGroups/YOUR_RG"
   ```

2. **Add your domain** to Azure DNS (create DNS zone)
3. **Set environment variables:**
   ```bash
   EXPOSEME_DNS_PROVIDER=azure
   EXPOSEME_AZURE_SUBSCRIPTION_ID=your_subscription_id
   EXPOSEME_AZURE_RESOURCE_GROUP=your_resource_group_with_dns_zone
   EXPOSEME_AZURE_CLIENT_ID=your_service_principal_client_id
   EXPOSEME_AZURE_CLIENT_SECRET=your_service_principal_secret
   EXPOSEME_AZURE_TENANT_ID=your_azure_tenant_id
   ```

## Configuration Reference

### Configuration Priority (highest to lowest)

ExposeME uses a **layered configuration system** where higher priority sources override lower ones:

1. **Command Line Arguments** (highest priority)
2. **Environment Variables**
3. **TOML Configuration File** (lowest priority)

### Typical Usage Patterns

**Development:**
```bash
# Override specific settings for testing
./exposeme-server --config dev.toml --staging --domain dev.example.com
```

**Production (Docker):**
```bash
# Base config in TOML, secrets via environment
EXPOSEME_DOMAIN=example.com
EXPOSEME_DIGITALOCEAN_TOKEN=secret_token
EXPOSEME_AUTH_TOKEN=secret_auth
```

**Local Testing:**
```bash
# Quick overrides without changing files
./exposeme-server --disable-https --domain localhost
```

### Available Command Line Arguments

#### Server Arguments
```bash
./exposeme-server [OPTIONS]

OPTIONS:
    -c, --config <FILE>           Configuration file path [default: server.toml]
        --http-bind <IP>          HTTP bind address
        --http-port <PORT>        HTTP port
        --https-port <PORT>       HTTPS port  
        --tunnel-path <PATH>      WebSocket upgrade path [default: /tunnel-ws]
        --domain <DOMAIN>         Server domain name
        --enable-https            Enable HTTPS
        --disable-https           Disable HTTPS
        --email <EMAIL>           Contact email for Let's Encrypt
        --staging                 Use Let's Encrypt staging environment
        --wildcard                Enable wildcard certificates
        --routing-mode <MODE>     Routing mode: path, subdomain, or both
        --request-timeout <SECS>  HTTP request timeout in seconds
        --generate-config         Generate default configuration file
    -v, --verbose                 Enable verbose logging
    -h, --help                    Print help information
```

#### Client Arguments
```bash
./exposeme-client [OPTIONS]

OPTIONS:
    -c, --config <FILE>           Configuration file path [default: client.toml]
    -s, --server-url <URL>        WebSocket server URL (upgrade endpoint)
    -t, --token <TOKEN>           Authentication token
    -T, --tunnel-id <ID>          Tunnel identifier
    -l, --local-target <URL>      Local service URL to forward to
        --insecure                Skip TLS certificate verification (for self-signed certificates)
        --generate-config         Generate default configuration file
    -v, --verbose                 Enable verbose logging
    -h, --help                    Print help information
        
    # WebSocket Configuration
        --websocket-cleanup-interval <SECS>    Cleanup check interval
        --websocket-connection-timeout <SECS>  Connection timeout
        --websocket-max-idle <SECS>            Maximum idle time
        --websocket-monitoring-interval <SECS> Monitoring interval
```

### Server Configuration

| Section | Option | Description | Default |
|---------|--------|-------------|---------|
| `[server]` | `domain` | Your domain name | `localhost` |
| `[server]` | `routing_mode` | `path`, `subdomain`, or `both` | `path` |
| `[server]` | `http_port` | HTTP port | `80` |
| `[server]` | `https_port` | HTTPS port | `443` |
| `[server]` | `tunnel_path` | WebSocket upgrade path | `/tunnel-ws` |
| `[ssl]` | `enabled` | Enable HTTPS | `false` |
| `[ssl]` | `wildcard` | Use wildcard certificates (required for subdomain routing) | `false` |
| `[ssl]` | `provider` | Certificate source: `letsencrypt` (automatic), `manual` (your own), `selfsigned` (development) | `letsencrypt` |
| `[ssl]` | `staging` | Use Let's Encrypt staging | `true` |
| `[ssl]` | `cert_cache_dir` | Directory for storing certificates | `/etc/exposeme/certs` |
| `[ssl.dns_provider]` | `provider` | DNS provider name (`digitalocean`, `azure`, `hetzner`) | - |
| `[auth]` | `tokens` | Authentication tokens | `["dev"]` |
| `[limits]` | `max_tunnels` | Maximum concurrent tunnels | `50` |
| `[limits]` | `request_timeout_secs` | HTTP request timeout in seconds | `30` |

### Client Configuration

| Section | Option | Description | Default |
|---------|--------|-------------|---------|
| `[client]` | `server_url` | WebSocket server URL (upgrade endpoint) | `ws://localhost/tunnel-ws` |
| `[client]` | `auth_token` | Authentication token | `dev` |
| `[client]` | `tunnel_id` | Unique tunnel identifier | `test` |
| `[client]` | `local_target` | Local service URL | `http://localhost:3300` |
| `[client]` | `auto_reconnect` | Auto-reconnect on disconnect | `true` |
| `[client]` | `insecure` | Skip TLS verification (for self-signed certificates) | `false` |
| `[client]` | `websocket_cleanup_interval_secs` | Cleanup check interval | `60` |
| `[client]` | `websocket_connection_timeout_secs` | Connection timeout | `10` |
| `[client]` | `websocket_max_idle_secs` | Maximum idle time | `600` |
| `[client]` | `websocket_monitoring_interval_secs` | Monitoring interval | `30` |

### Environment Variables

| Variable | Description                                   | Example                   |
|----------|-----------------------------------------------|---------------------------|
| `EXPOSEME_DOMAIN` | Your domain                                   | `example.com`             |
| `EXPOSEME_EMAIL` | Contact email for Let's Encrypt               | `admin@example.com`       |
| `EXPOSEME_STAGING` | Use staging certificates                      | `false`                   |
| `EXPOSEME_WILDCARD` | Enable wildcard certificates                  | `true`                    |
| `EXPOSEME_ROUTING_MODE` | Routing mode                                  | `both`                    |
| `EXPOSEME_DNS_PROVIDER` | DNS provider (only for wildcard certificates) | `digitalocean`, `azure`, or `hetzner` |
| `EXPOSEME_AUTH_TOKEN` | Authentication token                          | `secure_token`            |
| `EXPOSEME_REQUEST_TIMEOUT` | HTTP request timeout in seconds               | `30`                      |
| `RUST_LOG` | Logging level (e.g., `info`, `debug`)                 | `info`                    |

## API Endpoints

### Health Check
```bash
curl http://your-domain.com/api/health
```

### Certificate Status
```bash
curl http://your-domain.com/api/certificates/status
```

Response:
```json
{
   "domain": "your-domain.com",
   "exists": true,
   "expiry_date": "2024-08-15T10:30:00Z",
   "days_until_expiry": 45,
   "needs_renewal": false,
   "auto_renewal": true,
   "wildcard": true
}
```

## Building from Source

### Prerequisites
- Rust 1.88+
- Docker (optional)

### Build and Run

```bash
# Clone repository
git clone https://github.com/your-repo/exposeme
cd exposeme

# Build
cargo build --release

# Generate configurations
./target/release/exposeme-server --generate-config
./target/release/exposeme-client --generate-config

# Run server
./target/release/exposeme-server --config server.toml

# Run client (in another terminal)
./target/release/exposeme-client --config client.toml
```

### Docker Build

```bash
# Build images
docker build -t exposeme-server --target server .
docker build -t exposeme-client --target client .
```

## Troubleshooting

### View Logs
```bash
# Server logs
docker-compose logs -f exposeme-server

# Client logs
docker logs -f client-container-name
```

### Certificate Management

**Check certificate status:**
```bash
curl http://your-domain.com/api/certificates/status
```

**Manual certificate placement:**
```bash
# Place certificates in cert cache directory with correct names
# For domain "example.com":
/etc/exposeme/certs/example-com.pem
/etc/exposeme/certs/example-com.key

# For wildcard certificate:
/etc/exposeme/certs/wildcard-example-com.pem
/etc/exposeme/certs/wildcard-example-com.key
```

### Self-Signed Certificates

When using self-signed certificates for development, the client may fail to connect due to TLS verification errors. Use the `insecure` option to skip certificate verification:

**Configuration:**
```toml
[client]
server_url = "wss://your-domain.com/tunnel-ws"
insecure = true  # Skip TLS verification for self-signed certificates
```

**Command line:**
```bash
./exposeme-client --insecure --server-url wss://localhost/tunnel-ws
```

**⚠️ Security Warning**: The `insecure` option should only be used for development with self-signed certificates as it disables TLS certificate verification.

## License

MIT