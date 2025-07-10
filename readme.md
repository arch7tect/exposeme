# ExposeME

A fast, secure HTTP tunneling solution written in Rust that exposes local services to the internet through WebSocket connections.

## Features

- **Secure HTTP tunneling** via WebSocket connections
- **WebSocket proxying** for real-time applications
- **HTTPS support** with multiple certificate options:
    - **Automatic Let's Encrypt certificates** (HTTP-01 or DNS-01 challenges)
    - **Manual certificates** (bring your own)
    - **Self-signed certificates** (development only)
- **Wildcard certificates** for subdomain routing (requires DNS provider)
- **HTTP challenges** for single-domain certificates (no DNS provider needed)
- **Multiple routing modes**: Path-based, subdomain-based, or both
- **DNS providers**: DigitalOcean, Azure (with more coming soon)
- **Auto-renewal** of certificates when < 30 days left
- **Docker support** with pre-built images
- **Token-based authentication** for secure tunnel access control
- **Multiple concurrent tunnels** with configurable limits
- **Auto-reconnection** for reliable connections
- **Health check** and certificate status APIs

## Architecture

ExposeME creates secure HTTP tunnels to expose local services:

- **Server**: Receives HTTP/HTTPS requests from the internet and forwards them to clients
- **Client**: Connects to server via secure WebSocket (WSS/WS) and forwards requests to local services
- **Tunnel Flow**: Internet → Server → WebSocket → Client → Local Service → Response back

## Authentication & Security

ExposeME uses **token-based authentication** to control who can create tunnels on your server:

### Authentication Flow
1. **Server Configuration**: Server is configured with one or more authentication tokens
2. **Client Connection**: Client presents a token when connecting via WebSocket
3. **Token Validation**: Server validates the token before allowing tunnel creation
4. **Tunnel Authorization**: Only authenticated clients can expose services

### Security Model
- **Token Controls Access**: Anyone with a valid token can create tunnels
- **Tunnel Isolation**: Each tunnel has a unique ID and can't interfere with others
- **Transport Security**: WSS encrypts all tunnel communication (when SSL enabled)
- **No Public Discovery**: Tunnel URLs are only known to those who create them

```bash
# Example: Generate a secure token
openssl rand -base64 32
# Result: a1b2c3d4e5f6789... (use this as your EXPOSEME_AUTH_TOKEN)
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

ExposeME supports three certificate management approaches:

### 1. Automatic Let's Encrypt (recommended)
- **Single-domain certificates**: Uses HTTP-01 challenges (no DNS provider needed)
- **Wildcard certificates**: Uses DNS-01 challenges (requires DNS provider)
- **Auto-renewal**: Certificates renewed automatically when < 30 days left
- **Free**: No cost for certificates

### 2. Manual Certificates
- **Bring your own**: Use existing certificates from any provider
- **Full control**: Manage renewal and configuration yourself
- **No auto-renewal**: You handle certificate lifecycle

### 3. Self-signed Certificates
- **Development only**: Not suitable for production
- **No external dependencies**: Works without internet access
- **Browser warnings**: Browsers will show security warnings

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
      - "80:80"       # HTTP (ACME challenges + redirects)
      - "443:443"     # HTTPS
      - "8081:8081"   # WebSocket

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
ws_bind = "0.0.0.0"
ws_port = 8081
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
provider = "digitalocean"  # or "azure"

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
server_url = "wss://your-domain.com:8081"
auth_token = "your_secure_auth_token"
tunnel_id = "my-app"
local_target = "http://localhost:8000"
auto_reconnect = true
reconnect_delay_secs = 5
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
        --ws-bind <IP>            WebSocket bind address
        --ws-port <PORT>          WebSocket port
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
    -s, --server-url <URL>        WebSocket server URL
    -t, --token <TOKEN>           Authentication token
    -T, --tunnel-id <ID>          Tunnel identifier
    -l, --local-target <URL>      Local service URL to forward to
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
| `[server]` | `ws_port` | WebSocket port | `8081` |
| `[ssl]` | `enabled` | Enable HTTPS | `false` |
| `[ssl]` | `wildcard` | Use wildcard certificates (required for subdomain routing) | `false` |
| `[ssl]` | `provider` | Certificate source: `letsencrypt` (automatic), `manual` (your own), `selfsigned` (development) | `letsencrypt` |
| `[ssl]` | `staging` | Use Let's Encrypt staging | `true` |
| `[ssl.dns_provider]` | `provider` | DNS provider name (`digitalocean`, `azure`) | - |
| `[auth]` | `tokens` | Authentication tokens | `["dev"]` |
| `[limits]` | `max_tunnels` | Maximum concurrent tunnels | `50` |
| `[limits]` | `request_timeout_secs` | HTTP request timeout in seconds | `30` |

### Client Configuration

| Section | Option | Description | Default |
|---------|--------|-------------|---------|
| `[client]` | `server_url` | WebSocket server URL | `ws://localhost:8081` |
| `[client]` | `auth_token` | Authentication token | `dev` |
| `[client]` | `tunnel_id` | Unique tunnel identifier | `test` |
| `[client]` | `local_target` | Local service URL | `http://localhost:3300` |
| `[client]` | `auto_reconnect` | Auto-reconnect on disconnect | `true` |
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
| `EXPOSEME_DNS_PROVIDER` | DNS provider (only for wildcard certificates) | `digitalocean` or `azure` |
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
  "auto_renewal": true
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

## Use Cases

- **Development environments**: Expose local dev servers for testing
- **Webhooks**: Receive webhooks on local development machines
- **API testing**: Share REST APIs with external services
- **Real-time applications**: WebSocket-based chat, gaming, collaboration tools
- **Static sites**: Host local static sites temporarily
- **Demo applications**: Share work-in-progress applications

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
# Place certificates in cert cache directory
/etc/exposeme/certs/your-domain-com.pem
/etc/exposeme/certs/your-domain-com.key
```

## License

MIT