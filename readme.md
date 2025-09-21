# ExposeME

A fast, secure HTTP tunneling solution written in Rust that exposes local services to the internet through WebSocket connections.

## Introduction

ExposeME lets you share your local development server with the outside world by creating secure tunnels through your own domain. Turn `http://localhost:3000` into `https://myapp.yourdomain.com` and share your work with clients, teammates, or testing tools.

**How it works:** You run ExposeME on a server (like a VPS) with your own domain. A client program on your development machine connects to your server via WebSocket using a binary protocol. When someone visits your public URL, requests get forwarded through the secure tunnel to your local application.

**Why use your own server?** Full control with your own domain and SSL certificates, complete privacy with no third-party dependencies, no rate limits, and cost-effective hosting on any VPS.

## Features

- **Secure Tunneling** - WebSocket-based encrypted tunnels with token authentication and binary protocol
- **Your Own Domain** - Use your domain with automatic SSL certificates via Let's Encrypt
- **Multiple Routing Modes** - Path-based (`domain.com/app/`) or subdomain (`app.domain.com`) routing
- **Real-time Support** - WebSocket connections and Server-Sent Events (SSE) streaming
- **File Streaming** - Large file uploads/downloads without memory buffering
- **Auto-Reconnection** - Automatic reconnection with configurable retry intervals
- **Flexible SSL** - Let's Encrypt (auto), bring your own certificates, or self-signed for development
- **Multi-client Support** - Multiple tunnels with unique identifiers

## Web UI Dashboard

ExposeME includes a modern web dashboard built with Leptos (Rust WASM) for real-time monitoring and management.

### Features

- **Live Metrics** - Real-time server statistics with traffic visualization charts
- **Tunnel Management** - View active tunnels, disconnect sessions, monitor traffic
- **Certificate Management** - SSL status, expiration tracking, ACME renewal controls
- **Server Configuration** - Routing mode detection, DNS provider status
- **Professional Design** - TailwindCSS styling with responsive mobile layout

### Access

Visit `https://yourdomain.com/` when no tunnel routes match. Docker images include UI by default.

## Architecture

ExposeME creates secure HTTP tunnels to expose local services:

- **Tunnel Setup**: Client connects to server via WebSocket upgrade on `/tunnel-ws` (configurable) to establish a persistent tunnel
- **Request Forwarding**: When users visit your public URL, the server forwards their HTTP requests through the existing WebSocket tunnel to your local service using a binary protocol
- **Flow**: Internet User → Server (HTTP(S)) → WebSocket Tunnel → Client → Local Service → Response back

### Connection Types
- **HTTP mode**: Client connects to `ws://your-domain.com/tunnel-ws`
- **HTTPS mode**: Client connects to `wss://your-domain.com/tunnel-ws`
- **Custom path**: Configurable via `tunnel_path` setting

### Protocol
ExposeME uses a binary protocol over WebSocket connections for efficient communication between client and server. The protocol handles HTTP request/response streaming, WebSocket proxying, and authentication.

## Authentication & Security

ExposeME uses **token-based authentication** to control access. Configure your server with one or more tokens, and clients must provide a valid token to create tunnels.

**Security features:**
- **Token authentication**: Only clients with valid tokens can create tunnels
- **Tunnel isolation**: Each tunnel has a unique ID and operates independently
- **Transport encryption**: All tunnel communication is encrypted when SSL is enabled
- **Private URLs**: Tunnel URLs are only known to those who create them
- **Binary protocol**: Efficient binary communication reduces overhead

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

To use HTTPS, your server needs an SSL certificate. ExposeME gives you three ways to get one:

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

### Option 1: Try the Test Server (No Setup Required)

Want to test ExposeME quickly without setting up your own server? Use our public test server:

**No config file needed - just run with CLI args:**

```bash
docker run -it --rm arch7tect/exposeme-client:latest \
  --server-url "wss://exposeme.org/tunnel-ws" \
  --token "uoINplvTSD3z8nOuzcDC5JDq41sf4GGELoLELBymXTY=" \
  --tunnel-id "my-tunnel" \
  --local-target "http://host.docker.internal:3000"
```

**Or use the config file approach:**

```bash
# Download the pre-configured client template
curl -O https://raw.githubusercontent.com/arch7tect/exposeme/master/config/client.toml.template
mv client.toml.template client.toml

# Edit only these two lines in client.toml:
# tunnel_id = "my-tunnel"     # Choose a unique tunnel name  
# local_target = "http://host.docker.internal:3000"  # Your local service port

# Run the client
docker run -it --rm -v ./client.toml:/etc/exposeme/client.toml arch7tect/exposeme-client:latest
```

Your service will be accessible at: `https://my-tunnel.exposeme.org/`

**⚠️ Test Server Limitations:**
- **No uptime guarantee** - service may be unavailable
- **Testing only** - not suitable for production use
- **No support** - use at your own risk

### Option 2: Set Up Your Own Server (Recommended for Production)

### DNS Setup

Configure DNS records for your domain:

**Required:**
- `your-domain.com` → `your-server-ip` (A record)

**For subdomain routing:**
- `*.your-domain.com` → `your-server-ip` (A record)

Wait for DNS propagation before proceeding (test with `nslookup your-domain.com`).

### Quick VPS Setup

For rapid deployment on a fresh Ubuntu VPS, create and run this setup script:

```bash
#!/bin/bash
# vps.sh - Quick VPS setup script
sudo apt update
sudo apt install apt-transport-https ca-certificates curl software-properties-common git
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable"
apt-cache policy docker-ce
sudo apt install docker-ce
git clone https://github.com/arch7tect/exposeme.git
cd exposeme
mkdir -p certs && chmod 777 certs
cp config/server.toml.template config/server.toml
cat > .env <<EOF
EXPOSEME_DOMAIN=<your-domain.com>
EXPOSEME_EMAIL=<admin@your-domain.com>
EXPOSEME_DNS_PROVIDER=cloudflare
EXPOSEME_CLOUDFLARE_TOKEN=<your-cloudflare-token-here>
EXPOSEME_AUTH_TOKEN=<your-secure-auth-token-here>
EXPOSEME_ADMIN_TOKEN=<your-secure-admin-token-here>
RUST_LOG=info
EOF
```
**Important:** Replace the placeholders <...> in `.env` with your actual values!

### Start the server

```bash
docker compose pull
docker compose up -d
docker compose logs -f
```

### Client Setup

**Option A: Using command line only (no config file needed):**

```bash
docker run -it --rm arch7tect/exposeme-client:latest \
  --server-url "wss://example.com/tunnel-ws" \
  --token "your_secure_auth_token" \
  --tunnel-id "my-app" \
  --local-target "http://host.docker.internal:3000"
```

**Option B: Using config file:**

1. **Create client configuration:**

```toml
# client.toml
[client]
server_url = "wss://example.com/tunnel-ws"  # Uses WebSocket upgrade on HTTPS
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
   - Subdomain: `https://my-app.example.com/`
   - Path-based: `https://example.com/my-app/`

## DNS Provider Setup

**DNS providers are only required for automatic Let's Encrypt wildcard certificates** (subdomain routing). For path-based routing with single-domain certificates, ExposeME uses HTTP-01 challenges and no DNS provider configuration is needed. Wildcard certificates require DNS-01 challenges which need a DNS provider.

If you're using manual certificates or self-signed certificates, DNS providers are not needed regardless of routing mode.

### DigitalOcean
1. **Create API token** at https://cloud.digitalocean.com/account/api/tokens
2. **Add your domain** to DigitalOcean Domains
3. **Set environment variables:**
   ```bash
   EXPOSEME_DNS_PROVIDER=digitalocean
   EXPOSEME_DIGITALOCEAN_TOKEN=your_do_token
   ```

### Cloudflare
1. **Create API token** at https://dash.cloudflare.com/profile/api-tokens with:
   - **Zone:Zone:Read** permissions
   - **Zone:DNS:Edit** permissions
   - **Include: All zones** (or specific zones you want to manage)
2. **Add your domain** to Cloudflare
3. **Set environment variables:**
   ```bash
   EXPOSEME_DNS_PROVIDER=cloudflare
   EXPOSEME_CLOUDFLARE_TOKEN=your_cf_token
   ```

### Hetzner DNS
1. **Create API token** at https://dns.hetzner.com/ (Console → API tokens)
2. **Add your domain** to Hetzner DNS
3. **Set environment variables:**
   ```bash
   EXPOSEME_DNS_PROVIDER=hetzner
   EXPOSEME_HETZNER_TOKEN=your_hetzner_token
   ```

### Azure DNS
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
        
    # Connection Management
        --auto-reconnect              Enable automatic reconnection on disconnect
        --no-auto-reconnect           Disable automatic reconnection on disconnect
        --reconnect-delay-secs <SECS> Delay before reconnection attempts [default: 5]
        
    # WebSocket Configuration
        --websocket-cleanup-interval <SECS>    Cleanup check interval [default: 60]
        --websocket-connection-timeout <SECS>  Connection timeout [default: 10]
        --websocket-max-idle <SECS>            Maximum idle time [default: 600]
        --websocket-monitoring-interval <SECS> Monitoring interval [default: 30]
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
| `[ssl.dns_provider]` | `provider` | DNS provider name (`digitalocean`, `cloudflare`, `azure`, `hetzner`) | - |
| `[auth]` | `tokens` | Authentication tokens | `["dev"]` |
| `[auth]` | `admin_token` | Admin token for observability API | - |
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
| `EXPOSEME_DNS_PROVIDER` | DNS provider (only for wildcard certificates) | `digitalocean`, `cloudflare`, `azure`, or `hetzner` |
| `EXPOSEME_AUTH_TOKEN` | Authentication token                          | `secure_token`            |
| `EXPOSEME_ADMIN_TOKEN` | Admin token for observability API             | `admin_secure_token`      |
| `EXPOSEME_REQUEST_TIMEOUT` | HTTP request timeout in seconds               | `30`                      |
| `RUST_LOG` | Logging level (e.g., `info`, `debug`)                 | `info`                    |

## API Endpoints

ExposeME provides REST API endpoints for health monitoring, certificate management, and observability.

### Public API Endpoints (No Authentication)

**Health Check** - `GET /api/health`
```bash
curl https://your-domain.com/api/health
```

**Certificate Status** - `GET /api/certificates`
```bash
curl https://your-domain.com/api/certificates
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

**View Metrics** - `GET /api/metrics`
```bash
curl https://your-domain.com/api/metrics
```

Returns comprehensive server and per-tunnel statistics:
```json
{
  "server": {
    "uptime_seconds": 3600,
    "active_tunnels": 2,
    "total_requests": 1250,
    "total_bytes_in": 450000,
    "total_bytes_out": 890000, 
    "websocket_connections": 3,
    "websocket_bytes_in": 12000,
    "websocket_bytes_out": 8500,
    "error_count": 5
  },
  "tunnels": [
    {
      "tunnel_id": "my-app",
      "last_activity": 1699123456,
      "requests_count": 850,
      "bytes_in": 300000,
      "bytes_out": 600000,
      "websocket_connections": 2,
      "websocket_bytes_in": 8000,
      "websocket_bytes_out": 5000,
      "error_count": 2
    }
  ]
}
```

**Stream Metrics (SSE)** - `GET /api/metrics/stream`
```bash
curl https://your-domain.com/api/metrics/stream
```

Streams the same metrics data in real-time via Server-Sent Events.

### Admin Endpoints (Bearer Token Required)

Set the admin token via environment variable or TOML config:

**Environment variable:**
```bash
export EXPOSEME_ADMIN_TOKEN="your-secure-admin-token"
```

**Or in server.toml:**
```toml
[auth]
admin_token = "your-secure-admin-token"
```

**Force Disconnect Tunnel** - `DELETE /admin/tunnels/<tunnel-id>`  
```bash
curl -X DELETE \
  -H "Authorization: Bearer your-secure-admin-token" \
  https://your-domain.com/admin/tunnels/my-app
```

**Renew SSL Certificate** - `POST /admin/ssl/renew`
```bash  
curl -X POST \
  -H "Authorization: Bearer your-secure-admin-token" \
  https://your-domain.com/admin/ssl/renew
```

## Building from Source

### Prerequisites
- Rust 1.88+
- Docker (optional)
- cargo-leptos (for UI builds)

### Build

```bash
# Clone repository
git clone https://github.com/arch7tect/exposeme.git
cd exposeme

# Basic build (no UI)
cargo build --release

# Build with Web UI Dashboard
./scripts/build-with-ui.sh
# OR manually:
# cargo install cargo-leptos
# cargo leptos build --project ui --release  
# cargo build --release --features ui
```

### Docker Build

```bash
# Build images with UI included
docker build -t exposeme-server --target server .
docker build -t exposeme-client --target client .

# Or use the build script
./scripts/build-and-push.sh [version]
```

### Web UI Dashboard

When built with UI support (`--features ui`), the server includes a web dashboard:

- **Access**: Visit `https://yourdomain.com/` when no tunnels match the path
- **Features**: Real-time metrics, server status, SSL certificate monitoring
- **Technology**: Leptos WASM for <300KB bundle size
- **API**: Uses existing `/api/health`, `/api/metrics`, `/api/metrics/stream` endpoints

## Troubleshooting

**DNS issues:** Verify `nslookup your-domain.com` resolves to your server IP

**Permission denied:**
```bash
docker exec -it exposeme-server id  # Check UID
sudo chown -R <uid>:<gid> ./certs
docker compose restart
```

**View logs:** `docker compose logs -f exposeme-server`

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

**Security Warning**: The `insecure` option should only be used for development with self-signed certificates as it disables TLS certificate verification.

## Version Compatibility

ExposeME uses a binary protocol for communication between client and server. Both client and server must be compatible versions:

- **Major.Minor versions must match** (e.g., 1.3.x client works with 1.3.x server)
- **Patch versions are compatible** within the same major.minor release
- **Protocol changes** require both client and server updates

## New in v1.4.9

**Observability & Admin Features**
- Built-in metrics collection (server stats, per-tunnel analytics)
- Admin API with Bearer token authentication (`/admin/tunnels/<id>`, `/admin/ssl/renew`)

## New in v1.4

**CLI-First Experience & Enhanced Reliability**
- **No config files required** - run with command line arguments only
- **Public test server** - try ExposeME instantly without setup (exposeme.org)
- **Faster network detection** - 60s ping timeout detects connection issues sooner
- **Better resource cleanup** - improved tunnel and connection management
- **Enhanced streaming** - fixed client disconnection handling for large uploads
- **Important**: Requires both server and client to be v1.4+

## New in v1.3

**Binary Protocol Implementation**
- Replaced JSON protocol with efficient binary protocol using bincode
- Reduced protocol overhead for better performance
- Maintained backward compatibility checking
- **Important**: Requires both server and client to be v1.3+

## New in v1.1

**Enhanced Streaming Support**
- Full HTTP request/response streaming without memory buffering
- Support for large file uploads and downloads

**Real-Time Communication**
- Native Server-Sent Events (SSE) support with proper headers and streaming
- Automatic reconnection handling for both SSE and WebSocket connections

**Protocol Improvements**
- Enhanced client-server protocol for streaming support
- **Important**: Requires both server and client to be v1.1+

### Upgrading from Previous Versions

**Protocol Breaking Change**: Version 1.4 includes connection management improvements that require both server and client to be updated together.

```bash
# Update server
docker compose pull
docker compose down
docker compose up -d

# Update client - arch7tect/exposeme-client:1.4 == arch7tect/exposeme-client:latest
docker run -it --rm \
  -v ./client.toml:/etc/exposeme/client.toml \
  arch7tect/exposeme-client:latest
```

## License

MIT