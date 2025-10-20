# ExposeME

Secure HTTP tunneling solution written in Rust that exposes local services to the internet through WebSocket connections.

## Table of Contents

- [Introduction](#introduction)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Quick Start (Test Server)](#quick-start-test-server)
- [Production Setup (Your Server)](#production-setup-your-server)
- [Web UI Dashboard](#web-ui-dashboard)
- [Architecture](#architecture)
- [Authentication & Security](#authentication--security)
- [Routing Modes](#routing-modes)
- [Certificate Management](#certificate-management)
- [DNS Provider Setup](#dns-provider-setup)
- [Configuration Reference](#configuration-reference)
- [API Endpoints](#api-endpoints)
- [Building from Source](#building-from-source)
- [Troubleshooting](#troubleshooting)
- [Version Compatibility](#version-compatibility)
- [Changelog](#changelog)
- [License](#license)

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

## Prerequisites

Before setting up your own production server, ensure you have:

- **Domain name** - A registered domain with DNS management access
- **VPS or server** - A server with a public IP address and ports 80/443 accessible
- **DNS configuration** - Ability to create A records pointing to your server
- **SSL requirements** - Email address for Let's Encrypt, or your own certificates
- **For subdomain routing** - DNS provider API access (Cloudflare, DigitalOcean, Azure, or Hetzner)

> **Note:** If you just want to try ExposeME without setting up infrastructure, use the [Quick Start (Test Server)](#quick-start-test-server) option below.

## Quick Start (Test Server)

Want to test ExposeME quickly without setting up your own server? Use our public test server:

**No config file needed - just run with CLI args:**

```bash
docker run -it --rm ghcr.io/arch7tect/exposeme-client:latest \
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
tunnel_id = "my-tunnel"     # Choose a unique tunnel name
local_target = "http://host.docker.internal:3000"  # Your local service port

# Run the client
docker run -it --rm -v ./client.toml:/etc/exposeme/client.toml ghcr.io/arch7tect/exposeme-client:latest
```

Your service will be accessible at: `https://my-tunnel.exposeme.org/`

> **Warning:** Test Server Limitations:
> - No uptime guarantee - service may be unavailable
> - Testing only - not suitable for production use
> - No support - use at your own risk

## Production Setup (Your Server)

### DNS Setup

Configure DNS records for your domain:

**Required:**
- `your-domain.com` → `your-server-ip` (A record)

**For subdomain routing:**
- `*.your-domain.com` → `your-server-ip` (A record)

Wait for DNS propagation before proceeding (test with `nslookup your-domain.com`).

### Server Installation

For rapid deployment on a fresh Ubuntu VPS:

**Step 1: Install Docker**

```bash
sudo apt update
sudo apt install apt-transport-https ca-certificates curl software-properties-common git
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu focal stable"
sudo apt install docker-ce
```

**Step 2: Clone and Configure**

```bash
git clone https://github.com/arch7tect/exposeme.git
cd exposeme
mkdir -p certs && chmod 777 certs
cp config/server.toml.template config/server.toml
```

**Step 3: Create Environment Configuration**

```bash
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

> **Important:** Replace all placeholders `<...>` with your actual values!

**Step 4: Start the Server**

```bash
docker compose pull
docker compose up -d
docker compose logs -f
```

### Client Setup

**Option A: Command line only (no config file needed):**

```bash
docker run -it --rm ghcr.io/arch7tect/exposeme-client:latest \
  --server-url "wss://example.com/tunnel-ws" \
  --token "your_secure_auth_token" \
  --tunnel-id "my-app" \
  --local-target "http://host.docker.internal:3000"
```

**Option B: Using config file:**

Create `client.toml`:

```toml
[client]
server_url = "wss://example.com/tunnel-ws"
auth_token = "your_secure_auth_token"
tunnel_id = "my-app"
local_target = "http://host.docker.internal:3000"
auto_reconnect = true
reconnect_delay_secs = 5
insecure = false  # Set to true for self-signed certificates (development only)
```

Run the client:

```bash
docker run -it --rm \
  -v ./client.toml:/etc/exposeme/client.toml \
  ghcr.io/arch7tect/exposeme-client:latest
```

Access your service:
- **Subdomain:** `https://my-app.example.com/`
- **Path-based:** `https://example.com/my-app/`

## Web UI Dashboard

ExposeME includes a web dashboard built with Leptos (Rust WASM) for real-time monitoring and management.

**Access:** Visit `https://yourdomain.com/` when no tunnel routes match.

The dashboard provides:
- Real-time tunnel status and metrics
- Traffic visualization and statistics
- Certificate management and renewal controls
- Active connection monitoring

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

**Generate a secure token:**

```bash
openssl rand -base64 32
```

**Security features:**
- **Token authentication**: Only clients with valid tokens can create tunnels
- **Tunnel isolation**: Each tunnel has a unique ID and operates independently
- **Transport encryption**: All tunnel communication is encrypted when SSL is enabled
- **Private URLs**: Tunnel URLs are only known to those who create them
- **Binary protocol**: Efficient binary communication reduces overhead

## Routing Modes

ExposeME supports three routing modes. Choose based on your certificate setup and URL preferences.

### Path-based Routing (default)
```
https://your-domain.com/tunnel-id/path
```
- Single-domain SSL certificate
- HTTP-01 challenges (no DNS provider needed)
- Simpler setup

### Subdomain Routing
```
https://tunnel-id.your-domain.com/path
```
- Wildcard SSL certificate required
- DNS-01 challenges (DNS provider required)
- Cleaner URLs

### Both (recommended)
Supports both routing methods simultaneously.
- Wildcard SSL certificate required
- DNS-01 challenges (DNS provider required)
- Maximum flexibility

## Certificate Management

ExposeME supports three certificate options:

### 1. Automatic Let's Encrypt (recommended)

Free SSL certificates with automatic renewal.

- Works with just domain name and email
- Auto-renewal every 90 days
- Supports both regular and wildcard certificates

### 2. Bring Your Own Certificate

Use certificates from any provider (Cloudflare, Namecheap, etc.).

**File naming convention:**
- Regular: `your-domain-com.pem` and `your-domain-com.key`
- Wildcard: `wildcard-your-domain-com.pem` and `wildcard-your-domain-com.key`
- Example: For `example.com` → `example-com.pem` and `example-com.key`

**Location:** Place files in cert cache directory (default: `/etc/exposeme/certs`)

### 3. Self-Signed Certificate (development only)

For local development and testing.

> **Warning:** Browsers will show security warnings. Not suitable for production.

## DNS Provider Setup

> **Note:** DNS providers are only required for automatic Let's Encrypt wildcard certificates (subdomain routing). Path-based routing uses HTTP-01 challenges and requires no DNS provider. Manual or self-signed certificates don't require DNS providers regardless of routing mode.

### DigitalOcean

1. Create API token at https://cloud.digitalocean.com/account/api/tokens
2. Add your domain to DigitalOcean Domains
3. Set environment variables:

```bash
EXPOSEME_DNS_PROVIDER=digitalocean
EXPOSEME_DIGITALOCEAN_TOKEN=your_do_token
```

### Cloudflare

1. Create API token at https://dash.cloudflare.com/profile/api-tokens with:
   - **Zone:Zone:Read** permissions
   - **Zone:DNS:Edit** permissions
   - **Include: All zones** (or specific zones)
2. Add your domain to Cloudflare
3. Set environment variables:

```bash
EXPOSEME_DNS_PROVIDER=cloudflare
EXPOSEME_CLOUDFLARE_TOKEN=your_cf_token
```

### Hetzner DNS

1. Create API token at https://dns.hetzner.com/ (Console → API tokens)
2. Add your domain to Hetzner DNS
3. Set environment variables:

```bash
EXPOSEME_DNS_PROVIDER=hetzner
EXPOSEME_HETZNER_TOKEN=your_hetzner_token
```

### Azure DNS

1. Create a Service Principal with DNS Zone Contributor role:

```bash
az ad sp create-for-rbac --name "exposeme-dns" \
  --role "DNS Zone Contributor" \
  --scopes "/subscriptions/YOUR_SUBSCRIPTION_ID/resourceGroups/YOUR_RG"
```

2. Add your domain to Azure DNS (create DNS zone)
3. Set environment variables:

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

| Variable | Description | Example |
|----------|-------------|---------|
| `EXPOSEME_DOMAIN` | Your domain | `example.com` |
| `EXPOSEME_EMAIL` | Contact email for Let's Encrypt | `admin@example.com` |
| `EXPOSEME_STAGING` | Use staging certificates | `false` |
| `EXPOSEME_WILDCARD` | Enable wildcard certificates | `true` |
| `EXPOSEME_ROUTING_MODE` | Routing mode | `both` |
| `EXPOSEME_DNS_PROVIDER` | DNS provider (only for wildcard certificates) | `digitalocean`, `cloudflare`, `azure`, or `hetzner` |
| `EXPOSEME_AUTH_TOKEN` | Authentication token | `secure_token` |
| `EXPOSEME_ADMIN_TOKEN` | Admin token for observability API | `admin_secure_token` |
| `EXPOSEME_REQUEST_TIMEOUT` | HTTP request timeout in seconds | `30` |
| `RUST_LOG` | Logging level | `info`, `debug` |
| `TRACING_LOG` | Advanced file logging configuration | See below |

### File Logging with TRACING_LOG

Configure file logging with rotation using the `TRACING_LOG` environment variable:

```bash
# Size-based rotation (10MB per file, keep 7 files)
export TRACING_LOG="level=info,file=/var/log/exposeme/server.log,max_size=10M,max_files=7"

# Time-based rotation (daily rotation)
export TRACING_LOG="level=debug,file=/var/log/exposeme/server.log,rotation=daily"

# Simple file logging (no rotation)
export TRACING_LOG="level=info,file=/var/log/exposeme/server.log"
```

**TRACING_LOG Options:**
- `level` - Log level: `trace`, `debug`, `info`, `warn`, `error`
- `file` - Log file path
- `max_size` - Max file size before rotation (supports `K`, `M`, `G` suffixes)
- `max_files` - Number of rotated files to keep (required with `max_size`)
- `rotation` - Time-based rotation: `minutely`, `hourly`, `daily`, `never`
- `append` - Append to existing file: `true`, `false`

**Rotated file naming:** Files rotate as `app.log`, `app.log.1`, `app.log.2`, etc.

**Docker compose example:**

```yaml
environment:
  - TRACING_LOG=level=info,file=/var/log/exposeme/server.log,max_size=10M,max_files=7
volumes:
  - ./logs:/var/log/exposeme:rw
```

**Permissions:**

```bash
mkdir -p logs && chmod 777 logs/
```

**Viewing logs:**

```bash
tail -f logs/server.log
```

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
```

### Docker Build

```bash
# Build images with UI included
docker build -t exposeme-server --target server .
docker build -t exposeme-client --target client .

# Or use the build script
./scripts/build-and-push.sh [version]
```

## Troubleshooting

**DNS issues:**

```bash
nslookup your-domain.com  # Should resolve to your server IP
```

**Permission denied:**

```bash
docker exec -it exposeme-server id  # Check UID
sudo chown -R <uid>:<gid> ./certs
docker compose restart
```

**View logs:**

```bash
docker compose logs -f exposeme-server
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

> **Warning:** The `insecure` option should only be used for development with self-signed certificates as it disables TLS certificate verification.

## Version Compatibility

ExposeME uses a binary protocol for communication between client and server. Both client and server must be compatible versions:

- **Major.Minor versions must match** (e.g., 1.3.x client works with 1.3.x server)
- **Patch versions are compatible** within the same major.minor release
- **Protocol changes** require both client and server updates

### Upgrading from Previous Versions

**Protocol Breaking Change**: Version 1.4 includes connection management improvements that require both server and client to be updated together.

```bash
# Update server
docker compose pull
docker compose down
docker compose up -d

# Update client
docker pull ghcr.io/arch7tect/exposeme-client:latest
docker run -it --rm \
  -v ./client.toml:/etc/exposeme/client.toml \
  ghcr.io/arch7tect/exposeme-client:latest
```

## Changelog

### v1.4.57

**New Features**
- File Logging with rotation via TRACING_LOG

**Fixes**
- Stale connection handling with cancellation tokens
- Reliable tunnel cleanup on disconnect (RAII guards)
- WebSocket connection counter accuracy
- RWLock panic prevention (removed .unwrap() calls)

**Improvements**
- Tailwind build-time compilation (replaced CDN)
- WASM optimization (wasm-opt + compression)

### v1.4.34

**GitHub Container Registry Migration**
- Migrated Docker images from Docker Hub to GitHub Container Registry (ghcr.io)
- Automated CI/CD builds now publish directly to GitHub Packages

### v1.4.20

**Modern Web UI Dashboard**
- Modern Leptos WASM UI with TailwindCSS styling
- Real-time traffic visualization and metrics charts
- Enhanced certificate management with ACME renewal controls

### v1.4.9

**Observability & Admin Features**
- Built-in metrics collection (server stats, per-tunnel analytics)
- Admin API with Bearer token authentication (`/admin/tunnels/<id>`, `/admin/ssl/renew`)

### v1.4

**CLI-First Experience & Enhanced Reliability**
- No config files required - run with command line arguments only
- Public test server - try ExposeME instantly without setup (exposeme.org)
- Faster network detection - 60s ping timeout detects connection issues sooner
- Better resource cleanup - improved tunnel and connection management
- Enhanced streaming - fixed client disconnection handling for large uploads
- **Important**: Requires both server and client to be v1.4+

### v1.3

**Binary Protocol Implementation**
- Replaced JSON protocol with efficient binary protocol using bincode
- Reduced protocol overhead for better performance
- Maintained backward compatibility checking
- **Important**: Requires both server and client to be v1.3+

### v1.1

**Enhanced Streaming Support**
- Full HTTP request/response streaming without memory buffering
- Support for large file uploads and downloads

**Real-Time Communication**
- Native Server-Sent Events (SSE) support with proper headers and streaming
- Automatic reconnection handling for both SSE and WebSocket connections

**Protocol Improvements**
- Enhanced client-server protocol for streaming support
- **Important**: Requires both server and client to be v1.1+

## License

MIT