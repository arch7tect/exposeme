# ExposeME

A fast, secure HTTP tunneling solution written in Rust that exposes local services to the internet through WebSocket connections.

## Features

- **Secure HTTP tunneling** via WebSocket connections
- **HTTPS support** with automatic Let's Encrypt certificates
- **Wildcard certificates** for subdomain routing
- **Multiple routing modes**: Path-based, subdomain-based, or both
- **DNS providers**: DigitalOcean, Azure (with more coming soon)
- **Multiple SSL providers**: Let's Encrypt, self-signed, or manual certificates
- **Auto-renewal** of certificates when < 30 days left
- **Docker support** with pre-built images
- **Token-based authentication** for secure access
- **Multiple concurrent tunnels** with configurable limits
- **Auto-reconnection** for reliable connections
- **Health check** and certificate management APIs

## ⚠️ Current Limitations

- **WebSocket proxying is NOT supported** - Only HTTP/HTTPS requests are proxied
- For applications requiring WebSocket connections (like Socket.IO), force HTTP polling transport
- Real-time bidirectional connections are not supported

## Architecture

ExposeME uses a client-server architecture connected via WebSocket for tunnel management, while HTTP requests are proxied through the tunnel:

- **Server**: Accepts WebSocket connections from clients and forwards HTTP requests
- **Client**: Connects to server and forwards requests to local services
- **Protocol**: WebSocket for tunnel management, HTTP for request proxying
- **SSL/TLS**: Automatic certificate management with Let's Encrypt and DNS challenges

## Routing Modes

ExposeME supports three routing modes:

### 1. Path-based Routing (default)
```
https://your-domain.com/tunnel-id/path
```

### 2. Subdomain Routing
```
https://tunnel-id.your-domain.com/path
```
*Requires wildcard certificates*

### 3. Both (recommended)
Supports both routing methods simultaneously

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

         # DNS Provider - Choose one:
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

networks:
   default:
      name: exposeme-network
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

### DigitalOcean

1. **Create API token** at https://cloud.digitalocean.com/account/api/tokens
2. **Add your domain** to DigitalOcean Domains
3. **Set environment variables:**
   ```bash
   EXPOSEME_DNS_PROVIDER=digitalocean
   EXPOSEME_DIGITALOCEAN_TOKEN=your_do_token
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

### Server Configuration

| Section | Option | Description | Default |
|---------|--------|-------------|---------|
| `[server]` | `domain` | Your domain name | `localhost` |
| `[server]` | `routing_mode` | `path`, `subdomain`, or `both` | `path` |
| `[server]` | `http_port` | HTTP port | `80` |
| `[server]` | `https_port` | HTTPS port | `443` |
| `[server]` | `ws_port` | WebSocket port | `8081` |
| `[ssl]` | `enabled` | Enable HTTPS | `false` |
| `[ssl]` | `wildcard` | Use wildcard certificates | `false` |
| `[ssl]` | `provider` | `letsencrypt`, `manual`, `selfsigned` | `letsencrypt` |
| `[ssl]` | `staging` | Use Let's Encrypt staging | `true` |
| `[ssl.dns_provider]` | `provider` | DNS provider name (`digitalocean`, `azure`) | - |
| `[auth]` | `tokens` | Authentication tokens | `["dev"]` |
| `[limits]` | `max_tunnels` | Maximum concurrent tunnels | `50` |

#### DigitalOcean DNS Provider Config
| Section | Option | Description | Default |
|---------|--------|-------------|---------|
| `[ssl.dns_provider.config]` | `api_token` | DigitalOcean API token (TOML fallback) | - |
| `[ssl.dns_provider.config]` | `timeout_seconds` | DNS API timeout in seconds | `30` |

#### Azure DNS Provider Config
| Section | Option | Description | Default |
|---------|--------|-------------|---------|
| `[ssl.dns_provider.config]` | `subscription_id` | Azure subscription ID (TOML fallback) | - |
| `[ssl.dns_provider.config]` | `resource_group` | Azure resource group (TOML fallback) | - |
| `[ssl.dns_provider.config]` | `client_id` | Azure client ID (TOML fallback) | - |
| `[ssl.dns_provider.config]` | `client_secret` | Azure client secret (TOML fallback) | - |
| `[ssl.dns_provider.config]` | `tenant_id` | Azure tenant ID (TOML fallback) | - |
| `[ssl.dns_provider.config]` | `timeout_seconds` | DNS API timeout in seconds | `30` |
| `[limits]` | `max_tunnels` | Maximum concurrent tunnels | `50` |

### Environment Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `EXPOSEME_DOMAIN` | Your domain | `example.com` |
| `EXPOSEME_EMAIL` | Contact email for Let's Encrypt | `admin@example.com` |
| `EXPOSEME_STAGING` | Use staging certificates | `false` |
| `EXPOSEME_WILDCARD` | Enable wildcard certificates | `true` |
| `EXPOSEME_ROUTING_MODE` | Routing mode | `both` |
| `EXPOSEME_DNS_PROVIDER` | DNS provider | `digitalocean` or `azure` |
| `EXPOSEME_AUTH_TOKEN` | Authentication token | `secure_token` |

#### DigitalOcean DNS Variables
| Variable | Description |
|----------|-------------|
| `EXPOSEME_DIGITALOCEAN_TOKEN` | DigitalOcean API token |
| `EXPOSEME_DIGITALOCEAN_TIMEOUT` | Request timeout in seconds |

#### Azure DNS Variables
| Variable | Description |
|----------|-------------|
| `EXPOSEME_AZURE_SUBSCRIPTION_ID` | Azure subscription ID |
| `EXPOSEME_AZURE_RESOURCE_GROUP` | Resource group containing DNS zone |
| `EXPOSEME_AZURE_CLIENT_ID` | Service principal client ID |
| `EXPOSEME_AZURE_CLIENT_SECRET` | Service principal secret |
| `EXPOSEME_AZURE_TENANT_ID` | Azure tenant ID |
| `EXPOSEME_AZURE_TIMEOUT` | Request timeout in seconds |

### Client Configuration

| Section | Option | Description | Default |
|---------|--------|-------------|---------|
| `[client]` | `server_url` | WebSocket server URL | `ws://localhost:8081` |
| `[client]` | `auth_token` | Authentication token | `dev` |
| `[client]` | `tunnel_id` | Unique tunnel identifier | `test` |
| `[client]` | `local_target` | Local service URL | `http://localhost:3300` |
| `[client]` | `auto_reconnect` | Auto-reconnect on disconnect | `true` |

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

## WebSocket Limitations & Socket.IO

ExposeME **does not support WebSocket proxying**. For Socket.IO applications, force HTTP polling:

```javascript
// Frontend configuration
const socket = io('https://your-tunnel-url', {
  transports: ['polling'],  // Force HTTP polling
  upgrade: false            // Disable WebSocket upgrade
});
```

## Use Cases

- **Development environments**: Expose local dev servers for testing
- **Webhooks**: Receive webhooks on local development machines
- **API testing**: Share REST APIs with external services
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