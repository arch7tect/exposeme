# ExposeME

A fast, secure HTTP tunneling solution written in Rust that exposes local services to the internet through WebSocket connections.

## Features

- **Secure tunneling** via WebSocket connections
- **HTTPS support** with automatic Let's Encrypt certificates (auto-renewal when < 30 days left)
- **Multiple SSL providers**: Let's Encrypt, self-signed, or manual certificates
- **Docker support** with pre-built images
- **Token-based authentication** for secure access
- **Multiple concurrent tunnels** with configurable limits
- **Auto-reconnection** for reliable connections
- **Health checks** and monitoring endpoints

## Architecture

- **Server**: Accepts WebSocket connections and forwards HTTP requests
- **Client**: Connects to server and forwards requests to local services
- **Protocol**: WebSocket-based communication with JSON messages
- **SSL/TLS**: Automatic certificate management with Let's Encrypt

## Quick Start

### Server Setup with Let's Encrypt

1. **Configure the server:**

```toml
# config/server.toml
[server]
http_bind = "0.0.0.0"
http_port = 80
https_port = 443
ws_bind = "0.0.0.0"
ws_port = 8081
domain = "your-domain.com"

[ssl]
enabled = true
provider = "letsencrypt"
email = "admin@your-domain.com"
staging = false
cert_cache_dir = "/etc/exposeme/certs"

[auth]
tokens = [
    "your-secure-token-here",
    "another-token-for-client-2"
]

[limits]
max_tunnels = 100
request_timeout_secs = 30
```

2. **Run the server with Docker Compose:**

```yaml
# docker-compose.yml
services:
  exposeme-server:
    image: arch7tect/exposeme-server:latest
    container_name: exposeme-server
    restart: unless-stopped
    
    ports:
      - "80:80"       # HTTP
      - "443:443"     # HTTPS  
      - "8081:8081"   # WebSocket
    
    volumes:
      - ./config/server.toml:/etc/exposeme/server.toml:ro
      - ./exposeme-certs:/etc/exposeme/certs:rw
    
    environment:
      - EXPOSEME_DOMAIN=your-domain.com
      - EXPOSEME_EMAIL=admin@your-domain.com
      - EXPOSEME_STAGING=false
      - RUST_LOG=info
```

```bash
docker-compose up -d
```

### Client Configuration

1. **Configure the client:**

```toml
# client.toml
[client]
server_url = "wss://your-domain.com:8081"
auth_token = "your-secure-token-here"
tunnel_id = "my-app-tunnel"
local_target = "http://host.docker.internal:8000"
auto_reconnect = true
reconnect_delay_secs = 5
```

2. **Run the client:**

```bash
docker run -it --rm -v ./client.toml:/etc/exposeme/client.toml arch7tect/exposeme-client:latest
```

3. **Access your service:**
   Your local service will be available at: `https://your-domain.com/my-app-tunnel/`

## Building from Source

### Prerequisites
- Rust 1.70+

### Build
```bash
# Clone repository
git clone <repository-url>
cd exposeme

# Build server and client
cargo build --release

# Run server
./target/release/exposeme-server --generate-config
./target/release/exposeme-server

# Run client  
./target/release/exposeme-client --generate-config
./target/release/exposeme-client
```

## Configuration Options

### Server Configuration

| Section | Option | Description | Default |
|---------|--------|-------------|---------|
| `[server]` | `domain` | Domain name for certificates | `localhost` |
| `[server]` | `http_port` | HTTP port | `80` |
| `[server]` | `https_port` | HTTPS port | `443` |
| `[server]` | `ws_port` | WebSocket port | `8081` |
| `[ssl]` | `enabled` | Enable HTTPS | `false` |
| `[ssl]` | `provider` | SSL provider (`letsencrypt`, `manual`, `selfsigned`) | `letsencrypt` |
| `[ssl]` | `staging` | Use Let's Encrypt staging | `true` |
| `[auth]` | `tokens` | Authentication tokens | `["dev"]` |
| `[limits]` | `max_tunnels` | Maximum concurrent tunnels | `50` |

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

## Use Cases

- **Development environments**: Expose local dev servers for testing
- **Webhooks**: Receive webhooks on local development machines
- **IoT devices**: Connect devices behind NAT to cloud services
- **Microservices**: Temporary exposure of internal services
- **Demo applications**: Share work-in-progress applications

## Troubleshooting

### Docker Logs
```bash
docker-compose logs -f exposeme-server
```

## License

MIT License

---

**Made with ❤️ and Rust**