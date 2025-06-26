# ExposeME - Secure HTTP Tunneling Service

Simple HTTP tunneling service for exposing local development servers to external webhooks (MVP version).

## Quick Start

### 1. Build the project
```bash
cargo build --release
```

### 2. Start the server
```bash
cargo run --bin exposeme-server
```

The server will start:
- HTTP proxy on `http://localhost:8080`
- WebSocket server on `ws://localhost:8081`

### 3. Start a test local server
In another terminal:
```bash
cargo run --example test_server
```

This starts a simple HTTP server on `http://localhost:3300` that echoes requests.

### 4. Start the client
In a third terminal:
```bash
cargo run --bin exposeme-client
```

The client will:
- Connect to the WebSocket server
- Authenticate with token `"dev"` and tunnel_id `"test"`
- Forward requests to `http://localhost:3300`

### 5. Test the tunnel
In another terminal:
```bash
# Test basic request
curl http://localhost:8888/test/webhook -d "Hello from tunnel!"

# Test health endpoint
curl http://localhost:8888/test/health

# Test with JSON
curl -H "Content-Type: application/json" \
     -d '{"message": "test webhook"}' \
     http://localhost:8888/test/webhook
```

## How it works

```
External Request → Server (8888) → WebSocket → Client → Local Service (3300)
                                     ↑
                               Tunnel ID: "test"
```

1. External service sends HTTP request to `http://localhost:8888/test/webhook`
2. Server extracts tunnel ID (`test`) from URL path
3. Server forwards request via WebSocket to client
4. Client forwards request to local service at `localhost:3300`
5. Response flows back through the same path

## Configuration Priority

Settings are applied in the following order (higher priority overrides lower):

1. **CLI arguments** (highest priority)
2. **TOML configuration file**
3. **Default values** (lowest priority)

Example:
```bash
# This will use port 9999 even if server.toml specifies a different port
cargo run --bin exposeme-server -- --http-port 9999
``` (MVP - Hardcoded)

### Server
- HTTP proxy: `0.0.0.0:8888`
- WebSocket: `0.0.0.0:8081`
- Auth token: `"dev"`

### Client
- Server URL: `ws://localhost:8081`
- Auth token: `"dev"`
- Tunnel ID: `"test"`
- Local target: `http://localhost:3300`

## Project Structure

```
exposeme/
├── Cargo.toml
├── src/
│   ├── lib.rs              # Common types and protocol
│   ├── protocol.rs         # WebSocket message protocol
│   └── bin/
│       ├── server.rs       # Server binary
│       └── client.rs       # Client binary
├── examples/
│   └── test_server.rs      # Test HTTP server
└── README.md
```

## WebSocket Protocol

### Authentication
```json
// Client → Server
{"type": "auth", "token": "dev", "tunnel_id": "test"}

// Server → Client (success)
{"type": "auth_success", "tunnel_id": "test", "public_url": "http://localhost:8080/test"}

// Server → Client (error)
{"type": "auth_error", "error": "tunnel_id_taken", "message": "Tunnel ID already in use"}
```

### Request Forwarding
```json
// Server → Client
{
  "type": "http_request",
  "id": "req_12345",
  "method": "POST",
  "path": "/webhook",
  "headers": {"Content-Type": "application/json"},
  "body": "SGVsbG8gV29ybGQ="  // base64 encoded
}

// Client → Server
{
  "type": "http_response",
  "id": "req_12345", 
  "status": 200,
  "headers": {"Content-Type": "application/json"},
  "body": "eyJzdGF0dXMiOiJvayJ9"  // base64 encoded
}
```

## Production Deployment

For production use:

1. **Set custom domain** in `server.toml`:
```toml
[server]
domain = "tunnel.example.com"
```

2. **Use strong tokens**:
```toml
[auth]
tokens = ["very-long-random-token-here"]
```

3. **Configure limits**:
```toml
[limits]
max_tunnels = 100
request_timeout_secs = 45
```

4. **Run with systemd** or similar process manager

## Advanced Usage

### Environment Variables

You can also use environment variables (useful for Docker):

```bash
# Server
EXPOSEME_HTTP_PORT=9999 cargo run --bin exposeme-server

# Client  
EXPOSEME_TOKEN=my-secret cargo run --bin exposeme-client
```

### Docker Deployment

Example `docker-compose.yml`:
```yaml
version: '3.8'
services:
  exposeme-server:
    build: .
    ports:
      - "8888:8888"
      - "8081:8081" 
    volumes:
      - ./server.toml:/app/server.toml
    command: ["exposeme-server", "--config", "/app/server.toml"]
```

### Multiple Instances

Run multiple server instances with different configs:
```bash
# Instance 1: Development
cargo run --bin exposeme-server -- --config dev-server.toml --http-port 8888

# Instance 2: Testing
cargo run --bin exposeme-server -- --config test-server.toml --http-port 9999
```

Once running, you can use the tunnel URL `http://localhost:8888/test/` for:

- **Local development**: Test webhooks from external services
- **Telegram bots**: Set webhook URL to `http://your-server:8888/test/webhook`
- **WhatsApp**: Point webhook to your tunnel URL
- **GitHub webhooks**: Use for local development

## Testing with Real Webhooks

Once running, use your tunnel URL for:

- **Telegram bots**: `https://your-domain.com/my-bot/webhook`
- **WhatsApp Business**: Point webhook to tunnel URL
- **GitHub webhooks**: For local development
- **Stripe webhooks**: Test payment processing locally

### Webhook Examples

**Telegram Bot Setup:**
```bash
# Start tunnel
cargo run --bin exposeme-client -- -T telegram-bot

# Set webhook (replace TOKEN and DOMAIN)
curl -X POST "https://api.telegram.org/botTOKEN/setWebhook" \
     -d "url=https://DOMAIN/telegram-bot/webhook"
```

**GitHub Webhook:**
```bash
# Start tunnel for your local dev server
cargo run --bin exposeme-client -- -T github-dev -l http://localhost:3000

# Use URL: https://your-domain.com/github-dev/webhooks
```

- [ ] HTTPS support with Let's Encrypt
- [ ] Configuration files
- [ ] Multiple tunnels per client
- [ ] Web dashboard
- [ ] Custom domains
- [ ] Rate limiting
- [ ] Authentication system

## Next Steps (Future versions)

✅ **Already implemented:**
- [x] TOML configuration
- [x] CLI arguments
- [x] Multiple tunnels support
- [x] Auto-reconnection
- [x] Configurable limits and timeouts
- [x] Token-based authentication
- [x] Error handling and recovery

🔄 **In progress / Planned:**
- [ ] HTTPS support with Let's Encrypt
- [ ] Web dashboard for tunnel management
- [ ] Custom domains per tunnel
- [ ] Rate limiting per tunnel
- [ ] Request logging and replay
- [ ] Tunnel statistics and monitoring
- [ ] API for programmatic tunnel management
- [ ] Health check endpoints
- [ ] Metrics and observability

## Security Considerations

### Token Security
- **Never commit tokens** to version control
- **Use environment variables** for production tokens
- **Rotate tokens regularly** in production
- **Use different tokens** for different environments

### Network Security
- **Bind to localhost** for development: `http_bind = "127.0.0.1"`
- **Use HTTPS** in production (when implemented)
- **Firewall rules** to restrict access to WebSocket port
- **Monitor active tunnels** regularly

### Safe Practices
```bash
# Good: Use environment variable
EXPOSEME_TOKEN=$(cat /secure/token.txt) cargo run --bin exposeme-client

# Bad: Token visible in process list  
cargo run --bin exposeme-client -- --token secret-token-here
```

## License

MIT