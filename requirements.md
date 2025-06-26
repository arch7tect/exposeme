# ExposeME - Secure Tunneling Service
## Technical Requirements Document v1.0

### 1. Project Overview

**Project Name:** ExposeME  
**Type:** Secure HTTP/HTTPS tunneling service  
**Primary Use Case:** Local development webhook testing (Telegram, WhatsApp bots)  
**Target Audience:** Individual developers and small development teams

**Problem Statement:** Developers need to expose local development servers to external webhook services (Telegram, WhatsApp) for testing purposes without deploying to production or configuring complex network infrastructure.

### 2. Functional Requirements

#### 2.1 Core Features
- Create temporary public HTTPS URLs for local HTTP services
- Automatic SSL certificate provisioning and management
- Real-time traffic proxying with minimal latency
- Basic request/response logging for debugging
- Simple token-based authentication

#### 2.2 URL Structure
```
https://exposeme.io/{tunnel_id}/{path}
```
- `tunnel_id`: Client-specified identifier for tunnel (human-readable, e.g., "my-bot-dev")
- `path`: Forwarded to local service as-is
- **Advantage:** Predictable URLs allow one-time webhook configuration

#### 2.3 Supported Protocols
- **Inbound:** HTTP/HTTPS only
- **Outbound:** HTTP to localhost
- **Control Channel:** WebSocket

#### 2.4 Authentication
- Static token-based authentication
- Tokens configured in server config file
- No user registration/management system required

### 3. Technical Requirements

#### 3.1 Technology Stack
- **Language:** Rust
- **Runtime:** Tokio async runtime
- **TLS:** Let's Encrypt integration for automatic SSL
- **WebSocket:** tokio-tungstenite
- **HTTP:** hyper/axum for HTTP handling

#### 3.2 Performance Requirements
- Support for concurrent tunnels: 10-50 simultaneous connections
- Request latency overhead: < 100ms
- Automatic reconnection on connection drops
- Connection timeout: 30 seconds for WebSocket, 10 seconds for HTTP requests

#### 3.3 Platform Support
- **Server:** Linux (Ubuntu/Debian preferred)
- **Client:** Cross-platform (Windows, macOS, Linux)

### 4. System Architecture

#### 4.1 High-Level Architecture
```
Internet → [Load Balancer/Reverse Proxy] → ExposeME Server → WebSocket → Client → Local Service
```

#### 4.2 Components

**Server Components:**
- **HTTPS Proxy Handler:** Receives external requests, routes to appropriate tunnel
- **WebSocket Manager:** Manages client connections and tunnel mapping
- **SSL Certificate Manager:** Automatic Let's Encrypt certificate provisioning
- **Authentication Module:** Token validation
- **Request Logger:** Basic logging for debugging

**Client Components:**
- **WebSocket Client:** Maintains connection to server
- **HTTP Forwarder:** Forwards requests to local service
- **Reconnection Handler:** Automatic reconnection logic
- **Configuration Manager:** Token and target service configuration

#### 4.3 Data Flow
1. Client establishes WebSocket connection with authentication token and desired tunnel_id
2. Server validates tunnel_id uniqueness and confirms connection
3. External service sends webhook to `https://exposeme.io/{tunnel_id}/webhook`
4. Server receives request, identifies tunnel by tunnel_id
5. Server forwards request via WebSocket to client
6. Client forwards request to configured local service
7. Response flows back through the same path

### 5. Protocol Specifications

#### 5.1 WebSocket Protocol
**Connection:**
```json
{
  "type": "auth",
  "token": "user_auth_token",
  "tunnel_id": "my-telegram-bot"
}
```

**Server Response (Success):**
```json
{
  "type": "auth_success",
  "tunnel_id": "my-telegram-bot",
  "public_url": "https://exposeme.io/my-telegram-bot"
}
```

**Server Response (Tunnel ID Conflict):**
```json
{
  "type": "auth_error",
  "error": "tunnel_id_taken",
  "message": "Tunnel ID 'my-telegram-bot' is already in use"
}
```

**Request Forwarding:**
```json
{
  "type": "http_request",
  "id": "req_12345",
  "method": "POST",
  "path": "/webhook",
  "headers": {"Content-Type": "application/json"},
  "body": "base64_encoded_body"
}
```

**Response:**
```json
{
  "type": "http_response", 
  "id": "req_12345",
  "status": 200,
  "headers": {"Content-Type": "application/json"},
  "body": "base64_encoded_body"
}
```

#### 5.2 HTTP Headers Preservation
- All original headers must be forwarded
- Add custom headers:
    - `X-Forwarded-For`: Original client IP
    - `X-Forwarded-Proto`: https
    - `X-ExposeME-Tunnel-Id`: tunnel identifier

### 6. Security Requirements

#### 6.1 SSL/TLS
- Mandatory HTTPS for all public endpoints
- Automatic SSL certificate provisioning via Let's Encrypt
- TLS 1.2+ only

#### 6.2 Authentication
- Token-based authentication for tunnel creation
- Tokens stored in server configuration file
- No token transmitted in URL or logs

#### 6.3 Rate Limiting
- Per-tunnel rate limiting: 100 requests/minute
- WebSocket connection rate limiting: 5 connections/minute per IP

#### 6.4 Security Constraints
- No data persistence (stateless operation)
- No access to tunnel data by other users
- Automatic tunnel cleanup on disconnect

### 7. Configuration

#### 7.1 Server Configuration
```toml
[server]
bind_address = "0.0.0.0:443"
domain = "exposeme.io"

[ssl]
email = "admin@exposeme.io"
staging = false  # Let's Encrypt staging

[auth]
tokens = [
  "token1_for_user1",
  "token2_for_user2"
]

[limits]
max_tunnels = 50
request_rate_per_tunnel = 100  # per minute
```

#### 7.2 Client Configuration
```toml
[client]
server_url = "wss://exposeme.io/ws"
auth_token = "your_auth_token"
tunnel_id = "my-telegram-bot"
local_target = "http://localhost:3000"
auto_reconnect = true
```

### 8. Error Handling

#### 8.1 Tunnel ID Conflicts
- Server rejects connection if tunnel_id is already in use
- Client should prompt user to choose different tunnel_id
- Optional: server can suggest available alternatives

#### 8.2 Client Disconnection
#### 8.2 Client Disconnection
- Server removes tunnel mapping immediately
- Returns 503 Service Unavailable for incoming requests
- Client implements exponential backoff for reconnection

#### 8.3 Local Service Unavailable
- Client returns 502 Bad Gateway
- Log error for debugging
- Continue tunnel operation

#### 8.4 SSL Certificate Issues
- Fallback to staging Let's Encrypt on production failures
- Log certificate provisioning errors
- Graceful degradation

### 9. Limitations and Assumptions

#### 9.1 MVP Limitations
- No horizontal scaling (single server instance)
- No persistent storage
- No user management interface
- No custom domains
- No traffic analytics/dashboard

#### 9.2 Technical Assumptions
- Server has public IP and domain name
- Clients have reliable internet connection
- Local services respond within 10 seconds
- Maximum request body size: 10MB

### 10. Development Phases

#### Phase 1: Core Functionality
- [ ] Basic WebSocket server and client
- [ ] HTTP request/response forwarding
- [ ] Token authentication
- [ ] Basic error handling

#### Phase 2: Production Ready
- [ ] SSL certificate automation
- [ ] Rate limiting
- [ ] Proper logging
- [ ] Configuration management
- [ ] Client CLI tool

#### Phase 3: Enhanced Features
- [ ] Request inspection/debugging
- [ ] Multiple tunnel support per client
- [ ] Performance optimizations
- [ ] Monitoring and health checks

### 11. Success Criteria

#### Functional
- Successfully tunnel Telegram webhook requests to local development server
- Automatic SSL certificate provisioning working
- Client can reconnect automatically after network interruption

#### Performance
- < 100ms additional latency for webhook requests
- Handle 10+ concurrent tunnels without issues
- 99.9% uptime for tunnel connections

#### Security
- All traffic encrypted in transit
- No unauthorized access to tunnels
- No data leakage between tunnels

### 12. Deliverables

1. **Server Binary:** Single executable for Linux deployment
2. **Client Binary:** Cross-platform CLI tool
3. **Configuration Templates:** Sample server and client configs
4. **Documentation:** Installation and usage guide
5. **Source Code:** Complete Rust project with proper documentation

---

**Document Version:** 1.0  
**Last Updated:** June 25, 2025  
**Review Required:** Before Phase 2 implementation