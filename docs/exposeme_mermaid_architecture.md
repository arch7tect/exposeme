```mermaid
graph TD
%% External Layer
    Internet[Internet<br/>Browser Clients]
    DNS[DNS Providers<br/>DigitalOcean/Azure/Hetzner/Cloudflare]
    LE[Let's Encrypt<br/>ACME Directory]

%% VPS Server - Network Layer
    subgraph VPS ["VPS Server (your-domain.com)"]
        HTTP[HTTP Server<br/>Port 80]
        HTTPS[HTTPS Server<br/>Port 443]

    %% Core Services Layer
        subgraph CoreServices ["Core Services"]
            WSMgr[WebSocket Manager<br/>/tunnel-ws]
            Router[Request Router<br/>Path/Subdomain]
            SSLMgr[SSL Manager<br/>Certificate Handling]
            StreamMgr[Streaming Manager<br/>HTTP/SSE/File Streaming]
        end

    %% State Management Layer
        subgraph StateLayer ["State Management"]
            TunnelMap[(TunnelMap<br/>Active Tunnels)]
            ActiveReq[(ActiveRequests<br/>HTTP Correlation)]
            ActiveWS[(ActiveWebSockets<br/>WS Connections)]
            StreamState[(StreamingState<br/>Chunk Tracking)]
        end

    %% Configuration Layer
        subgraph ConfigLayer ["Configuration"]
            Config[ServerConfig<br/>Settings & Routing]
            Protocol[Message Protocol<br/>v1.1.0 Streaming]
        end
    end

%% Client Side
    subgraph ClientSide ["Developer Machine"]
    %% Client Services
        subgraph ClientServices ["ExposeME Client v1.1.0"]
            WSClient[WebSocket Client<br/>Tunnel Connection]
            HTTPForward[HTTP Forwarder<br/>Request Proxy]
            StreamHandler[Streaming Handler<br/>Chunked Transfer]
        end

    %% Local Development
        subgraph LocalDev ["Local Services"]
            WebApp[Web App<br/>localhost:3000]
            API[API Server<br/>localhost:3001]
            SSEService[SSE Service<br/>Real-time Events]
            FileService[File Service<br/>Large Uploads]
            DB[(Database<br/>PostgreSQL)]
        end
    end

%% External connections
    Internet -->|HTTPS/WSS| HTTPS
    Internet -->|HTTP| HTTP

%% SSL connections
    SSLMgr -->|DNS-01| DNS
    SSLMgr -->|ACME| LE

%% Server internal flow
    HTTP --> Router
    HTTPS --> Router
    HTTPS --> WSMgr

    Router --> TunnelMap
    Router --> ActiveReq
    Router --> StreamMgr
    WSMgr --> ActiveWS
    WSMgr --> TunnelMap
    StreamMgr --> StreamState

%% Configuration
    Config --> Router
    Config --> SSLMgr
    Protocol --> WSMgr
    Protocol --> StreamHandler

%% Client tunnel connection
    WSClient -.->|WebSocket Tunnel<br/>v1.1.0 Protocol| WSMgr

%% Client internal connections
    WSClient --> HTTPForward
    WSClient --> StreamHandler
    HTTPForward --> WebApp
    HTTPForward --> API
    StreamHandler --> SSEService
    StreamHandler --> FileService
    API --> DB

%% Styling
    classDef external fill:#fce4ec,stroke:#c2185b,stroke-width:2px
    classDef server fill:#e8f5e8,stroke:#2e7d32,stroke-width:2px
    classDef client fill:#e3f2fd,stroke:#1976d2,stroke-width:2px
    classDef data fill:#fff3e0,stroke:#f57c00,stroke-width:2px
    classDef config fill:#f3e5f5,stroke:#7b1fa2,stroke-width:2px
    classDef streaming fill:#e1f5fe,stroke:#0277bd,stroke-width:2px

    class Internet,DNS,LE external
    class HTTP,HTTPS,WSMgr,Router,SSLMgr server
    class WSClient,HTTPForward,WebApp,API client
    class TunnelMap,ActiveReq,ActiveWS,DB data
    class Config,Protocol config
    class StreamMgr,StreamHandler,SSEService,FileService,StreamState streaming
```