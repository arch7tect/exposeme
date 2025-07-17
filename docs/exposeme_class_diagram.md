# ExposeME Architecture Diagrams

## 1. Configuration Layer

```mermaid
classDiagram
    class ServerConfig:::config {
        +ServerSettings server
        +SslSettings ssl
        +AuthSettings auth
        +LimitSettings limits
        +load(args ServerArgs) ServerConfig
        +validate_tunnel_id(tunnel_id String) Result
        +http_addr() String
        +https_addr() String
        +get_public_url(tunnel_id String) String
    }

    class ServerSettings:::config {
        +String http_bind
        +u16 http_port
        +u16 https_port
        +String tunnel_path
        +String domain
        +RoutingMode routing_mode
    }

    class SslSettings:::config {
        +bool enabled
        +SslProvider provider
        +String email
        +bool staging
        +String cert_cache_dir
        +bool wildcard
        +Option_DnsProviderConfig dns_provider
    }

    class AuthSettings:::config {
        +Vec_String tokens
    }

    class LimitSettings:::config {
        +usize max_tunnels
        +u64 request_timeout_secs
    }

    class ClientConfig:::config {
        +ClientSettings client
        +load(args ClientArgs) ClientConfig
        +generate_default_file(path PathBuf)
    }

    class ClientSettings:::config {
        +String server_url
        +String auth_token
        +String tunnel_id
        +String local_target
        +bool auto_reconnect
        +u64 reconnect_delay_secs
        +bool insecure
    }

    class RoutingMode:::enums {
        <<enumeration>>
        Path
        Subdomain
        Both
    }

    class SslProvider:::enums {
        <<enumeration>>
        LetsEncrypt
        Manual
        SelfSigned
    }

    class DnsProviderConfig:::config {
        +String provider
        +serde_json_Value config
    }

    class ServerArgs:::args {
        +PathBuf config
        +Option_String domain
        +bool enable_https
        +bool verbose
        +bool wildcard
    }

    class ClientArgs:::args {
        +PathBuf config
        +Option_String server_url
        +Option_String tunnel_id
        +bool verbose
        +bool insecure
    }

%% Relationships
    ServerConfig --> ServerSettings
    ServerConfig --> SslSettings
    ServerConfig --> AuthSettings
    ServerConfig --> LimitSettings
    ServerSettings --> RoutingMode
    SslSettings --> SslProvider
    SslSettings --> DnsProviderConfig
    ClientConfig --> ClientSettings
    ServerArgs --> ServerConfig
    ClientArgs --> ClientConfig

%% Styling
classDef config fill:#e1f5fe,stroke:#01579b,stroke-width:2px;
classDef enums fill:#fff8e1,stroke:#ff6f00,stroke-width:2px;
classDef args fill:#f3e5f5,stroke:#4a148c,stroke-width:2px;
```

## 2. SSL & DNS Management

```mermaid
classDiagram
    class SslManager:::ssl {
        -ServerConfig config
        -Option_Arc_RustlsConfig rustls_config
        -ChallengeStore challenge_store
        -Option_Box_DnsProvider dns_provider
        +new(config ServerConfig) SslManager
        +initialize() Result
        +get_certificate_info() Result_CertificateInfo
        +force_renewal() Result
        -setup_letsencrypt() Result_RustlsConfig
        -generate_self_signed() Result_RustlsConfig
    }

    class CertificateInfo:::ssl {
        +String domain
        +bool exists
        +Option_DateTime_Utc expiry_date
        +Option_i64 days_until_expiry
        +bool needs_renewal
    }

    class DnsProvider:::interface {
        <<interface>>
        +list_zones_impl() Result_Vec_ZoneInfo
        +create_txt_record_impl(zone ZoneInfo, name String, value String) Result_String
        +delete_txt_record_impl(zone ZoneInfo, record_id String) Result
        +cleanup_txt_records(domain String, name String) Result
        +wait_for_propagation(domain String, name String, value String) Result
    }

    class ZoneInfo:::dns {
        +String id
        +String name
        +from_name(name String) ZoneInfo
        +new(id String, name String) ZoneInfo
    }

    class DigitalOceanProvider:::dns {
        -DigitalOceanConfig config
        -reqwest_Client client
        +new(config DigitalOceanConfig) DigitalOceanProvider
    }

    class AzureProvider:::dns {
        -AzureConfig config
        -reqwest_Client client
        -Option_String access_token
        +new(config AzureConfig) AzureProvider
        -get_access_token() Result_String
    }

    class HetznerProvider:::dns {
        -HetznerConfig config
        -reqwest_Client client
        +new(config HetznerConfig) HetznerProvider
    }

    class ChallengeStore:::store {
        <<abstract>>
        Arc_RwLock_HashMap_String_String
    }

    %% Relationships
    SslManager --> CertificateInfo
    SslManager --> DnsProvider
    SslManager --> ChallengeStore
    DigitalOceanProvider ..|> DnsProvider
    AzureProvider ..|> DnsProvider
    HetznerProvider ..|> DnsProvider
    DnsProvider --> ZoneInfo

    %% Styling
    classDef ssl fill:#e8f5e8,stroke:#1b5e20,stroke-width:2px;
    classDef dns fill:#fff3e0,stroke:#e65100,stroke-width:2px;
    classDef interface fill:#e0f2f1,stroke:#00695c,stroke-width:2px;
    classDef store fill:#f1f8e9,stroke:#33691e,stroke-width:2px;
```

## 3. Protocol & Service Layer

```mermaid
classDiagram
    class Message:::enums {
        <<enumeration>>
        Auth
        AuthSuccess
        AuthError
        HttpRequest
        HttpResponse
        WebSocketUpgrade
        WebSocketData
        WebSocketClose
        +to_json() Result_String
        +from_json(json String) Result_Message
    }

    class TunnelInfo:::protocol {
        +String tunnel_id
        +String token
        +SystemTime created_at
    }

    class UnifiedService:::service {
        +TunnelMap tunnels
        +PendingRequests pending_requests
        +ActiveWebSockets active_websockets
        +ServerConfig config
        +bool is_https
    }

    class WebSocketConnection:::service {
        +String tunnel_id
        +Instant created_at
        +Option_mpsc_UnboundedSender_WsMessage ws_tx
        +new(tunnel_id String) WebSocketConnection
        +connection_age() Duration
        +status_summary() String
    }

    class ActiveWebSocketConnection:::service {
        +String connection_id
        +mpsc_UnboundedSender_Vec_u8 local_tx
        +mpsc_UnboundedSender_Message to_server_tx
        +Instant created_at
        +update_activity()
        +is_idle(max_idle_duration Duration) bool
        +send_to_server(message Message) Result
    }

    class TunnelMap:::types {
        <<abstract>>
        Arc_RwLock_HashMap_String_mpsc_UnboundedSender_Message
    }

    class PendingRequests:::types {
        <<abstract>>
        Arc_RwLock_HashMap_String_mpsc_UnboundedSender_ResponseTuple
    }

    class ActiveWebSockets:::types {
        <<abstract>>
        Arc_RwLock_HashMap_String_WebSocketConnection
    }

    %% Relationships
    UnifiedService --> TunnelMap
    UnifiedService --> PendingRequests
    UnifiedService --> ActiveWebSockets
    ActiveWebSockets --> WebSocketConnection
    ActiveWebSocketConnection --> Message
    TunnelMap --> Message

    %% Styling
    classDef protocol fill:#f3e5f5,stroke:#4a148c,stroke-width:2px;
    classDef service fill:#fce4ec,stroke:#880e4f,stroke-width:2px;
    classDef types fill:#f1f8e9,stroke:#33691e,stroke-width:2px;
    classDef enums fill:#fff8e1,stroke:#ff6f00,stroke-width:2px;
```

## Architecture Overview

**🔵 Configuration Layer** - Handles all configuration management with CLI args, TOML files, and environment variables

**🟢 SSL & DNS Management** - Automatic certificate handling with Let's Encrypt integration and pluggable DNS providers

**🟣 Protocol & Service Layer** - Core tunneling logic with WebSocket communication and HTTP/WebSocket proxying
