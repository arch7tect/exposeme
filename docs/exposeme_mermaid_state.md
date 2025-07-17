## ExposeME State Diagrams

### Main Application States
The main diagram shows the **high-level application lifecycle** and **primary state transitions** that users and operators care about.

```mermaid
stateDiagram-v2
    [*] --> ServerStartup
    ServerStartup --> SSLSetup : SSL Enabled
    ServerStartup --> Listening : SSL Disabled
    
    SSLSetup --> Listening : Certificates Ready
    SSLSetup --> Failed : Certificate Error
    
    state Listening {
        [*] --> Idle
        Idle --> ProcessingHTTP : HTTP Request
        Idle --> TunnelManagement : Client Connection
        ProcessingHTTP --> Idle : Response Sent
        TunnelManagement --> TunnelActive : Auth Success
        TunnelManagement --> Idle : Auth Failed
    }
    
    TunnelActive --> Cleanup : Client Disconnect
    Cleanup --> Listening : Cleanup Complete
    
    Listening --> CertRenewal : Daily Check
    CertRenewal --> Listening : Check Complete
    
    Failed --> [*]
    Listening --> [*] : Shutdown
```

### SSL Setup Details (SSLSetup state breakdown)
Certificate acquisition and validation process

```mermaid
stateDiagram-v2
    [*] --> CheckingConfig
    CheckingConfig --> CheckingExisting : Config Valid
    CheckingExisting --> UsingExisting : Valid Cert Found
    CheckingExisting --> ObtainingNew : No/Invalid Cert
    
    state ObtainingNew {
        [*] --> DNSChallenge : Wildcard
        [*] --> HTTPChallenge : Single Domain
        [*] --> LoadingManual : Manual
        [*] --> GeneratingSelf : Self-Signed
        
        DNSChallenge --> WaitingPropagation
        WaitingPropagation --> RequestingCert
        HTTPChallenge --> RequestingCert
        RequestingCert --> CertObtained
        LoadingManual --> CertObtained
        GeneratingSelf --> CertObtained
    }
    
    UsingExisting --> CertReady
    CertObtained --> CertReady
    CertReady --> [*]
```

### Tunnel Active Details (TunnelActive state breakdown)
Active tunnel request handling and monitoring

```mermaid
stateDiagram-v2
    [*] --> Ready
    
    state Ready {
        [*] --> Idle
        Idle --> HTTPProcessing : HTTP Request
        Idle --> WSUpgrade : WebSocket Upgrade
        Idle --> HealthCheck : Monitoring
        
        HTTPProcessing --> ForwardingHTTP
        ForwardingHTTP --> WaitingHTTPResponse
        WaitingHTTPResponse --> SendingHTTPResponse
        SendingHTTPResponse --> Idle
        
        WSUpgrade --> ProxyingWebSocket
        
        state ProxyingWebSocket {
            [*] --> Establishing
            Establishing --> ActiveProxy : Success
            ActiveProxy --> ActiveProxy : Data Transfer
            ActiveProxy --> WSClosed : Connection Lost
            Establishing --> WSClosed : Failed
        }
        
        ProxyingWebSocket --> Idle : WS Closed
        HealthCheck --> Idle : Health OK
    }
    
    Ready --> Disconnecting : Connection Lost
    Disconnecting --> [*]
```

### HTTP Request Processing Details
Detailed request/response correlation flow

```mermaid
stateDiagram-v2
    [*] --> ReceivingRequest
    ReceivingRequest --> ExtractingTunnelID
    ExtractingTunnelID --> ValidatingTunnel : ID Extracted
    ExtractingTunnelID --> ErrorResponse : Invalid Format
    
    ValidatingTunnel --> GeneratingRequestID : Tunnel Found
    ValidatingTunnel --> ErrorResponse : Tunnel Not Found
    
    GeneratingRequestID --> StoringPending
    StoringPending --> ForwardingToClient
    ForwardingToClient --> WaitingClientResponse
    
    WaitingClientResponse --> ProcessingResponse : Response Received
    WaitingClientResponse --> TimeoutResponse : Timeout
    
    ProcessingResponse --> RemovingPending
    RemovingPending --> SendingToBrowser
    
    SendingToBrowser --> [*]
    ErrorResponse --> [*]
    TimeoutResponse --> [*]
```

### WebSocket Upgrade Flow Details
WebSocket proxy establishment process

```mermaid
stateDiagram-v2
    [*] --> ReceivingUpgrade
    ReceivingUpgrade --> ValidatingUpgrade
    ValidatingUpgrade --> GeneratingConnectionID : Valid
    ValidatingUpgrade --> RejectingUpgrade : Invalid
    
    GeneratingConnectionID --> StoringConnection
    StoringConnection --> ForwardingUpgrade
    ForwardingUpgrade --> WaitingUpgradeResponse
    
    WaitingUpgradeResponse --> CompletingUpgrade : Success
    WaitingUpgradeResponse --> RejectingUpgrade : Failed
    WaitingUpgradeResponse --> UpgradeTimeout : Timeout
    
    CompletingUpgrade --> ProxyEstablished
    
    state ProxyEstablished {
        [*] --> Proxying
        Proxying --> ForwardingToClient : Browser → Client
        Proxying --> ForwardingToBrowser : Client → Browser
        ForwardingToClient --> Proxying
        ForwardingToBrowser --> Proxying
        Proxying --> ConnectionClosed : Disconnect
    }
    
    ProxyEstablished --> [*]
    RejectingUpgrade --> [*]
    UpgradeTimeout --> [*]
```

### Cleanup Process Details
Resource cleanup and graceful shutdown

```mermaid
stateDiagram-v2
    [*] --> DetectingDisconnect
    DetectingDisconnect --> IdentifyingTunnel
    IdentifyingTunnel --> RemovingFromTunnelMap
    RemovingFromTunnelMap --> FindingRelatedConnections
    
    FindingRelatedConnections --> ClosingBrowserWebSockets : WS Connections Found
    FindingRelatedConnections --> CancellingPendingRequests : No WS Connections
    
    ClosingBrowserWebSockets --> CleaningActiveWebSockets
    CleaningActiveWebSockets --> CancellingPendingRequests
    
    CancellingPendingRequests --> NotifyingClients
    NotifyingClients --> CleanupComplete
    CleanupComplete --> [*]
```
