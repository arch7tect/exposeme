# ExposeME Development Roadmap

This document outlines planned features and improvements for ExposeME.

## High Priority

### HTTP Request Streaming

**Status**: Not implemented  
**Priority**: High  
**Complexity**: High

Current implementation uses `body.collect().await` which loads entire request body into memory, limiting file uploads to ~64MB and causing memory issues.

**Problem**:
- Large file uploads fail due to WebSocket message size limits
- Memory usage scales linearly with request size
- No support for `Transfer-Encoding: chunked` requests
- Request timeout (30s) insufficient for large transfers

**Approach**:
- Implement true streaming without collecting entire body in memory
- Design chunked protocol: `HttpStreamStart` → `HttpStreamChunk` (multiple) → `HttpStreamEnd`
- Support requests with unknown `Content-Length`
- Stream processing on both server and client sides

**Implementation**:
- Replace `body.collect()` with `body.frame()` streaming
- Add chunk size threshold (suggest 4MB chunks for >10MB requests)
- Implement client-side streaming to local services without buffering
- Handle backpressure and flow control

## Medium Priority

### Performance Optimization

**Status**: Not implemented  
**Priority**: Medium  
**Complexity**: Medium

**Binary Protocol Support**:
- Current JSON protocol has ~30% overhead from base64 encoding
- Consider MessagePack or Protocol Buffers for high-bandwidth usage
- Implement when AWS data transfer costs become significant (>$100/month)
- Maintain JSON for debugging and development

### DNS Provider Expansion

**Status**: Partially implemented  
**Priority**: Medium  
**Complexity**: Low-Medium

Current support: DigitalOcean, Azure DNS, Hetzner  
**Planned providers**:
- Cloudflare DNS
- AWS Route53
- Namecheap
- Google Cloud DNS

**Approach**: Follow existing provider-specific pattern rather than generic abstraction, as DNS APIs differ significantly in structure and authentication.

## Future Enhancements

### Tunnel Management UI

**Status**: Not implemented  
**Priority**: Low  
**Complexity**: Medium

A web-based management interface would improve operational visibility and control:

**Dashboard Features**:
- Real-time active tunnel monitoring with connection counts
- Historical traffic statistics and bandwidth usage graphs
- Client connection status and health indicators
- Request/response latency metrics

**Management Capabilities**:
- Tunnel creation and deletion through web interface
- Authentication token management and rotation
- Certificate status overview with renewal controls
- Configuration validation and deployment

**Operational Tools**:
- Live request/response inspection (debug mode)
- Error logs and troubleshooting interface
- Performance metrics and bottleneck identification
- Export capabilities for metrics and logs

## Known Issues

### WebSocket Frame Size Limits

**Issue**: Default 64MB WebSocket message limit  
**Workaround**: Increase tokio-tungstenite configuration  
**Long-term fix**: Implement chunked streaming (see HTTP Request Streaming above)

### Request Timeout

**Issue**: Default 30-second timeout may be insufficient for large file transfers  
**Configuration**: Increase via `request_timeout_secs` setting, `EXPOSEME_REQUEST_TIMEOUT` environment variable, or `--request-timeout` CLI argument  
**Long-term fix**: Dynamic timeout based on content size and transfer progress
