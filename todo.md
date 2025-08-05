# ExposeME Development Roadmap

This document outlines planned features and improvements for ExposeME.

## High Priority

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

Current support: Cloudflare DNS, DigitalOcean, Azure DNS, Hetzner  
**Planned providers**:
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

### Request Timeout

**Issue**: Default 30-second timeout may be insufficient for large file transfers  
**Configuration**: Increase via `request_timeout_secs` setting, `EXPOSEME_REQUEST_TIMEOUT` environment variable, or `--request-timeout` CLI argument  
**Long-term fix**: Dynamic timeout based on content size and transfer progress
