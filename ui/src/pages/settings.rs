use leptos::prelude::*;
use crate::api::*;
use crate::types::*;

#[component]
pub fn SettingsPage() -> impl IntoView {
    // Reactive signals for settings data
    let (health, set_health) = signal::<Option<HealthResponse>>(None);
    let (metrics, set_metrics) = signal::<Option<MetricsResponse>>(None);
    let (certificate_info, set_certificate_info) = signal::<Option<CertificateInfo>>(None);
    let (error, set_error) = signal::<Option<String>>(None);

    // Load initial data
    Effect::new(move |_| {
        leptos::task::spawn_local(async move {
            match fetch_health().await {
                Ok(health_data) => {
                    set_health.set(Some(health_data));
                    set_error.set(None);
                }
                Err(e) => set_error.set(Some(format!("Failed to load health data: {}", e))),
            }

            match fetch_metrics().await {
                Ok(metrics_data) => {
                    set_metrics.set(Some(metrics_data));
                }
                Err(e) => set_error.set(Some(format!("Failed to load metrics data: {}", e))),
            }

            match fetch_certificate_info().await {
                Ok(cert_data) => {
                    set_certificate_info.set(Some(cert_data));
                }
                Err(e) => set_error.set(Some(format!("Failed to load certificate info: {}", e))),
            }
        });
    });

    view! {
        <div class="page settings-page">
            <header class="page-header">
                <h1>"Settings & Configuration"</h1>
                <p>"Server configuration and system information"</p>
            </header>

            <div class="page-content">
                <ErrorDisplay error=error/>

                <div class="settings-grid">
                    <ServerConfiguration health=health certificate_info=certificate_info/>
                    <SystemInformation health=health metrics=metrics/>
                    <ApiEndpoints/>
                </div>
            </div>
        </div>
    }
}

#[component]
pub fn ServerConfiguration(
    health: ReadSignal<Option<HealthResponse>>,
    certificate_info: ReadSignal<Option<CertificateInfo>>
) -> impl IntoView {
    view! {
        <div class="settings-card">
            <h3>"Server Configuration"</h3>
            <div class="settings-content">
                {move || {
                    match (health.get(), certificate_info.get()) {
                        (Some(h), Some(cert)) => {
                            let domain = h.domain.clone();
                            let ssl_enabled = h.ssl_enabled;
                            let version = h.version.clone();
                            let status = h.status.clone();
                            let routing_mode = cert.server_config.routing_mode.clone();
                            let is_wildcard = cert.ssl_config.wildcard;

                            view! {
                                <div class="config-section">
                                    <h4>"Basic Settings"</h4>
                                    <div class="config-row">
                                        <span class="label">"Server Version:"</span>
                                        <span class="value">{version}</span>
                                    </div>
                                    <div class="config-row">
                                        <span class="label">"Domain:"</span>
                                        <span class="value">{domain.clone()}</span>
                                    </div>
                                    <div class="config-row">
                                        <span class="label">"SSL Enabled:"</span>
                                        <span class={if ssl_enabled { "value status-ok" } else { "value status-error" }}>
                                            {if ssl_enabled { "✓ Enabled" } else { "✗ Disabled" }}
                                        </span>
                                    </div>
                                    <div class="config-row">
                                        <span class="label">"Server Status:"</span>
                                        <span class="value status-ok">{status}</span>
                                    </div>
                                </div>

                                <div class="config-section">
                                    <h4>"Routing Configuration"</h4>
                                    <div class="config-row">
                                        <span class="label">"Current Mode:"</span>
                                        <span class="value status-ok">{routing_mode.clone()}</span>
                                    </div>
                                    <div class="config-row">
                                        <span class="label">"Wildcard Certificate:"</span>
                                        <span class={if is_wildcard { "value status-ok" } else { "value status-warning" }}>
                                            {if is_wildcard { "✓ Enabled" } else { "✗ Not configured" }}
                                        </span>
                                    </div>
                                    <div class="config-row">
                                        <span class="label">"Example URL:"</span>
                                        <span class="value">
                                            {
                                                let protocol = if ssl_enabled { "https" } else { "http" };
                                                match routing_mode.as_str() {
                                                    "subdomain" => format!("{}://tunnel-id.{}/path", protocol, domain),
                                                    "both" => format!("{}://tunnel-id.{}/path OR {}/tunnel-id/path", protocol, domain, domain),
                                                    _ => format!("{}://{}/tunnel-id/path", protocol, domain)
                                                }
                                            }
                                        </span>
                                    </div>
                                    <div class="config-info">
                                        <p><strong>"Routing Mode Details:"</strong></p>
                                        <ul>
                                            <li><strong>"path:"</strong> " Uses single domain certificate - tunnels accessed via paths"</li>
                                            <li><strong>"subdomain:"</strong> " Uses wildcard certificate - each tunnel gets own subdomain"</li>
                                            <li><strong>"both:"</strong> " Supports both modes with wildcard certificate"</li>
                                        </ul>
                                        {if !is_wildcard && routing_mode != "path" {
                                            Some(view! {
                                                <div class="config-note">
                                                    "⚠️ Subdomain routing is configured but wildcard certificate is not enabled. Only path-based routing will work."
                                                </div>
                                            })
                                        } else if is_wildcard && routing_mode == "path" {
                                            Some(view! {
                                                <div class="config-note">
                                                    "💡 Wildcard certificate is available. You can enable subdomain routing in server configuration."
                                                </div>
                                            })
                                        } else {
                                            None
                                        }}
                                    </div>
                                </div>
                            }.into_any()
                        },
                        (Some(h), None) => {
                            // Fallback when certificate info is not available
                            let domain = h.domain.clone();
                            let ssl_enabled = h.ssl_enabled;
                            let version = h.version.clone();
                            let status = h.status.clone();

                            view! {
                                <div class="config-section">
                                    <h4>"Basic Settings"</h4>
                                    <div class="config-row">
                                        <span class="label">"Server Version:"</span>
                                        <span class="value">{version}</span>
                                    </div>
                                    <div class="config-row">
                                        <span class="label">"Domain:"</span>
                                        <span class="value">{domain.clone()}</span>
                                    </div>
                                    <div class="config-row">
                                        <span class="label">"SSL Enabled:"</span>
                                        <span class={if ssl_enabled { "value status-ok" } else { "value status-error" }}>
                                            {if ssl_enabled { "✓ Enabled" } else { "✗ Disabled" }}
                                        </span>
                                    </div>
                                    <div class="config-row">
                                        <span class="label">"Server Status:"</span>
                                        <span class="value status-ok">{status}</span>
                                    </div>
                                </div>

                                <div class="config-section">
                                    <h4>"Routing Configuration"</h4>
                                    <div class="config-row">
                                        <span class="label">"Current Mode:"</span>
                                        <span class="value">Loading...</span>
                                    </div>
                                    <div class="config-info">
                                        <p>"Loading routing configuration details..."</p>
                                    </div>
                                </div>
                            }.into_any()
                        },
                        _ => view! {
                            <div class="config-section">
                                <h4>"Basic Settings"</h4>
                                <div class="config-row">
                                    <span class="label">"Server Version:"</span>
                                    <span class="value loading-skeleton">""</span>
                                </div>
                                <div class="config-row">
                                    <span class="label">"Domain:"</span>
                                    <span class="value loading-skeleton">""</span>
                                </div>
                                <div class="config-row">
                                    <span class="label">"SSL Enabled:"</span>
                                    <span class="value loading-skeleton">""</span>
                                </div>
                                <div class="config-row">
                                    <span class="label">"Server Status:"</span>
                                    <span class="value loading-skeleton">""</span>
                                </div>
                            </div>
                        }.into_any()
                    }
                }}
            </div>
        </div>
    }
}

#[component]
pub fn SystemInformation(
    health: ReadSignal<Option<HealthResponse>>,
    metrics: ReadSignal<Option<MetricsResponse>>,
) -> impl IntoView {
    view! {
        <div class="settings-card">
            <h3>"System Information"</h3>
            <div class="settings-content">
                {move || {
                    match (health.get(), metrics.get()) {
                        (Some(h), Some(m)) => view! {
                            <div class="system-section">
                                <h4>"Server Status"</h4>
                                <div class="config-row">
                                    <span class="label">"Uptime:"</span>
                                    <span class="value">{format_uptime(m.server.uptime_seconds)}</span>
                                </div>
                                <div class="config-row">
                                    <span class="label">"Health Check:"</span>
                                    <span class={if h.uptime_check == "OK" { "value status-ok" } else { "value status-error" }}>
                                        {h.uptime_check.clone()}
                                    </span>
                                </div>
                                <div class="config-row">
                                    <span class="label">"Active Connections:"</span>
                                    <span class="value">{m.server.active_tunnels}</span>
                                </div>
                                <div class="config-row">
                                    <span class="label">"WebSocket Connections:"</span>
                                    <span class="value">{m.server.websocket_connections}</span>
                                </div>
                            </div>

                            <div class="system-section">
                                <h4>"Traffic Statistics"</h4>
                                <div class="config-row">
                                    <span class="label">"Total Requests:"</span>
                                    <span class="value">{format_number(m.server.total_requests)}</span>
                                </div>
                                <div class="config-row">
                                    <span class="label">"HTTP Traffic:"</span>
                                    <span class="value">{format_bytes(m.server.total_bytes_in + m.server.total_bytes_out)}</span>
                                </div>
                                <div class="config-row">
                                    <span class="label">"WebSocket Traffic:"</span>
                                    <span class="value">{format_bytes(m.server.websocket_bytes_in + m.server.websocket_bytes_out)}</span>
                                </div>
                            </div>

                            <div class="system-section">
                                <h4>"Diagnostics"</h4>
                                <div class="config-row">
                                    <span class="label">"Errors:"</span>
                                    <span class={if h.errors.is_empty() { "value status-ok" } else { "value status-error" }}>
                                        {if h.errors.is_empty() { "None".to_string() } else { format!("{} errors", h.errors.len()) }}
                                    </span>
                                </div>
                                <div class="config-row">
                                    <span class="label">"Warnings:"</span>
                                    <span class={if h.warnings.is_empty() { "value status-ok" } else { "value status-warning" }}>
                                        {if h.warnings.is_empty() { "None".to_string() } else { format!("{} warnings", h.warnings.len()) }}
                                    </span>
                                </div>

                                {if !h.errors.is_empty() || !h.warnings.is_empty() {
                                    Some(view! {
                                        <div class="diagnostics-details">
                                            {if !h.errors.is_empty() {
                                                Some(view! {
                                                    <div class="error-list">
                                                        <h5>"Recent Errors:"</h5>
                                                        <ul>
                                                            {h.errors.iter().map(|error| view! {
                                                                <li class="error-item">{error.clone()}</li>
                                                            }).collect::<Vec<_>>()}
                                                        </ul>
                                                    </div>
                                                })
                                            } else {
                                                None
                                            }}

                                            {if !h.warnings.is_empty() {
                                                Some(view! {
                                                    <div class="warning-list">
                                                        <h5>"Recent Warnings:"</h5>
                                                        <ul>
                                                            {h.warnings.iter().map(|warning| view! {
                                                                <li class="warning-item">{warning.clone()}</li>
                                                            }).collect::<Vec<_>>()}
                                                        </ul>
                                                    </div>
                                                })
                                            } else {
                                                None
                                            }}
                                        </div>
                                    })
                                } else {
                                    None
                                }}
                            </div>
                        }.into_any(),
                        _ => view! {
                            <div class="system-section">
                                <h4>"Server Status"</h4>
                                <div class="config-row">
                                    <span class="label">"Uptime:"</span>
                                    <span class="value loading-skeleton">""</span>
                                </div>
                                <div class="config-row">
                                    <span class="label">"Health Check:"</span>
                                    <span class="value loading-skeleton">""</span>
                                </div>
                                <div class="config-row">
                                    <span class="label">"Active Connections:"</span>
                                    <span class="value loading-skeleton">""</span>
                                </div>
                                <div class="config-row">
                                    <span class="label">"WebSocket Connections:"</span>
                                    <span class="value loading-skeleton">""</span>
                                </div>
                            </div>
                        }.into_any()
                    }
                }}
            </div>
        </div>
    }
}

#[component]
pub fn ApiEndpoints() -> impl IntoView {
    view! {
        <div class="settings-card">
            <h3>"API Endpoints"</h3>
            <div class="settings-content">
                <div class="api-section">
                    <h4>"Public Endpoints"</h4>
                    <div class="api-list">
                        <div class="api-item">
                            <span class="api-method">"GET"</span>
                            <span class="api-path">"/api/health"</span>
                            <span class="api-desc">"Server health and status"</span>
                        </div>
                        <div class="api-item">
                            <span class="api-method">"GET"</span>
                            <span class="api-path">"/api/metrics"</span>
                            <span class="api-desc">"Current metrics snapshot"</span>
                        </div>
                        <div class="api-item">
                            <span class="api-method">"GET"</span>
                            <span class="api-path">"/api/metrics/stream"</span>
                            <span class="api-desc">"Live metrics via Server-Sent Events"</span>
                        </div>
                        <div class="api-item">
                            <span class="api-method">"GET"</span>
                            <span class="api-path">"/api/certificates"</span>
                            <span class="api-desc">"Certificate status information"</span>
                        </div>
                        <div class="api-item">
                            <span class="api-method">"GET"</span>
                            <span class="api-path">"/api/certificates/info"</span>
                            <span class="api-desc">"Detailed certificate information"</span>
                        </div>
                    </div>
                </div>

                <div class="api-section">
                    <h4>"Admin Endpoints"</h4>
                    <p class="api-note">"Require Authorization: Bearer <token> header"</p>
                    <div class="api-list">
                        <div class="api-item">
                            <span class="api-method admin-method">"DELETE"</span>
                            <span class="api-path">"/admin/tunnels/{id}"</span>
                            <span class="api-desc">"Disconnect specific tunnel"</span>
                        </div>
                        <div class="api-item">
                            <span class="api-method admin-method">"POST"</span>
                            <span class="api-path">"/admin/ssl/renew"</span>
                            <span class="api-desc">"Force SSL certificate renewal"</span>
                        </div>
                    </div>
                </div>

                <div class="api-section">
                    <h4>"Authentication"</h4>
                    <div class="auth-info">
                        <p>"Admin endpoints require a valid authentication token configured on the server."</p>
                        <p>"Tokens are passed via the Authorization header: <code>Bearer <your-token></code>"</p>
                        <p>"Token configuration is managed in the server configuration file or environment variables."</p>
                    </div>
                </div>
            </div>
        </div>
    }
}

#[component]
pub fn ErrorDisplay(error: ReadSignal<Option<String>>) -> impl IntoView {
    view! {
        {move || error.get().map(|err| view! {
            <div class="error-banner">
                <strong>"Error: "</strong>
                {err}
            </div>
        })}
    }
}

// Helper functions
fn format_bytes(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
    let mut size = bytes as f64;
    let mut unit_idx = 0;

    while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
        size /= 1024.0;
        unit_idx += 1;
    }

    if unit_idx == 0 {
        format!("{} {}", size as u64, UNITS[unit_idx])
    } else {
        format!("{:.1} {}", size, UNITS[unit_idx])
    }
}

fn format_number(n: u64) -> String {
    if n >= 1_000_000 {
        format!("{:.1}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

fn format_uptime(seconds: u64) -> String {
    if seconds < 60 {
        format!("{}s", seconds)
    } else if seconds < 3600 {
        let minutes = seconds / 60;
        let secs = seconds % 60;
        format!("{}m {}s", minutes, secs)
    } else if seconds < 86400 {
        let hours = seconds / 3600;
        let minutes = (seconds % 3600) / 60;
        format!("{}h {}m", hours, minutes)
    } else {
        let days = seconds / 86400;
        let hours = (seconds % 86400) / 3600;
        format!("{}d {}h", days, hours)
    }
}