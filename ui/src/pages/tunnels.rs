use leptos::prelude::*;
use crate::api::*;
use crate::types::*;
use crate::sse::SseGuard;

#[component]
pub fn TunnelsPage() -> impl IntoView {
    let (metrics, set_metrics) = signal::<Option<MetricsResponse>>(None);
    let (error, set_error) = signal::<Option<String>>(None);
    let (_connected, set_connected) = signal(false);

    let admin_token = use_context::<ReadSignal<String>>()
        .expect("Admin token signal should be provided in context");

    Effect::new(move |_| {
        leptos::task::spawn_local(async move {
            match fetch_metrics().await {
                Ok(metrics_data) => {
                    set_metrics.set(Some(metrics_data));
                    set_connected.set(true);
                    set_error.set(None);
                }
                Err(e) => set_error.set(Some(format!("Failed to load tunnel data: {}", e))),
            }
        });
    });

    #[cfg(debug_assertions)]
    console_error_panic_hook::set_once();

    let _sse_guard = StoredValue::new_local({
        let set_metrics = set_metrics;
        let set_connected = set_connected;
        let set_error = set_error;

        match SseGuard::new::<MetricsResponse>(
            "/api/metrics/stream",
            move |payload| {
                set_metrics.set(Some(payload));
                set_connected.set(true);
                set_error.set(None);
            },
            move |error_msg| {
                set_error.set(Some(error_msg));
            },
            move |connected| {
                set_connected.set(connected);
            },
        ) {
            Ok(guard) => Some(guard),
            Err(e) => {
                set_error.set(Some(e));
                None
            }
        }
    });

    view! {
        <div class="page tunnels-page">
            <header class="page-header">
                <h1>"Tunnel Management"</h1>
                <p>"Real-time tunnel monitoring and administration"</p>
            </header>

            <div class="page-content">
                <ErrorDisplay error=error/>

                <div class="tunnels-section">
                    <TunnelsList metrics=metrics admin_token=admin_token/>
                </div>
            </div>
        </div>
    }
}


#[component]
pub fn TunnelsList(
    metrics: ReadSignal<Option<MetricsResponse>>,
    admin_token: ReadSignal<String>,
) -> impl IntoView {
    view! {
        <div class="tunnels-list">
            <h3>"Active Tunnels"</h3>
            {move || {
                match metrics.get() {
                    Some(m) => {
                        if m.tunnels.is_empty() {
                            view! {
                                <div class="no-tunnels">
                                    <p>"No active tunnels"</p>
                                    <small>"Tunnels will appear here when clients connect"</small>
                                </div>
                            }.into_any()
                        } else {
                            view! {
                                <div class="tunnels-grid">
                                    {m.tunnels.iter().map(|tunnel| {
                                        view! {
                                            <TunnelCard tunnel=tunnel.clone() admin_token=admin_token/>
                                        }
                                    }).collect::<Vec<_>>()}
                                </div>
                            }.into_any()
                        }
                    }
                    None => view! {
                        <div class="tunnels-grid">
                            <div class="tunnel-card">
                                <div class="tunnel-header">
                                    <h4 class="tunnel-id loading-skeleton">""</h4>
                                    <div class="tunnel-status">
                                        <span class="status-indicator loading-skeleton">""</span>
                                    </div>
                                </div>
                                <div class="tunnel-metrics">
                                    <div class="metric-row">
                                        <span class="label">"Requests:"</span>
                                        <span class="value loading-skeleton">""</span>
                                    </div>
                                    <div class="metric-row">
                                        <span class="label">"HTTP Traffic:"</span>
                                        <span class="value loading-skeleton">""</span>
                                    </div>
                                    <div class="metric-row">
                                        <span class="label">"WebSocket Traffic:"</span>
                                        <span class="value loading-skeleton">""</span>
                                    </div>
                                    <div class="metric-row">
                                        <span class="label">"Last Activity:"</span>
                                        <span class="value loading-skeleton">""</span>
                                    </div>
                                </div>
                            </div>
                            <div class="tunnel-card">
                                <div class="tunnel-header">
                                    <h4 class="tunnel-id loading-skeleton">""</h4>
                                    <div class="tunnel-status">
                                        <span class="status-indicator loading-skeleton">""</span>
                                    </div>
                                </div>
                                <div class="tunnel-metrics">
                                    <div class="metric-row">
                                        <span class="label">"Requests:"</span>
                                        <span class="value loading-skeleton">""</span>
                                    </div>
                                    <div class="metric-row">
                                        <span class="label">"HTTP Traffic:"</span>
                                        <span class="value loading-skeleton">""</span>
                                    </div>
                                    <div class="metric-row">
                                        <span class="label">"WebSocket Traffic:"</span>
                                        <span class="value loading-skeleton">""</span>
                                    </div>
                                    <div class="metric-row">
                                        <span class="label">"Last Activity:"</span>
                                        <span class="value loading-skeleton">""</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    }.into_any()
                }
            }}
        </div>
    }
}

#[component]
pub fn TunnelCard(
    tunnel: TunnelMetrics,
    admin_token: ReadSignal<String>,
) -> impl IntoView {
    let tunnel_id = tunnel.tunnel_id.clone();
    let (disconnecting, set_disconnecting) = signal(false);
    let (disconnect_error, set_disconnect_error) = signal::<Option<String>>(None);

    let disconnect_tunnel = move |_| {
        let tunnel_id = tunnel_id.clone();
        let token = admin_token.get();

        if token.is_empty() {
            set_disconnect_error.set(Some("Admin token required".to_string()));
            return;
        }

        set_disconnecting.set(true);
        set_disconnect_error.set(None);

        leptos::task::spawn_local(async move {
            match disconnect_tunnel_request(&tunnel_id, &token).await {
                Ok(_) => {
                    set_disconnecting.set(false);
                }
                Err(e) => {
                    set_disconnect_error.set(Some(format!("Failed to disconnect: {}", e)));
                    set_disconnecting.set(false);
                }
            }
        });
    };

    view! {
        <div class="tunnel-card">
            <div class="tunnel-header">
                <h4 class="tunnel-id">{tunnel.tunnel_id.clone()}</h4>
                <div class="tunnel-status">
                    <span class="status-indicator status-connected">"● Connected"</span>
                </div>
            </div>

            <div class="tunnel-metrics">
                <div class="metric-row">
                    <span class="label">"Requests:"</span>
                    <span class="value">{format_number(tunnel.requests_count)}</span>
                </div>
                <div class="metric-row">
                    <span class="label">"HTTP Traffic:"</span>
                    <span class="value">{format_bytes(tunnel.bytes_in + tunnel.bytes_out)}</span>
                </div>
                <div class="metric-row">
                    <span class="label">"WebSocket Traffic:"</span>
                    <span class="value">{format_bytes(tunnel.websocket_bytes_in + tunnel.websocket_bytes_out)}</span>
                </div>
                <div class="metric-row">
                    <span class="label">"WebSocket Connections:"</span>
                    <span class="value">{tunnel.websocket_connections}</span>
                </div>
                <div class="metric-row">
                    <span class="label">"Errors:"</span>
                    <span class={if tunnel.error_count > 0 { "value status-error" } else { "value" }}>
                        {tunnel.error_count}
                    </span>
                </div>
                <div class="metric-row">
                    <span class="label">"Last Activity:"</span>
                    <span class="value">{format_timestamp(tunnel.last_activity)}</span>
                </div>
            </div>

            <div class="tunnel-actions">
                {move || {
                    if admin_token.get().is_empty() {
                        view! {
                            <div class="admin-required">
                                <p>"Admin access required for tunnel actions"</p>
                                <a href="/admin" class="admin-link">"Go to Admin Page →"</a>
                            </div>
                        }.into_any()
                    } else {
                        let disconnect_tunnel = disconnect_tunnel.clone();
                        view! {
                            <button
                                class="disconnect-btn"
                                disabled={move || disconnecting.get()}
                                on:click=disconnect_tunnel
                            >
                                {move || if disconnecting.get() { "Disconnecting..." } else { "Disconnect Tunnel" }}
                            </button>
                        }.into_any()
                    }
                }}

                {move || {
                    disconnect_error.get().map(|err| view! {
                        <div class="action-error">
                            {err}
                        </div>
                    })
                }}
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

fn format_timestamp(timestamp: u64) -> String {
    if timestamp == 0 {
        "Never".to_string()
    } else {
        let now = js_sys::Date::now() as u64 / 1000;
        let elapsed = if now > timestamp { now - timestamp } else { 0 };

        if elapsed < 60 {
            "Just now".to_string()
        } else if elapsed < 3600 {
            let minutes = elapsed / 60;
            if minutes == 1 {
                "1 minute ago".to_string()
            } else {
                format!("{} minutes ago", minutes)
            }
        } else if elapsed < 86400 {
            let hours = elapsed / 3600;
            if hours == 1 {
                "1 hour ago".to_string()
            } else {
                format!("{} hours ago", hours)
            }
        } else {
            let days = elapsed / 86400;
            if days == 1 {
                "1 day ago".to_string()
            } else {
                format!("{} days ago", days)
            }
        }
    }
}