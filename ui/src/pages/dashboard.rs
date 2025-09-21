use leptos::prelude::*;
use wasm_bindgen::prelude::*;
use wasm_bindgen::JsCast;
use crate::api::*;
use crate::types::*;

#[component]
pub fn Dashboard() -> impl IntoView {
    // Reactive signals for dashboard data
    let (health, set_health) = signal::<Option<HealthResponse>>(None);
    let (metrics, set_metrics) = signal::<Option<MetricsResponse>>(None);
    let (error, set_error) = signal::<Option<String>>(None);
    let (connected, set_connected) = signal(false);

    // Load initial data
    Effect::new(move |_| {
        leptos::task::spawn_local(async move {
            match fetch_health().await {
                Ok(health_data) => {
                    set_health.set(Some(health_data));
                    set_error.set(None);
                }
                Err(e) => set_error.set(Some(format!("Failed to load health: {}", e))),
            }

            match fetch_metrics().await {
                Ok(metrics_data) => {
                    set_metrics.set(Some(metrics_data));
                    set_connected.set(true);
                }
                Err(e) => set_error.set(Some(format!("Failed to load metrics: {}", e))),
            }
        });
    });

    // Setup live metrics stream with proper lifecycle management
    Effect::new(move |_| {
        if let Ok(event_source) = create_metrics_stream() {
            // Clone signals that will be moved into closures to avoid disposal issues
            let set_metrics_clone = set_metrics;
            let set_connected_clone = set_connected;
            let set_error_clone = set_error;

            // Create Leptos callback for metrics updates
            let metrics_callback = Callback::new(move |new_metrics: MetricsResponse| {
                set_metrics_clone.set(Some(new_metrics));
                set_connected_clone.set(true);
                set_error_clone.set(None);
            });

            // Setup SSE listener with panic-safe error handling
            let listener = setup_sse_listener(&event_source, metrics_callback);

            // Handle connection errors with cloned signals and panic safety
            let set_connected_err = set_connected;
            let set_error_err = set_error;
            let error_callback = Closure::wrap(Box::new(move |_: web_sys::Event| {
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    set_connected_err.set(false);
                    set_error_err.set(Some("Lost connection to server".to_string()));
                }));

                if result.is_err() {
                    web_sys::console::warn_1(&"SSE error callback failed (likely component disposed)".into());
                }
            }) as Box<dyn Fn(web_sys::Event)>);

            event_source.set_onerror(Some(error_callback.as_ref().unchecked_ref()));

            // Store the closures so they don't get dropped immediately
            // This approach avoids the "forget" pattern which was causing issues
            std::mem::forget(listener);
            std::mem::forget(error_callback);
        }
    });

    view! {
        <div class="max-w-7xl mx-auto">
            <header class="mb-8">
                <h1 class="text-3xl font-bold text-gray-900">"Dashboard"</h1>
                <p class="text-gray-600 mt-2">"Real-time server metrics and status overview"</p>
            </header>

            <div class="space-y-6">
                <ConnectionStatus connected=connected/>
                <ErrorDisplay error=error/>

                <div class="space-y-6">
                    <div class="grid grid-cols-1 lg:grid-cols-3 gap-6">
                        <ServerStatus health=health/>
                        <LiveMetrics metrics=metrics/>
                        <CertificateStatus health=health/>
                    </div>

                    // Add traffic visualization
                    <crate::components::TrafficChart metrics=metrics/>
                </div>
            </div>
        </div>
    }
}

#[component]
pub fn ConnectionStatus(connected: ReadSignal<bool>) -> impl IntoView {
    view! {
        <div class="connection-status">
            <span class={move || if connected.get() { "status-connected" } else { "status-disconnected" }}>
                {move || if connected.get() { "● Connected" } else { "● Disconnected" }}
            </span>
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

#[component]
pub fn ServerStatus(health: ReadSignal<Option<HealthResponse>>) -> impl IntoView {
    view! {
        <div class="metric-card">
            <h3>"Server Status"</h3>
            <div class="metric-content">
                {move || {
                    match health.get() {
                        Some(h) => view! {
                            <div class="metric-row">
                                <span class="label">"Status:"</span>
                                <span class="value status-ok">{h.status}</span>
                            </div>
                            <div class="metric-row">
                                <span class="label">"Version:"</span>
                                <span class="value">{h.version}</span>
                            </div>
                            <div class="metric-row">
                                <span class="label">"Domain:"</span>
                                <span class="value">{h.domain}</span>
                            </div>
                            <div class="metric-row">
                                <span class="label">"SSL Enabled:"</span>
                                <span class={if h.ssl_enabled { "value status-ok" } else { "value status-error" }}>
                                    {if h.ssl_enabled { "Yes" } else { "No" }}
                                </span>
                            </div>
                        }.into_any(),
                        None => view! {
                            <div class="metric-row">
                                <span class="label"></span>
                                <span class="value">"Loading..."</span>
                            </div>
                            <div class="metric-row">
                                <span class="label"></span>
                                <span class="value"></span>
                            </div>
                            <div class="metric-row">
                                <span class="label"></span>
                                <span class="value"></span>
                            </div>
                            <div class="metric-row">
                                <span class="label"></span>
                                <span class="value"></span>
                            </div>
                        }.into_any(),
                    }
                }}
            </div>
        </div>
    }
}

#[component]
pub fn LiveMetrics(metrics: ReadSignal<Option<MetricsResponse>>) -> impl IntoView {
    view! {
        <div class="metric-card">
            <h3>"Live Metrics"</h3>
            <div class="metric-content">
                {move || {
                    match metrics.get() {
                        Some(m) => view! {
                            <div class="metric-row">
                                <span class="label">"Active Tunnels:"</span>
                                <span class="value metric-highlight">{m.server.active_tunnels}</span>
                            </div>
                            <div class="metric-row">
                                <span class="label">"Total Requests:"</span>
                                <span class="value">{format_number(m.server.total_requests)}</span>
                            </div>
                            <div class="metric-row">
                                <span class="label">"Total Data In:"</span>
                                <span class="value">{format_bytes(m.server.total_bytes_in + m.server.websocket_bytes_in)}</span>
                            </div>
                            <div class="metric-row">
                                <span class="label">"Total Data Out:"</span>
                                <span class="value">{format_bytes(m.server.total_bytes_out + m.server.websocket_bytes_out)}</span>
                            </div>
                            <div class="metric-row">
                                <span class="label">"HTTP Traffic:"</span>
                                <span class="value">{format_bytes(m.server.total_bytes_in + m.server.total_bytes_out)}</span>
                            </div>
                            <div class="metric-row">
                                <span class="label">"WebSocket Traffic:"</span>
                                <span class="value">{format_bytes(m.server.websocket_bytes_in + m.server.websocket_bytes_out)}</span>
                            </div>
                            <div class="metric-row">
                                <span class="label">"WebSocket Connections:"</span>
                                <span class="value">{m.server.websocket_connections}</span>
                            </div>
                            <div class="metric-row">
                                <span class="label">"Server Uptime:"</span>
                                <span class="value">{format_uptime(m.server.uptime_seconds)}</span>
                            </div>
                        }.into_any(),
                        None => view! {
                            <div class="metric-row">
                                <span class="label"></span>
                                <span class="value">"Loading..."</span>
                            </div>
                            <div class="metric-row">
                                <span class="label"></span>
                                <span class="value"></span>
                            </div>
                            <div class="metric-row">
                                <span class="label"></span>
                                <span class="value"></span>
                            </div>
                            <div class="metric-row">
                                <span class="label"></span>
                                <span class="value"></span>
                            </div>
                            <div class="metric-row">
                                <span class="label"></span>
                                <span class="value"></span>
                            </div>
                            <div class="metric-row">
                                <span class="label"></span>
                                <span class="value"></span>
                            </div>
                            <div class="metric-row">
                                <span class="label"></span>
                                <span class="value"></span>
                            </div>
                        }.into_any(),
                    }
                }}
            </div>
        </div>
    }
}

#[component]
pub fn CertificateStatus(health: ReadSignal<Option<HealthResponse>>) -> impl IntoView {
    view! {
        <div class="metric-card">
            <h3>"System Status"</h3>
            <div class="metric-content">
                {move || {
                    match health.get() {
                        Some(h) => view! {
                            <div class="metric-row">
                                <span class="label">"SSL Enabled:"</span>
                                <span class={if h.ssl_enabled { "value status-ok" } else { "value status-error" }}>
                                    {if h.ssl_enabled { "Yes" } else { "No" }}
                                </span>
                            </div>
                            <div class="metric-row">
                                <span class="label">"Uptime Check:"</span>
                                <span class={if h.uptime_check == "OK" { "value status-ok" } else { "value status-error" }}>
                                    {h.uptime_check.clone()}
                                </span>
                            </div>
                            <div class="metric-row">
                                <span class="label">"Errors:"</span>
                                <span class={if h.errors.is_empty() { "value status-ok" } else { "value status-error" }}>
                                    {if h.errors.is_empty() { "-".to_string() } else { h.errors.len().to_string() }}
                                </span>
                            </div>
                            <div class="metric-row">
                                <span class="label">"Warnings:"</span>
                                <span class={if h.warnings.is_empty() { "value status-ok" } else { "value status-warning" }}>
                                    {if h.warnings.is_empty() { "-".to_string() } else { h.warnings.len().to_string() }}
                                </span>
                            </div>
                        }.into_any(),
                        None => view! {
                            <div class="metric-row">
                                <span class="label"></span>
                                <span class="value">"Loading..."</span>
                            </div>
                            <div class="metric-row">
                                <span class="label"></span>
                                <span class="value"></span>
                            </div>
                            <div class="metric-row">
                                <span class="label"></span>
                                <span class="value"></span>
                            </div>
                            <div class="metric-row">
                                <span class="label"></span>
                                <span class="value"></span>
                            </div>
                        }.into_any(),
                    }
                }}
            </div>
        </div>
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