use leptos::prelude::*;
use crate::types::*;

#[component]
pub fn TrafficChart(metrics: ReadSignal<Option<MetricsResponse>>) -> impl IntoView {
    view! {
        <div class="bg-white rounded-lg shadow-sm border border-gray-200 p-6">
            <h3 class="text-lg font-semibold text-gray-900 mb-4">"Traffic Overview"</h3>

            {move || {
                match metrics.get() {
                    Some(m) => {
                        let total_in = m.server.total_bytes_in + m.server.websocket_bytes_in;
                        let total_out = m.server.total_bytes_out + m.server.websocket_bytes_out;
                        let max_traffic = std::cmp::max(total_in, total_out) as f64;

                        let in_percentage = if max_traffic > 0.0 { (total_in as f64 / max_traffic * 100.0) as u32 } else { 0 };
                        let out_percentage = if max_traffic > 0.0 { (total_out as f64 / max_traffic * 100.0) as u32 } else { 0 };

                        view! {
                            <div class="space-y-6">
                                <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                                    <div class="p-4 bg-blue-50 rounded-lg">
                                        <h4 class="font-medium text-blue-900 mb-2">"HTTP Traffic"</h4>
                                        <div class="space-y-2">
                                            <div class="flex justify-between text-sm">
                                                <span>"In:"</span>
                                                <span class="font-mono">{format_bytes(m.server.total_bytes_in)}</span>
                                            </div>
                                            <div class="flex justify-between text-sm">
                                                <span>"Out:"</span>
                                                <span class="font-mono">{format_bytes(m.server.total_bytes_out)}</span>
                                            </div>
                                            <div class="flex justify-between text-sm font-medium">
                                                <span>"Total:"</span>
                                                <span class="font-mono">{format_bytes(m.server.total_bytes_in + m.server.total_bytes_out)}</span>
                                            </div>
                                        </div>
                                    </div>

                                    <div class="p-4 bg-green-50 rounded-lg">
                                        <h4 class="font-medium text-green-900 mb-2">"WebSocket Traffic"</h4>
                                        <div class="space-y-2">
                                            <div class="flex justify-between text-sm">
                                                <span>"In:"</span>
                                                <span class="font-mono">{format_bytes(m.server.websocket_bytes_in)}</span>
                                            </div>
                                            <div class="flex justify-between text-sm">
                                                <span>"Out:"</span>
                                                <span class="font-mono">{format_bytes(m.server.websocket_bytes_out)}</span>
                                            </div>
                                            <div class="flex justify-between text-sm font-medium">
                                                <span>"Total:"</span>
                                                <span class="font-mono">{format_bytes(m.server.websocket_bytes_in + m.server.websocket_bytes_out)}</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <div class="space-y-4">
                                    <h4 class="font-medium text-gray-900">"Traffic Distribution"</h4>

                                    <div class="space-y-3">
                                        <div>
                                            <div class="flex justify-between text-sm text-gray-600 mb-1">
                                                <span>"Data In"</span>
                                                <span class="font-mono">{format_bytes(total_in)}</span>
                                            </div>
                                            <div class="w-full bg-gray-200 rounded-full h-3">
                                                <div
                                                    class="bg-blue-500 h-3 rounded-full transition-all duration-500"
                                                    style:width=format!("{}%", in_percentage)
                                                ></div>
                                            </div>
                                        </div>

                                        <div>
                                            <div class="flex justify-between text-sm text-gray-600 mb-1">
                                                <span>"Data Out"</span>
                                                <span class="font-mono">{format_bytes(total_out)}</span>
                                            </div>
                                            <div class="w-full bg-gray-200 rounded-full h-3">
                                                <div
                                                    class="bg-green-500 h-3 rounded-full transition-all duration-500"
                                                    style:width=format!("{}%", out_percentage)
                                                ></div>
                                            </div>
                                        </div>
                                    </div>
                                </div>

                                <div class="grid grid-cols-3 gap-4 pt-4 border-t border-gray-200">
                                    <div class="text-center">
                                        <div class="text-2xl font-bold text-blue-600">{m.server.total_requests}</div>
                                        <div class="text-sm text-gray-500">"Total Requests"</div>
                                    </div>
                                    <div class="text-center">
                                        <div class="text-2xl font-bold text-green-600">{m.server.websocket_connections}</div>
                                        <div class="text-sm text-gray-500">"WebSocket Connections"</div>
                                    </div>
                                    <div class="text-center">
                                        <div class="text-2xl font-bold text-purple-600">{m.server.active_tunnels}</div>
                                        <div class="text-sm text-gray-500">"Active Tunnels"</div>
                                    </div>
                                </div>
                            </div>
                        }.into_any()
                    },
                    None => view! {
                        <div class="animate-pulse space-y-4">
                            <div class="grid grid-cols-2 gap-4">
                                <div class="h-24 bg-gray-200 rounded-lg"></div>
                                <div class="h-24 bg-gray-200 rounded-lg"></div>
                            </div>
                            <div class="space-y-3">
                                <div class="h-4 bg-gray-200 rounded"></div>
                                <div class="h-3 bg-gray-200 rounded"></div>
                                <div class="h-4 bg-gray-200 rounded"></div>
                                <div class="h-3 bg-gray-200 rounded"></div>
                            </div>
                        </div>
                    }.into_any()
                }
            }}
        </div>
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