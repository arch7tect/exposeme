use leptos::prelude::*;
use crate::types::*;

#[component]
pub fn Header(
    health: ReadSignal<Option<HealthResponse>>,
    connected: ReadSignal<bool>
) -> impl IntoView {
    view! {
        <header class="bg-white shadow-sm border-b border-gray-200 sticky top-0 z-50">
            <div class="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
                <div class="flex justify-between items-center h-16">
                    // Logo and title section
                    <div class="flex items-center space-x-4">
                        <div class="flex items-center space-x-3">
                            // ExposeME Logo (using emoji as placeholder)
                            <div class="w-8 h-8 bg-gradient-to-br from-blue-500 to-blue-600 rounded-lg flex items-center justify-center">
                                <span class="text-white text-lg font-bold">"E"</span>
                            </div>
                            <div>
                                <h1 class="text-xl font-bold text-gray-900">"ExposeME"</h1>
                                <p class="text-xs text-gray-500">"Tunnel Management Dashboard"</p>
                            </div>
                        </div>
                    </div>

                    // Server info and status section
                    <div class="flex items-center space-x-6">
                        // Server info
                        {move || {
                            health.get().map(|h| view! {
                                <div class="hidden sm:flex items-center space-x-4 text-sm">
                                    <div class="text-right">
                                        <div class="font-medium text-gray-900">{h.domain.clone()}</div>
                                        <div class="text-gray-500">
                                            "v" {h.version.clone()}
                                            {if h.ssl_enabled { " • SSL Enabled" } else { " • SSL Disabled" }}
                                        </div>
                                    </div>
                                </div>
                            })
                        }}

                        // Connection status
                        <div class="flex items-center space-x-2">
                            <div class={move || {
                                if connected.get() {
                                    "w-2 h-2 bg-green-400 rounded-full animate-pulse"
                                } else {
                                    "w-2 h-2 bg-red-400 rounded-full"
                                }
                            }}></div>
                            <span class={move || {
                                if connected.get() {
                                    "text-sm font-medium text-green-600"
                                } else {
                                    "text-sm font-medium text-red-600"
                                }
                            }}>
                                {move || if connected.get() { "Connected" } else { "Disconnected" }}
                            </span>
                        </div>
                    </div>
                </div>
            </div>
        </header>
    }
}