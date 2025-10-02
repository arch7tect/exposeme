use leptos::prelude::*;
use crate::types::*;

#[component]
pub fn Footer(health: ReadSignal<Option<HealthResponse>>) -> impl IntoView {
    view! {
        <footer class="bg-gray-50 border-t border-gray-200 mt-auto">
            <div class="max-w-7xl mx-auto py-4 px-4 sm:px-6 lg:px-8">
                <div class="flex flex-col sm:flex-row justify-between items-center space-y-2 sm:space-y-0">
                    <div class="flex items-center space-x-4 text-sm text-gray-600">
{move || {
                            match health.get() {
                                Some(h) => view! {
                                    <div class="flex items-center space-x-4">
                                        <span>
                                            "ExposeME Server v" {h.version.clone()}
                                        </span>
                                        <span class="text-gray-400">"|"</span>
                                        <span>
                                            "Status: "
                                            <span class="font-medium text-green-600">{h.status.clone()}</span>
                                        </span>
                                    </div>
                                }.into_any(),
                                None => view! {
                                    <div class="flex items-center space-x-4">
                                        <span>"Loading server info..."</span>
                                    </div>
                                }.into_any()
                            }
                        }}
                    </div>

                    <div class="flex items-center space-x-4 text-sm text-gray-500">
                        <span>
                            "Built with "
                            <span class="font-medium text-blue-600">"Rust + WASM"</span>
                        </span>
                        <span class="text-gray-400">"|"</span>
                        <span>
                            {js_sys::Date::new_0().to_iso_string().as_string()
                                .unwrap_or_else(|| "2024-01-01".to_string())
                                .chars().take(10).collect::<String>()}
                        </span>
                    </div>
                </div>

                <div class="mt-2 pt-2 border-t border-gray-200 text-xs text-center text-gray-400">
                    "Real-time tunnel monitoring and SSL certificate management"
                </div>
            </div>
        </footer>
    }
}