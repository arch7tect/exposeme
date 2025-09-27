use leptos::prelude::*;

#[component]
pub fn AdminPage() -> impl IntoView {
    // Get global admin token from context
    let admin_token = use_context::<ReadSignal<String>>()
        .expect("Admin token signal should be provided in context");
    let set_admin_token = use_context::<WriteSignal<String>>()
        .expect("Admin token setter should be provided in context");

    view! {
        <div class="page admin-page">
            <header class="page-header">
                <h1>"Admin Authentication"</h1>
                <p>"Manage admin access for tunnel and certificate operations"</p>
            </header>

            <div class="page-content">
                <div class="admin-main-section">
                    <div class="admin-auth-section">
                        <h3>"Admin Access Control"</h3>
                        <p>"Enter your admin token to enable administrative functions across the dashboard:"</p>
                        <div class="admin-token-input">
                            <input
                                type="password"
                                placeholder="Enter admin token..."
                                value={move || admin_token.get()}
                                on:input=move |ev| {
                                    set_admin_token.set(event_target_value(&ev));
                                }
                                class="token-input"
                            />
                            <div class="token-status">
                                {move || {
                                    if admin_token.get().is_empty() {
                                        view! { <span class="status-inactive">"No token provided"</span> }
                                    } else {
                                        view! { <span class="status-active">"Token entered (admin actions enabled)"</span> }
                                    }
                                }}
                            </div>
                        </div>
                    </div>

                    <div class="bg-white rounded-xl p-6 shadow-sm border border-gray-200 mb-6">
                        <h3 class="text-lg font-semibold mb-4 text-gray-900">"Admin Capabilities"</h3>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
                            <div class="bg-gray-50 border border-gray-200 rounded-lg p-4 hover:border-gray-300 hover:shadow-sm transition-all duration-200">
                                <h4 class="text-base font-semibold mb-2 text-gray-900 flex items-center gap-2">"🔌 Tunnel Management"</h4>
                                <p class="text-gray-600 text-sm mb-3 leading-relaxed">"Disconnect active tunnels"</p>
                                <div class="mb-3">
                                    {move || {
                                        if admin_token.get().is_empty() {
                                            view! { <span class="text-gray-400 font-medium text-sm">"❌ Disabled"</span> }
                                        } else {
                                            view! { <span class="text-green-600 font-medium text-sm">"✅ Enabled"</span> }
                                        }
                                    }}
                                </div>
                                <div class="pt-2 border-t border-gray-200">
                                    <a href="/tunnels" class="text-blue-600 hover:text-blue-700 text-sm font-medium inline-flex items-center gap-1 hover:underline transition-colors">"→ Manage Tunnels"</a>
                                </div>
                            </div>

                            <div class="bg-gray-50 border border-gray-200 rounded-lg p-4 hover:border-gray-300 hover:shadow-sm transition-all duration-200">
                                <h4 class="text-base font-semibold mb-2 text-gray-900 flex items-center gap-2">"🔒 Certificate Management"</h4>
                                <p class="text-gray-600 text-sm mb-3 leading-relaxed">"Force certificate renewal"</p>
                                <div class="mb-3">
                                    {move || {
                                        if admin_token.get().is_empty() {
                                            view! { <span class="text-gray-400 font-medium text-sm">"❌ Disabled"</span> }
                                        } else {
                                            view! { <span class="text-green-600 font-medium text-sm">"✅ Enabled"</span> }
                                        }
                                    }}
                                </div>
                                <div class="pt-2 border-t border-gray-200">
                                    <a href="/certificates" class="text-blue-600 hover:text-blue-700 text-sm font-medium inline-flex items-center gap-1 hover:underline transition-colors">"→ Manage Certificates"</a>
                                </div>
                            </div>
                        </div>
                    </div>

                </div>
            </div>
        </div>
    }
}