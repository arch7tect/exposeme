use leptos::prelude::*;
use leptos_router::components::A;

#[component]
pub fn Navigation() -> impl IntoView {
    view! {
        <nav class="fixed left-0 top-16 h-full w-64 bg-white shadow-lg border-r border-gray-200 z-40">
            <div class="p-6">
                <div class="space-y-1">
                    <A href="/" attr:class="flex items-center px-4 py-3 text-sm font-medium rounded-lg hover:bg-gray-100 transition-colors text-gray-700">
                        <span class="mr-3 text-lg">"📊"</span>
                        "Dashboard"
                    </A>
                    <A href="/tunnels" attr:class="flex items-center px-4 py-3 text-sm font-medium rounded-lg hover:bg-gray-100 transition-colors text-gray-700">
                        <span class="mr-3 text-lg">"🔌"</span>
                        "Tunnels"
                    </A>
                    <A href="/certificates" attr:class="flex items-center px-4 py-3 text-sm font-medium rounded-lg hover:bg-gray-100 transition-colors text-gray-700">
                        <span class="mr-3 text-lg">"🔒"</span>
                        "Certificates"
                    </A>
                    <A href="/settings" attr:class="flex items-center px-4 py-3 text-sm font-medium rounded-lg hover:bg-gray-100 transition-colors text-gray-700">
                        <span class="mr-3 text-lg">"⚙️"</span>
                        "Settings"
                    </A>
                </div>
            </div>
        </nav>
    }
}