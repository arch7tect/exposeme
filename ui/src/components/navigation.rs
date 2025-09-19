use leptos::prelude::*;
use leptos_router::components::A;

#[component]
pub fn Navigation() -> impl IntoView {
    view! {
        <nav class="navigation">
            <div class="nav-header">
                <h1 class="nav-title">"ExposeME"</h1>
                <span class="nav-subtitle">"Tunneling Dashboard"</span>
            </div>

            <ul class="nav-menu">
                <li class="nav-item">
                    <A href="/" attr:class="nav-link">
                        <span class="nav-icon">"📊"</span>
                        <span class="nav-text">"Dashboard"</span>
                    </A>
                </li>
                <li class="nav-item">
                    <A href="/tunnels" attr:class="nav-link">
                        <span class="nav-icon">"🔌"</span>
                        <span class="nav-text">"Tunnels"</span>
                    </A>
                </li>
                <li class="nav-item">
                    <A href="/certificates" attr:class="nav-link">
                        <span class="nav-icon">"🔒"</span>
                        <span class="nav-text">"Certificates"</span>
                    </A>
                </li>
                <li class="nav-item">
                    <A href="/settings" attr:class="nav-link">
                        <span class="nav-icon">"⚙️"</span>
                        <span class="nav-text">"Settings"</span>
                    </A>
                </li>
            </ul>
        </nav>
    }
}