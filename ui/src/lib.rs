use leptos::prelude::*;
use leptos_meta::*;
use leptos_router::components::*;
use leptos_router::StaticSegment;
use wasm_bindgen::prelude::wasm_bindgen;

mod pages;
mod components;
mod api;
mod types;

use pages::*;
use components::*;

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    view! {
        <Title text="ExposeME Dashboard"/>
        <Meta name="description" content="ExposeME Tunneling Server Dashboard"/>
        <Meta name="viewport" content="width=device-width, initial-scale=1"/>

        <Router>
            <div class="app">
                <Navigation/>
                <main class="app-content">
                    <Routes fallback=|| "Page not found.".into_view()>
                        <Route path=StaticSegment("") view=Dashboard/>
                        <Route path=StaticSegment("tunnels") view=TunnelsPage/>
                        <Route path=StaticSegment("certificates") view=CertificatesPage/>
                        <Route path=StaticSegment("settings") view=SettingsPage/>
                    </Routes>
                </main>
            </div>
        </Router>
    }
}

#[wasm_bindgen(start)]
pub fn main() {
    _ = console_log::init_with_level(log::Level::Debug);
    console_error_panic_hook::set_once();

    web_sys::console::log_1(&"🎨 ExposeME WASM initializing...".into());

    mount_to_body(|| view! { <App/> });

    web_sys::console::log_1(&"🎨 ExposeME App mounted!".into());
}