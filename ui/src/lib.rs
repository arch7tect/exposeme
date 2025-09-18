use leptos::prelude::*;
use leptos_meta::*;
use wasm_bindgen::prelude::wasm_bindgen;

mod dashboard;
mod api;
mod types;

use dashboard::Dashboard;

#[component]
pub fn App() -> impl IntoView {
    provide_meta_context();

    view! {
        <Title text="ExposeME Dashboard"/>
        <Meta name="description" content="ExposeME Tunneling Server Dashboard"/>
        <Meta name="viewport" content="width=device-width, initial-scale=1"/>
        
        <main class="app">
            <Dashboard/>
        </main>
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