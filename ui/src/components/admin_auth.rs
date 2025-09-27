use leptos::prelude::*;

#[component]
pub fn AdminAuth(
    #[prop(into)] admin_token: ReadSignal<String>,
    #[prop(into)] set_admin_token: WriteSignal<String>,
    #[prop(optional)] title: Option<String>,
    #[prop(optional)] description: Option<String>,
) -> impl IntoView {
    let title = title.unwrap_or_else(|| "Admin Authentication".to_string());
    let description = description.unwrap_or_else(|| "Enter admin token to enable admin actions:".to_string());

    view! {
        <div class="admin-auth-section">
            <h3>{title}</h3>
            <p>{description}</p>
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
    }
}