use leptos::prelude::*;
use crate::api::*;
use crate::types::*;

#[component]
pub fn CertificatesPage() -> impl IntoView {
    let (certificate_info, set_certificate_info) = signal::<Option<CertificateInfo>>(None);
    let (error, set_error) = signal::<Option<String>>(None);
    let (admin_token, set_admin_token) = signal(String::new());
    let (renewing, set_renewing) = signal(false);
    let (renewal_error, set_renewal_error) = signal::<Option<String>>(None);
    let (renewal_success, set_renewal_success) = signal(false);

    Effect::new(move |_| {
        leptos::task::spawn_local(async move {
            match fetch_certificate_info().await {
                Ok(cert_data) => {
                    set_certificate_info.set(Some(cert_data));
                    set_error.set(None);
                }
                Err(e) => set_error.set(Some(format!("Failed to load certificate info: {}", e))),
            }
        });
    });

    let renew_certificate = move |_| {
        let token = admin_token.get();
        if token.is_empty() {
            set_renewal_error.set(Some("Admin token required".to_string()));
            return;
        }

        set_renewing.set(true);
        set_renewal_error.set(None);
        set_renewal_success.set(false);

        leptos::task::spawn_local(async move {
            match renew_certificate_request(&token).await {
                Ok(_) => {
                    set_renewal_success.set(true);
                    set_renewing.set(false);
                }
                Err(e) => {
                    set_renewal_error.set(Some(format!("Failed to renew certificate: {}", e)));
                    set_renewing.set(false);
                }
            }
        });
    };

    view! {
        <div class="page certificates-page">
            <header class="page-header">
                <h1>"Certificate Management"</h1>
                <p>"SSL certificate status and administration"</p>
            </header>

            <div class="page-content">
                <div class="admin-auth-section">
                    <h3>"Admin Authentication"</h3>
                    <p>"Enter admin token to enable certificate management actions:"</p>
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

                {move || error.get().map(|err| view! {
                    <div class="error-banner">
                        <strong>"Error: "</strong>
                        {err}
                    </div>
                })}

                <div class="certificates-section">
                    {move || {
                        match certificate_info.get() {
                            Some(cert) => view! {
                                <div class="certificates-grid">
                                    <div class="certificate-card">
                                        <h3>"SSL Configuration"</h3>
                                        <div class="certificate-content">
                                            <div class="cert-row">
                                                <span class="label">"Domain:"</span>
                                                <span class="value">{cert.domain.clone()}</span>
                                            </div>
                                            <div class="cert-row">
                                                <span class="label">"SSL Enabled:"</span>
                                                <span class={if cert.ssl_config.enabled { "value status-ok" } else { "value status-error" }}>
                                                    {if cert.ssl_config.enabled { "✓ Enabled" } else { "✗ Disabled" }}
                                                </span>
                                            </div>
                                            <div class="cert-row">
                                                <span class="label">"Provider:"</span>
                                                <span class="value">{cert.ssl_config.provider.clone()}</span>
                                            </div>
                                            <div class="cert-row">
                                                <span class="label">"Auto Renewal:"</span>
                                                <span class={if cert.ssl_config.auto_renewal { "value status-ok" } else { "value status-warning" }}>
                                                    {if cert.ssl_config.auto_renewal { "✓ Enabled" } else { "Manual" }}
                                                </span>
                                            </div>
                                        </div>
                                    </div>

                                    {cert.certificate.as_ref().map(|cert_details| view! {
                                        <div class="certificate-card">
                                            <h3>"Certificate Status"</h3>
                                            <div class="certificate-content">
                                                <div class="cert-row">
                                                    <span class="label">"Certificate Exists:"</span>
                                                    <span class={if cert_details.exists { "value status-ok" } else { "value status-error" }}>
                                                        {if cert_details.exists { "✓ Found" } else { "✗ Not Found" }}
                                                    </span>
                                                </div>
                                                {cert_details.expiry_date.as_ref().map(|expiry| view! {
                                                    <div class="cert-row">
                                                        <span class="label">"Expires:"</span>
                                                        <span class="value">{expiry.clone()}</span>
                                                    </div>
                                                })}
                                                {cert_details.days_until_expiry.map(|days| view! {
                                                    <div class="cert-row">
                                                        <span class="label">"Days Until Expiry:"</span>
                                                        <span class={
                                                            if days <= 7 { "value status-error" }
                                                            else if days <= 30 { "value status-warning" }
                                                            else { "value status-ok" }
                                                        }>
                                                            {days.to_string()}
                                                            {if days <= 7 { " (Critical)" }
                                                             else if days <= 30 { " (Warning)" }
                                                             else { " (Good)" }}
                                                        </span>
                                                    </div>
                                                })}
                                                <div class="cert-row">
                                                    <span class="label">"Renewal Status:"</span>
                                                    <span class={if cert_details.needs_renewal { "value status-warning" } else { "value status-ok" }}>
                                                        {if cert_details.needs_renewal { "⚠️ Needs Renewal" } else { "✅ Current" }}
                                                    </span>
                                                </div>
                                            </div>
                                        </div>
                                    })}

                                    // Enhanced certificate details card
                                    <div class="certificate-card">
                                        <h3>"Certificate Details"</h3>
                                        <div class="certificate-content">
                                            <div class="cert-row">
                                                <span class="label">"Issuer:"</span>
                                                <span class="value">
                                                    {match cert.ssl_config.provider.as_str() {
                                                        "LetsEncrypt" => "Let's Encrypt (R3)",
                                                        "SelfSigned" => "Self-Signed Certificate",
                                                        "Manual" => "Custom Certificate Authority",
                                                        _ => "Unknown Certificate Authority"
                                                    }}
                                                </span>
                                            </div>
                                            <div class="cert-row">
                                                <span class="label">"Subject:"</span>
                                                <span class="value">
                                                    {if cert.ssl_config.wildcard {
                                                        format!("*.{}", cert.domain)
                                                    } else {
                                                        cert.domain.clone()
                                                    }}
                                                </span>
                                            </div>
                                            <div class="cert-row">
                                                <span class="label">"Certificate Type:"</span>
                                                <span class="value">
                                                    {if cert.ssl_config.wildcard {
                                                        "Wildcard (*.domain.com)"
                                                    } else {
                                                        "Single Domain"
                                                    }}
                                                </span>
                                            </div>
                                            <div class="cert-row">
                                                <span class="label">"Key Algorithm:"</span>
                                                <span class="value">"RSA 2048-bit"</span>
                                            </div>
                                            <div class="cert-row">
                                                <span class="label">"Signature Algorithm:"</span>
                                                <span class="value">"SHA256-RSA"</span>
                                            </div>
                                            <div class="cert-row">
                                                <span class="label">"ACME Challenge:"</span>
                                                <span class="value">
                                                    {if cert.ssl_config.wildcard {
                                                        "DNS-01 (Wildcard)"
                                                    } else {
                                                        "HTTP-01 (Single Domain)"
                                                    }}
                                                </span>
                                            </div>
                                            {cert.dns_provider.as_ref().map(|dns| view! {
                                                <div class="cert-row">
                                                    <span class="label">"DNS Provider:"</span>
                                                    <span class={if dns.configured { "value status-ok" } else { "value status-warning" }}>
                                                        {dns.provider.clone()}
                                                        {if dns.configured { " (Configured)" } else { " (Not Configured)" }}
                                                    </span>
                                                </div>
                                            })}
                                        </div>
                                    </div>

                                    <div class="certificate-card certificate-actions-card">
                                        <h3>"Certificate Actions"</h3>
                                        <div class="certificate-content">
                                            {move || {
                                                if admin_token.get().is_empty() {
                                                    view! {
                                                        <p class="admin-required">"Admin token required for certificate management"</p>
                                                    }.into_any()
                                                } else {
                                                    view! {
                                                        <div class="action-buttons">
                                                            <button
                                                                class="renew-btn"
                                                                disabled={move || renewing.get()}
                                                                on:click=renew_certificate
                                                            >
                                                                {move || if renewing.get() { "Renewing..." } else { "Force Certificate Renewal" }}
                                                            </button>
                                                        </div>
                                                    }.into_any()
                                                }
                                            }}

                                            {move || {
                                                renewal_error.get().map(|err| view! {
                                                    <div class="action-error">
                                                        <strong>"Error: "</strong>
                                                        {err}
                                                    </div>
                                                })
                                            }}

                                            {move || {
                                                if renewal_success.get() {
                                                    Some(view! {
                                                        <div class="action-success">
                                                            <strong>"Success: "</strong>
                                                            "Certificate renewal initiated. Check back in a few minutes for updated status."
                                                        </div>
                                                    })
                                                } else {
                                                    None
                                                }
                                            }}
                                        </div>
                                    </div>
                                </div>
                            }.into_any(),
                            None => view! {
                                <div class="certificates-grid">
                                    <div class="certificate-card">
                                        <h3>"SSL Configuration"</h3>
                                        <div class="certificate-content">
                                            <div class="cert-row">
                                                <span class="label">"Domain:"</span>
                                                <span class="value loading-skeleton">""</span>
                                            </div>
                                            <div class="cert-row">
                                                <span class="label">"SSL Enabled:"</span>
                                                <span class="value loading-skeleton">""</span>
                                            </div>
                                            <div class="cert-row">
                                                <span class="label">"Provider:"</span>
                                                <span class="value loading-skeleton">""</span>
                                            </div>
                                            <div class="cert-row">
                                                <span class="label">"Auto Renewal:"</span>
                                                <span class="value loading-skeleton">""</span>
                                            </div>
                                        </div>
                                    </div>
                                    <div class="certificate-card">
                                        <h3>"Certificate Status"</h3>
                                        <div class="certificate-content">
                                            <div class="cert-row">
                                                <span class="label">"Loading certificate information..."</span>
                                                <span class="value loading-skeleton">""</span>
                                            </div>
                                        </div>
                                    </div>
                                </div>
                            }.into_any()
                        }
                    }}
                </div>
            </div>
        </div>
    }
}