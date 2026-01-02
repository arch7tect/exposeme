
use crate::svc::{BoxError, ChallengeStore};
use crate::svc::types::ResponseBody;
use crate::svc::utils::boxed_body;
use hyper::{Request, Response, StatusCode, body::Incoming};
use tracing::{info, warn};

/// Handle ACME challenge requests for Let's Encrypt certificate validation
pub async fn handle_acme_challenge(
    req: Request<Incoming>,
    challenge_store: ChallengeStore,
) -> Result<Response<ResponseBody>, BoxError> {
    let path = req.uri().path();
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("unknown");

    info!(
        event = "acme.challenge.request",
        path,
        method = %req.method(),
        user_agent,
        remote_ip = ?req.headers().get("x-forwarded-for"),
        "ACME challenge request received."
    );

    if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
        info!(
            event = "acme.challenge.token",
            token,
            "ACME challenge token extracted."
        );

        let store = challenge_store.read().await;
        info!(
            event = "acme.challenge.tokens",
            tokens = ?store.keys().collect::<Vec<_>>(),
            "ACME challenge tokens listed."
        );

        if let Some(key_auth) = store.get(token) {
            info!(event = "acme.challenge.found", token, "ACME challenge found in store.");
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain")
                .body(boxed_body(key_auth.clone()))
                .unwrap());
        } else {
            warn!(
                event = "acme.challenge.missing",
                token,
                "ACME challenge not found in store."
            );
        }
    } else {
        warn!(
            event = "acme.challenge.invalid_path",
            path,
            "ACME challenge request had an invalid path."
        );
    }

    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(boxed_body("ACME challenge not found"))
        .unwrap())
}
