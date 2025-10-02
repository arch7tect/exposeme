
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

    info!("ACME challenge request received");
    info!("   Path: {}", path);
    info!("   Method: {}", req.method());
    info!("   User-Agent: {}", user_agent);
    info!("   Remote IP: {:?}", req.headers().get("x-forwarded-for"));

    if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
        info!("ACME challenge request for token: {}", token);

        let store = challenge_store.read().await;
        info!(
            "Available challenge tokens: {:?}",
            store.keys().collect::<Vec<_>>()
        );

        if let Some(key_auth) = store.get(token) {
            info!("ACME challenge found, responding with key authorization");
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", "text/plain")
                .body(boxed_body(key_auth.clone()))
                .unwrap());
        } else {
            warn!("ACME challenge not found for token: {}", token);
        }
    } else {
        warn!("Invalid ACME challenge path: {}", path);
    }

    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(boxed_body("ACME challenge not found"))
        .unwrap())
}