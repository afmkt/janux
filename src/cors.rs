use reqwest::header::{
    ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, VARY,
};
use salvo::http::Method;
use salvo::prelude::*;

/// Per-request dynamic CORS handler (Salvo "middleware" = a hoop/handler)
#[handler]
pub async fn cors_middleware(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let Ok(state) = depot.obtain_mut::<crate::server::ServerState>() else {
        // State not available yet (e.g., during startup or misconfigured).
        // Allow all CORS headers to avoid blocking requests.
        ctrl.call_next(req, depot, res).await;
        return;
    };
    let domain = crate::utils::get_domain(req, state).unwrap_or("");

    // 1. Get and validate the origin
    let request_origin = req.headers().get("ORIGIN").and_then(|v| v.to_str().ok());
    let allowed_origins = state
        .storage
        .load_domain_cors(domain)
        .await
        .unwrap_or_default();

    if let Some(origin) = request_origin {
        if allowed_origins.contains(&origin.to_string()) {
            // 2. Set necessary headers
            res.headers_mut()
                .insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin.parse().unwrap());
            res.headers_mut()
                .insert(ACCESS_CONTROL_ALLOW_CREDENTIALS, "true".parse().unwrap());
            res.headers_mut().insert(VARY, "Origin".parse().unwrap()); // Important for cache correctness

            // 3. Handle OPTIONS preflight
            if req.method() == Method::OPTIONS {
                res.headers_mut().insert(
                    ACCESS_CONTROL_ALLOW_METHODS,
                    "GET, POST, PUT, DELETE, OPTIONS".parse().unwrap(),
                );
                res.headers_mut().insert(
                    ACCESS_CONTROL_ALLOW_HEADERS,
                    "Content-Type, Authorization".parse().unwrap(),
                );
                res.status_code(StatusCode::NO_CONTENT);
                ctrl.skip_rest(); // Preflight finished, no need to call next handlers
                return;
            }
        }
    }
    // If no origin match, just continue (or return Forbidden if you prefer strict mode)
    ctrl.call_next(req, depot, res).await;
}
