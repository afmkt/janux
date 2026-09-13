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

    // `origin` came through `HeaderValue::to_str()` above, so it is
    // visible ASCII and this parse cannot fail today; the guard keeps
    // that invariant local. If a future edit echoes a configured
    // allow-list value instead of the request's own origin, an
    // unparsable value skips the CORS headers fail-closed (the request
    // continues below) instead of panicking the task.
    if let Some(origin) = request_origin
        && allowed_origins.contains(&origin.to_string())
        && let Ok(origin_value) = origin.parse::<salvo::http::HeaderValue>()
    {
        // 2. Set necessary headers
        res.headers_mut()
            .insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin_value);
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

    // If no origin match, just continue (or return Forbidden if you prefer strict mode)
    ctrl.call_next(req, depot, res).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    const DOMAIN: &str = "localhost";
    const ALLOWED: &str = "https://app.example.com";

    async fn cors_test_env() -> (crate::server::ServerState, tempfile::TempDir) {
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = crate::db::Storage::init(tmp.path())
            .await
            .expect("storage init");
        storage.new_tenant("test-tenant").await.expect("tenant");
        storage
            .add_domain(DOMAIN, "test-tenant")
            .await
            .expect("domain");
        storage
            .domain_cors(DOMAIN, vec![ALLOWED.to_string()])
            .await
            .expect("cors allow-list");
        let state = crate::server::ServerState::create_with(storage, false, &[], false)
            .await
            .expect("server state");
        (state, tmp)
    }

    #[handler]
    async fn ping(res: &mut Response) {
        res.render("pong");
    }

    fn cors_service(state: crate::server::ServerState) -> Service {
        Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state))
                .hoop(cors_middleware)
                .push(Router::with_path("ping").get(ping)),
        )
    }

    /// regression: an allow-listed origin is echoed with the CORS
    /// headers; an Origin that cannot round-trip a header value
    /// (non-ASCII obs-text) is filtered by `to_str` and skips the echo
    /// fail-closed — no panic, no `Access-Control-Allow-Origin`, and the
    /// request still runs; an origin missing from the allow-list gets
    /// nothing either.
    #[tokio::test]
    async fn cors_origin_echo_fails_closed() {
        let (state, _tmp) = cors_test_env().await;
        let service = cors_service(state);

        let res = salvo::test::TestClient::get("http://localhost/ping")
            .add_header("Host", DOMAIN, true)
            .add_header("Origin", ALLOWED, true)
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("status code"), StatusCode::OK);
        assert_eq!(
            res.headers()
                .get(ACCESS_CONTROL_ALLOW_ORIGIN)
                .and_then(|v| v.to_str().ok()),
            Some(ALLOWED),
            "an allow-listed origin must be echoed"
        );
        assert!(
            res.headers()
                .get(ACCESS_CONTROL_ALLOW_CREDENTIALS)
                .is_some()
                && res.headers().get(VARY).is_some(),
            "the echo carries credentials and Vary"
        );

        let res = salvo::test::TestClient::get("http://localhost/ping")
            .add_header("Host", DOMAIN, true)
            .add_header("Origin", "https://app.example.com/é", true)
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("status code"), StatusCode::OK);
        assert!(
            res.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).is_none(),
            "an origin that cannot round-trip a header value must skip CORS fail-closed"
        );

        let res = salvo::test::TestClient::get("http://localhost/ping")
            .add_header("Host", DOMAIN, true)
            .add_header("Origin", "https://evil.example.com", true)
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("status code"), StatusCode::OK);
        assert!(
            res.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN).is_none(),
            "an origin missing from the allow-list gets no CORS headers"
        );
    }
}
