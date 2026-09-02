//! E2E regression tests for unified host resolution (G-5/G-6 fixes).
//!
//! The shared test server runs with `trust_forwarded_headers = false` (the default),
//! so `X-Forwarded-*` headers must never influence tenant resolution. The
//! discovery endpoint is used as the probe: it returns 200 for a registered
//! tenant domain and 404 otherwise — no authentication involved.

/// Baseline: the seeded `localhost` tenant is reachable via the Host header.
#[tokio::test]
async fn discovery_resolves_seeded_tenant_from_host() {
    let base_url = super::shared_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!(
            "{}/.well-known/openid-configuration",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "localhost")
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200, "known tenant must resolve from Host");
}

/// Browsers send `Host: localhost:<port>`; the resolver must strip the port
/// and still match the seeded `localhost` domain.
#[tokio::test]
async fn discovery_strips_port_from_host_header() {
    let base_url = super::shared_server().await;
    let port = base_url
        .rsplit(':')
        .next()
        .expect("base_url carries a port")
        .trim_end_matches('/');
    let client = reqwest::Client::new();

    let resp = client
        .get(format!(
            "{}/.well-known/openid-configuration",
            base_url.trim_end_matches('/')
        ))
        .header("Host", format!("localhost:{port}"))
        .send()
        .await
        .expect("request");

    assert_eq!(
        resp.status(),
        200,
        "Host with an explicit port must resolve to the same tenant"
    );
}

/// G-6 regression: with `trust_forwarded_headers = false` a spoofed
/// `X-Forwarded-Host` must not steer tenant resolution. The unknown Host
/// wins, so the request must 404 even though XFH names a valid tenant.
#[tokio::test]
async fn spoofed_x_forwarded_host_is_ignored_when_untrusted() {
    let base_url = super::shared_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!(
            "{}/.well-known/openid-configuration",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "evil.example.com")
        .header("X-Forwarded-Host", "localhost")
        .send()
        .await
        .expect("request");

    assert_eq!(
        resp.status(),
        404,
        "X-Forwarded-Host must be ignored when trust_forwarded_headers is false"
    );
}

/// Unknown Host without any forwarding headers resolves to no tenant.
#[tokio::test]
async fn unknown_host_is_rejected() {
    let base_url = super::shared_server().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!(
            "{}/.well-known/openid-configuration",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "unknown.example.com")
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 404);
}

// ── trust_forwarded_headers = true (proxy deployment mode) ──────────────────────────
//
// These tests start their own server with `trust_forwarded_headers = true` and kill
// it on drop; the shared server keeps the default (untrusted) configuration.

/// Trusted mode: `X-Forwarded-Host` takes precedence over `Host` — the
/// situation when a reverse proxy rewrites Host to the upstream name.
#[tokio::test]
async fn trusted_mode_prefers_x_forwarded_host() {
    let env = super::common::TestEnv::new_trust_forwarded_headers().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!(
            "{}/.well-known/openid-configuration",
            env.base_url().trim_end_matches('/')
        ))
        .header("Host", "upstream.internal")
        .header("X-Forwarded-Host", "localhost")
        .send()
        .await
        .expect("request");

    assert_eq!(
        resp.status(),
        200,
        "trusted mode must resolve the tenant from X-Forwarded-Host"
    );
}

/// Trusted mode still validates XFH against registered tenants: an unknown
/// XFH falls back to Host.
#[tokio::test]
async fn trusted_mode_falls_back_to_host_when_xfh_unknown() {
    let env = super::common::TestEnv::new_trust_forwarded_headers().await;
    let client = reqwest::Client::new();

    let resp = client
        .get(format!(
            "{}/.well-known/openid-configuration",
            env.base_url().trim_end_matches('/')
        ))
        .header("Host", "localhost")
        .header("X-Forwarded-Host", "spoofed.example.com")
        .send()
        .await
        .expect("request");

    assert_eq!(resp.status(), 200);
}
