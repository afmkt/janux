//! E2E regression tests for unified host resolution (G-5/G-6 fixes).
//!
//! The shared test server runs with `trust_forwarded_headers = false` (the default),
//! so `X-Forwarded-*` headers must never influence tenant resolution. The
//! discovery endpoint is used as the probe — no authentication involved.
//! Tier-A discovery: registered domains get the full document
//! (`janux_provisioned: true`); unregistered hosts get a request-derived
//! skeleton (`janux_provisioned: false`, no factors) instead of a 404, so
//! the probe now asserts on the issuer the document carries — a spoofed
//! forwarded header must never steer it.

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
    let doc: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(doc["janux_provisioned"], serde_json::json!(true));
    assert_eq!(doc["issuer"], serde_json::json!("http://localhost"));
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
    // Tier-A answers 200 for ANY host, so the status alone no longer
    // proves resolution — the document must be the provisioned one. The
    // non-default test port is deliberately kept in the issuer (only the
    // scheme's default port is stripped).
    let doc: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(
        doc["janux_provisioned"],
        serde_json::json!(true),
        "Host with port must strip to the registered `localhost` domain"
    );
    assert_eq!(
        doc["issuer"],
        serde_json::json!(format!("http://localhost:{port}"))
    );
}

/// G-6 regression: with `trust_forwarded_headers = false` a spoofed
/// `X-Forwarded-Host` must not steer tenant resolution. The unknown Host
/// wins, so the Tier-A skeleton must carry the evil host's issuer and stay
/// unprovisioned even though XFH names a valid tenant.
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

    assert_eq!(resp.status(), 200, "Tier-A discovery always answers");
    let doc: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(
        doc["janux_provisioned"],
        serde_json::json!(false),
        "the spoofed XFH tenant must not be resolved"
    );
    assert_eq!(
        doc["issuer"],
        serde_json::json!("http://evil.example.com"),
        "X-Forwarded-Host must be ignored when trust_forwarded_headers is false"
    );
}

/// Unknown Host without any forwarding headers gets the Tier-A skeleton:
/// request-derived issuer, no factors, `janux_provisioned: false`.
#[tokio::test]
async fn unknown_host_gets_unprovisioned_skeleton() {
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

    assert_eq!(resp.status(), 200);
    let doc: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(doc["janux_provisioned"], serde_json::json!(false));
    assert_eq!(
        doc["issuer"],
        serde_json::json!("http://unknown.example.com")
    );
    assert_eq!(
        doc["janux_factors"],
        serde_json::json!({}),
        "an unprovisioned host must not advertise any factor"
    );
    assert_eq!(doc["acr_values_supported"], serde_json::json!([]));
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
    // Status alone is vacuous under Tier A (any host gets a 200 skeleton):
    // the document must be the PROVISIONED one for the XFH-named tenant.
    let doc: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(
        doc["janux_provisioned"],
        serde_json::json!(true),
        "trusted mode must resolve the tenant from X-Forwarded-Host"
    );
    assert_eq!(doc["issuer"], serde_json::json!("http://localhost"));
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
    // The fallback must land on the REGISTERED Host tenant, not the Tier-A
    // skeleton — status alone cannot tell those apart anymore.
    let doc: serde_json::Value = resp.json().await.expect("json");
    assert_eq!(doc["janux_provisioned"], serde_json::json!(true));
    assert_eq!(doc["issuer"], serde_json::json!("http://localhost"));
}
