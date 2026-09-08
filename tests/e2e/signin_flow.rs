//! E2E test: sign-in surface contracts over HTTP.
//!
//! G-158: this file used to claim Playwright-driven form interactions
//! and assert `resp.is_ok()` — which passes on 500s. There is no browser
//! in this tier; what is pinned here is the wire contract of the hosted
//! login surface: the SPA page serves, the passwordless API refuses
//! password-shaped bodies, unauthenticated admin calls fail closed, and
//! a REAL provisioned root session can read roles through the full
//! protect → policy → handler stack.

use crate::fixtures::TestApiClient;

/// The hosted login SPA must serve at /login (the magic-link landing —
/// G-133 — and the factor picker).
#[tokio::test]
async fn test_login_page_serves() {
    let base_url = super::shared_server().await;

    assert!(
        TestApiClient::is_server_healthy(&base_url).await,
        "Janux server must be healthy at {}",
        base_url
    );

    let resp = reqwest::Client::new()
        .get(format!("{}/login", base_url.trim_end_matches('/')))
        .send()
        .await
        .expect("login page request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body = resp.text().await.expect("login page body");
    assert!(!body.is_empty(), "the SPA shell must not be empty");
}

/// Janux is PASSWORDLESS: the session-verification endpoint takes a
/// ceremony JWT, never a user/password pair — a password-shaped body
/// must be refused 401, not 200 and not 500.
#[tokio::test]
async fn test_password_shaped_verify_is_refused() {
    let base_url = super::shared_server().await;

    let resp = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/auth/verify",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "localhost")
        .json(&serde_json::json!({
            "user": "admin@test.local",
            "password": "wrong-password-xyz"
        }))
        .send()
        .await
        .expect("verify request");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "a password-shaped body carries no ceremony JWT — must fail closed"
    );
}

/// Health endpoint contract before the rest of the suite runs.
#[tokio::test]
async fn test_verify_server_healthy_before_signin() {
    let base_url = super::shared_server().await;

    let resp = reqwest::Client::new()
        .get(format!("{}/api/v1/healthy", base_url.trim_end_matches('/')))
        .send()
        .await
        .expect("health request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["ok"], true, "healthy body: {body}");
}

// ─── Admin surface under real and missing sessions ──────────────────────────

/// The social provider list is admin-gated: no session → 401, never 200.
#[tokio::test]
async fn test_social_provider_list_requires_auth() {
    let base_url = super::shared_server().await;

    let resp = reqwest::Client::new()
        .get(format!(
            "{}/api/v1/admin/provider/list",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "localhost")
        .send()
        .await
        .expect("provider list request");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "admin surface must fail closed without a session"
    );
}

/// The passkey request endpoint is reachable and refuses a bodyless
/// request with 400 — never 404 (route missing) or 500.
#[tokio::test]
async fn test_passkey_request_endpoint_accessible() {
    let base_url = super::shared_server().await;
    let resp = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/auth/passkey/request",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "localhost")
        .send()
        .await
        .expect("passkey request");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "a bodyless passkey request is a validation error, not a crash"
    );
}

/// G-158: the old version of this test called a password login that
/// always returned None, so the `if let Some(token)` body — the actual
/// assertion — never ran. With the provisioned root session it now
/// exercises the full protect → policy → handler stack over HTTP.
#[tokio::test]
async fn test_user_roles_lookup_works() {
    let base_url = super::shared_server().await;
    let token = TestApiClient::admin_bearer_token().await;

    let resp = reqwest::Client::new()
        .get(format!(
            "{}/api/v1/admin/user/roles",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "localhost")
        .header("Authorization", format!("Bearer {token}"))
        .query(&[("user", "root@test.local")])
        .send()
        .await
        .expect("roles request");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "the provisioned root session must pass protect + the policy gate"
    );
    // ApiResponse<Vec<String>>: {ok, data: [role ids]}
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["ok"], true, "roles body: {body}");
    let names: Vec<&str> = body["data"]
        .as_array()
        .unwrap_or_else(|| panic!("roles response shape: {body}"))
        .iter()
        .filter_map(|r| r.as_str())
        .collect();
    assert!(
        names.contains(&"root"),
        "root@test.local must hold the root role, got {names:?}"
    );
}
