//! E2E test: passkey surface contracts over HTTP.
//!
//! The WebAuthn ceremony itself needs a browser authenticator (covered
//! by the lib-level softauth tests in `src/passkey.rs`); this tier pins
//! the wire contract: endpoints reachable, bodyless requests refused
//! with 400 (never 404/500), and the admin SPA served at its real path.

/// The passkey registration/login entry point is reachable and refuses
/// a bodyless request with 400 — never 404 (route missing) or 500.
#[tokio::test]
async fn test_passkey_registration_request() {
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

/// Same contract for the verify half. G-158: this test used to be
/// `#[ignore]`d and asserted only `is_ok()`.
#[tokio::test]
async fn test_passkey_verify_requires_body() {
    let base_url = super::shared_server().await;

    let resp = reqwest::Client::new()
        .post(format!(
            "{}/api/v1/auth/passkey/verify",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "localhost")
        .send()
        .await
        .expect("passkey verify request");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "a bodyless passkey verify is a validation error, not a crash"
    );
}

/// The admin console SPA is served at /admin (the old test fetched
/// /admin.html, which never existed).
#[tokio::test]
async fn test_admin_page_accessible() {
    let base_url = super::shared_server().await;

    let resp = reqwest::Client::new()
        .get(format!("{}/admin", base_url.trim_end_matches('/')))
        .send()
        .await
        .expect("admin page request");

    assert_eq!(resp.status(), reqwest::StatusCode::OK, "admin SPA serves");
}
