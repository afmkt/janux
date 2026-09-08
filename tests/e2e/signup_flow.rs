//! E2E test: signup surface contracts over HTTP.
//!
//! Janux has ONE hosted SPA at `/login` that runs both signin and
//! signup ceremonies (strict mode: signup provisions only a NEW
//! username). G-158: the old tests here fetched a nonexistent
//! `/signup` page and an `#[ignore]`d "form fields" probe asserted
//! password-era markup the SPA never had — both removed; browser-driven
//! UI coverage is tracked in gaps.md.

use crate::fixtures::TestApiClient;

/// The hosted SPA serves at /login — the single entry for signin AND
/// signup ceremonies.
#[tokio::test]
async fn test_login_page_accessible() {
    let base_url = super::shared_server().await;

    assert!(
        TestApiClient::is_server_healthy(&base_url).await,
        "Server must be running"
    );

    let resp = reqwest::Client::new()
        .get(format!("{}/login", base_url.trim_end_matches('/')))
        .send()
        .await
        .expect("login page request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

/// Health contract before the signup-surface probes run.
#[tokio::test]
async fn test_verify_server_healthy() {
    let base_url = super::shared_server().await;

    assert!(TestApiClient::is_server_healthy(&base_url).await);
}

/// Signup provisioning happens through the factor ceremony API, not a
/// page (and needs a configured mail provider, which the e2e config does
/// not carry). What IS pinned here: the old "GET /authorize should work
/// even without parameters" claim, corrected to its real contract — a
/// parameterless authorize answers with a 302 to the hosted error page
/// carrying `error=invalid_request`, never 500 and never a silent 200.
#[tokio::test]
async fn test_signup_ceremony_and_authorize_contract() {
    let base_url = super::shared_server().await;
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");

    let resp = client
        .get(format!("{}/authorize", base_url.trim_end_matches('/')))
        .header("Host", "localhost")
        .send()
        .await
        .expect("authorize request");
    assert_eq!(resp.status(), reqwest::StatusCode::FOUND);
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        location.contains("error=invalid_request"),
        "the error redirect must carry the RFC 6749 code: {location}"
    );
}
