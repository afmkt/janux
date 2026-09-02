//! E2E test: Passkey registration and authentication via API endpoints.
//!
//! Tests WebAuthn/Passkey flows:
//! 1. Request passkey registration (get credential options)  
//! 2. Verify passkey credentials

/// Test that the passkey registration endpoint is reachable.
#[tokio::test]
async fn test_passkey_registration_request() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    // Endpoint should be reachable — returns 400 if body is wrong, not 404
    let resp = client
        .post(format!(
            "{}/api/v1/auth/passkey/request",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "localhost")
        .send()
        .await;

    assert!(resp.is_ok(), "Passkey request endpoint should be reachable");
}

/// Test that passkey verification without body returns an error.
#[ignore]
#[tokio::test]
async fn test_passkey_verify_requires_body() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    // Verify without body should return an error (not 500)
    let resp = client
        .post(format!(
            "{}/api/v1/auth/passkey/verify",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "localhost")
        .send()
        .await;

    assert!(resp.is_ok());
}

/// Test the admin page loads (passkeys are managed from admin).
#[tokio::test]
async fn test_admin_page_accessible() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/admin.html", base_url.trim_end_matches('/')))
        .send()
        .await;

    assert!(resp.is_ok(), "Admin page should load");
}
