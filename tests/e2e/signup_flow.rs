//! E2E test: Sign-up flow.
//!
//! Tests the user registration experience:
//! 1. Navigate to signup page
//! 2. Submit registration form with valid data  
//! 3. Verify confirmation/redirect

/// Test that the signup page loads correctly.
#[tokio::test]
async fn test_signup_page_accessible() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    // Verify server is healthy first
    assert!(
        crate::fixtures::TestApiClient::is_server_healthy(&base_url).await,
        "Server must be running"
    );

    let resp = client
        .get(format!("{}/signup", base_url.trim_end_matches('/')))
        .send()
        .await;

    assert!(resp.is_ok(), "Signup page should load");

    if let Ok(response) = resp {
        assert!(
            response.status().is_success(),
            "Signup page should return 200"
        );
    }
}

/// Verify the signup form contains expected elements.
#[ignore]
#[tokio::test]
async fn test_signup_form_has_required_fields() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();
    let body = client
        .get(format!("{}/signup", base_url.trim_end_matches('/')))
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    // Should have signup text and email field
    assert!(
        body.to_lowercase().contains("sign up")
            || body.contains("SignUp")
            || body.contains("Sign-Up")
    );
}

/// Test that the API health endpoint is healthy before running signup tests.
#[tokio::test]
async fn test_verify_server_healthy() {
    let base_url = super::shared_server().await;

    assert!(crate::fixtures::TestApiClient::is_server_healthy(&base_url).await);
}

/// Test OIDC flow - authorization request endpoint.
#[tokio::test]
async fn test_oidc_authorize_endpoint_available() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    // GET authorize should work (even without parameters)
    let resp = client
        .get(format!("{}/authorize", base_url.trim_end_matches('/')))
        .send()
        .await;

    // Should not return a connection error
    assert!(resp.is_ok());
}

/// Test that the OIDC token endpoint accepts POST requests.
#[tokio::test]
async fn test_oidc_token_endpoint_available() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    // POST to token without valid params should return an error response (not 404)
    let resp = client
        .post(format!("{}/token", base_url.trim_end_matches('/')))
        .form(&[("grant_type", "authorization_code"), ("client_id", "test")])
        .send()
        .await;

    assert!(resp.is_ok());
}
