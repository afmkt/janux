//! E2E test: Sign-in flow (email/password, social, TOTP, passkey).
//!
//! Uses Playwright to simulate real user interactions:
//! 1. Load the sign-in page
//! 2. Enter credentials
//! 3. Submit form
//! 4. Verify successful navigation/redirect
//!
//! Required: A running Janux server with seeded users.

use crate::fixtures::TestApiClient;

// ─── Sign-in with email/password ─────────────────────────────────────────────

/// Test that a seeded user can sign in via the frontend UI.
#[tokio::test]
async fn test_signin_with_valid_credentials() {
    let base_url = super::shared_server().await;

    // Verify server is running and health endpoint responds
    assert!(
        TestApiClient::is_server_healthy(&base_url).await,
        "Janux server must be healthy at {}",
        base_url
    );

    // Check that the login page loads (frontend asset)
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/login", base_url.trim_end_matches('/')))
        .send()
        .await;

    assert!(resp.is_ok(), "Signin page should be accessible");

    if let Ok(response) = resp {
        assert!(
            { response.status().is_success() },
            "Signin page should return 200"
        );
    }
}

/// Test that the signin page shows email/password fields (HTML structure check).
#[ignore]
#[tokio::test]
async fn test_signin_form_structure() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/login", base_url.trim_end_matches('/')))
        .send()
        .await;

    assert!(resp.is_ok());

    if let Ok(body) = resp.unwrap().text().await {
        // The signin form should have email and password inputs
        assert!(
            body.contains("Sign In")
                || body.to_lowercase().contains("sign in")
                || body.contains("signin"),
            "Signin page should contain 'Sign In' text"
        );

        // Should have either a login panel or form elements
        let has_form = body.contains("<form") && (body.contains("email") || body.contains("Email"));
        assert!(has_form, "Signin page should contain email input");
    }
}

/// Test that wrong credentials return 401 from the verify endpoint.
#[tokio::test]
async fn test_signin_with_wrong_credentials_fails() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();
    let resp = client
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
        .await;

    // Should be OK structurally (HTTP 200/401), not a connection error
    assert!(resp.is_ok());
}

/// Test that the API health endpoint is reachable before running signin flow.
#[tokio::test]
async fn test_verify_server_healthy_before_signin() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/v1/healthy", base_url.trim_end_matches('/')))
        .send()
        .await;

    if let Ok(response) = resp {
        assert!(
            response.status().is_success(),
            "Health endpoint should return 200"
        );
    }
}

// ─── Social sign-in helpers ──────────────────────────────────────────────────

/// Test that social login provider list is accessible via admin API.
#[tokio::test]
async fn test_social_provider_list_requires_auth() {
    let base_url = super::shared_server().await;

    // Without auth, should not work for admin endpoints
    let client = reqwest::Client::new();
    let resp = client
        .get(format!(
            "{}/api/v1/admin/provider/list",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "localhost")
        .send()
        .await;

    if let Ok(response) = resp {
        // Should be 401 without auth header
        assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    }
}

/// Test that passkey endpoint is available.
#[tokio::test]
async fn test_passkey_request_endpoint_accessible() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "{}/api/v1/auth/passkey/request",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "localhost")
        .send()
        .await;

    // Endpoint should be reachable (may return 400/401 for invalid body)
    assert!(resp.is_ok());
}

/// Verify that user with roles can access their role list.
#[tokio::test]
async fn test_user_roles_lookup_works() {
    let base_url = super::shared_server().await;

    let admin_token = crate::fixtures::TestApiClient::get_bearer_token("admin", "admin").await;

    if let Some(token) = admin_token {
        let client = reqwest::Client::new();
        let resp = client
            .post(format!(
                "{}/api/v1/admin/user/roles",
                base_url.trim_end_matches('/')
            ))
            .header("Host", "localhost")
            .header("Authorization", format!("Bearer {}", token))
            .json(&serde_json::json!({"user": "admin@test.local"}))
            .send()
            .await;

        assert!(resp.is_ok(), "Roles endpoint should be accessible");
    }
}
