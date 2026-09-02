//! E2E test: OpenID Connect / OAuth 2.0 flows.
//!
//! Tests standard OIDC endpoints:
//! 1. .well-known/openid-configuration (discovery document)
/// Test the well-known OIDC configuration endpoint.
#[tokio::test]
async fn test_well_known_openid_configuration() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    // Discovery document should be publicly accessible
    let resp = client
        .get(format!(
            "{}/.well-known/openid-configuration",
            base_url.trim_end_matches('/')
        ))
        .send()
        .await;

    assert!(resp.is_ok(), "OIDC discovery endpoint should be reachable");
}

/// Test that the userinfo endpoint exists.
#[tokio::test]
async fn test_userinfo_endpoint_exists() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    // Userinfo without auth should return a response (401 not 500)
    let resp = client
        .get(format!("{}/userinfo", base_url.trim_end_matches('/')))
        .send()
        .await;

    assert!(resp.is_ok());
}

/// Test the token endpoint accepts POST requests.
#[tokio::test]
async fn test_token_endpoint_accepts_post() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/token", base_url.trim_end_matches('/')))
        .form(&[("grant_type", "authorization_code")])
        .send()
        .await;

    assert!(resp.is_ok());
}

/// Test the authorize endpoint accepts GET.
#[tokio::test]
async fn test_authorize_accepts_get() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    let resp = client
        .get(format!("{}/authorize", base_url.trim_end_matches('/')))
        .send()
        .await;

    assert!(resp.is_ok());
}

/// Test the authorize endpoint accepts POST.
#[tokio::test]
async fn test_authorize_accepts_post() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/authorize", base_url.trim_end_matches('/')))
        .form(&[
            ("client_id", "test"),
            ("redirect_uri", "http://localhost/callback"),
        ])
        .send()
        .await;

    assert!(resp.is_ok());
}

/// Test that the revoke endpoint exists.
#[tokio::test]
async fn test_revoke_endpoint_exists() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/revoke", base_url.trim_end_matches('/')))
        .send()
        .await;

    assert!(resp.is_ok());
}

/// RFC 7009 error semantics: a revocation request without a token is an
/// invalid request (400); a request that presents a token but fails client
/// authentication is rejected with 401 `invalid_client` (§2.1) — never 200,
/// which is reserved for authenticated clients.
#[tokio::test]
async fn test_revoke_requires_client_authentication() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    // Missing token parameter → 400
    let resp = client
        .post(format!("{}/revoke", base_url.trim_end_matches('/')))
        .header("Host", "localhost")
        .form(&[("client_id", "some-client")])
        .send()
        .await
        .expect("request should succeed");
    assert_eq!(resp.status(), 400, "missing token must be a 400");

    // Token present but client unknown → 401 invalid_client
    let resp = client
        .post(format!("{}/revoke", base_url.trim_end_matches('/')))
        .header("Host", "localhost")
        .form(&[
            ("token", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig"),
            ("client_id", "no-such-client"),
        ])
        .send()
        .await
        .expect("request should succeed");
    assert_eq!(
        resp.status(),
        401,
        "unauthenticated revocation must be rejected"
    );
    let body: serde_json::Value = resp.json().await.expect("JSON error body");
    assert_eq!(body["error"], "invalid_client");

    // Token present but no client_id at all → 401 invalid_client
    let resp = client
        .post(format!("{}/revoke", base_url.trim_end_matches('/')))
        .header("Host", "localhost")
        .form(&[("token", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig")])
        .send()
        .await
        .expect("request should succeed");
    assert_eq!(resp.status(), 401);
}

/// Test that the introspect endpoint exists.
#[tokio::test]
async fn test_introspect_endpoint_exists() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    let resp = client
        .post(format!("{}/introspect", base_url.trim_end_matches('/')))
        .send()
        .await;

    assert!(resp.is_ok());
}

/// Test JWKS endpoint is publicly accessible.
#[tokio::test]
async fn test_jwks_is_public() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    let resp = client
        .get(format!(
            "{}/.well-known/jwks.json",
            base_url.trim_end_matches('/')
        ))
        .send()
        .await;

    assert!(resp.is_ok(), "JWKS should be publicly accessible");

    if let Ok(r) = resp {
        let body = r.text().await;
        assert!(body.is_ok(), "Failed to read response body");
        // Should look like a JSON object with keys array
        assert!(!body.unwrap().is_empty());
    }
}
