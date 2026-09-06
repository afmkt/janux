//! E2E test: Tenant lifecycle management via admin APIs.
//!
//! Unauthenticated-contract tests: the admin surface must fail closed
//! (401) without a session, and public endpoints must answer 200. The
//! old `assert!(resp.is_ok())` only proved "some HTTP response arrived"
//! — a 500 passed just like a 200 (H8). The AUTHENTICATED lifecycle
//! (create → bootstrap → delete → backup) runs in
//! `z_integration_tests::full_tenant_lifecycle_create_and_delete`, which
//! provisions a real root session.

/// Test server is healthy before tenant creation.
#[tokio::test]
async fn test_server_healthy_before_tenant_ops() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/v1/healthy", base_url.trim_end_matches('/')))
        .send()
        .await
        .expect("health request");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("json body");
    assert_eq!(body["ok"], true, "healthy body: {body}");
}

/// Test tenant list endpoint requires auth.
#[tokio::test]
async fn test_tenant_list_requires_auth() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    let resp = client
        .get(format!(
            "{}/api/v1/admin/tenant/list",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "localhost")
        .send()
        .await
        .expect("tenant list request");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "admin surface must fail closed without a session"
    );
}

/// Test that the tenant delete endpoint requires proper auth.
#[tokio::test]
async fn test_tenant_delete_requires_auth() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    let resp = client
        .post(format!(
            "{}/api/v1/admin/tenant/delete",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "localhost")
        .json(&serde_json::json!({"name": "test-tenant"}))
        .send()
        .await
        .expect("tenant delete request");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "tenant delete must fail closed without a session"
    );
}

/// Test domain list endpoint.
#[tokio::test]
async fn test_domain_list_requires_auth() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    let resp = client
        .get(format!(
            "{}/api/v1/admin/domain/list",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "localhost")
        .send()
        .await
        .expect("domain list request");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "domain list must fail closed without a session"
    );
}

/// Test that the email request endpoint rejects a body-less call.
#[tokio::test]
async fn test_email_request_endpoint_rejects_empty_body() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    let resp = client
        .post(format!(
            "{}/api/v1/auth/email/request",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "localhost")
        .send()
        .await
        .expect("email request");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "a body-less magic-link request must be refused"
    );
}

/// Test logout endpoint.
#[tokio::test]
async fn test_logout_endpoint_requires_token() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    let resp = client
        .post(format!(
            "{}/api/v1/auth/logout",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "localhost")
        .send()
        .await
        .expect("logout request");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "logout without a session must fail closed"
    );
}

/// Test the refresh token endpoint.
#[tokio::test]
async fn test_refresh_endpoint_requires_token() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    let resp = client
        .post(format!(
            "{}/api/v1/auth/refresh",
            base_url.trim_end_matches('/')
        ))
        .send()
        .await
        .expect("refresh request");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "refresh without a token must fail closed"
    );
}
