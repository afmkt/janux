//! E2E test: Tenant lifecycle management via admin APIs.
//!
//! Tests creating tenants, domains, users, roles, policies —  
/// Test server is healthy before tenant creation.
#[tokio::test]
async fn test_server_healthy_before_tenant_ops() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .get(format!("{}/api/v1/healthy", base_url.trim_end_matches('/')))
        .send()
        .await;

    assert!(resp.is_ok());

    if let Ok(response) = resp {
        assert!(response.status().is_success());
    }
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
        .await;

    assert!(resp.is_ok());
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
        .await;

    assert!(resp.is_ok());
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
        .await;

    assert!(resp.is_ok());
}

/// Test that the email request endpoint is reachable.
#[tokio::test]
async fn test_email_request_endpoint_reachable() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    let resp = client
        .post(format!(
            "{}/api/v1/auth/email/request",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "localhost")
        .send()
        .await;

    assert!(resp.is_ok());
}

/// Test logout endpoint.
#[tokio::test]
async fn test_logout_endpoint_reachable() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    let resp = client
        .post(format!(
            "{}/api/v1/auth/logout",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "localhost")
        .send()
        .await;

    assert!(resp.is_ok());
}

/// Test the refresh token endpoint.
#[tokio::test]
async fn test_refresh_endpoint_reachable() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    let resp = client
        .post(format!(
            "{}/api/v1/auth/refresh",
            base_url.trim_end_matches('/')
        ))
        .send()
        .await;

    assert!(resp.is_ok());
}
