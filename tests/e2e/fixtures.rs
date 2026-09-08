//! Fixtures and helpers for the HTTP-level E2E tests.
//!
//! G-158: this module used to advertise a `TestBrowser` (a stub holding
//! no browser), password-shaped selectors for pages that never existed,
//! and a `get_bearer_token` that posted a username/password to a
//! PASSWORDLESS server — always returning `None`, so every "authenticated"
//! test silently asserted nothing. The shared server is now provisioned
//! with a real root+admin session (`all_tests::shared_admin_token`), and
//! the helpers below are the only ones actually used.

/// Shared API helpers.
pub struct TestApiClient;

impl TestApiClient {
    /// The shared server's real root+admin bearer token.
    pub async fn admin_bearer_token() -> String {
        super::shared_admin_token().await
    }

    /// Health check against `/api/v1/healthy`.
    pub async fn is_server_healthy(base_url: &str) -> bool {
        let client = reqwest::Client::new();
        let healthy_url = format!("{}/api/v1/healthy", base_url.trim_end_matches('/'));
        let resp = client.get(&healthy_url).send().await.ok();
        if let Some(resp) = resp {
            let body = resp.json::<serde_json::Value>().await.unwrap_or_default();
            body.get("ok").and_then(|v| v.as_bool()).unwrap_or(false)
        } else {
            false
        }
    }
}
