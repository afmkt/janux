//! Fixtures and setup helpers for E2E auth tests.
//!
//! Provides:
//! - `shared_server()` — returns the URL of the single shared test server (auto-starts if needed)
//! - `TestBrowser` — manages Playwright browser state across tests  
//! - `AdminFixtures` — helpers to create admin/test user accounts via API
//! - Cleanup hooks to ensure no leftover test data between runs

pub use crate::auth_config::{admin_page, signin_page, signup_page};

use serde_json::json;
use std::sync::{Arc, Mutex};

/// State shared between e2e test modules.
pub struct TestBrowser {
    pub base_url: String,
    pub headless: bool,
    // In a real implementation this would hold a playwright::Browser instance
    _browser_state: Arc<Mutex<Option<String>>>,
}

impl TestBrowser {
    /// Create a new browser context from the config.
    pub fn new(base_url: String, headless: bool) -> Result<Self, String> {
        Ok(Self {
            base_url,
            headless,
            _browser_state: Arc::new(Mutex::new(None)),
        })
    }

    /// Page URL for signin.
    pub fn signin_page(&self) -> String {
        format!("{}/signin.html", self.base_url.trim_end_matches('/'))
    }

    /// Page URL for signup.
    pub fn signup_page(&self) -> String {
        format!("{}/signup.html", self.base_url.trim_end_matches('/'))
    }

    /// Page URL for admin panel.
    pub fn admin_page(&self) -> String {
        format!("{}/admin.html", self.base_url.trim_end_matches('/'))
    }
}

// ─── API helpers used by all e2e tests ────────────────────────────────────────

pub struct TestApiClient;

impl TestApiClient {
    /// Authenticate with username/password and return the bearer token.
    pub async fn get_bearer_token(username: &str, password: &str) -> Option<String> {
        let base_url = super::shared_server().await;

        let client = reqwest::Client::new();
        let resp = client
            .post(format!(
                "{}/api/v1/auth/verify",
                base_url.trim_end_matches('/')
            ))
            .header("Host", "localhost")
            .json(&serde_json::json!({
                "user": username,
                "password": password
            }))
            .send()
            .await
            .ok()?;

        resp.json::<serde_json::Value>().await.ok().and_then(|v| {
            v.get("token")
                .or_else(|| v.get("access_token"))
                .and_then(|t| t.as_str())
                .map(String::from)
        })
    }

    /// Get a bearer token from the server (via OIDC token endpoint).
    pub async fn get_oidc_token(client_id: &str, code: &str) -> Option<String> {
        let base_url = super::shared_server().await;

        let client = reqwest::Client::new();
        let resp = client
            .post(format!("{}/token", base_url.trim_end_matches('/')))
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("client_id", client_id),
            ])
            .send()
            .await
            .ok()?;

        resp.json::<serde_json::Value>().await.ok().and_then(|v| {
            v.get("access_token")
                .or_else(|| v.get("token"))
                .and_then(|t| t.as_str())
                .map(String::from)
        })
    }

    /// Health check.
    pub async fn is_server_healthy(base_url: &str) -> bool {
        let client = reqwest::Client::new();
        let healthy_url = format!("{}/api/v1/healthy", base_url.trim_end_matches('/'));
        let resp = client.get(&healthy_url).send().await.ok();
        if let Some(resp) = resp {
            let body = resp.json::<serde_json::Value>().await.unwrap_or_default();
            body.get("ok").map(|v| v == true).unwrap_or(false)
        } else {
            false
        }
    }

    /// List all tenants (requires admin auth).
    pub async fn list_tenants(base_url: &str, token: &str) -> Option<Vec<String>> {
        let client = reqwest::Client::new();
        let resp = client
            .get(format!(
                "{}/api/v1/admin/tenant/list",
                base_url.trim_end_matches('/')
            ))
            .header("Authorization", format!("Bearer {}", token))
            .send()
            .await
            .ok()?;

        resp.json::<serde_json::Value>().await.ok().and_then(|v| {
            let arr = v.get("data")?.as_array()?;
            Some(
                arr.iter()
                    .filter_map(|item| item.as_str().map(String::from))
                    .collect(), // Collects into Vec<String>, which is then wrapped in Some
            )
        })
    }

    /// Get JWKS (public, no auth needed).
    pub async fn get_jwks(base_url: &str) -> Option<serde_json::Value> {
        let client = reqwest::Client::new();
        let resp = client
            .get(format!(
                "{}/.well-known/jwks.json",
                base_url.trim_end_matches('/')
            ))
            .send()
            .await
            .ok()?;

        resp.json::<serde_json::Value>().await.ok()
    }
}

// ─── Shared state for cleanup ────────────────────────────────────────────────

/// Create a test tenant via admin API.
pub async fn create_test_tenant(tenant_name: &str) -> bool {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!(
            "{}/api/v1/admin/tenant/create",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "localhost")
        .json(&json!({ "name": tenant_name }))
        .send()
        .await
        .ok();

    resp.is_some_and(|r| r.status().is_success())
}

/// Cleanup a test tenant created during e2e tests.
pub async fn cleanup_test_tenant(tenant_name: &str) {
    let base_url = super::shared_server().await;

    let _client = reqwest::Client::new();
    let _resp = _client
        .post(format!(
            "{}/api/v1/admin/tenant/delete",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "localhost")
        .json(&json!({ "name": tenant_name }))
        .send()
        .await;
}

// ─── Page element selectors (for Playwright interactions) ─────────────────────

/// CSS selectors used by the frontend signin page.
pub mod selectors {
    pub const SIGNIN_EMAIL_INPUT: &str = "input[name=email]";
    pub const SIGNIN_PASSWORD_INPUT: &str = "input[name=password]";
    pub const SIGNIN_BUTTON: &str =
        "button[type=submit], input[type=submit], button[data-action=signin]";

    pub const SIGNUP_EMAIL_INPUT: &str = "input[name=email]";
    pub const SIGNUP_PASSWORD_INPUT: &str = "input[name=password]";
    pub const SIGNUP_BUTTON: &str =
        "button[type=submit], input[type=submit], button[data-action=signup]";

    pub const ADMIN_LOGIN_PANEL: &str = "[data-panel=admin-login]";
}
