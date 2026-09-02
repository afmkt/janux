//! Configuration module for E2E tests.
//!
//! Provides a shared `base_url()` helper that reads from `tests/test_config.toml`
//! with sensible defaults — no environment variables needed.

/// Load the base URL from `tests/test_config.toml`.
/// Falls back to `http://127.0.0.1:18092` if file is missing or parse fails.
pub fn load_base_url() -> String {
    let content = std::fs::read_to_string("tests/test_config.toml").unwrap_or_default();

    // Try server.port first, then bind.port
    let port_str = extract_port(&content);
    let port: u16 = port_str.unwrap_or(18092);

    format!("http://127.0.0.1:{port}")
}

/// Extract port from a TOML value in the config content.
fn extract_port(content: &str) -> Option<u16> {
    for line in content.lines() {
        let line = line.trim();
        if line.starts_with("port") && !line.starts_with("[[seed]") {
            if let Some(val_str) = line.split('=').nth(1).map(|s| s.trim().trim_matches('"')) {
                if let Ok(v) = val_str.parse::<u16>() {
                    return Some(v);
                }
            }
        }
    }
    None
}

/// Return the server base URL from test_config.toml.
/// This is the shared helper used by all e2e tests.
pub fn base_url() -> String {
    load_base_url()
}

/// Get the full signin page URL.
pub fn signin_page(base_url: &str) -> String {
    format!("{}/signin.html", base_url.trim_end_matches('/'))
}

/// Get the full signup page URL.
pub fn signup_page(base_url: &str) -> String {
    format!("{}/signup.html", base_url.trim_end_matches('/'))
}

/// Get the admin page URL.
pub fn admin_page(base_url: &str) -> String {
    format!("{}/admin.html", base_url.trim_end_matches('/'))
}

/// OIDC authorize endpoint.
pub fn oidc_authorize(base_url: &str) -> String {
    format!("{}/authorize", base_url.trim_end_matches('/'))
}

/// OIDC token endpoint.
pub fn oidc_token(base_url: &str) -> String {
    format!("{}/token", base_url.trim_end_matches('/'))
}

// Convenience macro for all e2e tests.
#[macro_export]
#[allow(unused)]
macro_rules! base_url {
    () => {{ $crate::e2e::auth_config::load_base_url() }};
}
