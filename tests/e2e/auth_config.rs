//! Configuration helpers for the HTTP-level E2E tests.
//!
//! Provides a shared `base_url()` helper that reads from
//! `tests/test_config.toml` with sensible defaults — no environment
//! variables needed. (G-158: the old page helpers here pointed at
//! `/signin.html`, `/signup.html` and `/admin.html` — pages that never
//! existed. The hosted SPA lives at `/login`, `/admin`, `/consent` and
//! `/device`; tests that need those URLs build them inline.)

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
        if line.starts_with("port")
            && !line.starts_with("[[seed]]")
            && let Some(val_str) = line.split('=').nth(1).map(|s| s.trim().trim_matches('"'))
            && let Ok(v) = val_str.parse::<u16>()
        {
            return Some(v);
        }
    }
    None
}

/// Return the server base URL from test_config.toml.
pub fn base_url() -> String {
    load_base_url()
}
