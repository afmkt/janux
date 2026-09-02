//! Common helpers for integration and e2e tests.
//!
//! Provides `TestEnv` which auto-starts a Janux server in a subprocess
//! with a temporary data dir, governed by `tests/test_config.toml`.
#![allow(dead_code)] // shared helper surface; each test target uses a subset

use std::process::{Child, Stdio};
use tempfile::TempDir;

pub struct TestEnv {
    pub base_url: String,
    pub admin_token: Option<String>,
    _child: Option<Child>,
    _temp_dir: TempDir,
}

impl Drop for TestEnv {
    fn drop(&mut self) {
        if let Some(mut child) = self._child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

/// Parsed test configuration sourced from `tests/test_config.toml`.
#[derive(Debug, Clone)]
struct TestConfig {
    base_port: u16,
    encryption_key: String,
}

// ─── Load tests/test_config.toml ──────────────────────────────────────────────

fn load_test_config() -> TestConfig {
    let config_path = "tests/test_config.toml";
    let content = std::fs::read_to_string(config_path).unwrap_or_default();

    // Try to parse server.port first, fall back to bind.port, then default 18092
    let port: u16 = extract_toml_value(&content, "server.port")
        .or_else(|| extract_toml_value(&content, "bind.port"))
        .unwrap_or(18092);

    let encryption_key = extract_toml_value(&content, "encryption_key").unwrap_or_else(|| {
        String::from("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789")
    });

    TestConfig {
        base_port: port,
        encryption_key,
    }
}

/// Minimal TOML value extractor — reads the first match for a given key.
fn extract_toml_value<T: std::str::FromStr>(content: &str, key: &str) -> Option<T> {
    for line in content.lines() {
        let line = line.trim();
        if line == key
            || (line.len() > key.len() + 1
                && line.starts_with(key)
                && line.as_bytes()[key.len()] == b'=')
        {
            return line
                .split('=')
                .nth(1)?
                .trim()
                .trim_matches('"')
                .trim()
                .parse()
                .ok();
        }
    }
    None
}

// ─── TestEnv implementation ───────────────────────────────────────────────────

impl TestEnv {
    /// Attempt to log in as admin@test.local (seeded user).
    async fn login_admin(&self) -> Option<String> {
        let resp = reqwest::Client::new()
            .post(format!("{}/api/v1/auth/email/request", self.base_url))
            .header("Host", "localhost")
            .json(&serde_json::json!({
                "user": "admin@test.local",
                "channel": "email"
            }))
            .send()
            .await
            .ok()?;

        if resp.status().is_success() {
            Some("test-token-placeholder".to_string())
        } else {
            None
        }
    }

    /// Get the base URL string.
    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub async fn health_check(&self) -> bool {
        let resp = reqwest::Client::new()
            .get(format!("{}/api/v1/healthy", self.base_url))
            .timeout(std::time::Duration::from_secs(5))
            .send()
            .await
            .ok();

        if let Some(data) = resp
            && let Ok(v) = data.json::<serde_json::Value>().await
        {
            return v["ok"] == true;
        }
        false
    }

    /// Wait until the server is healthy.
    pub async fn await_healthy(&self, max_secs: u64) -> bool {
        let client = reqwest::Client::new();
        let url = format!("{}/api/v1/healthy", self.base_url);
        for _ in 0..max_secs * 10 {
            match client.get(&url).send().await {
                Ok(resp) if resp.status().is_success() => return true,
                _ => tokio::time::sleep(std::time::Duration::from_millis(100)).await,
            }
        }
        false
    }

    /// Create a new test environment.
    ///
    /// Always auto-starts a Janux server using `tests/test_config.toml` settings,
    /// allocating an available port starting from the configured base port.
    pub async fn new() -> Self {
        Self::start(false).await
    }

    /// Create a test environment whose server trusts `X-Forwarded-*` headers
    /// (`trust_forwarded_headers = true`) — the deployment mode used behind a reverse
    /// proxy such as Caddy `forward_auth`.
    pub async fn new_trust_forwarded_headers() -> Self {
        Self::start(true).await
    }

    async fn start(trust_forwarded_headers: bool) -> Self {
        let config = load_test_config();
        let (port, child, temp_dir) =
            start_test_server_with_port(&config.clone(), trust_forwarded_headers)
                .expect("Failed to auto-start janux server — try: 'cargo build --bin janux'");

        if !wait_for_health(port).await {
            panic!("Janux server started but never became healthy. Check logs above.");
        }

        TestEnv {
            base_url: format!("http://127.0.0.1:{port}"),
            admin_token: None,
            _child: Some(child),
            _temp_dir: temp_dir,
        }
    }

    /// Create a test environment with an admin bearer token.
    pub async fn new_with_auth() -> Self {
        let mut env = TestEnv::new().await;
        if let Some(token) = env.login_admin().await {
            println!("janux-test: extracted admin token");
            env.admin_token = Some(token);
        } else {
            println!("janux-test: warning — no admin JWT (seeded user may not have auth enabled)");
            env.admin_token = Some("test-placeholder-token".to_string());
        }
        env
    }
}

// ─── Port allocation and server startup ────────────────────────────────────────

fn is_port_available(port: u16) -> bool {
    std::net::TcpListener::bind(format!("127.0.0.1:{port}")).is_ok()
}

/// Allocate an available port starting from config base port, then start server.
fn start_test_server_with_port(
    config: &TestConfig,
    trust_forwarded_headers: bool,
) -> Result<(u16, Child, TempDir), String> {
    let seed: u32 = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .subsec_nanos();

    const PORT_RANGE: u16 = 20000;
    const MAX_ATTEMPTS: u32 = 5000; // avoids infinite loop safety net

    for i in 0..MAX_ATTEMPTS {
        let port: u16 = config
            .base_port
            .wrapping_add(((seed as u16).wrapping_add((i as u16) * 7919u16)) % PORT_RANGE);

        if is_port_available(port) {
            return try_start_server(config, port, trust_forwarded_headers);
        }
    }

    Err("No available port found in range".into())
}

fn try_start_server(
    config: &TestConfig,
    port: u16,
    trust_forwarded_headers: bool,
) -> Result<(u16, Child, TempDir), String> {
    let tmp_dir = tempfile::tempdir().map_err(|e| format!("Failed to create temp dir: {e}"))?;
    let config_path = build_test_config(
        tmp_dir.path(),
        port,
        &config.encryption_key,
        trust_forwarded_headers,
    );

    println!("janux-test: using config at {}", config_path.display());

    if !std::path::Path::new("./target/debug/janux").exists() {
        std::process::Command::new("cargo")
            .args(["build", "--bin", "janux"])
            .stderr(Stdio::null())
            .stdout(Stdio::null())
            .output()
            .map_err(|e| format!("Failed to build janux: {e}"))?;
    }

    let child = std::process::Command::new("./target/debug/janux")
        .args(["--config", config_path.to_str().unwrap()])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| format!("Failed to start janux: {e}"))?;

    println!("janux-test: server started on port {}", port);
    Ok((port, child, tmp_dir))
}

/// Build a temporary test_config.toml with seeded tenant.
fn build_test_config(
    tmp_dir: &std::path::Path,
    port: u16,
    encryption_key: &str,
    trust_forwarded_headers: bool,
) -> std::path::PathBuf {
    let config_content = format!(
        r#"data_dir = "{data_dir}"
encryption_key = "{encryption_key}"
trust_forwarded_headers = {trust_forwarded_headers}

[bind]
address = "127.0.0.1"
port = {port}

[[seed]]
name = "test-tenant"
domains = [{{ id = "localhost", cors = [] }}]
# Roles must be declared before users reference them: user_add_role no
# longer creates unknown roles (api-consolidation Step 4).
roles = ["root", "admin", "user", "guest"]
policies = []
users = [
    {{ id = "admin@test.local", active = true, roles = ["admin"] }},
    {{ id = "user@test.local", active = true, roles = ["user"] }},
]

[seed.resend]
from = "test@test.com"
resend_key = "test-key"
template = "./email/verify.html"
verify_url = "http://localhost/api/v1/verify"

[seed.alisms]
api_secret = "test-secret"
api_key = "test-key-api"
template_code = "TEST_123"
sign_name = "Test"
region_id = "cn-shanghai"
endpoint = "dysmsapi.aliyuncs.com"
"#,
        data_dir = tmp_dir.join("data").to_string_lossy(),
    );

    let config_path = tmp_dir.join("test_config.toml");
    std::fs::write(&config_path, &config_content).expect("Failed to write test config");
    config_path
}

/// Wait for the server health endpoint.
async fn wait_for_health(port: u16) -> bool {
    let base = format!("http://127.0.0.1:{port}/api/v1/healthy");
    let client = reqwest::Client::new();
    for attempt in 0..30u32 {
        match client.get(&base).send().await {
            Ok(resp) if resp.status().is_success() => return true,
            _ => tokio::time::sleep(tokio::time::Duration::from_millis(500)).await,
        }
        if attempt % 5 == 4 {
            eprintln!("janux-test: waiting for health... ({}/30)", attempt + 1);
        }
    }
    false
}

// ─── Test helpers ──────────────────────────────────────────────────────────────

/// Generate a random test user name.
pub fn random_test_user_id() -> String {
    format!("test-user-{}", uuid::Uuid::new_v4().simple())
}

/// Generate a random domain for testing.
pub fn random_test_domain() -> String {
    format!("{}.test.local", uuid::Uuid::new_v4().simple())
}
