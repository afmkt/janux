//! Common helpers for integration and e2e tests.
//!
//! Provides `TestEnv` which auto-starts a Janux server in a subprocess
//! with a temporary data dir, governed by `tests/test_config.toml`.
#![allow(dead_code)] // shared helper surface; each test target uses a subset

use std::process::{Child, Stdio};
use std::sync::LazyLock;
use tempfile::TempDir;

/// Scratch backing dir for the test process's revocation-store singleton
/// (see `provision_admin_session`) — must outlive every TestEnv.
static PROVISION_STORE_DIR: LazyLock<TempDir> =
    LazyLock::new(|| tempfile::tempdir().expect("provision store tempdir"));
static PROVISION_STORE_INIT: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

pub struct TestEnv {
    pub base_url: String,
    pub admin_token: Option<String>,
    /// A session for the seeded `user@test.local` (only the `user` role) —
    /// the deny-path principal: valid token, insufficient roles (G-28).
    pub user_token: Option<String>,
    /// The running server's data dir — for on-disk assertions (e.g. the
    /// tenant-delete backup under `backups/{name}-{ts}/janux.db`).
    data_dir: std::path::PathBuf,
    encryption_key: String,
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
        Self::start(false, false).await
    }

    /// Create a test environment whose server trusts `X-Forwarded-*` headers
    /// (`trust_forwarded_headers = true`) — the deployment mode used behind a reverse
    /// proxy such as Caddy `forward_auth`.
    pub async fn new_trust_forwarded_headers() -> Self {
        Self::start(true, false).await
    }

    /// Create a test environment with a REAL admin bearer token (H8).
    ///
    /// The old `login_admin` posted a wrong-shaped body and always fell
    /// back to a placeholder string, so every "authenticated" test was
    /// actually exercising the 401 path behind `assert!(resp.is_ok())`.
    ///
    /// Provisioning runs BEFORE the server starts (the tenant DBs are
    /// exclusively locked while a process holds them) and does what a
    /// deploying operator must do after seeding: seed the tenant from the
    /// same config the server would use, create its first signing key
    /// (seeding deliberately creates none), and mint a session for the
    /// seeded `root@test.local` (root+admin — tenant/* policies bind
    /// `root`, the rest `admin`). The server then starts with seeding
    /// disabled and simply loads the provisioned data dir.
    pub async fn new_with_auth() -> Self {
        Self::start(false, true).await
    }

    async fn start(trust_forwarded_headers: bool, provision: bool) -> Self {
        let config = load_test_config();
        let temp_dir = tempfile::tempdir().expect("temp dir");
        let port = pick_port(&config);
        let data_dir = temp_dir.path().join("data");

        let mut admin_token = None;
        let mut user_token = None;
        let server_config_path = if provision {
            // Seed + key + session in THIS process, then hand the server a
            // config without a seed block so it cannot double-seed (policy
            // rows have a unique constraint — a second seed would fail
            // startup).
            let seed_config =
                build_test_config(temp_dir.path(), port, &config.encryption_key, false, true);
            let (admin, user) = provision_sessions(&data_dir, &seed_config, &config.encryption_key)
                .await
                .unwrap_or_else(|e| {
                    panic!(
                        "janux-test: failed to provision test sessions: {e:#} — \
                             authenticated integration tests cannot run"
                    )
                });
            println!(
                "janux-test: provisioned seed + signing key + real admin and user-role sessions"
            );
            admin_token = Some(admin);
            user_token = Some(user);
            build_test_config(
                temp_dir.path(),
                port,
                &config.encryption_key,
                trust_forwarded_headers,
                false,
            )
        } else {
            build_test_config(
                temp_dir.path(),
                port,
                &config.encryption_key,
                trust_forwarded_headers,
                true,
            )
        };

        let child = spawn_server(&server_config_path)
            .expect("Failed to auto-start janux server — try: 'cargo build --bin janux'");

        if !wait_for_health(port).await {
            panic!("Janux server started but never became healthy. Check logs above.");
        }

        TestEnv {
            base_url: format!("http://127.0.0.1:{port}"),
            admin_token,
            user_token,
            data_dir,
            encryption_key: config.encryption_key.clone(),
            _child: Some(child),
            _temp_dir: temp_dir,
        }
    }

    /// The server's data directory (tenants/, backups/, revocation store).
    pub fn data_dir(&self) -> &std::path::Path {
        &self.data_dir
    }
}

/// Seed the tenant, create its first signing key and mint the test
/// sessions — all through the janux lib, before the server process exists.
/// Returns `(admin_token, user_token)`: the admin session drives the
/// happy paths; the user-role session is the deny-path principal (G-28 —
/// a VALID token with insufficient roles must get 403, not 401/200).
async fn provision_sessions(
    data_dir: &std::path::Path,
    seed_config: &std::path::Path,
    encryption_key: &str,
) -> anyhow::Result<(String, String)> {
    // Same key for every env (tests/test_config.toml); the setter is
    // process-wide first-call-wins and errors on later calls.
    let _ = janux::crypto::setup_encryption_key(encryption_key);
    // Occupy the process-wide revocation-store singleton with a scratch
    // dir BEFORE `Storage::init`: the store opens its jwt.db exclusively,
    // and binding the singleton to an env data dir would collide with the
    // server process that later opens the same file.
    PROVISION_STORE_INIT
        .get_or_init(|| async {
            janux::jwt::InvalidJwt::init_global(PROVISION_STORE_DIR.path())
                .await
                .expect("scratch revocation store");
        })
        .await;

    let cfg = janux::server::JanuxConfig::load_from(&[seed_config
        .to_str()
        .expect("config path utf-8")
        .to_string()])?;
    let mut storage = janux::db::Storage::init(data_dir).await?;
    storage = storage.seed(&cfg).await?;
    let mut tenant = storage
        .tenant_by_id("test-tenant")
        .ok_or_else(|| anyhow::anyhow!("seeded tenant 'test-tenant' missing"))?;
    tenant.key_create("localhost", "key1").await?;
    let token = tenant
        .authenticate_jwt(
            &std::collections::HashSet::new(),
            "http://localhost",
            "localhost",
            "root@test.local",
            120,
        )
        .await?;
    let user_token = tenant
        .authenticate_jwt(
            &std::collections::HashSet::new(),
            "http://localhost",
            "localhost",
            "user@test.local",
            120,
        )
        .await?;
    // `storage`/`tenant` drop here, releasing the tenant DB handles so the
    // server process can open them exclusively-clean on boot.
    Ok((token, user_token))
}

// ─── Port allocation and server startup ────────────────────────────────────────

fn is_port_available(port: u16) -> bool {
    std::net::TcpListener::bind(format!("127.0.0.1:{port}")).is_ok()
}

/// Allocate an available port starting from the configured base port.
fn pick_port(config: &TestConfig) -> u16 {
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
            return port;
        }
    }
    panic!("No available port found in range");
}

fn spawn_server(config_path: &std::path::Path) -> Result<Child, String> {
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

    println!(
        "janux-test: server started with config {}",
        config_path.display()
    );
    Ok(child)
}

/// Build a temporary server config. `include_seed` controls whether the
/// server seeds the tenant itself (plain envs) or loads an already
/// provisioned data dir (authenticated envs — double-seeding would trip
/// the policy unique constraint and fail startup).
fn build_test_config(
    tmp_dir: &std::path::Path,
    port: u16,
    encryption_key: &str,
    trust_forwarded_headers: bool,
    include_seed: bool,
) -> std::path::PathBuf {
    let seed_block = if include_seed {
        format!(
            r#"
[[seed]]
name = "test-tenant"
domains = [{{ id = "localhost", cors = [] }}]
# Roles must be declared before users reference them: user_add_role no
# longer creates unknown roles (api-consolidation Step 4). `scim` joins
# the catalog so the seeded tenant mirrors bootstrap_tenant's builtin set.
roles = ["root", "admin", "scim", "user", "guest"]
# The seeded tenant gets ONLY the policies listed here (bootstrap_tenant's
# standard set applies to runtime-created tenants), so mirror it — with an
# empty list the protect hoop default-denies every admin endpoint and the
# "authenticated" integration tests silently exercise nothing (H8).
policies = [
{policies}
]
users = [
    # root+admin: tenant/* policies bind `root`, the rest bind `admin` —
    # an operator session needs both to walk the whole admin surface.
    {{ id = "root@test.local", active = true, roles = ["root", "admin"] }},
    {{ id = "admin@test.local", active = true, roles = ["admin"] }},
    {{ id = "user@test.local", active = true, roles = ["user"] }},
]

[seed.resend]
from = "test@test.com"
resend_key = "test-key"
template = "./email/verify.html"
verify_url = "http://localhost/login"
# Dead address: email ceremonies fail closed and FAST in tests instead of
# calling the real Resend API with a dummy key.
base_url = "http://127.0.0.1:1"

[seed.alisms]
api_secret = "test-secret"
api_key = "test-key-api"
template_code = "TEST_123"
sign_name = "Test"
region_id = "cn-shanghai"
endpoint = "dysmsapi.aliyuncs.com"
"#,
            policies = seed_policy_rows("localhost")
        )
    } else {
        String::new()
    };

    let config_content = format!(
        r#"data_dir = "{data_dir}"
encryption_key = "{encryption_key}"
trust_forwarded_headers = {trust_forwarded_headers}

[bind]
address = "127.0.0.1"
port = {port}
{seed_block}"#,
        data_dir = tmp_dir.join("data").to_string_lossy(),
    );

    // Distinct file names so the provisioned env's seed config and server
    // config can coexist in one temp dir.
    let file_name = if include_seed {
        "seed_config.toml"
    } else {
        "test_config.toml"
    };
    let config_path = tmp_dir.join(file_name);
    std::fs::write(&config_path, &config_content).expect("Failed to write test config");
    config_path
}

/// TOML rows mirroring `STANDARD_ADMIN_POLICIES` (src/seed.rs) for the
/// seeded test tenant: root owns tenant lifecycle, admin owns the rest,
/// user gets the self-service rows.
fn seed_policy_rows(domain: &str) -> String {
    const ROOT: &[&str] = &[
        "/api/v1/admin/tenant/list",
        "/api/v1/admin/tenant/create",
        "/api/v1/admin/tenant/delete",
    ];
    const ADMIN: &[&str] = &[
        "/api/v1/admin/domain/list",
        "/api/v1/admin/domain/create",
        "/api/v1/admin/domain/delete",
        "/api/v1/admin/user/list",
        "/api/v1/admin/user/create",
        "/api/v1/admin/user/activate",
        "/api/v1/admin/user/delete",
        "/api/v1/admin/user/add_role",
        "/api/v1/admin/user/remove_role",
        "/api/v1/admin/user/remove_email",
        "/api/v1/admin/user/attach_email",
        "/api/v1/admin/user/remove_mobile",
        "/api/v1/admin/user/remove_passkey",
        "/api/v1/admin/user/remove_social",
        "/api/v1/admin/user/roles",
        "/api/v1/admin/role/list",
        "/api/v1/admin/role/create",
        "/api/v1/admin/role/delete",
        "/api/v1/admin/provider/list",
        "/api/v1/admin/provider/create",
        "/api/v1/admin/provider/delete",
        "/api/v1/admin/policy/list",
        "/api/v1/admin/policy/create",
        "/api/v1/admin/policy/delete",
        "/api/v1/admin/key/list",
        "/api/v1/admin/key/create",
        "/api/v1/admin/key/delete",
        "/api/v1/admin/key/retire",
        "/api/v1/admin/totp/list",
        "/api/v1/admin/totp/remove",
        "/api/v1/admin/oauth2client/list",
        "/api/v1/admin/oauth2client/create",
        "/api/v1/admin/oauth2client/delete",
        "/api/v1/admin/oauth2client/meta",
        "/api/v1/admin/oidc/config",
        "/api/v1/admin/metrics",
    ];
    const USER: &[&str] = &[
        "/api/v1/admin/user/activate/self",
        "/api/v1/admin/user/delete/self",
    ];
    let mut rows = Vec::new();
    for (role, paths) in [("root", ROOT), ("admin", ADMIN), ("user", USER)] {
        for p in paths {
            rows.push(format!(
                "    {{ domain = \"{domain}\", resource = \"{p}\", role = \"{role}\", source = \"Nothing\", target = \"Nothing\", mfa = false, allowed = true }},"
            ));
        }
    }
    rows.join("\n")
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
