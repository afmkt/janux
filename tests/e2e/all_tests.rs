// E2E test entry point for Janux auth.
//
// A single Janux server is automatically started once (on first access) using
// `tests/test_config.toml` settings and a temporary data directory. It stays
// alive until the test run ends, regardless of which individual test borrows
// it — so tests **must** be run serially (`--test-threads=1`).

use std::sync::Mutex;

#[path = "../common.rs"]
mod common;

pub mod auth_config;
pub mod fixtures;
mod host_resolution;
mod oidc_flow;
mod passkey_flow;
mod signin_flow;
mod signup_flow;
mod tenant_lifecycle;

/// Shared environment — the only running Janux server for all E2E tests.
static SHARED_ENV: Mutex<Option<common::TestEnv>> = Mutex::new(None);

/// Lazily start (or reuse) the shared Janux server and return its base URL string.  
#[allow(clippy::await_holding_lock)] // one-shot lazy init; e2e runs single-threaded
async fn shared_server() -> String {
    let mut guard = SHARED_ENV.lock().unwrap();
    if guard.is_none() {
        println!("janux-test: starting single shared test server for all E2E tests…");
        *guard = Some(common::TestEnv::new().await);
    }
    guard.as_ref().unwrap().base_url().to_string()
}
