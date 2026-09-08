// E2E test entry point for Janux auth.
//
// HTTP-level end-to-end: a single REAL Janux server binary is
// automatically started once (on first access) against a provisioned
// data dir, and the tests drive its public surfaces over reqwest —
// discovery, JWKS, factor ceremonies, the admin API under a real root
// session, and the hosted SPA pages. There is no browser automation in
// this tier (G-158: the old "Playwright-driven" claims described tests
// that never existed); browser-driven UI coverage is tracked separately
// in gaps.md.
//
// The server stays alive until the test run ends, regardless of which
// individual test borrows it — so tests **must** be run serially
// (`--test-threads=1`).

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
/// Provisioned WITH a real admin session (H8): `new_with_auth` seeds the
/// tenant, creates its signing key and mints a root+admin token before
/// the server starts, so authenticated tests exercise the real RBAC
/// stack instead of asserting nothing behind `Option::None`.
static SHARED_ENV: Mutex<Option<common::TestEnv>> = Mutex::new(None);

/// Lazily start (or reuse) the shared Janux server and return its base URL string.
#[allow(clippy::await_holding_lock)] // one-shot lazy init; e2e runs single-threaded
async fn shared_server() -> String {
    let mut guard = SHARED_ENV.lock().unwrap();
    if guard.is_none() {
        println!("janux-test: starting single shared test server for all E2E tests…");
        *guard = Some(common::TestEnv::new_with_auth().await);
    }
    guard.as_ref().unwrap().base_url().to_string()
}

/// The shared server's real root+admin bearer token (panics if the
/// provisioning failed — authenticated e2e tests cannot run without it).
#[allow(clippy::await_holding_lock)] // one-shot lazy init; e2e runs single-threaded
async fn shared_admin_token() -> String {
    let mut guard = SHARED_ENV.lock().unwrap();
    if guard.is_none() {
        *guard = Some(common::TestEnv::new_with_auth().await);
    }
    guard
        .as_ref()
        .unwrap()
        .admin_token
        .clone()
        .expect("shared e2e server must be provisioned with an admin session")
}
