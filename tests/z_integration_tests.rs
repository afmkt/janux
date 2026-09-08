//! Integration tests for Janux auth.
//!
//! These tests auto-start a server via `tests/test_config.toml`.
//!
//!
//! To run:
//!   cargo test --test integration_tests

mod common;

use common::TestEnv;
use reqwest::Client;
use serde_json::json;

// ─── Health endpoint tests ──────────────────────────────────────────────────

#[tokio::test]
async fn health_check_returns_ok() {
    let env = TestEnv::new().await;
    let resp = Client::new()
        .get(format!("{}/api/v1/healthy", env.base_url()))
        .send()
        .await;

    assert!(resp.is_ok(), "Health endpoint must be reachable");
    let body = resp
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .expect("valid JSON");
    assert_eq!(body["ok"], true);
}

// ─── Tenant management tests ────────────────────────────────────────────────

#[tokio::test]
async fn admin_list_tenants_requires_auth() {
    let env = TestEnv::new().await;
    let resp = Client::new()
        .get(format!("{}/api/v1/admin/tenant/list", env.base_url()))
        .header("Host", "localhost")
        .send()
        .await;

    assert!(resp.is_ok());
    // Without auth should return 401
    let status = resp.unwrap().status();
    assert_eq!(status, reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn admin_create_tenant() {
    let env = TestEnv::new_with_auth().await;

    let resp = Client::new()
        .post(format!("{}/api/v1/admin/tenant/create", env.base_url()))
        .header("Host", "localhost")
        .header(
            "Authorization",
            format!("Bearer {}", env.admin_token.clone().unwrap()),
        )
        .json(&json!({ "name": "integration-tenant" }))
        .send()
        .await;

    assert!(resp.is_ok(), "Tenant create should not error");
    let status = resp.as_ref().unwrap().status();
    let body = resp
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .expect("valid JSON");
    // With a real root session (H8 provisioning) the create must succeed —
    // the old placeholder token made every call a silent 401.
    assert_eq!(status, reqwest::StatusCode::OK, "tenant create: {body}");
    assert_eq!(body["ok"], true, "tenant create body: {body}");
}

// ─── Domain management tests ────────────────────────────────────────────────

#[tokio::test]
async fn admin_delete_domain_validates_host() {
    let env = TestEnv::new_with_auth().await;

    // No explicit Host header: the request resolves against
    // 127.0.0.1:<port>, which is not a provisioned domain — the session
    // cannot validate against an unknown tenant/issuer, so protect fails
    // closed with 401 and never a 5xx. (G-28: this test used to assert
    // only that the transport didn't error.)
    let resp = Client::new()
        .post(format!("{}/api/v1/admin/domain/delete", env.base_url()))
        .header(
            "Authorization",
            format!("Bearer {}", env.admin_token.clone().unwrap()),
        )
        .send()
        .await
        .expect("request must reach the server");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::UNAUTHORIZED,
        "an unresolvable domain fails closed at the auth hoop"
    );
}

// ─── User lifecycle tests ────────────────────────────────────────────────────

#[tokio::test]
async fn admin_create_user_success() {
    let env = TestEnv::new_with_auth().await;

    let resp = Client::new()
        .post(format!("{}/api/v1/admin/user/create", env.base_url()))
        .header("Host", "localhost")
        .header(
            "Authorization",
            format!("Bearer {}", env.admin_token.clone().unwrap()),
        )
        .json(&json!({ "name": "test-integration-user" }))
        .send()
        .await
        .expect("request must reach the server");

    // G-28: a real status+body assertion — `is_ok()` passed on 401/500.
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body = resp.json::<serde_json::Value>().await.expect("json");
    assert_eq!(body["ok"], true, "user create body: {body}");
}

#[tokio::test]
async fn admin_list_users_returns_json_array() {
    let env = TestEnv::new_with_auth().await;

    let resp = Client::new()
        .get(format!("{}/api/v1/admin/user/list", env.base_url()))
        .header("Host", "localhost")
        .header(
            "Authorization",
            format!("Bearer {}", env.admin_token.clone().unwrap()),
        )
        .send()
        .await;

    assert!(resp.is_ok());
    let body = resp
        .unwrap()
        .json::<serde_json::Value>()
        .await
        .expect("valid JSON");
    // Response should contain ok field (success) or status field (error like 401)
    assert!(
        body.get("ok").is_some() || body.get("status").is_some(),
        "Response should have ok or status field: {:?}",
        body
    );
}

#[tokio::test]
async fn admin_delete_user_by_name() {
    let env = TestEnv::new_with_auth().await;
    let client = Client::new();
    let auth = format!("Bearer {}", env.admin_token.clone().unwrap());

    // Create the user first — each env is a fresh server, so the old test
    // was deleting a nonexistent user and passing on the transport-level
    // `is_ok()` alone (G-28).
    let resp = client
        .post(format!("{}/api/v1/admin/user/create", env.base_url()))
        .header("Host", "localhost")
        .header("Authorization", &auth)
        .json(&json!({ "name": "delete-me" }))
        .send()
        .await
        .expect("create request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let resp = client
        .post(format!("{}/api/v1/admin/user/delete", env.base_url()))
        .header("Host", "localhost")
        .header("Authorization", &auth)
        .json(&json!({ "user": "delete-me" }))
        .send()
        .await
        .expect("delete request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body = resp.json::<serde_json::Value>().await.expect("json");
    assert_eq!(body["ok"], true, "user delete body: {body}");
}

#[tokio::test]
async fn admin_activate_deactivate_user() {
    let env = TestEnv::new_with_auth().await;
    let client = Client::new();
    let auth = format!("Bearer {}", env.admin_token.clone().unwrap());

    for (active, label) in [
        (true, "activate"),
        (false, "deactivate"),
        (true, "re-activate"),
    ] {
        let resp = client
            .post(format!("{}/api/v1/admin/user/activate", env.base_url()))
            .header("Host", "localhost")
            .header("Authorization", &auth)
            .json(&json!({ "user": "admin@test.local", "active": active }))
            .send()
            .await
            .expect("activate request");
        // G-28: root outranks admin (H3), so every transition must be a
        // real 200 — `is_ok()` used to pass on the 403/500 paths too.
        assert_eq!(resp.status(), reqwest::StatusCode::OK, "{label}");
        let body = resp.json::<serde_json::Value>().await.expect("json");
        assert_eq!(body["ok"], true, "{label} body: {body}");
    }
}

// ─── Role management tests ──────────────────────────────────────────────────

#[tokio::test]
async fn admin_create_role_and_delete() {
    let env = TestEnv::new_with_auth().await;
    let client = Client::new();
    let auth = format!("Bearer {}", env.admin_token.clone().unwrap());

    // Create role (level is REQUIRED — the old body omitted it and the
    // test passed on the transport-level `is_ok()` despite the 400).
    let resp = client
        .post(format!("{}/api/v1/admin/role/create", env.base_url()))
        .header("Host", "localhost")
        .header("Authorization", &auth)
        .json(&json!({ "name": "test-role-xyz", "level": 50 }))
        .send()
        .await
        .expect("role create request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Delete role — G-154: the delete cascades policies/memberships and
    // must be a real 200.
    let resp2 = client
        .post(format!("{}/api/v1/admin/role/delete", env.base_url()))
        .header("Host", "localhost")
        .header("Authorization", &auth)
        .json(&json!({ "name": "test-role-xyz" }))
        .send()
        .await
        .expect("role delete request");
    assert_eq!(resp2.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn admin_list_roles_returns_builtin_catalog() {
    let env = TestEnv::new_with_auth().await;

    let resp = Client::new()
        .get(format!("{}/api/v1/admin/role/list", env.base_url()))
        .header("Host", "localhost")
        .header(
            "Authorization",
            format!("Bearer {}", env.admin_token.clone().unwrap()),
        )
        .send()
        .await
        .expect("role list request");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body = resp.json::<serde_json::Value>().await.expect("json");
    let names: Vec<&str> = body["data"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("role list shape: {body}"))
        .iter()
        .filter_map(|r| r["name"].as_str())
        .collect();
    for builtin in ["root", "admin", "scim", "user", "guest"] {
        assert!(
            names.contains(&builtin),
            "missing builtin {builtin}: {names:?}"
        );
    }
}

// ─── Policy management tests ────────────────────────────────────────────────

#[tokio::test]
async fn admin_create_policy_get_and_delete() {
    let env = TestEnv::new_with_auth().await;
    let client = Client::new();
    let auth = format!("Bearer {}", env.admin_token.clone().unwrap());

    // Create policy — the caller is root@test.local (level 100), the
    // target role is admin (80): the level gate allows the downward
    // write, and G-28 wants the real 200 asserted.
    let resp = client
        .post(format!("{}/api/v1/admin/policy/create", env.base_url()))
        .header("Host", "localhost")
        .header("Authorization", &auth)
        .json(&json!({
            "domain": "localhost",
            "resource": "test/path",
            "action": "GET",
            "role": "admin",
            "source": "Nothing",
            "target": "Nothing",
            "mfa": false,
            "allowed": true
        }))
        .send()
        .await
        .expect("policy create request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    // Delete policy
    let resp2 = client
        .post(format!("{}/api/v1/admin/policy/delete", env.base_url()))
        .header("Host", "localhost")
        .header("Authorization", &auth)
        .json(&json!({
            "domain": "localhost",
            "resource": "test/path",
            "action": "GET",
            "role": "admin"
        }))
        .send()
        .await
        .expect("policy delete request");
    assert_eq!(resp2.status(), reqwest::StatusCode::OK);
}

// ─── Social provider tests ──────────────────────────────────────────────────

#[tokio::test]
async fn admin_create_provider_and_delete() {
    let env = TestEnv::new_with_auth().await;
    let client = Client::new();
    let auth = format!("Bearer {}", env.admin_token.clone().unwrap());

    // The full provider shape — the old body carried only `id` and the
    // test passed on `is_ok()` despite the 400 (G-28).
    let resp = client
        .post(format!("{}/api/v1/admin/provider/create", env.base_url()))
        .header("Host", "localhost")
        .header("Authorization", &auth)
        .json(&json!({
            "name": "google-oauth2-test",
            "client_id": "test-client-id",
            "client_secret": "test-client-secret",
            "issuer_url": "https://accounts.google.com"
        }))
        .send()
        .await
        .expect("provider create request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);

    let resp = client
        .post(format!("{}/api/v1/admin/provider/delete", env.base_url()))
        .header("Host", "localhost")
        .header("Authorization", &auth)
        .json(&json!({ "name": "google-oauth2-test" }))
        .send()
        .await
        .expect("provider delete request");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

#[tokio::test]
async fn admin_list_providers_returns_json() {
    let env = TestEnv::new_with_auth().await;

    let resp = Client::new()
        .get(format!("{}/api/v1/admin/provider/list", env.base_url()))
        .header("Host", "localhost")
        .header(
            "Authorization",
            format!("Bearer {}", env.admin_token.clone().unwrap()),
        )
        .send()
        .await
        .expect("provider list request");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let raw = resp.text().await.expect("body");
    let body: serde_json::Value = serde_json::from_str(&raw).expect("json");
    assert!(
        body["data"]["items"].is_array(),
        "provider list shape: {body}"
    );
    // G-147 pinned at the HTTP level: the secret is write-only.
    assert!(
        !raw.contains("client_secret"),
        "the provider list must never serialize client_secret: {raw}"
    );
}

// ─── Key / JWKS tests ───────────────────────────────────────────────────────

#[tokio::test]
async fn public_jwks_endpoint_accessible_without_auth() {
    let env = TestEnv::new().await;

    let resp = Client::new()
        .get(format!("{}/.well-known/jwks.json", env.base_url()))
        .send()
        .await
        .expect("jwks request");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body = resp.json::<serde_json::Value>().await.expect("json");
    // The seed creates a signing key per domain (G-136), so even this
    // unprovisioned-host skeleton answers with a keys array.
    assert!(body["keys"].is_array(), "jwks shape: {body}");
}

#[tokio::test]
async fn admin_add_key_returns_response() {
    let env = TestEnv::new_with_auth().await;

    // Addkey takes {domain, name} — the old `key_id` body 400'd while the
    // test passed on `is_ok()` (G-28).
    let resp = Client::new()
        .post(format!("{}/api/v1/admin/key/create", env.base_url()))
        .header("Host", "localhost")
        .header(
            "Authorization",
            format!("Bearer {}", env.admin_token.clone().unwrap()),
        )
        .json(&json!({
            "domain": "",
            "name": "test-key-for-integration"
        }))
        .send()
        .await
        .expect("key create request");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body = resp.json::<serde_json::Value>().await.expect("json");
    assert_eq!(body["ok"], true, "key create body: {body}");
}

// ─── Passwordless auth tests ──────────────────────────────────────────────────

#[tokio::test]
async fn email_request_fails_closed_without_a_reachable_provider() {
    let env = TestEnv::new_with_auth().await;

    // The test config points Resend at a dead address (127.0.0.1:1), so
    // the ceremony must fail CLOSED with a determinate client error —
    // never 404 (route missing) or 5xx (crash). The old test accepted
    // literally any outcome, including a transport error (G-28).
    let resp = Client::new()
        .post(format!("{}/api/v1/auth/email/request", env.base_url()))
        .header("Host", "localhost")
        .json(&json!({
            "name": "admin",
            "email": "admin@test.local"
        }))
        .send()
        .await
        .expect("email/request must be reachable");

    let status = resp.status();
    assert_ne!(
        status,
        reqwest::StatusCode::NOT_FOUND,
        "the route must be wired"
    );
    assert!(
        status.is_client_error(),
        "an unreachable provider must produce a determinate 4xx, got {status}"
    );
}

// ─── User self-management tests ──────────────────────────────────────────────

/// G-28's core gap: no HTTP-level test asserted the policy engine's DENY
/// path — a valid session with insufficient roles must get 403 (not 401,
/// and certainly not 200) from the real `protect` hoop.
#[tokio::test]
async fn admin_surface_denies_valid_session_with_insufficient_role() {
    let env = TestEnv::new_with_auth().await;
    let user_token = env
        .user_token
        .clone()
        .expect("provisioned user-role session");

    let resp = Client::new()
        .get(format!("{}/api/v1/admin/user/list", env.base_url()))
        .header("Host", "localhost")
        .header("Authorization", format!("Bearer {user_token}"))
        .send()
        .await
        .expect("request must reach the server");

    assert_eq!(
        resp.status(),
        reqwest::StatusCode::FORBIDDEN,
        "a valid `user`-role session must be denied the admin surface by the policy engine"
    );
}

#[tokio::test]
async fn user_delete_self_requires_auth() {
    let env = TestEnv::new().await;

    let resp = Client::new()
        .post(format!("{}/api/v1/admin/user/delete/self", env.base_url()))
        .header("Host", "localhost")
        .send()
        .await
        .expect("request must reach the server");

    // G-28: fail closed with 401 — `is_ok()` passed on any status.
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn user_activate_self_requires_auth() {
    let env = TestEnv::new().await;

    let resp = Client::new()
        .post(format!(
            "{}/api/v1/admin/user/activate/self",
            env.base_url()
        ))
        .header("Host", "localhost")
        .send()
        .await;

    assert!(resp.is_ok());
}

// ─── Role assignment tests ──────────────────────────────────────────────────

#[tokio::test]
async fn admin_add_role_to_user() {
    let env = TestEnv::new_with_auth().await;

    let resp = Client::new()
        .post(format!("{}/api/v1/admin/user/add_role", env.base_url()))
        .header("Host", "localhost")
        .header(
            "Authorization",
            format!("Bearer {}", env.admin_token.clone().unwrap()),
        )
        .json(&json!({
            "user": "user@test.local",
            "role": "admin"
        }))
        .send()
        .await;

    assert!(resp.is_ok());

    // Remove role
    let resp2 = Client::new()
        .post(format!("{}/api/v1/admin/user/remove_role", env.base_url()))
        .header("Host", "localhost")
        .header(
            "Authorization",
            format!("Bearer {}", env.admin_token.clone().unwrap()),
        )
        .json(&json!({
            "user": "user@test.local",
            "role": "admin"
        }))
        .send()
        .await;

    assert!(resp2.is_ok());
}

#[tokio::test]
async fn user_roles_returns_list() {
    let env = TestEnv::new_with_auth().await;

    // Router config uses .get() for user/roles, not POST
    let resp = Client::new()
        .get(format!("{}/api/v1/admin/user/roles", env.base_url()))
        .header("Host", "localhost")
        .query(&[("name", "admin@test.local")])
        .send()
        .await;

    assert!(resp.is_ok());
    // Route accepts GET with query param 'name' (matching UserRoleRequest which also checks request.query)
}

// ─── Tenant lifecycle test (create → verify → delete) ──────────────────────

/// H8: the full lifecycle under a REAL root+admin session, asserting every
/// step's status and body — plus the three properties the old `is_ok()`
/// smoke test never verified: role bootstrap on the new tenant, the H9
/// domain binding of key/create, and the on-disk delete backup.
#[tokio::test]
async fn full_tenant_lifecycle_create_and_delete() {
    let env = TestEnv::new_with_auth().await;
    let token = env.admin_token.clone().unwrap();
    let client = Client::new();

    let tenant_name = format!("lifecycle-tenant-{}", uuid::Uuid::new_v4().simple());
    let domain = format!("{}.test.local", tenant_name);

    // Authenticated call helper: `host` selects the tenant/domain the
    // policy engine evaluates against.
    async fn call(
        client: &Client,
        env: &TestEnv,
        token: &str,
        method: reqwest::Method,
        host: &str,
        path: &str,
        body: Option<serde_json::Value>,
    ) -> (reqwest::StatusCode, serde_json::Value) {
        let mut rb = client
            .request(method, format!("{}{path}", env.base_url()))
            .header("Host", host)
            .header("Authorization", format!("Bearer {}", token));
        if let Some(b) = body {
            rb = rb.json(&b);
        }
        let resp = rb.send().await.expect("request transport");
        let status = resp.status();
        let body = resp.json().await.unwrap_or(serde_json::Value::Null);
        (status, body)
    }

    // 1. Create the tenant WITH its first domain and admin — the
    //    bootstrap path (a fresh tenant has no domain to route
    //    domain/create through; `NewTenant.domain` is the trust anchor).
    let (status, body) = call(
        &client,
        &env,
        &token,
        reqwest::Method::POST,
        "localhost",
        "/api/v1/admin/tenant/create",
        Some(json!({
            "name": &tenant_name,
            "domain": &domain,
            "admin": format!("admin@{}", tenant_name),
        })),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "tenant create: {body}");
    assert_eq!(body["ok"], true, "tenant create body: {body}");

    // 2. The new tenant is listed. Its INTERIORS (role catalog, policies,
    //    first admin) cannot be inspected over HTTP from this session:
    //    JWTs are domain-bound and the fresh domain has no signing key
    //    yet, so no session can exist on it. The bootstrap contract is
    //    pinned at lib level instead — see
    //    seed::tests::bootstrap_tenant_provisions_catalog_policies_and_admin.
    let (status, body) = call(
        &client,
        &env,
        &token,
        reqwest::Method::GET,
        "localhost",
        "/api/v1/admin/tenant/list",
        None,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "tenant list: {body}");
    let listed: Vec<String> = body["data"]["items"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    assert!(
        listed.iter().any(|n| n == &tenant_name),
        "the new tenant must be listed: {listed:?}"
    );

    // 3. Delete the tenant (root-only policy row, evaluated on the
    //    operator's Host; the target is named in the body).
    let (status, body) = call(
        &client,
        &env,
        &token,
        reqwest::Method::POST,
        "localhost",
        "/api/v1/admin/tenant/delete",
        Some(json!({ "name": &tenant_name })),
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "tenant delete: {body}");

    // 8. Cascade: the tenant is gone from the directory...
    let (status, body) = call(
        &client,
        &env,
        &token,
        reqwest::Method::GET,
        "localhost",
        "/api/v1/admin/tenant/list",
        None,
    )
    .await;
    assert_eq!(status, reqwest::StatusCode::OK, "tenant list: {body}");
    let listed: Vec<String> = body["data"]["items"]
        .as_array()
        .unwrap_or(&Vec::new())
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();
    assert!(
        !listed.iter().any(|n| n == &tenant_name),
        "the deleted tenant must not be listed: {listed:?}"
    );

    // 9. ...and the delete left a DB backup on disk (H2b). Router/domain
    //    cascade is pinned at lib level (db::tests::tenant_delete_backups_
    //    are_pruned_to_retention) — no HTTP probe can distinguish it here:
    //    sessions are domain-bound, so every admin call on the deleted
    //    domain 401s both before and after the delete.
    let backups = env.data_dir().join("backups");
    let prefix = format!("{tenant_name}-");
    let backed_up = std::fs::read_dir(&backups)
        .expect("backups dir must exist after a tenant delete")
        .filter_map(|e| e.ok())
        .any(|e| {
            e.file_name().to_string_lossy().starts_with(&prefix)
                && e.path().join("janux.db").exists()
        });
    assert!(
        backed_up,
        "tenant delete must back up the database under backups/{prefix}*/janux.db"
    );
}

/// H9 over HTTP: the operator's root session may seed a SIBLING domain's
/// first signing key through its own Host — the only path that can, since
/// sessions are domain-bound and `current_key` is per-domain — while a
/// domain outside the tenant stays refused even for root.
#[tokio::test]
async fn root_session_provisions_sibling_domain_key() {
    let env = TestEnv::new_with_auth().await;
    let token = env.admin_token.clone().unwrap();
    let client = Client::new();
    let sibling = format!("sibling-{}.local", uuid::Uuid::new_v4().simple());

    // Attach the sibling domain to the seeded tenant.
    let resp = client
        .post(format!("{}/api/v1/admin/domain/create", env.base_url()))
        .header("Host", "localhost")
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({ "domain": &sibling, "tenant": "test-tenant" }))
        .send()
        .await
        .expect("domain create");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "sibling domain create must succeed for the tenant's own root"
    );

    // Root provisions its first key through the operator's domain.
    let resp = client
        .post(format!("{}/api/v1/admin/key/create", env.base_url()))
        .header("Host", "localhost")
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({ "domain": &sibling, "name": "key-sibling" }))
        .send()
        .await
        .expect("key create");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::OK,
        "root must be able to seed a sibling domain's first key"
    );

    // A domain outside the tenant is refused even for root.
    let resp = client
        .post(format!("{}/api/v1/admin/key/create", env.base_url()))
        .header("Host", "localhost")
        .header("Authorization", format!("Bearer {}", token))
        .json(&json!({ "domain": "foreign.example", "name": "key-foreign" }))
        .send()
        .await
        .expect("key create");
    assert_eq!(
        resp.status(),
        reqwest::StatusCode::BAD_REQUEST,
        "a foreign domain must be refused even for root"
    );
}

// ─── OAuth2 client CRUD tests ──────────────────────────────────────────────

#[tokio::test]
async fn admin_create_delete_oauth2_client() {
    let env = TestEnv::new_with_auth().await;

    // Create client
    let resp1 = Client::new()
        .post(format!(
            "{}/api/v1/admin/oauth2client/create",
            env.base_url()
        ))
        .header("Host", "localhost")
        .header(
            "Authorization",
            format!("Bearer {}", env.admin_token.clone().unwrap()),
        )
        .json(&json!({
            "client_id": "test-oauth2-client",
            "secret": "test-secret",
            "redirect_uris": "https://rp.example/cb",
            "grant_types": "authorization_code refresh_token",
            "response_types": "code",
            "token_endpoint_auth_method": "client_secret_post",
            "default_scopes": "openid email profile"
        }))
        .send()
        .await
        .expect("client create");
    assert_eq!(resp1.status(), reqwest::StatusCode::OK, "client create");

    // List clients — paginated envelope, and the page's redirect URIs are
    // batch-fetched in one query (G-113 follow-up), so the DTO must carry them.
    let resp2 = Client::new()
        .get(format!("{}/api/v1/admin/oauth2client/list", env.base_url()))
        .header("Host", "localhost")
        .header(
            "Authorization",
            format!("Bearer {}", env.admin_token.clone().unwrap()),
        )
        .send()
        .await
        .expect("client list");
    assert_eq!(resp2.status(), reqwest::StatusCode::OK, "client list");
    let body = resp2
        .json::<serde_json::Value>()
        .await
        .expect("valid JSON list body");
    let items = body["data"]["items"]
        .as_array()
        .unwrap_or_else(|| panic!("list must return a page of items: {body}"));
    let listed = items
        .iter()
        .find(|c| c["id"] == "test-oauth2-client")
        .unwrap_or_else(|| panic!("created client must be listed: {body}"));
    assert_eq!(
        listed["redirect_uris"].as_str().unwrap_or(""),
        "https://rp.example/cb",
        "the batched redirect-URI lookup must populate the DTO"
    );

    // Delete client
    let resp3 = Client::new()
        .post(format!(
            "{}/api/v1/admin/oauth2client/delete",
            env.base_url()
        ))
        .header("Host", "localhost")
        .header(
            "Authorization",
            format!("Bearer {}", env.admin_token.clone().unwrap()),
        )
        .json(&json!({
            "client_id": "test-oauth2-client"
        }))
        .send()
        .await
        .expect("client delete");
    assert_eq!(resp3.status(), reqwest::StatusCode::OK, "client delete");
}

// ─── OIDC /authorize continuation endpoint tests ────────────────────────────
//
// These endpoints resume a parked /authorize request after login. They all
// require a valid session JWT; without one they must reject with 401 and a
// JSON body pointing the SPA back at /login.

#[tokio::test]
async fn authorize_resume_requires_session_jwt() {
    let env = TestEnv::new().await;
    let resp = Client::new()
        .get(format!(
            "{}/authorize/resume?state=some-state",
            env.base_url()
        ))
        .header("Host", "test.local")
        .send()
        .await;

    assert!(resp.is_ok());
    let resp = resp.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    let body = resp
        .json::<serde_json::Value>()
        .await
        .expect("valid JSON body");
    assert_eq!(body["redirect"], "/login?error=session_expired");
}

#[tokio::test]
async fn consent_info_requires_session_jwt() {
    let env = TestEnv::new().await;
    let resp = Client::new()
        .get(format!("{}/consent/info?state=some-state", env.base_url()))
        .header("Host", "test.local")
        .send()
        .await;

    assert!(resp.is_ok());
    let resp = resp.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn consent_submit_requires_session_jwt() {
    let env = TestEnv::new().await;
    let resp = Client::new()
        .post(format!("{}/consent", env.base_url()))
        .header("Host", "test.local")
        .json(&json!({
            "state": "some-state",
            "decision": "accept"
        }))
        .send()
        .await;

    assert!(resp.is_ok());
    let resp = resp.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    let body = resp
        .json::<serde_json::Value>()
        .await
        .expect("valid JSON body");
    assert_eq!(body["redirect"], "/login?error=session_expired");
}

#[tokio::test]
async fn authorize_without_session_redirects() {
    let env = TestEnv::new().await;
    // Do NOT follow redirects — we want to observe the 302 itself.
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    // No session JWT on /authorize: the request must end in a 302 — either
    // parked towards /login (FLOW A) or an OAuth2 error redirect when an
    // earlier validation step (e.g. unknown client) fires first.
    let resp = client
        .get(format!(
            "{}/authorize?response_type=code&client_id=missing-client&redirect_uri=https://rp.example/cb&scope=openid&state=xyz",
            env.base_url()
        ))
        .header("Host", "localhost")
        .send()
        .await;

    assert!(resp.is_ok());
    let resp = resp.unwrap();
    assert_eq!(resp.status(), reqwest::StatusCode::FOUND);
    let loc = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        loc.starts_with("/error") || loc.starts_with("/login"),
        "unexpected redirect target: {loc}"
    );
}

// ─── OIDC extension tests: DCR gate, RP-Initiated + Back-Channel Logout ─────

/// Discovery advertises the logout surface (always) and the registration
/// endpoint only when the tenant opted into Dynamic Client Registration —
/// the seeded test tenant has not, so `registration_endpoint` is absent.
#[tokio::test]
async fn discovery_advertises_logout_profiles() {
    let env = TestEnv::new().await;
    let resp = Client::new()
        .get(format!(
            "{}/.well-known/openid-configuration",
            env.base_url()
        ))
        .header("Host", "localhost")
        .send()
        .await
        .expect("discovery reachable");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let doc = resp.json::<serde_json::Value>().await.expect("valid JSON");

    let end_session = doc["end_session_endpoint"]
        .as_str()
        .expect("end_session_endpoint");
    assert!(
        end_session.ends_with("/end_session"),
        "unexpected end_session_endpoint: {end_session}"
    );
    assert_eq!(doc["backchannel_logout_supported"], json!(true));
    // Stateless sessions carry no `sid` — logout tokens identify by `sub`.
    assert_eq!(doc["backchannel_logout_session_supported"], json!(false));
    assert!(
        doc.get("registration_endpoint").is_none(),
        "registration_endpoint must not be advertised while DCR is disabled"
    );
}

/// RFC 7591 registration is tenant-gated: the default is closed, so a
/// well-formed request still gets an OAuth2-style error, not a client.
#[tokio::test]
async fn register_rejected_while_dcr_disabled() {
    let env = TestEnv::new().await;
    let resp = Client::new()
        .post(format!("{}/register", env.base_url()))
        .header("Host", "localhost")
        .json(&json!({
            "redirect_uris": ["https://rp.example.com/callback"],
            "client_name": "test rp"
        }))
        .send()
        .await
        .expect("register reachable");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    let body = resp.json::<serde_json::Value>().await.expect("valid JSON");
    assert_eq!(body["error"], "invalid_client_metadata");
}

/// A bare `/end_session` with no parameters is a valid logout (no client,
/// no redirect) — it must answer 200, never 500.
#[tokio::test]
async fn end_session_without_params_returns_ok() {
    let env = TestEnv::new().await;
    let resp = Client::new()
        .get(format!("{}/end_session", env.base_url()))
        .header("Host", "localhost")
        .send()
        .await
        .expect("end_session reachable");
    assert_eq!(resp.status(), reqwest::StatusCode::OK);
}

/// RP-Initiated Logout 1.0 §2: `post_logout_redirect_uri` must be
/// previously registered. An unknown client / unregistered URI gets a
/// direct 400 — never a redirect to the unvalidated URI.
#[tokio::test]
async fn end_session_rejects_unregistered_post_logout_redirect_uri() {
    let env = TestEnv::new().await;
    let client = Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    let resp = client
        .get(format!(
            "{}/end_session?client_id=missing-client&post_logout_redirect_uri=https://evil.example/cb&state=abc",
            env.base_url()
        ))
        .header("Host", "localhost")
        .send()
        .await
        .expect("end_session reachable");
    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
    assert!(
        resp.headers().get(reqwest::header::LOCATION).is_none(),
        "must not redirect to an unvalidated post_logout_redirect_uri"
    );
}
