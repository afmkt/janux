use crate::db::Tenant;
use crate::domain::Domain;
use crate::utils::{ApiProblem, ApiResponse};
use anyhow::Result;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use dashmap::DashMap;

use rsa::pkcs8::DecodePublicKey;

use jsonwebtoken::jwk::{
    AlgorithmParameters, CommonParameters, Jwk, JwkSet, PublicKeyUse, RSAKeyParameters, RSAKeyType,
};

use rsa::RsaPublicKey;

use rsa::traits::PublicKeyParts;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use toasty::*;
#[derive(Debug, toasty::Model, Clone)]
#[unique(public, private)]
pub struct Key {
    #[key]
    pub id: String,

    pub public: Vec<u8>,
    pub private: Vec<u8>,
    #[index]
    pub domain_id: String,
    #[belongs_to(key = domain_id, references = id)]
    pub domain: Deferred<Domain>,
}
impl Key {
    pub fn public_pem(&self) -> Result<String> {
        String::from_utf8(self.public.clone()).map_err(Into::into)
    }
    /// The private signing key PEM. Stored ciphertext (AES-256-GCM, H2) is
    /// decrypted with the process-wide key; rows written before encryption
    /// at rest load through the legacy-plaintext fallback — the AES-GCM
    /// auth tag makes the two forms unambiguous. Rotate (delete + recreate)
    /// to upgrade a legacy row. A DB or backup disclosure therefore no
    /// longer hands out the material to forge any session/ID/refresh token.
    pub fn private_pem(&self) -> Result<String> {
        let stored = String::from_utf8(self.private.clone())?;
        Ok(crate::crypto::decrypt_secret_or_legacy(&stored))
    }
}

impl Tenant {
    /// Populates the per-domain active key cache, which is used as a default signer
    /// when issuing new JWTs.
    ///
    /// A domain may have multiple keys (e.g. during rotation), but signing only needs
    /// one. Any key in the DB can sign tokens — the `kid` carried by each JWT header
    /// uniquely routes verification to the correct key regardless of which one this
    /// cache holds.
    ///
    /// Since iteration order of `all_keys()` is nondeterministic, if a domain has
    /// multiple keys the "active" key is chosen arbitrarily. This is intentional:
    /// any key works for signing. To remove a key from consideration entirely,
    /// delete it from the database.
    pub async fn active_key_cache(&mut self) -> Result<DashMap<String, Key>> {
        let ret = DashMap::new();
        let ks = self.all_keys().await?;
        for k in ks {
            ret.insert(k.domain_id.clone(), k);
        }
        Ok(ret)
    }

    pub fn current_key(&self, domain: &str) -> Result<Key> {
        match self.keys.get(domain) {
            Some(key) => Ok(key.value().clone()),
            None => Err(anyhow::anyhow!("No active key")),
        }
    }

    pub async fn key_create(&mut self, domain: &str, name: &str) -> Result<()> {
        let alg = &rcgen::PKCS_RSA_SHA256;
        let pruned_key = rcgen::KeyPair::generate_for(alg)?;
        // H2: the private signing key is the crown jewel — encrypt it at
        // rest like every other secret (TOTP/social/provider). Fail closed
        // when the process encryption key is missing: production cannot
        // reach this point without one (main exits during startup), and a
        // silent plaintext fallback would recreate exactly the exposure
        // this fixes. Reads go through `private_pem`'s legacy fallback, so
        // pre-existing plaintext rows keep signing.
        let private = crate::crypto::encrypt_secret(&pruned_key.serialize_pem())?.into_bytes();
        let public = pruned_key.public_key_pem().into_bytes();

        toasty::create!(Key {
            id: name,
            public,
            private,
            domain_id: domain,
        })
        .exec(&mut self.database)
        .await
        .map(|_| ())
        .map_err::<anyhow::Error, _>(Into::into)?;

        // Insert the new key into the in-memory cache so it is visible for signing.
        if let Ok(key) = self.key(name).await {
            self.keys.insert(domain.to_string(), key);
        }

        Ok(())
    }

    pub async fn key(&mut self, name: &str) -> Result<Key> {
        Key::get_by_id(&mut self.database, name)
            .await
            .map_err(Into::into)
    }

    pub async fn all_keys(&mut self) -> Result<Vec<Key>> {
        Key::all()
            .exec(&mut self.database)
            .await
            .map_err(Into::into)
    }

    pub async fn key_delete(&mut self, name: &str) -> Result<()> {
        let k = self.key(name).await?;

        // Remove from persistent storage
        if let Err(e) = Key::delete_by_id(&mut self.database, name).await {
            return Err(anyhow::anyhow!(
                "failed to delete key '{}' from DB: {}",
                name,
                e
            ));
        }
        if let Some((s, k)) = self.keys.remove(&k.domain_id) {
            assert!(s == k.domain_id);
            // Re-seat the active-key cache from the remaining rows of this
            // domain. Queried directly instead of via `domain.keys.get()`:
            // the deferred relation panics ("deferred field not loaded")
            // on a plain `Domain::get_by_id` row — deleting a domain's
            // cached active key used to crash the request task.
            if let Ok(remaining) = self.all_keys().await
                && let Some(new_key) = remaining
                    .into_iter()
                    .find(|key| key.domain_id == k.domain_id)
            {
                self.keys.insert(k.domain_id, new_key);
            }
        }
        Ok(())
    }
}

#[derive(Serialize, Deserialize, ToSchema)]
pub struct KeyEntry {
    pub name: String,
    pub public: String,
    pub domain: String,
}

#[endpoint(
    summary = "List all keys in a tenant",
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<Vec<KeyEntry>>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
    )
)]
pub async fn all_keys(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    if let Some(mut tenant) = state.storage.tenant_by_domain(domain)
        && let Ok(keys) = tenant.all_keys().await
    {
        res.status_code(StatusCode::OK);
        res.render(Json(ApiResponse::ok(
            keys.iter()
                .map(|entry| {
                    if let Ok(dk) = entry.public_pem() {
                        return KeyEntry {
                            name: entry.id.clone(),
                            public: dk,
                            domain: entry.domain_id.clone(),
                        };
                    }
                    KeyEntry {
                        name: entry.id.clone(),
                        public: String::from("Invalid public key"),
                        domain: entry.domain_id.clone(),
                    }
                })
                .collect::<Vec<_>>(),
        )));
        return;
    }

    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

#[derive(Serialize, Deserialize, ToSchema)]
struct Addkey {
    /// The domain the key is for. H9: the AUTHENTICATED request domain is
    /// authoritative — a non-empty mismatch is refused unless the caller
    /// is root (level 100) AND the claimed domain is a sibling of the
    /// same tenant, the only path that can seed a second domain's first
    /// signing key.
    domain: String,
    name: String,
}

#[endpoint(
    summary = "Add scope to tenant",
    request_body = Addkey,
    responses(
        (status_code = 200, description = "Scope created successfully", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request, or non-root cross-domain claim", body = ApiProblem),
        (status_code = 401, description = "Cross-domain claim without a verified session", body = ApiProblem)
    )
)]
pub async fn add_key(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    // Extract the caller BEFORE borrowing ServerState out of the depot —
    // `obtain_mut` keeps depot mutably borrowed for the rest of the handler.
    let caller = crate::utils::caller_from_depot(depot);
    if let Some(body) = crate::utils::extract::<Addkey>(req, None).await {
        let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();
        let domain = crate::utils::get_domain(req, state).unwrap_or("");
        if let Some(mut tenant) = state.storage.tenant_by_domain(domain) {
            // H9: the authenticated domain is authoritative. A body domain
            // is honored only for a ROOT caller provisioning a SIBLING
            // domain of the same tenant — without that exception a second
            // domain could never obtain its first signing key (sessions
            // are domain-bound and `current_key` is per-domain), but
            // admin-level cross-domain injection stays refused.
            let target = if body.domain.is_empty() || body.domain == domain {
                domain.to_string()
            } else {
                let caller = match caller {
                    Some(c) => c,
                    None => {
                        res.status_code(StatusCode::UNAUTHORIZED);
                        res.render(Json(ApiProblem::unauthorized()));
                        return;
                    }
                };
                let is_root =
                    tenant.effective_level(&caller).await == crate::role::builtin_level("root");
                let is_sibling = tenant.domain(&body.domain).await.is_ok();
                if !is_root || !is_sibling {
                    let err = ApiProblem::validation_error(
                        "domain does not match the authenticated request domain",
                    );
                    res.status_code(StatusCode::BAD_REQUEST);
                    res.render(Json(err));
                    return;
                }
                body.domain.clone()
            };
            if tenant.key_create(&target, &body.name).await.is_ok() {
                let resp = ApiResponse::ok(());
                res.status_code(StatusCode::OK);
                res.render(Json(resp));
                return;
            }
        }
    };
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

#[derive(Deserialize, ToSchema)]
pub struct DeleteKey {
    pub name: String,
}

#[endpoint(
    summary = "Remove a scope from tenant",
    request_body = DeleteKey,
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
        (status_code = 403, description = "Key belongs to another domain", body = ApiProblem)
    )
)]
pub async fn delete_key(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    if let Some(body) = crate::utils::extract::<DeleteKey>(req, None).await {
        let state = depot.obtain_mut::<crate::server::ServerState>().unwrap();
        let domain = crate::utils::get_domain(req, state).unwrap_or("");
        if let Some(mut tenant) = state.storage.tenant_by_domain(domain) {
            // H9 (same class as create): one domain's admin must not
            // delete another domain's signing keys. Fully qualified call —
            // `tenant.key` would resolve to the DashMap guard's method.
            match Tenant::key(&mut tenant, &body.name).await {
                Ok(key) if key.domain_id != domain => {
                    res.status_code(StatusCode::FORBIDDEN);
                    res.render(Json(ApiProblem::forbidden()));
                    return;
                }
                Ok(_) => {
                    if tenant.key_delete(&body.name).await.is_ok() {
                        let resp = ApiResponse::ok(());
                        res.status_code(StatusCode::OK);
                        res.render(Json(resp));
                        return;
                    }
                }
                Err(_) => {}
            }
        }
    };
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

// #[endpoint(
// summary = "OIDC Discovery Configuration",
// responses((status_code = 200, description = "Success", body = serde_json::Value))
// )]
// pub async fn oidc_configuration(req: &mut Request, res: &mut Response) {
// let host = req
// .headers()
// .get("HOST")
// .and_then(|v| v.to_str().ok())
// .unwrap_or("localhost");
// let base_url = format!("https://{}", host);

// let config = serde_json::json!({
// "issuer": base_url,
// "jwks_uri": format!("{}/.well-known/jwks.json", base_url),
// "id_token_signing_alg_values_supported": ["RS256"],
// "subject_types_supported": ["public"],
// });

// res.render(Json(config));
// }

#[endpoint(
    summary = "JSON Web Key Set (JWKS)",
    responses((status_code = 200, description = "Success", body = serde_json::Value))
)]
pub async fn jwks_endpoint(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or("");

    let mut jwk_set = JwkSet { keys: vec![] };

    if let Some(mut tenant) = state.storage.tenant_by_domain(domain)
        && let Ok(keys) = tenant.all_keys().await
    {
        for key_model in keys {
            // Convert stored PEM public key into a jsonwebtoken JWK
            if let Ok(public_pem) = key_model.public_pem()
                && let Ok(jwk) = pem_to_jwk(&public_pem, &key_model.id)
            {
                jwk_set.keys.push(jwk);
            }
        }
    }

    res.render(Json(jwk_set));
}

fn pem_to_jwk(pub_pem: &str, kid: &str) -> Result<Jwk, Box<dyn std::error::Error>> {
    let pub_key = RsaPublicKey::from_public_key_pem(pub_pem)?;

    let n_bytes = pub_key.n().to_bytes_be();
    let e_bytes = pub_key.e().to_bytes_be();

    let n = URL_SAFE_NO_PAD.encode(n_bytes);
    let e = URL_SAFE_NO_PAD.encode(e_bytes);

    let jwk = Jwk {
        common: CommonParameters {
            key_id: Some(kid.to_string()),
            public_key_use: Some(PublicKeyUse::Signature),
            ..Default::default()
        },
        algorithm: AlgorithmParameters::RSA(RSAKeyParameters {
            key_type: RSAKeyType::RSA,
            n,
            e,
        }),
    };

    Ok(jwk)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::LazyLock;

    const TENANT: &str = "test-tenant";
    const DOMAIN_A: &str = "a.local";
    const DOMAIN_B: &str = "b.local";

    /// The revocation store is a process-wide singleton, so all tests share
    /// one backing directory that must outlive every individual test's
    /// TempDir (same pattern as the otp.rs/totp.rs endpoint tests).
    static TEST_STORE_DIR: LazyLock<tempfile::TempDir> =
        LazyLock::new(|| tempfile::tempdir().expect("tempdir"));

    /// toasty spawns the store's connection task on whichever runtime is
    /// current during `init_global`; a `#[tokio::test]` runtime dies with
    /// its test. Initialize once on a dedicated multi-thread runtime whose
    /// workers outlive every individual test.
    static TEST_STORE_RT: LazyLock<tokio::runtime::Runtime> = LazyLock::new(|| {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .expect("store runtime")
    });
    static TEST_STORE_INIT: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

    async fn init_revocation_store() {
        TEST_STORE_RT
            .spawn(TEST_STORE_INIT.get_or_init(|| async {
                crate::jwt::InvalidJwt::init_global(TEST_STORE_DIR.path())
                    .await
                    .expect("init revocation store");
            }))
            .await
            .expect("store init task");
    }

    /// Tenant serving two domains so cross-domain injection has a target.
    async fn key_test_env() -> (crate::server::ServerState, tempfile::TempDir) {
        init_revocation_store().await;
        // Signing keys are encrypted at rest (H2); the process-wide
        // encryption key is first-call-wins across test envs.
        let _ = crate::crypto::setup_encryption_key(&"0".repeat(64));
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = crate::db::Storage::init(tmp.path())
            .await
            .expect("storage init");
        storage.new_tenant(TENANT).await.expect("tenant");
        storage
            .add_domain(DOMAIN_A, TENANT)
            .await
            .expect("domain a");
        storage
            .add_domain(DOMAIN_B, TENANT)
            .await
            .expect("domain b");
        {
            // The builtin catalog gives `effective_level` something to
            // resolve the injected session roles against (admin=80,
            // root=100) — the H9 root exception is level-based.
            let mut tenant = storage.tenant_by_id(TENANT).expect("tenant");
            let bootstrap = crate::role::Caller::Bootstrap;
            for (name, _) in crate::role::BUILTIN_ROLES {
                tenant
                    .role_create(&bootstrap, name, 0)
                    .await
                    .expect("builtin role");
            }
        }
        let state = crate::server::ServerState::create(storage, false)
            .await
            .expect("server state");
        (state, tmp)
    }

    fn key_service(state: crate::server::ServerState) -> Service {
        Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state))
                .push(Router::with_path("key/create").post(add_key))
                .push(Router::with_path("key/delete").post(delete_key)),
        )
    }

    /// Session injectors for the caller-level branch of the H9 gate.
    /// `effective_level` resolves the JWT role names against the live Role
    /// table, so the env's builtin catalog gives admin=80 / root=100.
    macro_rules! session_injector {
        ($name:ident, $user:literal, [$($role:literal),* $(,)?]) => {
            #[salvo::prelude::handler]
            async fn $name(
                req: &mut Request,
                depot: &mut Depot,
                res: &mut Response,
                ctrl: &mut FlowCtrl,
            ) {
                depot.inject(crate::db::JwtVerify {
                    can_access: true,
                    jwt_data: crate::db::JwtData {
                        user: uuid::Uuid::nil().to_string(),
                        username: $user.to_string(),
                        domain: DOMAIN_A.to_string(),
                        mfa: std::collections::HashSet::new(),
                        roles: std::collections::HashSet::from([
                            $($role.to_string()),*
                        ]),
                    },
                    expect_mfa: false,
                    domain: DOMAIN_A.to_string(),
                    auth_time: None,
                });
                ctrl.call_next(req, depot, res).await;
            }
        };
    }
    session_injector!(inject_admin_session, "adminny", ["admin"]);
    session_injector!(inject_root_session, "rooty", ["root"]);

    fn keyed_service<H: salvo::Handler + 'static>(
        state: crate::server::ServerState,
        injector: H,
    ) -> Service {
        Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state))
                .hoop(injector)
                .push(Router::with_path("key/create").post(add_key))
                .push(Router::with_path("key/delete").post(delete_key)),
        )
    }

    async fn post_key(
        service: &Service,
        host: &str,
        path: &str,
        body: &serde_json::Value,
    ) -> StatusCode {
        let res = salvo::test::TestClient::post(format!("http://{host}/{path}"))
            .add_header("Host", host, true)
            .json(body)
            .send(service)
            .await;
        res.status_code.expect("status code")
    }

    /// regression H9: the authenticated request domain is authoritative —
    /// a body-claimed foreign domain is refused. Without a session the
    /// root exception cannot be evaluated: fail closed with 401.
    #[tokio::test]
    async fn key_create_refuses_cross_domain_injection() {
        let (state, _tmp) = key_test_env().await;
        let service = key_service(state.clone());

        let status = post_key(
            &service,
            DOMAIN_A,
            "key/create",
            &serde_json::json!({ "domain": DOMAIN_B, "name": "injected" }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "a cross-domain claim without a session must fail closed"
        );

        // The refused key must not exist.
        let mut tenant = state.storage.tenant_by_domain(DOMAIN_A).expect("tenant");
        assert!(Tenant::key(&mut tenant, "injected").await.is_err());
    }

    /// regression H9: an ADMIN-level caller (80 < root 100) may not inject
    /// a key for a sibling domain — the pre-fix handler honored the body
    /// domain with only the tenant-level policy gate.
    #[tokio::test]
    async fn key_create_refuses_admin_level_cross_domain() {
        let (state, _tmp) = key_test_env().await;
        let service = keyed_service(state.clone(), inject_admin_session);

        let status = post_key(
            &service,
            DOMAIN_A,
            "key/create",
            &serde_json::json!({ "domain": DOMAIN_B, "name": "injected" }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let mut tenant = state.storage.tenant_by_domain(DOMAIN_A).expect("tenant");
        assert!(Tenant::key(&mut tenant, "injected").await.is_err());
    }

    /// The root exception that keeps multi-domain tenants operable: the
    /// tenant apex (level 100) provisions a SIBLING domain's first signing
    /// key — sessions are domain-bound and `current_key` is per-domain, so
    /// without this path a second domain could never mint its first token.
    /// A domain outside the tenant stays refused.
    #[tokio::test]
    async fn key_create_root_may_provision_sibling_domain() {
        let (state, _tmp) = key_test_env().await;
        let service = keyed_service(state.clone(), inject_root_session);

        let status = post_key(
            &service,
            DOMAIN_A,
            "key/create",
            &serde_json::json!({ "domain": DOMAIN_B, "name": "key-b" }),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "root must be able to seed a sibling domain's first key"
        );

        // A domain that is NOT part of the tenant is still refused.
        let status = post_key(
            &service,
            DOMAIN_A,
            "key/create",
            &serde_json::json!({ "domain": "foreign.example", "name": "key-f" }),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let mut tenant = state.storage.tenant_by_domain(DOMAIN_A).expect("tenant");
        let key_b = Tenant::key(&mut tenant, "key-b").await.expect("key-b");
        assert_eq!(key_b.domain_id, DOMAIN_B);
        assert!(Tenant::key(&mut tenant, "key-f").await.is_err());
    }

    /// The matching (or empty) body domain creates the key for the
    /// AUTHENTICATED domain.
    #[tokio::test]
    async fn key_create_binds_to_the_authenticated_domain() {
        let (state, _tmp) = key_test_env().await;
        let service = key_service(state.clone());

        let status = post_key(
            &service,
            DOMAIN_A,
            "key/create",
            &serde_json::json!({ "domain": DOMAIN_A, "name": "key-a" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Empty domain = no claim; the authenticated domain still rules.
        let status = post_key(
            &service,
            DOMAIN_B,
            "key/create",
            &serde_json::json!({ "domain": "", "name": "key-b" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        let mut tenant = state.storage.tenant_by_domain(DOMAIN_A).expect("tenant");
        let key_a = Tenant::key(&mut tenant, "key-a").await.expect("key-a");
        assert_eq!(key_a.domain_id, DOMAIN_A);
        let key_b = Tenant::key(&mut tenant, "key-b").await.expect("key-b");
        assert_eq!(key_b.domain_id, DOMAIN_B);
    }

    /// regression H9 (delete side): one domain's admin surface must not
    /// delete another domain's signing key.
    #[tokio::test]
    async fn key_delete_refuses_cross_domain_keys() {
        let (state, _tmp) = key_test_env().await;
        let service = key_service(state.clone());

        let status = post_key(
            &service,
            DOMAIN_B,
            "key/create",
            &serde_json::json!({ "domain": "", "name": "key-b" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);

        // Deleting B's key through A's authenticated domain: refused.
        let status = post_key(
            &service,
            DOMAIN_A,
            "key/delete",
            &serde_json::json!({ "name": "key-b" }),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN);

        // The key survives; its own domain can delete it.
        let mut tenant = state.storage.tenant_by_domain(DOMAIN_A).expect("tenant");
        assert!(Tenant::key(&mut tenant, "key-b").await.is_ok());
        drop(tenant);
        let status = post_key(
            &service,
            DOMAIN_B,
            "key/delete",
            &serde_json::json!({ "name": "key-b" }),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }
}
