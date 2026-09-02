use crate::cache::EphemCache;
use crate::db::{AuthType, JwtVerify, Tenant};
use crate::domain::Domain;
use crate::server::ServerState;
use crate::user::User;
use crate::utils::{ApiProblem, ApiResponse};
use anyhow::Result;
use base64::Engine as _;
use salvo::http::cookie::{Cookie, SameSite};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::sync::LazyLock;
use toasty::*;
use url::Url;
use webauthn_rs::prelude::{self as pk, RequestChallengeResponse};
// ─── Database Models ────────────────────────────────────────────────────────

/// Primary passkey credential with realm support.
#[derive(Debug, toasty::Model, Clone)]
pub struct Passkey {
    #[key]
    pub id: String,

    #[index]
    pub user_id: uuid::Uuid,

    #[index]
    pub domain_id: String,

    #[index]
    pub active: bool,

    pub credential: Vec<u8>,

    #[index]
    pub public_key: String,

    #[auto]
    pub created_at: jiff::Timestamp,
    #[auto]
    pub updated_at: jiff::Timestamp,

    #[belongs_to(key = user_id, references = id)]
    pub user: Deferred<User>,

    #[belongs_to(key = domain_id, references = id)]
    pub domain: Deferred<Domain>,
}

impl Passkey {
    pub fn get_passkey(&self) -> Result<pk::Passkey> {
        serde_json::from_slice::<pk::Passkey>(&self.credential).map_err(Into::into)
    }
    pub fn cred_id(credential: &[u8]) -> Result<String> {
        let passkey = serde_json::from_slice::<pk::Passkey>(credential)?;
        let cred_id_bytes = passkey.cred_id();
        Ok(base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(cred_id_bytes))
    }
}

// ─── Tenant Methods ─────────────────────────────────────────────────────────

impl Tenant {
    /// Create a passkey credential record.
    pub async fn passkey_create(
        &mut self,
        user: &str,
        domain: &str,
        credential: Vec<u8>,
        public_key_str: String,
    ) -> Result<Passkey> {
        let user = self.user(user).await?;
        toasty::create!(Passkey {
            id: Passkey::cred_id(&credential)?,
            user_id: user.id,
            domain_id: domain.to_string(),
            active: true,
            credential,
            public_key: public_key_str,
        })
        .exec(&mut self.database)
        .await
        .map_err(Into::into)
    }
    pub async fn active_passkey(
        &mut self,
        user: Option<&str>,
        domain: Option<&str>,
    ) -> Result<Vec<Passkey>> {
        match self.passkey(user, domain).await {
            Ok(ps) => Ok(ps.into_iter().filter(|p| p.active).collect()),
            Err(e) => Err(e),
        }
    }
    /// Get all passkeys for a user (optionally scoped to realm).
    pub async fn passkey(
        &mut self,
        user: Option<&str>,
        domain: Option<&str>,
    ) -> Result<Vec<Passkey>> {
        let uid = match user {
            Some(name) => Some(self.user(name).await?.id),
            None => None,
        };
        match (uid, domain) {
            (Some(uid), Some(rid)) => Passkey::filter(
                Passkey::fields()
                    .user_id()
                    .eq(uid)
                    .and(Passkey::fields().domain_id().eq(rid)),
            )
            .exec(&mut self.database),
            (Some(uid), None) => {
                Passkey::filter(Passkey::fields().user_id().eq(uid)).exec(&mut self.database)
            }
            (None, Some(rid)) => {
                Passkey::filter(Passkey::fields().domain_id().eq(rid)).exec(&mut self.database)
            }
            (None, None) => Passkey::all().exec(&mut self.database),
        }
        .await
        .map_err(Into::into)
    }

    /// Deactivate all passkeys for a user in a realm.
    pub async fn deactivate_passkeys(&mut self, user: &str, domain: &str) -> Result<()> {
        let user = self.user(user).await?;
        toasty::update!(Passkey::filter(
            Passkey::fields()
                .user_id()
                .eq(user.id)
                .and(Passkey::fields().domain_id().eq(domain))
        ) { active: false })
        .exec(&mut self.database)
        .await
        .map(|_| ())
        .map_err(Into::into)
    }
}

static WEBAUTHN_CACHE: LazyLock<EphemCache<String, pk::Webauthn>> =
    LazyLock::new(|| EphemCache::new("webauthn_cache", None));

async fn build_webauthn(domain: &str, origin: &str) -> Result<pk::Webauthn> {
    let cache_key = format!("{}|{}", domain, origin);
    if let Some(tmp) = WEBAUTHN_CACHE.get(&cache_key).await {
        return Ok(tmp);
    }
    // The origin MUST be exactly the URL clients reach this server at
    // (`<scheme>://<host>[:port]`, i.e. the issuer): WebAuthn verifies the
    // browser's `collectedClientData.origin` by exact match, and browsers
    // include the scheme and any non-default port. Hardcoding `https` or
    // dropping the port breaks every ceremony on http dev origins
    // (`http://localhost:8080` is a browser secure context) and on
    // non-default ports.
    let origin_url = Url::parse(origin)?;
    let webauthn = pk::WebauthnBuilder::new(domain, &origin_url)
        .map_err(|e| anyhow::anyhow!("Invalid WebAuthN configuration: {}", e))?;

    let ret = webauthn.rp_name("Passkey").build().map_err(Into::into);
    if let Ok(tmp) = ret {
        let cached = (*WEBAUTHN_CACHE).get_or_insert(cache_key, tmp).await;
        Ok(cached)
    } else {
        ret
    }
}

// ─── Registration Flow Helpers ──────────────────────────────────────────────

/// Challenge-cache key. The `token` is a random per-flow UUID handed to the
/// client with the challenge and echoed back at `verify` time. Keying
/// by username (the old `uuid_v5(username)` scheme) let an attacker who can
/// reach the unauthenticated login endpoint start a flow for a victim and
/// block the victim's own flow for the whole 600 s TTL ("Duplicated
/// request"); a random key is unguessable and collisions are impossible.
#[derive(Clone, Hash, Eq, PartialEq)]
struct PasskeyCacheKey {
    domain: String,
    token: uuid::Uuid,
}

#[derive(Clone)]
struct PasskeyCacheRegistrationValue(pk::PasskeyRegistration);

static PASSKEY_CACHE: LazyLock<EphemCache<PasskeyCacheKey, PasskeyCacheRegistrationValue>> =
    LazyLock::new(|| EphemCache::new("passkey_session", Some(600)));

async fn start_passkey_registration(
    domain: &str,
    origin: &str,
    username: &str,
    existing: &[pk::Passkey],
) -> Result<(pk::CreationChallengeResponse, uuid::Uuid)> {
    let webauthn = build_webauthn(domain, origin).await?;
    let user_uuid = uuid::Uuid::new_v5(&uuid::Uuid::NAMESPACE_DNS, username.as_bytes());
    let token = uuid::Uuid::new_v4();
    let key = PasskeyCacheKey {
        domain: domain.to_string(),
        token,
    };
    // tell the authenticator which credentials already exist so it
    // refuses to re-register one of them (imported/stale credentials would
    // otherwise duplicate or shadow the stored ones).
    let exclude_credentials = if existing.is_empty() {
        None
    } else {
        Some(existing.iter().map(|c| c.cred_id().clone()).collect())
    };
    match webauthn.start_passkey_registration(user_uuid, username, username, exclude_credentials) {
        Ok((challenge_opts, reg_state)) => {
            PASSKEY_CACHE
                .insert(key, PasskeyCacheRegistrationValue(reg_state))
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            Ok((challenge_opts, token))
        }
        Err(e) => Err(anyhow::anyhow!("Passkey registration start failed: {}", e)),
    }
}

async fn finish_passkey_registration(
    domain: &str,
    origin: &str,
    token: uuid::Uuid,
    credential: &pk::RegisterPublicKeyCredential,
) -> Result<pk::Passkey> {
    let webauthn = build_webauthn(domain, origin).await?;
    let key = PasskeyCacheKey {
        domain: domain.to_string(),
        token,
    };
    if let Some(PasskeyCacheRegistrationValue(state)) = PASSKEY_CACHE.get_one_shot(&key).await {
        match webauthn.finish_passkey_registration(credential, &state) {
            Ok(passkey) => Ok(passkey),
            Err(e) => Err(anyhow::anyhow!("Passkey verification failed: {}", e)),
        }
    } else {
        Err(anyhow::anyhow!("Unrecognized passkey registration token"))
    }
}

// ─── Login Flow Helpers ──────────────────────────────────────────────────────

#[derive(Clone)]
struct PasskeyCacheRequestValue(pk::PasskeyAuthentication);

static LOGIN_CACHE: LazyLock<EphemCache<PasskeyCacheKey, PasskeyCacheRequestValue>> =
    LazyLock::new(|| EphemCache::new("passkey_session", Some(600)));

async fn start_passkey_login(
    creds: &[pk::Passkey],
    domain: &str,
    origin: &str,
) -> Result<(RequestChallengeResponse, uuid::Uuid)> {
    let webauthn = build_webauthn(domain, origin).await?;
    let token = uuid::Uuid::new_v4();
    let key = PasskeyCacheKey {
        domain: domain.to_string(),
        token,
    };
    match webauthn.start_passkey_authentication(creds) {
        Ok((challenge_opts, auth_state)) => {
            LOGIN_CACHE
                .insert(key, PasskeyCacheRequestValue(auth_state))
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;

            Ok((challenge_opts, token))
        }
        Err(e) => Err(anyhow::anyhow!("Passkey login start failed: {}", e)),
    }
}

async fn finish_passkey_login(
    domain: &str,
    origin: &str,
    token: uuid::Uuid,
    credential: &pk::PublicKeyCredential,
) -> Result<pk::AuthenticationResult> {
    let webauthn = build_webauthn(domain, origin).await?;
    let key = PasskeyCacheKey {
        domain: domain.to_string(),
        token,
    };

    if let Some(PasskeyCacheRequestValue(state)) = LOGIN_CACHE.get_one_shot(&key).await {
        webauthn
            .finish_passkey_authentication(credential, &state)
            .map_err(Into::into)
    } else {
        Err(anyhow::anyhow!("Unrecognized passkey login token"))
    }
}

async fn render_passkey_auth_success(
    res: &mut Response,
    tenant: &mut Tenant,
    issuer: &str,
    domain: &str,
    username: &str,
    previous_fa: &HashSet<String>,
    cookie_name: Option<String>,
) {
    // Step-up consistent with the other verify handlers: a passkey
    // ceremony completed inside an existing session carries the session's
    // prior factors forward instead of collapsing to passkey-only.
    let mut fa = previous_fa.clone();
    fa.insert(AuthType::PassKey.as_str().to_string());
    if let Ok(jwt) = tenant
        .authenticate_jwt(&fa, issuer, domain, username, 15)
        .await
    {
        if let Some(cookie_name) = cookie_name {
            let cookie = Cookie::build((cookie_name, jwt.clone()))
                .path("/")
                .http_only(true)
                .secure(true)
                .same_site(SameSite::Strict)
                .build();
            res.add_cookie(cookie);
        }
        res.status_code(StatusCode::OK);
        res.render(Json(ApiResponse::ok(jwt)));
    } else {
        // e.g. the `User` row disappeared between challenge and verify —
        // deletion cascades its passkeys, so this is only a race
        // window. Report an auth failure, never a server error.
        res.status_code(StatusCode::UNAUTHORIZED);
        res.render(Json(ApiProblem::unauthorized()));
    }
}

// ─── Request Endpoint (Registration Challenge) ─────────────────────────────

#[derive(Deserialize, Serialize, Debug, ToSchema)]
pub struct PasskeyRequest(String);

async fn login(domain: &str, origin: &str, creds: &[pk::Passkey], res: &mut Response) {
    match start_passkey_login(creds, domain, origin).await {
        Ok((challenge_opts, token)) => {
            res.status_code(StatusCode::OK);
            res.render(Json(PasskeyResponse {
                public_key_opts: serde_json::to_value(challenge_opts).unwrap_or_default(),
                token,
            }));
        }
        Err(_e) => {
            res.status_code(StatusCode::UNAUTHORIZED);
            let err = ApiProblem::unauthorized();
            res.render(Json(err))
        }
    }
}

async fn register(
    domain: &str,
    origin: &str,
    reg_req: &PasskeyRequest,
    existing: &[pk::Passkey],
    res: &mut Response,
) {
    // Start passkey registration flow; PASSKEY_CACHE now holds challenge + identity.
    match start_passkey_registration(domain, origin, reg_req.0.as_str(), existing).await {
        Ok((challenge_opts, token)) => {
            res.status_code(StatusCode::OK);
            res.render(Json(PasskeyResponse {
                public_key_opts: serde_json::to_value(challenge_opts).unwrap_or_default(),
                token,
            }));
        }
        Err(_e) => {
            res.status_code(StatusCode::UNAUTHORIZED);
            let err = ApiProblem::unauthorized();
            res.render(Json(err))
        }
    }
}

/// Response body for the registration/login challenge.
#[derive(Serialize, ToSchema)]
pub struct PasskeyResponse {
    #[serde(rename = "publicKey")]
    pub public_key_opts: serde_json::Value,
    // pk::CreationChallengeResponse for registration request
    // pk::RequestChallengeResponse for login request
    /// Opaque per-flow handle the client must echo back to `verify`
    ///. Replaces the old username-derived cache key.
    pub token: uuid::Uuid,
}

#[endpoint(
    summary = "Request a new passkey registration challenge",
    description = "Initiates the WebAuthN passkey registration flow.",
    request_body = PasskeyRequest,
    responses(
        (status_code = 200, description = "Registration started successfully", body = PasskeyResponse),
        (status_code = 401, description = "Failed or no tenant found")
    )
)]
pub async fn request(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    if let Some(passkey_req) = crate::utils::extract::<PasskeyRequest>(req, None).await {
        if !passkey_req.0.is_empty() {
            let state = depot.obtain_mut::<ServerState>().unwrap();
            let domain = crate::utils::get_domain(req, state)
                .unwrap_or("")
                .to_string();
            // Exact client-visible origin (scheme + host + non-default port) —
            // WebAuthn matches it against the browser's collected origin.
            let origin = crate::utils::get_issuer(req, state).unwrap_or_default();

            // Collect the stored credentials and release the tenant borrow
            // before touching the depot again (session validation below).
            let (active_creds, all_creds) = match state.storage.tenant_by_domain(&domain) {
                Some(mut tenant) => {
                    let active_creds: Vec<pk::Passkey> = tenant
                        .active_passkey(Some(&passkey_req.0), Some(&domain))
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .filter_map(|s| s.get_passkey().ok())
                        .collect();
                    // Deactivated credentials still live in authenticators,
                    // so a registration must exclude every stored one.
                    let all_creds: Vec<pk::Passkey> = tenant
                        .passkey(Some(&passkey_req.0), Some(&domain))
                        .await
                        .unwrap_or_default()
                        .into_iter()
                        .filter_map(|s| s.get_passkey().ok())
                        .collect();
                    (active_creds, all_creds)
                }
                None => (Vec::new(), Vec::new()),
            };

            if !active_creds.is_empty() {
                return login(&domain, &origin, &active_creds, res).await;
            }
            // No active passkey — this is a registration. It requires a valid
            // session for exactly this user, validated without the
            // policy engine so MFA step-up is not circular.
            match crate::utils::validate_session(req, depot).await {
                Some(session) if session.jwt_data.username == passkey_req.0 => {
                    return register(&domain, &origin, &passkey_req, &all_creds, res).await;
                }
                _ => {
                    res.status_code(StatusCode::UNAUTHORIZED);
                    res.render(Json(ApiProblem::unauthorized()));
                }
            }
        } else {
            res.status_code(StatusCode::BAD_REQUEST);
            let err = ApiProblem::validation_error("Bad request: Empty user name");
            res.render(Json(err))
        }
    } else {
        res.status_code(StatusCode::BAD_REQUEST);
        let err = ApiProblem::validation_error("Bad request: Missing request body");
        res.render(Json(err))
    }
}

// ─── Login Verify Endpoint ──────────────────────────────────────────────────
#[derive(Debug, Deserialize, ToSchema)]
pub struct VerifyRequest {
    pub username: String,
    #[serde(rename = "credential")]
    pub credential_json: serde_json::Value,
    /// Flow handle from `passkey/request`: selects the cached
    /// challenge. Required — without it no ceremony can be completed.
    pub token: uuid::Uuid,
    pub cookie: Option<String>,
}

#[endpoint(
    summary = "Verify passkey registration/login",
    description = "Validates the WebAuthN credential returned from the authenticator during login.",
    request_body = VerifyRequest,
    responses(
        (status_code = 200, description = "Login successful", body = ApiResponse<String>),
        (status_code = 401, description = "Verification failed or expired token")
    )
)]
pub async fn verify(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    // Session gate for the *registration* branch, policy-free so MFA
    // step-up is not circular. Login may proceed without a session.
    let session = crate::utils::validate_session(req, depot).await;
    let state = depot.obtain_mut::<ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    let issuer = crate::utils::get_issuer(req, state).unwrap_or_default();

    if let Some(mut tenant) = state.storage.tenant_by_domain(&domain)
        && let Some(rqst) = crate::utils::extract::<VerifyRequest>(req, None).await
    {
        if let Ok(x) =
            serde_json::from_value::<pk::RegisterPublicKeyCredential>(rqst.credential_json.clone())
        {
            if session.as_ref().map(|s| s.jwt_data.username.as_str())
                != Some(rqst.username.as_str())
            {
                res.status_code(StatusCode::UNAUTHORIZED);
                res.render(Json(ApiProblem::unauthorized()));
                return;
            }
            match finish_passkey_registration(&domain, &issuer, rqst.token, &x).await {
                Ok(passkey) => {
                    let credential_bytes = match serde_json::to_vec(&passkey) {
                        Ok(b) => b,
                        Err(_e) => {
                            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                            let err = ApiProblem::server_error("error");
                            res.render(Json(err));
                            return;
                        }
                    };
                    let public_key_str = match serde_json::to_string(passkey.get_public_key()) {
                        Ok(s) => s,
                        Err(_e) => {
                            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                            let err = ApiProblem::server_error("error");
                            res.render(Json(err));
                            return;
                        }
                    };
                    if tenant
                        .passkey_create(&rqst.username, &domain, credential_bytes, public_key_str)
                        .await
                        .is_err()
                    {
                        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
                        let err = ApiProblem::server_error("Failed to persist passkey");
                        res.render(Json(err));
                        return;
                    }
                    // Registration happens inside a session — carry its
                    // factors forward (consistency).
                    let previous_fa = session
                        .as_ref()
                        .map(|s| s.jwt_data.mfa.clone())
                        .unwrap_or_default();
                    render_passkey_auth_success(
                        res,
                        &mut tenant,
                        &issuer,
                        &domain,
                        &rqst.username,
                        &previous_fa,
                        rqst.cookie.clone(),
                    )
                    .await;
                    return;
                }
                Err(_e) => {
                    res.status_code(StatusCode::UNAUTHORIZED);
                    let err = ApiProblem::unauthorized();
                    res.render(Json(err));
                    return;
                }
            }
        }
        if let Ok(x) = serde_json::from_value::<pk::PublicKeyCredential>(rqst.credential_json) {
            match finish_passkey_login(&domain, &issuer, rqst.token, &x).await {
                Ok(auth_result) => {
                    if let Ok(stored_passkeys) = tenant
                        .active_passkey(Some(&rqst.username), Some(&domain))
                        .await
                        && let Some(stored) = stored_passkeys.into_iter().next()
                        && let Ok(mut passkey) = stored.get_passkey()
                        && passkey.update_credential(&auth_result).unwrap_or(false)
                        && let Ok(updated_bytes) = serde_json::to_vec(&passkey)
                    {
                        let _ = toasty::update!(
                                        Passkey::filter(Passkey::fields().id().eq(stored.id))
                                    { credential: updated_bytes })
                        .exec(&mut tenant.database)
                        .await;
                    }
                    // A login completed while already holding a session
                    // for the same user accumulates factors; an unrelated
                    // or absent session contributes none.
                    let previous_fa = session
                        .as_ref()
                        .filter(|s| s.jwt_data.username == rqst.username)
                        .map(|s| s.jwt_data.mfa.clone())
                        .unwrap_or_default();
                    render_passkey_auth_success(
                        res,
                        &mut tenant,
                        &issuer,
                        &domain,
                        &rqst.username,
                        &previous_fa,
                        rqst.cookie.clone(),
                    )
                    .await;
                    return;
                }
                Err(_) => {
                    res.status_code(StatusCode::UNAUTHORIZED);
                    res.render(Json(ApiProblem::unauthorized()));
                    return;
                }
            }
        }
    }

    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err));
}

// ─── Remove Endpoint (Deactivate Own Passkeys) ─────────────────────────────

#[endpoint(
    summary = "Deactivate all passkeys of the authenticated user",
    description = "Requires an authenticated session; deactivates the caller's own passkeys only.",
    responses(
        (status_code = 200, description = "Passkeys deactivated", body = ApiResponse<String>),
        (status_code = 401, description = "Unauthorized")
    )
)]
pub async fn remove(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let user = match depot.obtain_mut::<JwtVerify>() {
        Ok(v) => v.jwt_data.username.clone(),
        Err(_) => {
            res.status_code(StatusCode::UNAUTHORIZED);
            res.render(Json(ApiProblem::unauthorized()));
            return;
        }
    };
    let state = depot.obtain_mut::<ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref())
        && tenant.deactivate_passkeys(&user, &domain).await.is_ok()
    {
        res.status_code(StatusCode::OK);
        res.render(Json(ApiResponse::ok(String::new())));
        return;
    }

    res.status_code(StatusCode::UNAUTHORIZED);
    res.render(Json(ApiProblem::unauthorized()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use salvo::test::ResponseExt;
    use std::sync::LazyLock;

    /// Must be a registrable domain (dots) — `WebauthnBuilder::new` rejects
    /// `localhost` because `Url::domain()` is None for it.
    const DOMAIN: &str = "auth.example.com";
    const TEST_ISSUER: &str = "http://auth.example.com";

    /// The revocation store is a process-wide singleton, so all tests share one
    /// backing directory that must outlive every individual test's TempDir
    /// (same pattern as the totp.rs/oidc.rs endpoint tests).
    static TEST_STORE_DIR: LazyLock<tempfile::TempDir> =
        LazyLock::new(|| tempfile::tempdir().expect("tempdir"));

    /// toasty spawns the store's connection task on whichever runtime is
    /// current during `init_global`; a `#[tokio::test]` runtime dies with its
    /// test. Initialize once on a dedicated multi-thread runtime whose
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

    /// In-process tenant with a signing key and one user.
    async fn passkey_test_env() -> (crate::server::ServerState, tempfile::TempDir) {
        init_revocation_store().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = crate::db::Storage::init(tmp.path())
            .await
            .expect("storage init");
        storage.new_tenant("test-tenant").await.expect("tenant");
        storage
            .add_domain(DOMAIN, "test-tenant")
            .await
            .expect("domain");
        {
            let mut tenant = storage.tenant_by_id("test-tenant").expect("tenant");
            tenant
                .key_create(DOMAIN, "key1")
                .await
                .expect("signing key");
            tenant.user_create("alice").await.expect("user");
        }
        let state = crate::server::ServerState::create(storage, false)
            .await
            .expect("server state");
        (state, tmp)
    }

    fn passkey_service(state: crate::server::ServerState) -> Service {
        Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state))
                .push(Router::with_path("passkey/request").post(request))
                .push(Router::with_path("passkey/verify").post(verify)),
        )
    }

    /// A real single-factor session for `alice`, minted exactly like the
    /// magic-link/OTP verify handlers do.
    async fn alice_token(state: &crate::server::ServerState) -> String {
        let mut tenant = state.storage.tenant_by_domain(DOMAIN).expect("tenant");
        tenant
            .authenticate_jwt(&HashSet::new(), TEST_ISSUER, DOMAIN, "alice", 15)
            .await
            .expect("session token")
    }

    async fn post_request(
        service: &Service,
        body: &serde_json::Value,
        bearer: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut client = salvo::test::TestClient::post(format!("http://{DOMAIN}/passkey/request"))
            .add_header("Host", DOMAIN, true);
        if let Some(token) = bearer {
            client = client.add_header("Authorization", format!("Bearer {token}"), true);
        }
        let mut res = client.json(body).send(service).await;
        let status = res.status_code.expect("status code");
        let body = res.take_string().await.unwrap_or_default();
        (
            status,
            serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    async fn post_verify(
        service: &Service,
        body: &serde_json::Value,
        bearer: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let mut client = salvo::test::TestClient::post(format!("http://{DOMAIN}/passkey/verify"))
            .add_header("Host", DOMAIN, true);
        if let Some(token) = bearer {
            client = client.add_header("Authorization", format!("Bearer {token}"), true);
        }
        let mut res = client.json(body).send(service).await;
        let status = res.status_code.expect("status code");
        let body = res.take_string().await.unwrap_or_default();
        (
            status,
            serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    /// A syntactically valid `RegisterPublicKeyCredential` (field names per
    /// webauthn-rs-proto); the ceremony itself cannot complete because the
    /// challenge is unknown — enough to exercise the gating around it.
    fn registration_credential() -> serde_json::Value {
        serde_json::json!({
            "id": "AAAA",
            "rawId": "AAAA",
            "response": {
                "attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjk",
                "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0"
            },
            "type": "public-key"
        })
    }

    // ── regression: registration is session-gated ──────────────────────

    #[tokio::test]
    async fn registration_without_a_session_is_rejected() {
        let (state, _tmp) = passkey_test_env().await;
        let service = passkey_service(state.clone());

        let (status, _body) = post_request(&service, &serde_json::json!("alice"), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn registration_for_another_user_is_rejected() {
        let (state, _tmp) = passkey_test_env().await;
        let service = passkey_service(state.clone());
        let token = alice_token(&state).await;

        // Alice's session cannot start a registration for bob.
        let (status, _body) = post_request(&service, &serde_json::json!("bob"), Some(&token)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn registration_with_a_matching_session_starts_a_challenge() {
        let (state, _tmp) = passkey_test_env().await;
        let service = passkey_service(state.clone());
        let token = alice_token(&state).await;

        let (status, body) =
            post_request(&service, &serde_json::json!("alice"), Some(&token)).await;
        assert_eq!(status, StatusCode::OK);
        assert!(body["publicKey"].is_object());
        assert!(
            body["token"].is_string(),
            "challenge must carry a flow token"
        );
    }

    // ── regression: per-flow tokens kill the username-keyed DoS ───────

    #[tokio::test]
    async fn concurrent_registration_flows_do_not_block_each_other() {
        let (state, _tmp) = passkey_test_env().await;
        let service = passkey_service(state.clone());
        let token = alice_token(&state).await;

        // The old scheme keyed the challenge cache by uuid_v5(username) and
        // rejected duplicates, so a second flow within the 600 s TTL failed.
        let (status1, body1) =
            post_request(&service, &serde_json::json!("alice"), Some(&token)).await;
        let (status2, body2) =
            post_request(&service, &serde_json::json!("alice"), Some(&token)).await;
        assert_eq!(status1, StatusCode::OK);
        assert_eq!(status2, StatusCode::OK, "a second flow must not be blocked");
        assert_ne!(
            body1["token"], body2["token"],
            "every flow gets its own random token"
        );
    }

    #[tokio::test]
    async fn verify_with_an_unknown_flow_token_is_rejected() {
        let (state, _tmp) = passkey_test_env().await;
        let service = passkey_service(state.clone());
        let token = alice_token(&state).await;

        let (status, _body) = post_verify(
            &service,
            &serde_json::json!({
                "username": "alice",
                "credential": registration_credential(),
                "token": uuid::Uuid::new_v4(),
            }),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn verify_without_a_flow_token_is_a_bad_request() {
        let (state, _tmp) = passkey_test_env().await;
        let service = passkey_service(state.clone());
        let token = alice_token(&state).await;

        let (status, _body) = post_verify(
            &service,
            &serde_json::json!({
                "username": "alice",
                "credential": registration_credential(),
            }),
            Some(&token),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn registration_verify_without_a_session_is_rejected() {
        let (state, _tmp) = passkey_test_env().await;
        let service = passkey_service(state.clone());

        // Registration-shaped credential but no session: the registration
        // branch must not run unauthenticated.
        let (status, _body) = post_verify(
            &service,
            &serde_json::json!({
                "username": "alice",
                "credential": registration_credential(),
                "token": uuid::Uuid::new_v4(),
            }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}
