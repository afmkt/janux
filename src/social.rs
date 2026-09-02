use anyhow::{Result, anyhow};
use dashmap::DashMap;

use crate::crypto::{decrypt_client_secret, encrypt_client_secret};
use crate::db::JwtVerify;
use crate::db::Tenant;
use crate::server::ServerState;
use crate::user::User;
use crate::utils::{ApiProblem, ApiResponse};
use toasty::*;

use std::sync::LazyLock;

use crate::cache::EphemCache;

use oauth2::{AuthorizationCode, CsrfToken};

use openidconnect::core::{
    CoreAuthDisplay, CoreAuthPrompt, CoreErrorResponseType, CoreGenderClaim, CoreJsonWebKey,
    CoreJweContentEncryptionAlgorithm, CoreProviderMetadata, CoreResponseType, CoreRevocableToken,
    CoreRevocationErrorResponse, CoreTokenIntrospectionResponse, CoreTokenResponse,
};
use openidconnect::{
    AccessToken, AccessTokenHash, AuthenticationFlow, Client, ClientId, ClientSecret,
    EmptyAdditionalClaims, EndpointMaybeSet, EndpointNotSet, EndpointSet, IssuerUrl, Nonce,
    OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier, ProviderMetadata, Scope,
    StandardErrorResponse, TokenResponse,
};

// use openidconnect::*;

use oauth2::reqwest::Client as HttpClient;
use salvo::http::cookie::{Cookie, SameSite};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
// use std::collections::HashMap;
// use toasty::*;

// Concrete `Client` type produced by OIDC discovery. `from_provider_metadata`
// returns a client whose auth + token endpoints are set (required for the
// authorization-code flow), so we pin those type-state params here.
type DiscoveredClient = Client<
    EmptyAdditionalClaims,
    CoreAuthDisplay,
    CoreGenderClaim,
    CoreJweContentEncryptionAlgorithm,
    CoreJsonWebKey,
    CoreAuthPrompt,
    StandardErrorResponse<CoreErrorResponseType>,
    CoreTokenResponse,
    CoreTokenIntrospectionResponse,
    CoreRevocableToken,
    CoreRevocationErrorResponse,
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
    EndpointMaybeSet,
>;

// TTL-based cache of social providers keyed by tenant domain (10 min).
static SOCIAL_PROVIDERS_CACHE: LazyLock<EphemCache<String, Vec<SocialProvider>>> =
    LazyLock::new(|| EphemCache::new("social_providers", Some(600)));

/// Module-level cache for OAuth2 auth sessions during the authorize/verify flow.
pub static SOCIAL_SESSION_CACHE: LazyLock<EphemCache<String, SocialAuthSession>> =
    LazyLock::new(|| EphemCache::new("oauth2_sessions", Some(900)));

/// One-shot login codes issued at the social callback. The callback
/// is a top-level browser navigation, so the session JWT cannot be rendered
/// for JS to read; instead the browser is redirected to the login page with
/// a short-lived one-shot code that the SPA exchanges at `redeem` — the
/// authorization-code pattern applied to the internal hop, so the JWT never
/// appears in a URL, log, or browser history.
pub static SOCIAL_LOGIN_CODE_CACHE: LazyLock<EphemCache<String, LoginCodeEntry>> =
    LazyLock::new(|| EphemCache::new("social_login_codes", Some(120)));

/// Name of the HttpOnly cookie that binds a login code to the browser that
/// completed the IdP round-trip (login-CSRF mitigation, see `redeem`).
pub const SOCIAL_BIND_COOKIE: &str = "janux_social_bind";

/// A one-shot login-code entry: the session JWT plus a browser-binding
/// secret. The secret is set as an HttpOnly cookie on the callback's 303
/// and must be presented alongside the code at `redeem`, so a code copied
/// from the address bar (or crafted via an attacker's own login) cannot be
/// exchanged by a different browser.
#[derive(Clone)]
pub struct LoginCodeEntry {
    pub jwt: String,
    pub bind: String,
}

// ── 1. Provider config ─────────────────────────────────────────────────────
#[derive(Debug, toasty::Model, Clone)]

pub struct OAuth2 {
    #[key]
    #[index]
    pub provider_id: String,
    #[key]
    pub provider_user_id: String,

    #[index]
    pub user_id: uuid::Uuid,

    #[auto]
    pub created_at: jiff::Timestamp,
    #[auto]
    pub updated_at: jiff::Timestamp,

    #[belongs_to(key = provider_id, references = id)]
    pub provider: Deferred<SocialProvider>,

    #[belongs_to(key = user_id, references = id)]
    pub user: Deferred<User>,
}

#[derive(Debug, Clone, Serialize, Deserialize, toasty::Model, ToSchema)]
#[unique(client_id, issuer_url)]
pub struct SocialProvider {
    #[key]
    pub id: String,
    pub client_id: String,
    pub client_secret: String,
    pub issuer_url: String,
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
}

fn default_scopes() -> Vec<String> {
    vec![
        "openid".to_string(),
        "email".to_string(),
        "profile".to_string(),
    ]
}

pub struct SocialLoginEntry {
    pub scopes: Vec<String>,
    pub client: DiscoveredClient,
}

impl SocialProvider {
    pub async fn build(&self) -> Result<DiscoveredClient> {
        let http_client = HttpClient::new();
        let issuer = IssuerUrl::new(self.issuer_url.clone())?;

        let provider_metadata: CoreProviderMetadata =
            ProviderMetadata::discover_async(issuer, &http_client).await?;

        let token_uri = provider_metadata
            .token_endpoint()
            .cloned()
            .ok_or_else(|| anyhow!("provider metadata is missing a token endpoint"))?;

        let plaintext_secret = decrypt_client_secret(&self.client_secret)?;

        Ok(Client::from_provider_metadata(
            provider_metadata,
            ClientId::new(self.client_id.clone()),
            Some(ClientSecret::new(plaintext_secret)),
        )
        .set_token_uri(token_uri))
    }
}

impl Tenant {
    pub async fn all_providers(&mut self) -> Vec<SocialProvider> {
        if let Ok(ps) = SocialProvider::all().exec(&mut self.database).await {
            ps
        } else {
            vec![]
        }
    }

    /// Build a `DashMap` from pre-fetched providers (no DB query).
    pub async fn all_providers_as_entries(
        &self,
        providers: &[SocialProvider],
    ) -> DashMap<String, SocialLoginEntry> {
        let ret = DashMap::new();
        for p in providers {
            if let Ok(client) = p.build().await {
                ret.insert(
                    p.id.clone(),
                    SocialLoginEntry {
                        scopes: p.scopes.clone(),
                        client,
                    },
                );
            }
        }
        ret
    }

    /// Build a `SocialLoginRegistry` from pre-fetched providers (no DB query).
    async fn build_registry_from_providers(
        &self,
        providers: &[SocialProvider],
    ) -> SocialLoginRegistry {
        let entries = self.all_providers_as_entries(providers).await;
        SocialLoginRegistry { entries }
    }

    /// Build a `SocialLoginRegistry`, first checking the shared TTL-based cache.
    /// Returns `(registry, cache_hit)` — on cache miss this populates it for subsequent calls.
    pub async fn build_registry_cached(&mut self, domain: &str) -> (SocialLoginRegistry, bool) {
        // Check cache first
        if let Some(providers) = SOCIAL_PROVIDERS_CACHE.get(domain).await {
            let registry = self.build_registry_from_providers(&providers).await;
            return (registry, true);
        }

        // Cache miss — fetch from DB and build
        let providers = self.all_providers().await;
        if !providers.is_empty() {
            SOCIAL_PROVIDERS_CACHE
                .insert(domain.to_string(), providers.clone())
                .await
                .ok();
        }
        let registry = self.build_registry_from_providers(&providers).await;
        (registry, false)
    }

    /// Invalidate the social providers cache for a tenant's domain.
    /// Call this after a provider is created or deleted.
    pub async fn invalidate_social_cache(&self, domain: &str) {
        SOCIAL_PROVIDERS_CACHE.invalidate(domain).await;
    }
    pub async fn provider_create(
        &mut self,
        id: &str,
        client_id: &str,
        client_secret: &str,
        issuer_url: &str,
    ) -> Result<SocialProvider> {
        let encrypted = encrypt_client_secret(client_secret)?;
        toasty::create!(SocialProvider {
            id,
            client_id,
            client_secret: encrypted,
            issuer_url,
            scopes: default_scopes(),
        })
        .exec(&mut self.database)
        .await
        .map_err(Into::into)
    }

    pub async fn provider_delete(&mut self, id: &str) -> Result<()> {
        SocialProvider::delete_by_id(&mut self.database, id)
            .await
            .map_err(Into::into)
    }

    pub async fn all_oauth2(&mut self, username: Option<&str>) -> Result<Vec<OAuth2>> {
        if let Some(user_name) = username {
            let user = self.user(user_name).await?;
            OAuth2::filter(OAuth2::fields().user_id().eq(user.id))
                .exec(&mut self.database)
                .await
                .map_err(Into::into)
        } else {
            OAuth2::all()
                .exec(&mut self.database)
                .await
                .map_err(Into::into)
        }
    }

    /// Look up the user an IdP identity is bound to: the
    /// `(provider, subject)` pair is the authentication key for social
    /// logins.
    pub async fn oauth2_by_subject(
        &mut self,
        provider_id: &str,
        provider_user_id: &str,
    ) -> Result<OAuth2> {
        let mut rows: Vec<OAuth2> = OAuth2::filter(
            OAuth2::fields()
                .provider_id()
                .eq(provider_id)
                .and(OAuth2::fields().provider_user_id().eq(provider_user_id)),
        )
        .exec(&mut self.database)
        .await
        .map_err(anyhow::Error::from)?;
        rows.pop()
            .ok_or_else(|| anyhow::anyhow!("no OAuth2 binding for subject"))
    }

    pub async fn oauth2_create(
        &mut self,
        user_name: &str,
        provider_id: String,
        provider_user_id: String,
    ) -> Result<OAuth2> {
        let user = self.user(user_name).await?;
        toasty::create!(OAuth2 {
            user_id: user.id,
            provider_id,
            provider_user_id,
        })
        .exec(&mut self.database)
        .await
        .map_err(Into::into)
    }

    pub async fn oauth2_delete(
        &mut self,
        user_name: &str,
        provider: &str,
        provider_user_id: &str,
    ) -> Result<()> {
        let user = self.user(user_name).await?;
        OAuth2::filter(
            OAuth2::fields()
                .provider_id()
                .eq(provider)
                .and(OAuth2::fields().provider_user_id().eq(provider_user_id))
                .and(OAuth2::fields().user_id().eq(user.id)),
        )
        .delete()
        .exec(&mut self.database)
        .await
        .map_err(Into::into)
    }
}

pub struct ExchangeResult {
    pub access_token: AccessToken,
    pub token_type: String, // typically "Bearer"
    pub id_token: Option<
        openidconnect::IdToken<
            EmptyAdditionalClaims,
            CoreGenderClaim,
            CoreJweContentEncryptionAlgorithm,
            openidconnect::core::CoreJwsSigningAlgorithm,
        >,
    >,
    pub subject: Option<String>,
    pub email: Option<String>,
}

/// Resolve the user for a social login, subject-first.
///
/// 1. An existing `(provider, subject)` binding IS the identity — the
/// email asserted by the IdP is never consulted for authentication.
/// 2. Without a binding, provision a new UUID user and record the
/// binding. A verified email is attached only when no other user owns
/// it; a claimed email is skipped, never merged into — linking an IdP
/// identity to an existing account must be an explicit, authenticated
/// decision, not a side effect of any configured IdP's email
/// assertion.
///
/// Provisioning is all-or-nothing: if recording the binding fails (e.g.
/// a concurrent first login for the same subject won the race), the
/// just-created user (and any attached email) is rolled back so no orphan
/// rows accumulate.
pub async fn ensure_user_from_social(
    tenant: &mut Tenant,
    provider_id: &str,
    subject: &str,
    email: Option<&str>,
) -> Result<String> {
    if let Ok(binding) = tenant.oauth2_by_subject(provider_id, subject).await {
        let user = tenant.user_by_id(binding.user_id).await?;
        return Ok(user.name);
    }
    let uid = uuid::Uuid::new_v4().to_string();
    tenant
        .user_create(&uid)
        .await
        .map_err(|_| anyhow!("failed to create user account"))?;
    if let Some(email) = email {
        // Fails (and is skipped) when another user already owns the
        // email — provisioning never merges into an existing account.
        let _ = tenant.email_create(&uid, email).await;
    }
    if let Err(e) = tenant
        .oauth2_create(&uid, provider_id.to_string(), subject.to_string())
        .await
    {
        if let Some(email) = email {
            tenant.email_delete(&uid, email).await.ok();
        }
        // System-initiated rollback — 's gate does not apply.
        tenant
            .user_delete(&crate::role::Caller::Bootstrap, &uid)
            .await
            .ok();
        return Err(e);
    }
    Ok(uid)
}

/// explicit, session-gated identity link. Attaches the
/// `(provider, subject)` binding to `link_user` — never resolves or
/// creates a user, so a link ceremony cannot provision or take over an
/// account. A binding that already belongs to ANOTHER user is refused;
/// one already owned by `link_user` is idempotent success. The
/// IdP-asserted email is attached only when no other user owns it (same
/// rule as provisioning) — linking never moves email ownership.
pub async fn link_user_from_social(
    tenant: &mut Tenant,
    link_user: &str,
    provider_id: &str,
    subject: &str,
    email: Option<&str>,
) -> Result<()> {
    let linked = tenant.user(link_user).await?;
    match tenant.oauth2_by_subject(provider_id, subject).await {
        Ok(binding) if binding.user_id == linked.id => return Ok(()),
        Ok(_) => return Err(anyhow!("identity already linked to another account")),
        Err(_) => {}
    }
    tenant
        .oauth2_create(link_user, provider_id.to_string(), subject.to_string())
        .await?;
    if let Some(email) = email {
        // Fails (and is skipped) when another user already owns the
        // email — linking never merges into an existing account.
        let _ = tenant.email_create(link_user, email).await;
    }
    Ok(())
}

// ── 3. Client registry ─────────────────────────────────────────────────────

pub struct SocialLoginRegistry {
    entries: DashMap<String, SocialLoginEntry>,
}

impl SocialLoginRegistry {
    /// Build an authorization URL with a fresh PKCE challenge.
    ///
    /// Returns `(auth_url, csrf_token)`. The caller **must** persist the CSRF
    /// token together with the PKCE *verifier* secret in the session cache
    /// before redirecting — see [`SocialAuthSession`].
    pub fn authorization_url(
        &self,
        provider_id: &str,
        _app_base_url: &str,
    ) -> Option<(String, PkceCodeVerifier, CsrfToken, Nonce)> {
        let entry = self.entries.get(provider_id)?;

        // Generate a fresh PKCE challenge/verifier pair.
        let (pkce_challenge, pkce_verifier_string) = PkceCodeChallenge::new_random_sha256();

        let csrf = CsrfToken::new_random();
        let nonce = Nonce::new_random();
        // Capture our own nonce so we can verify the ID token on callback.
        let mut auth_req = entry.client.authorize_url(
            AuthenticationFlow::<CoreResponseType>::AuthorizationCode,
            move || csrf.clone(),
            move || nonce.clone(),
        );

        // Add each scope individually — passing them comma-joined creates a single
        // composite scope that the IdP won't understand.
        for scope_str in &entry.scopes {
            auth_req = auth_req.add_scope(Scope::new(scope_str.clone()));
        }

        let (auth_url, csrf_returned, idp_nonce) =
            auth_req.set_pkce_challenge(pkce_challenge).url();
        Some((
            auth_url.to_string(),
            pkce_verifier_string,
            csrf_returned,
            idp_nonce,
        ))
    }

    /// Exchange an authorization code for tokens + ID token.
    /// Call this method afer CSRF checking
    pub async fn exchange_code(
        &self,
        provider_id: &str,
        auth_code: AuthorizationCode,
        pkce_verifier: PkceCodeVerifier,
        nonce: &Nonce,
    ) -> Result<ExchangeResult> {
        let entry = self
            .entries
            .get(provider_id)
            .ok_or_else(|| anyhow!("provider '{}' not found in registry", provider_id))?;

        let http_client = HttpClient::new();

        let token_response = entry
            .client
            .exchange_code(auth_code)
            .set_pkce_verifier(pkce_verifier)
            .request_async(&http_client)
            .await
            .map_err(|err| anyhow!("token exchange failed: {err}"))?;

        let id_token = token_response
            .id_token()
            .ok_or_else(|| anyhow!("Server did not return an ID token"))?;

        let id_token_verifier = entry.client.id_token_verifier();
        let claim = id_token.claims(&id_token_verifier, nonce)?;

        if let Some(hash) = claim.access_token_hash() {
            let actual_hash = AccessTokenHash::from_token(
                token_response.access_token(),
                id_token.signing_alg()?,
                id_token.signing_key(&id_token_verifier)?,
            )?;
            if actual_hash != *hash {
                return Err(anyhow!("Invalid access token"));
            }
        }

        let access_token = token_response.access_token().secret().to_string();
        let token_type = token_response.token_type().as_ref().to_string();
        let subject = Some(claim.subject().to_string());
        let email = match claim.email_verified() {
            Some(true) => claim.email().map(|e| e.to_string()),
            _ => None,
        };

        Ok(ExchangeResult {
            access_token: openidconnect::AccessToken::new(access_token),
            token_type,
            id_token: Some(id_token.clone()),
            subject,
            email,
        })
    }
}

/// Session state persisted in `ServerState.cache` during the OAuth dance.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SocialAuthSession {
    /// Provider id (matches callback path segment).
    pub provider: String,
    /// CSRF state token — validated against the IdP's `state` query param.
    pub csrf_token: String,
    /// PKCE code *verifier* secret (not the challenge) — needed for `/token`.
    pub pkce_verifier_secret: String,
    /// OIDC nonce sent with the authorize request — used to verify the ID token on callback.
    pub nonce: Nonce,
    /// Parked OIDC `/authorize` context carried from the login page:
    /// the `client_id` + `state` query params the SPA needs after login to
    /// resume the authorization request via `/authorize/resume`. `state` is
    /// the server-side `auth_pending` cache key, so nothing about the parked
    /// request itself travels through the external IdP.
    pub oidc_client_id: Option<String>,
    pub oidc_state: Option<String>,
    /// Post-login `redirect_uri` carried from the login page for the
    /// non-OIDC hop (validated by the frontend).
    pub redirect_uri: Option<String>,
    /// set when the dance was started via `link` — the IdP identity
    /// must be attached to THIS (session-derived) user instead of running
    /// the resolve-or-provision login path. `#[serde(default)]` keeps
    /// entries parked before this field existed login-only.
    #[serde(default)]
    pub link_user: Option<String>,
}

/// Generate a unique key prefix so every `request` call writes to its own
/// one-shot slot inside the 15-minute moka cache.
fn auth_key(domain: &str, csrf: &CsrfToken) -> String {
    format!("{}:oauth2:{}", domain, csrf.secret())
}

/// Post-callback landing URL: the login page plus a one-shot `code`
/// to redeem for the session JWT at `redeem`, plus any return context
/// carried through the social round-trip. Always a same-origin relative
/// path — the callback never redirects off-site.
fn landing_url(session: &SocialAuthSession, code: &str) -> String {
    let mut url = format!("/login?code={}", urlencoding::encode(code));
    if let Some(client_id) = &session.oidc_client_id {
        url.push_str(&format!("&client_id={}", urlencoding::encode(client_id)));
    }
    if let Some(state) = &session.oidc_state {
        url.push_str(&format!("&state={}", urlencoding::encode(state)));
    }
    if let Some(redirect_uri) = &session.redirect_uri {
        url.push_str(&format!(
            "&redirect_uri={}",
            urlencoding::encode(redirect_uri)
        ));
    }
    url
}

#[endpoint(
    summary = "Start social (OAuth2/OIDC) login via redirect to IdP",

    parameters(("id" = String, Path, description = "Provider id, e.g. `github`")),
    responses((status_code = 303, description = "Redirect to IdP auth page"))
)]
pub async fn request(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .obtain::<ServerState>()
        .expect("ServerState not found");

    // The route segment is `{id}` (see router.rs) — reading any other name
    // silently yields an empty provider id and a 400 for every request.
    let provider_id = req.param::<String>("id").unwrap_or_default();

    // 1. Grab the tenant so we can query SocialProvider records from DB.
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();

    let mut tenant = match state.storage.tenant_by_domain(domain.as_ref()) {
        Some(t) => t,
        None => {
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            return res.render(Json(ApiProblem::validation_error("tenant not found")));
        }
    };

    // 2. Build the registry (in-memory client pool) from discovered providers.
    // Uses TTL-based cache in Storage — invalidated on provider CRUD.
    let (registry, _cache_hit) = tenant.build_registry_cached(domain.as_ref()).await;

    // 3. Generate auth URL + fresh PKCE challenge + nonce.
    let (auth_url, pkce_verifier, csrf, nonce) = match registry.authorization_url(&provider_id, "")
    {
        Some(tuple) => tuple,
        None => {
            res.status_code(StatusCode::BAD_REQUEST);
            return res.render(Json(ApiProblem::validation_error(&format!(
                "Provider '{}' not found or misconfigured",
                provider_id
            ))));
        }
    };

    // 4. Persist the full auth session in server cache (for verify to consume).
    // The login page's return context (parked OIDC `/authorize` params or a
    // plain post-login `redirect_uri`) rides along in the session record so
    // the callback knows where to send the user afterwards — the
    // external IdP only ever sees our opaque CSRF `state`.
    let session = SocialAuthSession {
        provider: provider_id.clone(),
        csrf_token: csrf.secret().to_string(),
        pkce_verifier_secret: pkce_verifier.secret().to_string(),
        nonce,
        oidc_client_id: req.query::<String>("client_id").filter(|s| !s.is_empty()),
        oidc_state: req.query::<String>("state").filter(|s| !s.is_empty()),
        redirect_uri: req
            .query::<String>("redirect_uri")
            .filter(|s| !s.is_empty()),
        link_user: None,
    };
    let key = auth_key(domain.as_str(), &csrf);
    if SOCIAL_SESSION_CACHE.insert(key, session).await.is_err() {
        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        return res.render(Json(ApiProblem::validation_error(
            "failed to cache auth session",
        )));
    }

    // 5. Redirect the user-agent to the IdP's authorization page. A URL the
    // IdP library produced should always parse; if it somehow does not, fail
    // closed with a server error instead of redirecting somewhere bogus.
    let location = match url::Url::parse(&auth_url) {
        Ok(u) => u,
        Err(_) => {
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            return res.render(Json(ApiProblem::server_error(
                "provider produced an invalid authorization URL",
            )));
        }
    };
    res.status_code(StatusCode::SEE_OTHER);
    res.headers_mut().insert(
        salvo::http::header::LOCATION,
        salvo::http::HeaderValue::from_str(location.as_str()).unwrap(),
    );
}

#[endpoint(
    summary = "Link an IdP identity to the session's own account",

    parameters(("id" = String, Path, description = "Provider id, e.g. `github`")),
    responses(
        (status_code = 303, description = "Redirect to IdP auth page"),
        (status_code = 401, description = "No valid session", body = ApiProblem)
    )
)]
pub async fn link(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    // session-gated — the identity the IdP binding attaches to is
    // the session's own user, never anything client-supplied.
    let user = match depot.obtain_mut::<JwtVerify>() {
        Ok(v) => v.jwt_data.username.clone(),
        Err(_) => {
            res.status_code(StatusCode::UNAUTHORIZED);
            return res.render(Json(ApiProblem::unauthorized()));
        }
    };
    let state = depot
        .obtain::<ServerState>()
        .expect("ServerState not found");
    let provider_id = req.param::<String>("id").unwrap_or_default();
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();

    let mut tenant = match state.storage.tenant_by_domain(domain.as_ref()) {
        Some(t) => t,
        None => {
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            return res.render(Json(ApiProblem::validation_error("tenant not found")));
        }
    };

    let (registry, _cache_hit) = tenant.build_registry_cached(domain.as_ref()).await;

    let (auth_url, pkce_verifier, csrf, nonce) = match registry.authorization_url(&provider_id, "")
    {
        Some(tuple) => tuple,
        None => {
            res.status_code(StatusCode::BAD_REQUEST);
            return res.render(Json(ApiProblem::validation_error(&format!(
                "Provider '{}' not found or misconfigured",
                provider_id
            ))));
        }
    };

    // Same dance as login, but flagged for the callback: no OIDC parking
    // context (there is no RP to return to), and the session user rides
    // along as the link target.
    let session = SocialAuthSession {
        provider: provider_id.clone(),
        csrf_token: csrf.secret().to_string(),
        pkce_verifier_secret: pkce_verifier.secret().to_string(),
        nonce,
        oidc_client_id: None,
        oidc_state: None,
        redirect_uri: None,
        link_user: Some(user),
    };
    let key = auth_key(domain.as_str(), &csrf);
    if SOCIAL_SESSION_CACHE.insert(key, session).await.is_err() {
        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        return res.render(Json(ApiProblem::validation_error(
            "failed to cache auth session",
        )));
    }

    let location = match url::Url::parse(&auth_url) {
        Ok(u) => u,
        Err(_) => {
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            return res.render(Json(ApiProblem::server_error(
                "provider produced an invalid authorization URL",
            )));
        }
    };
    res.status_code(StatusCode::SEE_OTHER);
    res.headers_mut().insert(
        salvo::http::header::LOCATION,
        salvo::http::HeaderValue::from_str(location.as_str()).unwrap(),
    );
}

#[endpoint(
    summary = "Handle OAuth2/OIDC authorization callback from an IdP",

    parameters(("id" = String, Path)),
    responses(
        (status_code = 303, description = "Redirect to the login page with a one-shot login code"),
        (status_code = 400, description = "Missing code/state, invalid or expired state, or exchange/user failure"),
        (status_code = 401, description = "State mismatch — possible CSRF attack"),
    )
)]
pub async fn verify(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    // prior factors are inherited only from a session belonging to
    // the user being authenticated; an unrelated session contributes none
    // (passkey pattern). Captured here and filtered once the authenticated
    // identity is known below.
    let prior_session = depot
        .obtain_mut::<JwtVerify>()
        .ok()
        .map(|a| (a.jwt_data.username.clone(), a.jwt_data.mfa.clone()));

    let state = depot
        .obtain::<ServerState>()
        .expect("ServerState not found");

    // (provider from path is available via request params if needed)
    let auth_code = match req.query::<String>("code") {
        Some(code) if !code.is_empty() => code,
        _ => {
            res.status_code(StatusCode::BAD_REQUEST);
            return res.render(Json(ApiProblem::validation_error(
                "missing authorization code",
            )));
        }
    };
    let returned_state = match req.query::<String>("state") {
        Some(s) if !s.is_empty() => s,
        _ => {
            res.status_code(StatusCode::BAD_REQUEST);
            return res.render(Json(ApiProblem::validation_error(
                "missing state parameter",
            )));
        }
    };

    // 1. Rebuild registry and get tenant.
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    let issuer = crate::utils::get_issuer(req, state).unwrap_or_default();

    let mut tenant = match state.storage.tenant_by_domain(domain.as_ref()) {
        Some(t) => t,
        None => {
            res.status_code(StatusCode::BAD_REQUEST);
            return res.render(Json(ApiProblem::validation_error("tenant not found")));
        }
    };

    let (registry, _cache_hit) = tenant.build_registry_cached(domain.as_ref()).await;

    let auth_key = format!("{}:oauth2:{}", domain, returned_state);
    let session = match SOCIAL_SESSION_CACHE.get_one_shot(&auth_key).await {
        Some(s) => s,
        None => {
            res.status_code(StatusCode::UNAUTHORIZED);
            return res.render(Json(ApiProblem::validation_error(
                "invalid or expired state",
            )));
        }
    };

    // 2. Validate the IdP-returned state against our stored CSRF token.
    if session.csrf_token != returned_state {
        res.status_code(StatusCode::UNAUTHORIZED);
        return res.render(Json(ApiProblem::validation_error(
            "state mismatch — possible CSRF attack",
        )));
    }

    // 3. Exchange the authorization code for tokens (PKCE verifier + nonce needed).
    let pkce_verifier = PkceCodeVerifier::new(session.pkce_verifier_secret.clone());
    let auth_code_obj = AuthorizationCode::new(auth_code);
    let exchange_result = match registry
        .exchange_code(
            &session.provider,
            auth_code_obj,
            pkce_verifier,
            &session.nonce, // proper OIDC nonce verification
        )
        .await
    {
        Ok(r) => r,
        Err(e) => {
            return res.render(Json(ApiProblem::validation_error(&format!(
                "token exchange failed: {}",
                e
            ))));
        }
    };

    // 4. authenticate on `(provider, subject)` — the binding is the
    // identity. The email is used only for first-time provisioning and
    // never merges into an existing account. A missing subject fails
    // closed (the old code recorded an empty-subject binding instead).
    let subject = match exchange_result.subject.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => {
            return res.render(Json(ApiProblem::validation_error(
                "missing subject in ID token",
            )));
        }
    };
    let email = exchange_result.email.as_deref();

    // explicit session-gated link — attach the IdP identity to the
    // linking user and stop; never run the resolve-or-provision path.
    if let Some(link_user) = session.link_user.clone() {
        match link_user_from_social(&mut tenant, &link_user, &session.provider, subject, email)
            .await
        {
            Ok(()) => {
                // The caller keeps its existing session — nothing to
                // redeem. Send the browser back with a marker the
                // frontend can surface.
                res.status_code(StatusCode::SEE_OTHER);
                res.headers_mut().insert(
                    salvo::http::header::LOCATION,
                    salvo::http::HeaderValue::from_str(&format!(
                        "/?social_linked={}",
                        urlencoding::encode(&session.provider)
                    ))
                    .unwrap(),
                );
            }
            Err(e) => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ApiProblem::validation_error(&format!(
                    "identity link failed: {e}"
                ))));
            }
        }
        return;
    }

    let username =
        match ensure_user_from_social(&mut tenant, &session.provider, subject, email).await {
            Ok(uid) => uid,
            Err(e) => {
                return res.render(Json(ApiProblem::validation_error(&format!(
                    "user creation/lookup failed: {}",
                    e
                ))));
            }
        };

    // 6. Issue a JWT for the authenticated session.
    // inherit only if the injected session belongs to the user being
    // authenticated.
    let mut previous_fa = prior_session
        .as_ref()
        .filter(|(user, _)| user == &username)
        .map(|(_, mfa)| mfa.clone())
        .unwrap_or_default();
    previous_fa.insert(crate::db::AuthType::OAuth2.as_str().to_string());

    let jwt = match tenant
        .authenticate_jwt(
            &previous_fa,
            issuer.as_str(),
            domain.as_ref(),
            &username,
            15,
        )
        .await
    {
        Ok(j) => j,
        Err(e) => {
            return res.render(Json(ApiProblem::validation_error(&format!(
                "JWT generation failed: {}",
                e
            ))));
        }
    };

    // 7. Hand the session to the login page: store the JWT under a
    // one-shot code and 303 to the landing page, carrying the return
    // context through. Rendering the JWT as JSON to this top-level
    // navigation stranded it with no consumer. The bind secret couples
    // the code to THIS browser: it travels only via HttpOnly cookie, so
    // a code copied from the address bar cannot be redeemed elsewhere
    // (login CSRF).
    let login_code = crate::oidc::random_urlsafe_string();
    let bind = crate::oidc::random_urlsafe_string();
    if SOCIAL_LOGIN_CODE_CACHE
        .insert(
            login_code.clone(),
            LoginCodeEntry {
                jwt,
                bind: bind.clone(),
            },
        )
        .await
        .is_err()
    {
        res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        return res.render(Json(ApiProblem::server_error("failed to store login code")));
    }
    let cookie = Cookie::build((SOCIAL_BIND_COOKIE, bind))
        .path("/api/v1/auth/social")
        .http_only(true)
        .secure(true)
        .same_site(SameSite::Lax)
        .build();
    res.add_cookie(cookie);
    let location = landing_url(&session, &login_code);
    res.status_code(StatusCode::SEE_OTHER);
    res.headers_mut().insert(
        salvo::http::header::LOCATION,
        salvo::http::HeaderValue::from_str(&location).unwrap(),
    );
}

#[derive(Deserialize, Debug, ToSchema)]
struct RedeemRequest {
    code: String,
}

#[derive(Serialize, Debug, ToSchema)]
struct RedeemResponse {
    ok: bool,
    code: u16,
    msg: String,
    jwt: Option<String>,
}

#[endpoint(
    summary = "Redeem a one-shot social login code for the session JWT",
    request_body = RedeemRequest,
    responses(
        (status_code = 200, description = "ok — session JWT issued"),
        (status_code = 401, description = "Unknown, expired, or already-redeemed code"),
    )
)]
pub async fn redeem(req: &mut Request, _depot: &mut Depot, res: &mut Response) {
    // The bind cookie was set by the callback's 303 for the browser that
    // completed the IdP round-trip. Requiring it at exchange couples the
    // code to that browser — a code copied from the address bar (or an
    // attacker's own completed login) cannot be redeemed by anyone else
    // (login CSRF).
    let bind = req
        .cookie(SOCIAL_BIND_COOKIE)
        .map(|c| c.value().to_string());
    if let Some(body) = crate::utils::extract::<RedeemRequest>(req, None).await
        && let Some(entry) = SOCIAL_LOGIN_CODE_CACHE.get_one_shot(&body.code).await
        && bind.as_deref() == Some(entry.bind.as_str())
    {
        res.status_code(StatusCode::OK);
        res.render(Json(RedeemResponse {
            ok: true,
            code: StatusCode::OK.as_u16(),
            msg: "Success".to_string(),
            jwt: Some(entry.jwt),
        }));
        return;
    }
    // A missing/mismatched bind cookie still consumes the code (one-shot
    // take above), so a stolen or replayed code burns instead of leaking.
    res.status_code(StatusCode::UNAUTHORIZED);
    res.render(Json(RedeemResponse {
        ok: false,
        code: StatusCode::UNAUTHORIZED.as_u16(),
        msg: "Invalid or expired login code".to_string(),
        jwt: None,
    }));
}

#[derive(Deserialize, Serialize, Debug, ToSchema)]
pub struct RemoveOAuth2 {
    pub name: String,
    pub provider: String,
    pub provider_user_id: String,
}

#[endpoint(
    summary = "Remove OAuth2/OIDC authentication record",
    responses(
        (status_code = 200, description = "Success"),
        (status_code = 400, description = "Failure"),
    )
)]
pub async fn remove(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain_mut::<ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    if let Some(req_request) = crate::utils::extract::<RemoveOAuth2>(req, None).await {
        if !req_request.name.is_empty() {
            if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
                if let Ok(_) = tenant
                    .oauth2_delete(
                        &req_request.name,
                        &req_request.provider,
                        &req_request.provider_user_id,
                    )
                    .await
                {
                    let resp = ApiResponse::ok(());
                    res.status_code(StatusCode::OK);
                    res.render(Json(resp));
                    return;
                }
            }
        }
    }
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

#[derive(Deserialize, Serialize, Debug, ToSchema)]
struct AllIdentityRequest {
    pub name: Option<String>,
}
#[derive(Deserialize, Serialize, Debug, ToSchema)]
struct IdentityEntry {
    pub name: String,
    pub provider: String,
    pub provider_user_id: String,
}

#[endpoint(
    summary = "Return all social identity of a user",
    request_body = AllIdentityRequest,
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<Vec<IdentityEntry>>),
        (status_code = 400, description = "Failure", body = ApiProblem),
    )
)]
pub async fn all_oauth2(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain_mut::<ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    if let Some(req_request) = crate::utils::extract::<AllIdentityRequest>(req, None).await {
        if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
            if let Ok(data) = tenant.all_oauth2(req_request.name.as_deref()).await {
                let tmp: Vec<IdentityEntry> = data
                    .iter()
                    .map(|a| IdentityEntry {
                        provider: a.provider_id.clone(),
                        provider_user_id: a.provider_user_id.clone(),
                        name: a.user.get().name.clone(),
                    })
                    .collect();
                res.status_code(StatusCode::OK);
                res.render(Json(ApiResponse {
                    ok: true,
                    data: Some(tmp),
                }));
                return;
            }
        }
    }
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

#[derive(Deserialize, Serialize, Debug, ToSchema)]
pub struct AddProvider {
    pub name: String,
    pub issuer_url: String,
    pub client_id: String,
    pub client_secret: String,
}

#[endpoint(
    summary = "Add external IdP",
    request_body = AddProvider,
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<()>),
        (status_code = 400, description = "Token exchange failed", body = ApiProblem),
    )
)]
pub async fn add_provider(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain_mut::<ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    if let Some(req_request) = crate::utils::extract::<AddProvider>(req, None).await {
        if !req_request.name.is_empty() {
            if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
                if let Ok(_) = tenant
                    .provider_create(
                        &req_request.name,
                        &req_request.client_id,
                        &req_request.client_secret,
                        &req_request.issuer_url,
                    )
                    .await
                {
                    // Invalidate TTL-based social providers cache so next login uses fresh discovery
                    let _ = tenant.invalidate_social_cache(domain.as_ref()).await;
                    let resp = ApiResponse::ok(());
                    res.status_code(StatusCode::OK);
                    res.render(Json(resp));
                    return;
                }
            }
        }
    }
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

#[endpoint(
    summary = "List all external IdPs",
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<Vec<SocialProvider>>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
    )
)]
pub async fn all_providers(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain_mut::<ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
        let data = tenant.all_providers().await;
        res.status_code(StatusCode::OK);
        res.render(Json(ApiResponse {
            ok: true,
            data: Some(data),
        }));
        return;
    }
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

#[derive(Deserialize, Serialize, Debug, ToSchema)]
pub struct RemoveProvider {
    pub name: String,
}

#[endpoint(
    summary = "Remove an external IdP",
    request_body = RemoveProvider,
    responses(
        (status_code = 200, description = "Success", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
    )
)]
pub async fn remove_provider(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot.obtain_mut::<ServerState>().unwrap();
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or("")
        .to_string();
    if let Some(req_request) = crate::utils::extract::<RemoveProvider>(req, None).await {
        if !req_request.name.is_empty() {
            if let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_ref()) {
                if let Ok(_) = tenant.provider_delete(&req_request.name).await {
                    // Invalidate TTL-based social providers cache so next login uses fresh discovery
                    let _ = tenant.invalidate_social_cache(domain.as_ref()).await;
                    let resp = ApiResponse::ok(());
                    res.status_code(StatusCode::OK);
                    res.render(Json(resp));
                    return;
                }
            }
        }
    }
    let err = ApiProblem::validation_error("Failed to parse request body");
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(err))
}

#[cfg(test)]
mod tests {
    use super::*;
    use salvo::conn::{Listener, TcpListener};
    use salvo::test::ResponseExt;
    use std::sync::LazyLock;

    const DOMAIN: &str = "social.test";

    /// The revocation store is a process-wide singleton, so all tests share
    /// one backing directory that must outlive every individual test's
    /// TempDir (same pattern as the totp.rs/oidc.rs endpoint tests).
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

    /// In-process tenant with one registered social provider whose issuer
    /// points at a local mock discovery server.
    async fn social_test_env(issuer_url: &str) -> (crate::server::ServerState, tempfile::TempDir) {
        social_test_env_for(issuer_url, DOMAIN).await
    }

    /// Like `social_test_env`, but on an explicit domain. The social
    /// provider registry cache is keyed by domain and process-wide, so
    /// endpoint tests that build the registry must not share a domain or
    /// they serve each other's cached providers.
    async fn social_test_env_for(
        issuer_url: &str,
        domain: &str,
    ) -> (crate::server::ServerState, tempfile::TempDir) {
        init_revocation_store().await;
        // Client-secret encryption uses a process-wide key; first test wins.
        let _ = crate::crypto::setup_encryption_key(&"0".repeat(64));
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = crate::db::Storage::init(tmp.path())
            .await
            .expect("storage init");
        storage.new_tenant("test-tenant").await.expect("tenant");
        storage
            .add_domain(domain, "test-tenant")
            .await
            .expect("domain");
        {
            let mut tenant = storage.tenant_by_id("test-tenant").expect("tenant");
            tenant
                .provider_create("mockp", "client-1", "secret-1", issuer_url)
                .await
                .expect("provider");
        }
        let state = crate::server::ServerState::create(storage, false)
            .await
            .expect("server state");
        (state, tmp)
    }

    /// Minimal OIDC discovery document, built from the request's Host so
    /// the `issuer` always matches what the client requested.
    #[handler]
    async fn mock_discovery(req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        let host = req
            .headers()
            .get("host")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("127.0.0.1")
            .to_string();
        let base = format!("http://{}", host);
        res.render(Json(serde_json::json!({
            "issuer": base,
            "authorization_endpoint": format!("{}/authorize", base),
            "token_endpoint": format!("{}/token", base),
            "jwks_uri": format!("{}/jwks", base),
            "response_types_supported": ["code"],
            "subject_types_supported": ["public"],
            "id_token_signing_alg_values_supported": ["RS256"],
        })));
    }

    /// Empty JWKS — discovery fetches it right after the metadata document.
    #[handler]
    async fn mock_jwks(_req: &mut Request, _depot: &mut Depot, res: &mut Response) {
        res.render(Json(serde_json::json!({ "keys": [] })));
    }

    /// Spawn a real HTTP server serving the mock discovery document and
    /// return its issuer URL.
    async fn spawn_mock_issuer() -> String {
        let router = Router::new()
            .push(Router::with_path(".well-known/openid-configuration").get(mock_discovery))
            .push(Router::with_path("jwks").get(mock_jwks));
        // Bind port 0 and read back the address actually assigned. The old
        // bind → drop → rebind sequence raced other tests for the freed
        // port, leaving this issuer dead on arrival.
        let acceptor = TcpListener::new("127.0.0.1:0").bind().await;
        let addr = acceptor.local_addr().expect("bound addr");
        tokio::spawn(async move {
            Server::new(acceptor).serve(router).await;
        });
        format!("http://{}", addr)
    }

    // ── regression tests ─────────────────────────────────────────────

    fn session_with_context() -> SocialAuthSession {
        SocialAuthSession {
            provider: "mockp".to_string(),
            csrf_token: "csrf".to_string(),
            pkce_verifier_secret: "verifier".to_string(),
            nonce: Nonce::new("n".to_string()),
            oidc_client_id: Some("rp-1".to_string()),
            oidc_state: Some("parked state/&x".to_string()),
            redirect_uri: Some("https://app.example/after?x=1".to_string()),
            link_user: None,
        }
    }

    #[test]
    fn landing_url_without_context_is_plain_login() {
        let session = SocialAuthSession {
            provider: "mockp".to_string(),
            csrf_token: "csrf".to_string(),
            pkce_verifier_secret: "verifier".to_string(),
            nonce: Nonce::new("n".to_string()),
            oidc_client_id: None,
            oidc_state: None,
            redirect_uri: None,
            link_user: None,
        };
        assert_eq!(landing_url(&session, "abc123"), "/login?code=abc123");
    }

    /// The parked OIDC context and post-login target survive the IdP hop
    /// via the landing URL, percent-encoded.
    #[test]
    fn landing_url_carries_return_context_encoded() {
        let url = landing_url(&session_with_context(), "abc123");
        assert!(url.starts_with("/login?code=abc123"));
        assert!(url.contains("&client_id=rp-1"));
        assert!(url.contains("&state=parked%20state%2F%26x"));
        assert!(url.contains("&redirect_uri=https%3A%2F%2Fapp.example%2Fafter%3Fx%3D1"));
    }

    fn redeem_service() -> Service {
        Service::new(Router::with_path("redeem").post(redeem))
    }

    /// Seed a login-code entry the way `verify` does; returns (code, bind).
    async fn seed_login_code(jwt: &str) -> (String, String) {
        let code = crate::oidc::random_urlsafe_string();
        let bind = crate::oidc::random_urlsafe_string();
        SOCIAL_LOGIN_CODE_CACHE
            .insert(
                code.clone(),
                LoginCodeEntry {
                    jwt: jwt.to_string(),
                    bind: bind.clone(),
                },
            )
            .await
            .expect("insert");
        (code, bind)
    }

    async fn post_redeem(
        service: &Service,
        body: &serde_json::Value,
        bind: Option<&str>,
    ) -> (StatusCode, serde_json::Value) {
        let client = salvo::test::TestClient::post("http://localhost/redeem").json(body);
        let client = match bind {
            Some(b) => client.add_header("Cookie", &format!("{}={}", SOCIAL_BIND_COOKIE, b), true),
            None => client,
        };
        let mut res = client.send(service).await;
        let status = res.status_code.expect("status code");
        let body = res.take_string().await.unwrap_or_default();
        (
            status,
            serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    #[tokio::test]
    async fn redeem_exchanges_one_shot_code_for_jwt() {
        let service = redeem_service();
        let (code, bind) = seed_login_code("session-jwt").await;

        let (status, body) =
            post_redeem(&service, &serde_json::json!({ "code": code }), Some(&bind)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["ok"], true);
        assert_eq!(body["jwt"], "session-jwt");
    }

    #[tokio::test]
    async fn redeem_code_is_single_use() {
        let service = redeem_service();
        let (code, bind) = seed_login_code("session-jwt").await;

        let (status, _) =
            post_redeem(&service, &serde_json::json!({ "code": code }), Some(&bind)).await;
        assert_eq!(status, StatusCode::OK);

        let (status, body) =
            post_redeem(&service, &serde_json::json!({ "code": code }), Some(&bind)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_ne!(body["ok"], true);
    }

    #[tokio::test]
    async fn redeem_refuses_unknown_code() {
        let service = redeem_service();
        let (status, body) = post_redeem(
            &service,
            &serde_json::json!({ "code": "no-such-code" }),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_ne!(body["ok"], true);
    }

    /// Login-CSRF binding (review): a code is only redeemable by the
    /// browser that received the callback's bind cookie. A missing or wrong
    /// cookie is refused AND burns the code, so a stolen code cannot be
    /// retried with the victim's cookie either.
    #[tokio::test]
    async fn redeem_requires_matching_binding_cookie() {
        let service = redeem_service();
        let (code, bind) = seed_login_code("session-jwt").await;

        let (status, _) = post_redeem(&service, &serde_json::json!({ "code": code }), None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // The failed attempt consumed the code — even the rightful cookie
        // cannot redeem it afterwards.
        let (status, _) =
            post_redeem(&service, &serde_json::json!({ "code": code }), Some(&bind)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);

        // A fresh code with a WRONG cookie is refused too.
        let (code2, _bind2) = seed_login_code("session-jwt").await;
        let (status, body) = post_redeem(
            &service,
            &serde_json::json!({ "code": code2 }),
            Some("attacker-bind"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_ne!(body["ok"], true);
    }

    /// `request` carries the login page's return context into the cached
    /// session (keyed by the CSRF state sent to the IdP), so `verify` can
    /// rebuild the landing URL after the callback.
    #[tokio::test]
    async fn request_carries_return_context_into_session() {
        let issuer = spawn_mock_issuer().await;
        let (state, _tmp) = social_test_env(&issuer).await;
        let service = Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state.clone()))
                .push(Router::with_path("social/{id}/request").get(request)),
        );

        let res = salvo::test::TestClient::get(
            "http://social.test/social/mockp/request?client_id=rp-1&state=parked-1&redirect_uri=https%3A%2F%2Fapp%2Fafter",
        )
        .add_header("Host", DOMAIN, true)
        .send(&service)
        .await;

        assert_eq!(res.status_code, Some(StatusCode::SEE_OTHER));
        let location = res
            .headers()
            .get(salvo::http::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .expect("Location header")
            .to_string();
        // The browser is sent to the external IdP's authorization endpoint…
        assert!(location.starts_with(&format!("{}/authorize", issuer)));
        // …carrying only our opaque CSRF state.
        let csrf = url::Url::parse(&location)
            .expect("parse location")
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.to_string())
            .expect("state param");

        let session = SOCIAL_SESSION_CACHE
            .get(&format!("{}:oauth2:{}", DOMAIN, csrf))
            .await
            .expect("cached session");
        assert_eq!(session.provider, "mockp");
        assert_eq!(session.oidc_client_id.as_deref(), Some("rp-1"));
        assert_eq!(session.oidc_state.as_deref(), Some("parked-1"));
        assert_eq!(session.redirect_uri.as_deref(), Some("https://app/after"));
    }

    // ── regression test ──────────────────────────────────────────────

    /// A first-time social login must attach the email to the freshly
    /// created UUID user — not to a phantom user named after the provider —
    /// and a repeat login with the same subject must land on the same user.
    #[tokio::test]
    async fn social_email_attaches_to_new_user_not_provider() {
        let issuer = spawn_mock_issuer().await;
        let (state, _tmp) = social_test_env(&issuer).await;
        let mut tenant = state.storage.tenant_by_id("test-tenant").expect("tenant");

        let uid = ensure_user_from_social(&mut tenant, "mockp", "sub-1", Some("alice@example.com"))
            .await
            .expect("ensure user");

        let by_email = tenant
            .user_by_email("alice@example.com")
            .await
            .expect("email must resolve to a user");
        assert_eq!(by_email.name, uid);
        assert!(tenant.user("mockp").await.is_err());

        let again =
            ensure_user_from_social(&mut tenant, "mockp", "sub-1", Some("alice@example.com"))
                .await
                .expect("second login with same subject");
        assert_eq!(again, uid);
    }

    // ── regression tests ─────────────────────────────────────────────

    /// The `(provider, subject)` binding is the identity: a repeat login
    /// under the same subject resolves to the same user even when the IdP
    /// now asserts a different email — and the new email is not attached.
    #[tokio::test]
    async fn social_login_is_subject_keyed_not_email_keyed() {
        let issuer = spawn_mock_issuer().await;
        let (state, _tmp) = social_test_env(&issuer).await;
        let mut tenant = state.storage.tenant_by_id("test-tenant").expect("tenant");

        let uid = ensure_user_from_social(&mut tenant, "mockp", "sub-1", Some("alice@example.com"))
            .await
            .expect("first login");

        let again =
            ensure_user_from_social(&mut tenant, "mockp", "sub-1", Some("other@example.com"))
                .await
                .expect("repeat login, changed email");
        assert_eq!(again, uid, "subject binding must win over email");
        assert!(
            tenant.user_by_email("other@example.com").await.is_err(),
            "a changed IdP email must not be attached on signin"
        );
    }

    /// No email-merge takeover: a social login asserting a verified email
    /// that another user already owns must NOT merge into that account. It
    /// provisions a distinct user (without the email), and the binding
    /// makes subsequent logins stable.
    #[tokio::test]
    async fn social_login_never_merges_into_existing_email_owner() {
        let issuer = spawn_mock_issuer().await;
        let (state, _tmp) = social_test_env(&issuer).await;
        let mut tenant = state.storage.tenant_by_id("test-tenant").expect("tenant");

        // bob owns the email via a different factor.
        tenant.user_create("bob").await.expect("bob");
        tenant
            .email_create("bob", "bob@example.com")
            .await
            .expect("bob email");

        let uid = ensure_user_from_social(&mut tenant, "mockp", "sub-9", Some("bob@example.com"))
            .await
            .expect("social login");
        assert_ne!(uid, "bob", "must not merge into the email owner's account");
        assert_eq!(
            tenant
                .user_by_email("bob@example.com")
                .await
                .expect("bob keeps his email")
                .name,
            "bob"
        );

        // The binding makes the new account stable across logins.
        let again = ensure_user_from_social(&mut tenant, "mockp", "sub-9", Some("bob@example.com"))
            .await
            .expect("repeat login");
        assert_eq!(again, uid);
    }

    /// Logins without a verified email are stable: the subject binding
    /// resolves the same user every time (no throwaway UUID per login).
    #[tokio::test]
    async fn social_login_without_email_is_stable() {
        let issuer = spawn_mock_issuer().await;
        let (state, _tmp) = social_test_env(&issuer).await;
        let mut tenant = state.storage.tenant_by_id("test-tenant").expect("tenant");

        let uid = ensure_user_from_social(&mut tenant, "mockp", "sub-2", None)
            .await
            .expect("first login without email");
        let again = ensure_user_from_social(&mut tenant, "mockp", "sub-2", None)
            .await
            .expect("second login without email");
        assert_eq!(again, uid, "subject binding must prevent throwaway users");
    }

    /// Different providers isolating the same subject: the same subject
    /// string under a different provider is a different identity.
    #[tokio::test]
    async fn social_binding_is_scoped_to_provider() {
        let issuer = spawn_mock_issuer().await;
        let (state, _tmp) = social_test_env(&issuer).await;
        let mut tenant = state.storage.tenant_by_id("test-tenant").expect("tenant");
        tenant
            .provider_create("otherp", "client-2", "secret-2", &issuer)
            .await
            .expect("second provider");

        let uid_a = ensure_user_from_social(&mut tenant, "mockp", "sub-1", None)
            .await
            .expect("provider A login");
        let uid_b = ensure_user_from_social(&mut tenant, "otherp", "sub-1", None)
            .await
            .expect("provider B login");
        assert_ne!(uid_a, uid_b, "subjects must not collide across providers");
    }

    // ── regression tests (explicit identity link) ─────────────────────

    /// Linking attaches the IdP binding to the given user; re-linking the
    /// same identity is idempotent; a later social login with the linked
    /// subject resolves to that user (no duplicate account).
    #[tokio::test]
    async fn link_attaches_binding_to_the_session_user() {
        let issuer = spawn_mock_issuer().await;
        let (state, _tmp) = social_test_env(&issuer).await;
        let mut tenant = state.storage.tenant_by_id("test-tenant").expect("tenant");
        tenant.user_create("alice").await.expect("alice");

        link_user_from_social(
            &mut tenant,
            "alice",
            "mockp",
            "sub-link",
            Some("alice@example.com"),
        )
        .await
        .expect("link");
        let alice = tenant.user("alice").await.expect("alice");
        assert_eq!(
            tenant
                .oauth2_by_subject("mockp", "sub-link")
                .await
                .expect("binding")
                .user_id,
            alice.id
        );
        assert_eq!(
            tenant
                .user_by_email("alice@example.com")
                .await
                .expect("email attached")
                .name,
            "alice"
        );

        // Idempotent re-link.
        link_user_from_social(&mut tenant, "alice", "mockp", "sub-link", None)
            .await
            .expect("re-link");

        // A social login with the linked subject lands on alice — no
        // duplicate account.
        let uid = ensure_user_from_social(&mut tenant, "mockp", "sub-link", None)
            .await
            .expect("login");
        assert_eq!(uid, "alice");
    }

    /// Linking never steals a binding that belongs to another user, and
    /// never moves email ownership.
    #[tokio::test]
    async fn link_refuses_foreign_bindings_and_keeps_email_ownership() {
        let issuer = spawn_mock_issuer().await;
        let (state, _tmp) = social_test_env(&issuer).await;
        let mut tenant = state.storage.tenant_by_id("test-tenant").expect("tenant");
        tenant.user_create("alice").await.expect("alice");
        tenant.user_create("bob").await.expect("bob");
        tenant
            .email_create("bob", "bob@example.com")
            .await
            .expect("bob email");

        // bob's identity cannot be re-linked to alice.
        link_user_from_social(&mut tenant, "bob", "mockp", "sub-bob", None)
            .await
            .expect("bob links");
        assert!(
            link_user_from_social(&mut tenant, "alice", "mockp", "sub-bob", None)
                .await
                .is_err(),
            "a binding owned by another user must be refused"
        );

        // Linking with an email owned by bob attaches the binding but
        // leaves the email with bob.
        link_user_from_social(
            &mut tenant,
            "alice",
            "mockp",
            "sub-a2",
            Some("bob@example.com"),
        )
        .await
        .expect("link proceeds");
        assert_eq!(
            tenant
                .user_by_email("bob@example.com")
                .await
                .expect("email still owned")
                .name,
            "bob",
            "linking must never move email ownership"
        );
    }

    #[handler]
    async fn inject_alice_session(
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        depot.inject(JwtVerify {
            can_access: true,
            jwt_data: crate::db::JwtData {
                user: "alice".to_string(),
                username: "alice".to_string(),
                domain: DOMAIN.to_string(),
                mfa: std::collections::HashSet::new(),
                roles: std::collections::HashSet::new(),
            },
            expect_mfa: false,
            domain: DOMAIN.to_string(),
            auth_time: None,
        });
        ctrl.call_next(req, depot, res).await;
    }

    /// The link dance parks a session flagged with the session user and no
    /// RP return context; without a session it fails closed.
    #[tokio::test]
    async fn link_parks_the_session_user_and_requires_a_session() {
        // Own domain: the provider registry cache is keyed by domain and
        // process-wide — endpoint tests must not share it.
        const LINK_DOMAIN: &str = "link.test";
        let issuer = spawn_mock_issuer().await;
        let (state, _tmp) = social_test_env_for(&issuer, LINK_DOMAIN).await;
        let service = Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state.clone()))
                .push(
                    Router::with_path("social/{id}/link")
                        .hoop(inject_alice_session)
                        .get(link),
                )
                .push(Router::with_path("social/{id}/link-anon").get(link)),
        );

        let res = salvo::test::TestClient::get("http://social.test/social/mockp/link")
            .add_header("Host", LINK_DOMAIN, true)
            .send(&service)
            .await;
        assert_eq!(res.status_code, Some(StatusCode::SEE_OTHER));
        let location = res
            .headers()
            .get(salvo::http::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .expect("Location header")
            .to_string();
        assert!(location.starts_with(&format!("{}/authorize", issuer)));
        let csrf = url::Url::parse(&location)
            .expect("parse location")
            .query_pairs()
            .find(|(k, _)| k == "state")
            .map(|(_, v)| v.to_string())
            .expect("state param");
        let session = SOCIAL_SESSION_CACHE
            .get(&format!("{}:oauth2:{}", LINK_DOMAIN, csrf))
            .await
            .expect("cached session");
        assert_eq!(
            session.link_user.as_deref(),
            Some("alice"),
            "the dance must carry the session user as link target"
        );
        assert!(session.oidc_client_id.is_none());

        // No session → 401.
        let res = salvo::test::TestClient::get("http://social.test/social/mockp/link-anon")
            .add_header("Host", LINK_DOMAIN, true)
            .send(&service)
            .await;
        assert_eq!(
            res.status_code,
            Some(StatusCode::UNAUTHORIZED),
            "linking without a session must fail closed"
        );
    }
}
