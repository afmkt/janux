use anyhow::Result;

use std::sync::LazyLock;

use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use crate::db::{acr_value, amr_values};
use crate::idp::OAuth2Client;
use crate::jwt::{JwtOidcParams, jwt_authenticate};
use base64::Engine;
use jiff::{Timestamp, ToSpan};

use sha2::Digest;

use crate::cache::EphemCache;
use crate::utils::{ApiProblem, ApiResponse};

pub struct OidcDeviceCache {
    pub codes: EphemCache<String, serde_json::Value>,
    pub by_user_code: EphemCache<String, String>,
}

pub static OIDC_DEVICE_CACHE: LazyLock<OidcDeviceCache> = LazyLock::new(|| OidcDeviceCache {
    codes: EphemCache::new("oidc_device_codes", Some(1800)),
    by_user_code: EphemCache::new("oidc_device_by_user", Some(1800)),
});

pub static OIDC_PKCE_CACHE: LazyLock<EphemCache<String, serde_json::Value>> =
    LazyLock::new(|| EphemCache::new("oidc_pkce", Some(600)));

pub static OIDC_AUTH_CODE_CACHE: LazyLock<EphemCache<String, serde_json::Value>> =
    LazyLock::new(|| EphemCache::new("oidc_auth_codes", Some(600)));

pub static OIDC_AUTH_PENDING_CACHE: LazyLock<EphemCache<String, serde_json::Value>> =
    LazyLock::new(|| EphemCache::new("oidc_auth_pending", Some(1800)));

pub static OIDC_TOKEN_CACHE: LazyLock<EphemCache<String, serde_json::Value>> =
    LazyLock::new(|| EphemCache::new("oidc_tokens", Some(3600)));

/// OAuth 2.0 Device Authorization Grant type (RFC 8628).
pub const GRANT_TYPE_DEVICE_CODE: &str = "urn:ietf:params:oauth:grant-type:device_code";

/// Grant types the `/token` endpoint implements at all (server-side
/// support; per-client allowance is enforced against `client.grant_types`).
const SUPPORTED_GRANT_TYPES: &[&str] = &[
    "authorization_code",
    "refresh_token",
    "client_credentials",
    GRANT_TYPE_DEVICE_CODE,
];

fn oauth2_error_url(uri: &str, error: &str, description: &str, state: Option<&str>) -> String {
    let mut loc = format!("{}?error={}", uri, urlencoding::encode(error));
    if !description.is_empty() {
        loc.push('&');
        loc.push_str(&format!(
            "error_description={}",
            urlencoding::encode(description)
        ));
    }
    if let Some(s) = state {
        loc.push('&');
        loc.push_str(&format!("state={}", urlencoding::encode(s)));
    }
    loc
}

fn oauth2_error(
    res: &mut Response,
    uri: &str,
    error: &str,
    description: &str,
    state: Option<&str>,
) {
    let loc = oauth2_error_url(uri, error, description, state);
    redirect_to(res, &loc);
}

#[derive(Debug, Serialize, ToSchema)]
pub struct OAuth2TokenError {
    pub error: String,
    pub error_description: String,
}

pub(crate) fn token_error(res: &mut Response, status: StatusCode, error: &str, description: &str) {
    res.status_code(status);
    res.headers_mut().insert(
        salvo::http::header::CACHE_CONTROL,
        salvo::http::HeaderValue::from_static("no-store"),
    );
    res.headers_mut().insert(
        salvo::http::header::PRAGMA,
        salvo::http::HeaderValue::from_static("no-cache"),
    );
    res.render(Json(OAuth2TokenError {
        error: error.to_string(),
        error_description: description.to_string(),
    }));
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub(crate) fn redirect_to(res: &mut Response, url: &str) {
    res.status_code(StatusCode::FOUND);
    res.headers_mut().insert(
        salvo::http::header::LOCATION,
        salvo::http::HeaderValue::from_str(url).expect("valid header"),
    );
}

pub(crate) fn random_urlsafe_string() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn scopes_cover(granted: &str, requested: &str) -> bool {
    let granted: std::collections::HashSet<&str> = granted.split_whitespace().collect();
    requested.split_whitespace().all(|s| granted.contains(s))
}

fn scope_label(scope: &str) -> &'static str {
    match scope {
        "openid" => "Sign in with your identity",
        "profile" => "Read your profile information",
        "email" => "Read your email address",
        "offline_access" => "Retain access while you are not present",
        _ => "Additional access",
    }
}

/// The scope vocabulary this server understands: `openid` gates the
/// ID token, `offline_access` the refresh family, `email`/`profile` the
/// userinfo claims. Anything else has no semantics here and is rejected
/// rather than flowed through tokens.
pub(crate) const KNOWN_SCOPES: &[&str] = &["openid", "profile", "email", "offline_access"];

/// the requested scope must be server-known and contained in the
/// client's registered scope. Enforced before parking/consent so an
/// oversized grant can never reach a token, a consent record, or a refresh
/// family.
fn validate_requested_scope(requested: &str, registered: &[String]) -> Result<(), String> {
    for s in requested.split_whitespace() {
        if !KNOWN_SCOPES.contains(&s) {
            return Err(format!("unknown scope '{s}'"));
        }
        if !registered.iter().any(|r| r == s) {
            return Err(format!("scope '{s}' is not registered for this client"));
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn store_auth_pending(
    csrf_state: &str,
    client_id: &str,
    callback_uri: &str,
    requested_scope: &str,
    rp_state: Option<&str>,
    nonce: Option<&str>,
    pkce: Option<&(&'static str, String)>,
    stage: &str,
    // the session user when a session existed at park time (consent
    // stage). Consumers must refuse any other session — janux sessions are
    // stateless JWTs, so this field IS the session binding. `None` at the
    // login stage: the identity is only established by the login that
    // follows, so whoever completes it owns the flow (the protection there
    // is the unguessable server-random key).
    park_user: Option<&str>,
) -> Result<(), String> {
    let entry = serde_json::json!({
        "client_id": client_id,
        "callback_uri": callback_uri,
        "scope": requested_scope,
        "state": rp_state,
        "nonce": nonce,
        "code_challenge": pkce.map(|(_, c)| c),
        "code_challenge_method": pkce.map(|(m, _)| m),
        "stage": stage,
        "park_user": park_user,
        "created_at": Timestamp::now().as_second(),
    });
    let key = format!("auth_pending:{csrf_state}");
    OIDC_AUTH_PENDING_CACHE.remove(&key).await;
    OIDC_AUTH_PENDING_CACHE.insert(key, entry).await
}

/// a pending entry parked while a session existed is bound to that
/// session's user (janux has no server-side session store — the JWT is the
/// session, so the binding is recorded on the entry itself). Any other
/// session must be refused; entries parked without a session (login stage)
/// carry no binding.
fn pending_user_matches(pending: &serde_json::Value, session_user: &str) -> bool {
    match pending["park_user"].as_str() {
        Some(u) => u == session_user,
        None => true,
    }
}

#[allow(clippy::too_many_arguments)]
async fn issue_authorization_code(
    tenant: &mut crate::db::Tenant,
    client_id: &str,
    callback_uri: &str,
    user_id: &str,
    approved_scope: &str,
    nonce: Option<&str>,
    pkce: Option<(&'static str, String)>,
    mfa: &std::collections::HashSet<String>,
    auth_time: usize,
) -> Result<String, String> {
    let now_ts = Timestamp::now().as_second();
    let jti = uuid::Uuid::new_v4().to_string();

    let auth_code = loop {
        let candidate = random_urlsafe_string();
        let key = format!("auth_code:{candidate}");
        if OIDC_AUTH_CODE_CACHE.contains_key(&key).await {
            continue;
        }
        let entry = serde_json::json!({
            "client_id": client_id,
            "callback_uri": callback_uri,
            "user_id": user_id,
            "scope": approved_scope,
            "nonce": nonce,
            "code_challenge_method": pkce.as_ref().map(|(m, _)| *m),
            "mfa": mfa,
            "auth_time": auth_time,
            "jti": jti,
            "created_at": now_ts,
            "expires_at": now_ts + 600,
        });
        match OIDC_AUTH_CODE_CACHE.insert(key, entry).await {
            Ok(()) => break candidate,
            Err(_) => continue,
        }
    };

    let code_hash = hex::encode(sha2::Sha256::digest(auth_code.as_bytes()));
    let expires_at =
        jiff::Timestamp::from_second(now_ts + 600).map_err(|e| format!("bad timestamp: {e}"))?;
    if let Err(e) = tenant
        .auth_grant_create(
            &jti,
            client_id,
            user_id,
            approved_scope,
            &code_hash,
            expires_at,
        )
        .await
    {
        OIDC_AUTH_CODE_CACHE
            .remove(&format!("auth_code:{auth_code}"))
            .await;
        return Err(format!("Failed to record authorization grant: {e}"));
    }

    if let Some((method, challenge)) = pkce
        && OIDC_PKCE_CACHE
            .insert(
                format!("pkce:{auth_code}"),
                serde_json::json!({ "method": method, "challenge": challenge }),
            )
            .await
            .is_err()
    {
        OIDC_AUTH_CODE_CACHE
            .remove(&format!("auth_code:{auth_code}"))
            .await;
        return Err("Failed to store PKCE challenge".to_string());
    }

    Ok(auth_code)
}

fn callback_url_with_code(
    callback_uri: &str,
    auth_code: &str,
    state: Option<&str>,
    scope: Option<&str>,
) -> String {
    let mut url = format!("{}?code={}", callback_uri, urlencoding::encode(auth_code));
    if let Some(s) = state {
        url.push_str("&state=");
        url.push_str(&urlencoding::encode(s));
    }
    if let Some(s) = scope {
        url.push_str("&scope=");
        url.push_str(&urlencoding::encode(s));
    }
    url
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct OidcRedirectResponse {
    pub redirect: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ScopeDetail {
    pub scope: String,
    pub label: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ConsentRequestInfo {
    pub client_id: String,
    pub scopes: Vec<ScopeDetail>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DeviceApproveResult {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub already_processed: Option<bool>,
}

fn render_redirect_json(res: &mut Response, status: StatusCode, url: String) {
    res.status_code(status);
    res.render(Json(OidcRedirectResponse { redirect: url }));
}

fn get_bearer_token(req: &Request) -> Option<&str> {
    req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| {
            if h.starts_with("Bearer ") || h.starts_with("bearer ") {
                Some(&h[7..])
            } else {
                None
            }
        })
}

fn generate_device_code() -> String {
    let mut bytes = [0u8; 32];
    rand::fill(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

async fn authenticate_client_by_id_secret(
    tenant: &mut crate::db::Tenant,
    client_id: &str,
    client_secret: Option<&str>,
    req: &Request,
) -> Result<OAuth2Client, String> {
    if client_id.is_empty() {
        return Err("Missing required parameter: client_id".into());
    }
    let client = tenant
        .oauth2client_get(client_id)
        .await
        .map_err(|e| e.to_string())?;
    let auth_method = &client.token_endpoint_auth_method;
    match auth_method.as_str() {
        "client_secret_post" => {
            let secret = client_secret.ok_or("Missing required parameter: client_secret")?;
            if !client.verify_password(secret).map_err(|e| e.to_string())? {
                return Err("Invalid client_credentials".into());
            }
        }
        "client_secret_basic" => {
            verify_client_secret_basic(&client, client_id, client_secret, req)?;
        }
        "none" => {}
        other => return Err(format!("Unsupported token_endpoint_auth_method: {}", other)),
    }
    Ok(client)
}

/// token-issuance points re-check `user.active`. Login and
/// refresh already do, but a parked auth code or an approved device entry
/// can outlive an admin deactivation by its whole validity window; the
/// tokens must not be minted. A missing user fails closed too.
async fn require_active_user(tenant: &mut crate::db::Tenant, user_id: &str) -> Result<(), String> {
    let id = uuid::Uuid::try_parse(user_id).map_err(|_| "unknown user".to_string())?;
    match tenant.user_by_id(id).await {
        Ok(u) if u.active => Ok(()),
        Ok(_) => Err("user is deactivated".to_string()),
        Err(_) => Err("unknown user".to_string()),
    }
}

/// Long lifetime for machine principals: IdPs paste one static
/// bearer into their SCIM config and never refresh, so expiry is a
/// backstop and `/revoke` is the off switch.
const CLIENT_CREDENTIALS_TOKEN_LIFETIME_MINUTES: i32 = 90 * 24 * 60;

/// The client_credentials grant (RFC 6749 §4.4): machine principals
/// for SCIM provisioning. Mints a long-lived, session-shaped JWT bound to
/// the client's service identity (`OAuth2Client.uuid`) carrying the
/// `scim` role, so `protect`/RBAC evaluate it unchanged. The grant
/// requires client authentication — public clients
/// (`token_endpoint_auth_method = "none"`) are refused.
async fn handle_client_credentials(
    tenant: &mut crate::db::Tenant,
    client: &OAuth2Client,
    issuer: &str,
    domain: &str,
    res: &mut Response,
) {
    if client.token_endpoint_auth_method == "none" {
        token_error(
            res,
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client_credentials requires a confidential client",
        );
        return;
    }
    let key = match tenant.current_key(domain) {
        Ok(k) => k,
        Err(_) => {
            token_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "No active signing key for this tenant",
            );
            return;
        }
    };
    let data = crate::db::JwtData {
        user: client.uuid.to_string(),
        username: format!("client:{}", client.id),
        domain: domain.to_string(),
        mfa: std::collections::HashSet::new(),
        roles: std::collections::HashSet::from(["scim".to_string()]),
    };
    match jwt_authenticate(
        issuer,
        &client.uuid.to_string(),
        &data,
        &key,
        CLIENT_CREDENTIALS_TOKEN_LIFETIME_MINUTES,
        JwtOidcParams {
            client_id: client.id.clone(),
            nonce: None,
            amr: None,
            acr: None,
            access_token: None,
            auth_time: None,
        },
    ) {
        Ok(access_token) => {
            crate::ops::token_issued("client_credentials");
            res.status_code(StatusCode::OK);
            res.render(Json(TokenResponse {
                access_token,
                token_type: "Bearer".into(),
                expires_in: (CLIENT_CREDENTIALS_TOKEN_LIFETIME_MINUTES as u64) * 60,
                scope: None,
                id_token: None,
                refresh_token: None,
            }));
        }
        Err(_) => token_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            "Failed to sign token",
        ),
    }
}

async fn mint_token_response(
    tenant: &mut crate::db::Tenant,
    client: &OAuth2Client,
    issuer: &str,
    domain: &str,
    user_id: &str,
    scope: String,
    nonce: Option<String>,
    auth_time: Option<usize>,
) -> Result<TokenResponse, String> {
    let now = Timestamp::now().as_second();
    let auth_time = auth_time.unwrap_or(now as usize);
    let jti = uuid::Uuid::new_v4().to_string();

    let key = tenant
        .current_key(domain)
        .map_err(|_| "No active signing key for this tenant".to_string())?;

    let mfa: std::collections::HashSet<String> = std::collections::HashSet::new();
    let amr = amr_values(&mfa);
    let acr = acr_value(&mfa);

    let at_data = OidcAccessTokenData {
        scope: scope.clone(),
        jti: jti.clone(),
        client_id: client.id.clone(),
    };
    let access_token = jwt_authenticate(
        issuer,
        user_id,
        &at_data,
        &key,
        60,
        JwtOidcParams {
            client_id: client.id.clone(),
            nonce: nonce.clone(),
            amr: amr.clone(),
            acr: acr.clone(),
            access_token: None,
            auth_time: Some(auth_time),
        },
    )
    .map_err(|_| "Failed to sign access token".to_string())?;

    let id_token = if scope.split_whitespace().any(|s| s == "openid") {
        Some(
            jwt_authenticate(
                issuer,
                user_id,
                &serde_json::json!({}),
                &key,
                15,
                JwtOidcParams {
                    client_id: client.id.clone(),
                    nonce: nonce.clone(),
                    amr: amr.clone(),
                    acr: acr.clone(),
                    access_token: Some(access_token.clone()),
                    auth_time: Some(auth_time),
                },
            )
            .map_err(|_| "Failed to sign ID token".to_string())?,
        )
    } else {
        None
    };

    let refresh_token = if scope.split_whitespace().any(|s| s == "offline_access") {
        let family = uuid::Uuid::new_v4().to_string();
        let rt = issue_refresh_token_jwt(
            issuer,
            &key,
            user_id,
            client.id.as_str(),
            scope.as_str(),
            &mfa,
            auth_time,
            &family,
            // The family starts NOW, not at the original authentication:
            // auth_time can be arbitrarily old for reused sessions, and a
            // backdated family window would expire the token on arrival.
            now,
            (OIDC_REFRESH_FAMILY_LIFETIME / 60) as i32,
        )
        .map_err(|_| "Failed to sign refresh token".to_string())?;
        Some(rt)
    } else {
        None
    };

    let at_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(&sha2::Sha256::digest(access_token.as_bytes())[..16]);
    let at_entry = serde_json::json!({
        "type": "access",
        "client_id": client.id.as_str(),
        "user_id": user_id,
        "scope": scope.as_str(),
        "jti": jti.as_str(),
        "at_hash": at_hash.as_str(),
        "nonce": nonce.as_deref(),
        "amr": &amr,
        "acr": &acr,
        "iat": now,
        "exp": now + 3600,
    });
    OIDC_TOKEN_CACHE
        .insert(format!("token:access:{access_token}"), at_entry)
        .await
        .ok();

    tracing::info!(
        target: "oidc::token",
        client_id = client.id.as_str(),
        user_id = user_id,
        scope = scope.as_str(),
        jti = jti.as_str(),
        at_hash = at_hash.as_str(),
        "issued tokens via device_code grant"
    );

    Ok(TokenResponse {
        access_token,
        token_type: "Bearer".into(),
        expires_in: 3600,
        scope: if scope.is_empty() { None } else { Some(scope) },
        id_token,
        refresh_token,
    })
}

#[endpoint(
    summary = "OpenID Connect discovery endpoint",
    responses(
        (status_code = 200, description = "Discovery document", body = serde_json::Value),
    )
)]
pub async fn well_known(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or_default()
        .to_string();
    let Some(issuer) = crate::utils::get_issuer(req, state) else {
        res.status_code(StatusCode::NOT_FOUND);
        return;
    };
    let base = issuer.clone();

    // First-party login factor discovery (`janux_factors`): which factors
    // this tenant has configured, and where their request/verify endpoints
    // live. Origin-relative URLs; presence means enabled. The `identifier`
    // field tells a login page which extra input the factor needs (null =
    // username-only). ACR values carry the same set, per OIDC Discovery.
    let mut acr_values: Vec<String> = Vec::new();
    let mut factors = serde_json::Map::new();
    let mut dcr_enabled = false;
    if let Some(mut tenant) = state.storage.tenant_by_domain(&domain) {
        dcr_enabled = tenant.dcr_enabled().await;
        if crate::config::ResendDTO::load(&mut tenant).await.is_some() {
            acr_values.push("email".into());
            factors.insert(
                "email".into(),
                serde_json::json!({
                    "enabled": true,
                    "request": "/api/v1/auth/email/request",
                    "verify": "/api/v1/auth/email/verify",
                    "identifier": "email",
                }),
            );
        }
        if crate::config::OTPDTO::load(&mut tenant).await.is_some() {
            acr_values.push("otp".into());
            factors.insert(
                "otp".into(),
                serde_json::json!({
                    "enabled": true,
                    "request": "/api/v1/auth/otp/request",
                    "verify": "/api/v1/auth/otp/verify",
                    "identifier": "mobile",
                }),
            );
        }
        let providers: Vec<serde_json::Value> = tenant
            .all_providers()
            .await
            .into_iter()
            .map(|p| {
                serde_json::json!({
                    "id": p.id,
                    "request": format!("/api/v1/auth/social/{}/request", p.id),
                })
            })
            .collect();
        if !providers.is_empty() {
            acr_values.push("social".into());
            factors.insert(
                "social".into(),
                serde_json::json!({ "enabled": true, "providers": providers }),
            );
        }
    }
    acr_values.push("passkey".into());
    factors.insert(
        "passkey".into(),
        serde_json::json!({
            "enabled": true,
            "request": "/api/v1/auth/passkey/request",
            "verify": "/api/v1/auth/passkey/verify",
            "identifier": null,
        }),
    );

    res.status_code(StatusCode::OK);
    let mut doc = serde_json::json!({
        "issuer": issuer,
        "jwks_uri": format!("{}/.well-known/jwks.json", base),
        "authorization_endpoint": format!("{}/authorize", base),
        "token_endpoint": format!("{}/token", base),
        "userinfo_endpoint": format!("{}/userinfo", base),
        "revocation_endpoint": format!("{}/revoke", base),
        "introspection_endpoint": format!("{}/introspect", base),
        "device_authorization_endpoint": format!("{}/device_authorization", base),
        "end_session_endpoint": format!("{}/end_session", base),
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": false,
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": [
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code"
        ],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "code_challenge_methods_supported": ["S256", "plain"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_post",
            "client_secret_basic",
            "none"
        ],
        "tls_client_certificate_bound_access_tokens": false,
        "acr_values_supported": acr_values,
        "janux_factors": factors,
        "claims_supported": [
            "iss", "sub", "aud", "exp", "iat", "nbf", "auth_time",
            "acr", "amr", "nonce", "at_hash",
            "name", "given_name", "family_name", "preferred_username",
            "email", "email_verified", "picture"
        ],
        "claims_parameter_supported": false,
    });
    // The registration endpoint is only advertised when the tenant opted
    // into Dynamic Client Registration — discovery is per-tenant, so the
    // advertisement tracks the same gate `/register` enforces.
    if dcr_enabled {
        doc["registration_endpoint"] = serde_json::json!(format!("{}/register", base));
    }
    res.render(Json(doc));
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct AuthorizeRequest {
    #[serde(rename = "response_type")]
    pub response_type: String,
    #[serde(default)]
    pub client_id: String,
    pub redirect_uri: Option<String>,
    pub scope: Option<String>,
    pub state: Option<String>,
    pub nonce: Option<String>,
    #[serde(rename = "code_challenge")]
    pub code_challenge: Option<String>,
    #[serde(rename = "code_challenge_method")]
    pub code_challenge_method: Option<String>,
}

#[endpoint(
    summary = "OIDC Authorization endpoint — initiate the authorization code flow",
    request_body = AuthorizeRequest,
    responses(
        (status_code = 302, description = "Redirect to callback URL"),
        (status_code = 400, description = "Invalid request", body = serde_json::Value),
    )
)]
pub async fn authorize(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let params: AuthorizeRequest = match crate::utils::extract(req, None).await {
        Some(p) => p,
        None => {
            oauth2_error(
                res,
                "/error",
                "invalid_request",
                "can not extract AuthorizeRequest",
                None,
            );
            return;
        }
    };
    authorize_flow(req, depot, res, params).await
}

async fn authorize_flow(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    params: AuthorizeRequest,
) {
    if params.response_type != "code" {
        oauth2_error(
            res,
            "/error",
            "unsupported_response_type",
            &format!("response_type '{}' is not supported", params.response_type),
            params.state.as_deref(),
        );
        return;
    }

    let client_id = if params.client_id.is_empty() {
        oauth2_error(
            res,
            "/error",
            "invalid_client",
            "Missing required parameter: client_id",
            params.state.as_deref(),
        );
        return;
    } else {
        &params.client_id
    };

    let state = params.state.clone();

    let state_h = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state_h).unwrap_or("");

    let mut tenant = match state_h.storage.tenant_by_domain(domain) {
        Some(t) => t,
        None => {
            oauth2_error(
                res,
                "/error",
                "invalid_client",
                "Unknown domain/tenant",
                state.as_deref(),
            );
            return;
        }
    };

    let client = match tenant.oauth2client_get(client_id).await {
        Ok(c) => c,
        Err(_) => {
            oauth2_error(
                res,
                "/error",
                "invalid_client",
                &format!("Unknown client '{}'", client_id),
                state.as_deref(),
            );
            return;
        }
    };

    // the client must be registered for the requested response_type
    // (RFC 6749 §4.1.2.1 `unauthorized_client`). The server itself only
    // supports "code" (validated above), so the allowlist is consulted for
    // exactly that value.
    if !client
        .get_response_types()
        .iter()
        .any(|t| t == &params.response_type)
    {
        oauth2_error(
            res,
            "/error",
            "unauthorized_client",
            &format!(
                "client '{}' is not registered for response_type '{}'",
                client.id, params.response_type
            ),
            state.as_deref(),
        );
        return;
    }

    let callback_uri = match &params.redirect_uri {
        Some(uri) => uri.clone(),
        None => {
            oauth2_error(
                res,
                "/error",
                "invalid_request",
                "Missing required parameter: redirect_uri",
                state.as_deref(),
            );
            return;
        }
    };

    // `oauth2client_get` never loads the `redirect_uris` deferred —
    // query the relation explicitly (pattern) instead of panicking on
    // `.into_inner()`.
    let registered_uris: Vec<String> = match tenant.oauth2client_redirect_uris(client_id).await {
        Ok(uris) => uris.into_iter().map(|r| r.id).collect(),
        Err(e) => {
            oauth2_error(
                res,
                "/error",
                "server_error",
                &format!("Failed to load redirect URIs: {e}"),
                state.as_deref(),
            );
            return;
        }
    };
    if !registered_uris.contains(&callback_uri) {
        oauth2_error(
            res,
            "/error",
            "invalid_redirect_uri",
            &format!(
                "Redirect URI '{}' is not registered for this client",
                callback_uri
            ),
            state.as_deref(),
        );
        return;
    }
    let mut pkce: Option<(&'static str, String)> = None;

    if let Some(ref code_challenge) = params.code_challenge {
        match params
            .code_challenge_method
            .as_deref()
            .unwrap_or("plain")
            .to_lowercase()
            .as_str()
        {
            "s256" => {
                let challenge = code_challenge.as_str();
                if !(43..=128).contains(&challenge.len())
                    || !challenge.bytes().all(|b| {
                        matches!(
                            b,
                            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
                        )
                    })
                {
                    oauth2_error(
                        res,
                        "/error",
                        "invalid_request",
                        "Malformed code_challenge: must be 43-128 chars of [A-Z a-z 0-9 -._~]",
                        state.as_deref(),
                    );
                    return;
                }

                pkce = Some(("s256", challenge.to_string()));
            }
            "plain" => {
                // X-Forwarded-Proto is attacker-controlled unless the server
                // runs behind a proxy that owns it — honor it only in the
                // same trusted-forwarding mode as host/path resolution.
                let is_tls = if state_h.trust_forwarded_headers {
                    req.headers()
                        .get("X-Forwarded-Proto")
                        .and_then(|v| v.to_str().ok())
                        .map(|v| v.eq_ignore_ascii_case("https"))
                        .unwrap_or_else(|| {
                            req.uri().scheme().is_some_and(|s| s.as_str() == "https")
                        })
                } else {
                    req.uri().scheme().is_some_and(|s| s.as_str() == "https")
                };
                if !is_tls {
                    oauth2_error(
                        res,
                        "/error",
                        "invalid_request",
                        "code_challenge_method 'plain' requires TLS",
                        state.as_deref(),
                    );
                    return;
                }

                let challenge = code_challenge.as_str();
                if !(43..=128).contains(&challenge.len())
                    || !challenge.bytes().all(|b| {
                        matches!(
                            b,
                            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~'
                        )
                    })
                {
                    oauth2_error(
                        res,
                        "/error",
                        "invalid_request",
                        "Malformed code_challenge: must be 43-128 chars of [A-Z a-z 0-9 -._~]",
                        state.as_deref(),
                    );
                    return;
                }

                pkce = Some(("plain", challenge.to_string()));
            }
            m => {
                oauth2_error(
                    res,
                    "/error",
                    "invalid_request",
                    &format!("Unsupported code_challenge_method: '{}'", m),
                    state.as_deref(),
                );
                return;
            }
        }
    } else if client.token_endpoint_auth_method == "none" {
        oauth2_error(
            res,
            "/error",
            "invalid_request",
            "PKCE is required for public clients",
            state.as_deref(),
        );
        return;
    }

    if client.domain_id != tenant.name {
        oauth2_error(
            res,
            "/error",
            "invalid_client",
            "Client is not registered for this tenant",
            state.as_deref(),
        );
        return;
    }

    let requested_scope = params
        .scope
        .clone()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| client.scope.clone());

    // bound the requested scope by the server's vocabulary and the
    // client's registered scope before parking/consent — an oversized
    // grant here would persist through consent and every refresh.
    if let Err(e) = validate_requested_scope(&requested_scope, &client.get_scope()) {
        oauth2_error(res, "/error", "invalid_scope", &e, state.as_deref());
        return;
    }

    drop(tenant);

    let session = crate::utils::validate_jwt(req, depot).await;

    let state_h = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let mut tenant = match state_h.storage.tenant_by_domain(domain) {
        Some(t) => t,
        None => {
            oauth2_error(
                res,
                "/error",
                "server_error",
                "Tenant unavailable",
                state.as_deref(),
            );
            return;
        }
    };

    let (user_id, approved_scope, mfa, auth_time) = match session {
        None => {
            // the pending key is ALWAYS server-random — never the
            // RP-supplied state, which travels through the user's browser
            // (URLs, Referer, history) and may be observable or guessable
            // outside it. The RP state rides inside the entry and is
            // echoed back on the callback.
            let csrf_state = random_urlsafe_string();
            if store_auth_pending(
                &csrf_state,
                client_id,
                &callback_uri,
                &requested_scope,
                params.state.as_deref(),
                params.nonce.as_deref(),
                pkce.as_ref(),
                "login",
                None,
            )
            .await
            .is_err()
            {
                oauth2_error(
                    res,
                    "/error",
                    "server_error",
                    "Failed to store pending authorization request",
                    state.as_deref(),
                );
                return;
            }
            let mut loc = format!(
                "/login?client_id={}&state={}&redirect_uri={}",
                urlencoding::encode(client_id),
                urlencoding::encode(&csrf_state),
                urlencoding::encode(&callback_uri),
            );
            if crate::utils::get_jwt(req).is_some() {
                loc.push_str("&error=session_expired");
            }
            redirect_to(res, &loc);
            return;
        }

        Some(verify) => {
            let user_id = verify.jwt_data.user.clone();
            let mfa = verify.jwt_data.mfa.clone();
            let auth_time = verify
                .auth_time
                .unwrap_or_else(|| Timestamp::now().as_second() as usize);

            match tenant.auth_grant_find(&user_id, client_id).await {
                Ok(Some(grant)) if scopes_cover(&grant.scope, &requested_scope) => {
                    (user_id, requested_scope, mfa, auth_time)
                }
                Ok(_) => {
                    // server-random key (never the RP state) and the
                    // entry is bound to THIS session's user — consent is a
                    // decision of the identity that was present at /authorize.
                    let csrf_state = random_urlsafe_string();
                    if store_auth_pending(
                        &csrf_state,
                        client_id,
                        &callback_uri,
                        &requested_scope,
                        params.state.as_deref(),
                        params.nonce.as_deref(),
                        pkce.as_ref(),
                        "consent",
                        Some(&user_id),
                    )
                    .await
                    .is_err()
                    {
                        oauth2_error(
                            res,
                            "/error",
                            "server_error",
                            "Failed to store pending consent request",
                            state.as_deref(),
                        );
                        return;
                    }
                    redirect_to(
                        res,
                        &format!("/consent?state={}", urlencoding::encode(&csrf_state)),
                    );
                    return;
                }
                Err(e) => {
                    oauth2_error(
                        res,
                        "/error",
                        "server_error",
                        &format!("Failed to query consent grants: {e}"),
                        state.as_deref(),
                    );
                    return;
                }
            }
        }
    };

    let auth_code = match issue_authorization_code(
        &mut tenant,
        client_id,
        &callback_uri,
        &user_id,
        &approved_scope,
        params.nonce.as_deref(),
        pkce,
        &mfa,
        auth_time,
    )
    .await
    {
        Ok(code) => code,
        Err(msg) => {
            oauth2_error(res, "/error", "server_error", &msg, state.as_deref());
            return;
        }
    };

    let url = callback_url_with_code(
        &callback_uri,
        &auth_code,
        state.as_deref(),
        params.scope.as_deref(),
    );
    redirect_to(res, &url);
}

fn continuation_tenant<'a>(
    req: &Request,
    state: &'a crate::server::ServerState,
) -> Option<dashmap::mapref::one::RefMut<'a, String, crate::db::Tenant>> {
    let domain = crate::utils::get_domain(req, state)?;
    state.storage.tenant_by_domain(domain)
}

#[endpoint(
    summary = "Resume a parked /authorize request after login (SPA, Bearer JWT)",
    responses(
        (status_code = 200, description = "Next hop URL", body = OidcRedirectResponse),
        (status_code = 400, description = "Unknown or expired state", body = OidcRedirectResponse),
        (status_code = 401, description = "No valid session JWT", body = OidcRedirectResponse),
    )
)]
pub async fn authorize_resume(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let verify = match crate::utils::validate_jwt(req, depot).await {
        Some(v) => v,
        None => {
            render_redirect_json(
                res,
                StatusCode::UNAUTHORIZED,
                "/login?error=session_expired".to_string(),
            );
            return;
        }
    };

    let csrf_state = match req.query::<String>("state").filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => {
            render_redirect_json(
                res,
                StatusCode::BAD_REQUEST,
                "/login?error=invalid_state".to_string(),
            );
            return;
        }
    };
    let pending = match OIDC_AUTH_PENDING_CACHE
        .get_one_shot(&format!("auth_pending:{csrf_state}"))
        .await
    {
        Some(p) => p,
        None => {
            render_redirect_json(
                res,
                StatusCode::BAD_REQUEST,
                "/login?error=invalid_state".to_string(),
            );
            return;
        }
    };

    // an entry parked while a session existed is bound to that
    // session's user — a different session must not consume it.
    if !pending_user_matches(&pending, &verify.jwt_data.user) {
        render_redirect_json(
            res,
            StatusCode::BAD_REQUEST,
            "/login?error=invalid_state".to_string(),
        );
        return;
    }

    let client_id = pending["client_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let callback_uri = pending["callback_uri"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let requested_scope = pending["scope"].as_str().unwrap_or_default().to_string();
    let rp_state = pending["state"].as_str().map(str::to_string);
    let nonce = pending["nonce"].as_str().map(str::to_string);
    let pkce = pending["code_challenge"].as_str().map(|c| {
        let method = if pending["code_challenge_method"].as_str() == Some("plain") {
            "plain"
        } else {
            "s256"
        };
        (method, c.to_string())
    });

    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let mut tenant = match continuation_tenant(req, state) {
        Some(t) => t,
        None => {
            render_redirect_json(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                oauth2_error_url("/error", "server_error", "Tenant unavailable", None),
            );
            return;
        }
    };

    match tenant.oauth2client_get(&client_id).await {
        Ok(c) if c.domain_id == tenant.name => {}
        _ => {
            render_redirect_json(
                res,
                StatusCode::BAD_REQUEST,
                oauth2_error_url(
                    "/error",
                    "invalid_client",
                    &format!("Unknown client '{}'", client_id),
                    rp_state.as_deref(),
                ),
            );
            return;
        }
    }

    let user_id = verify.jwt_data.user.clone();
    let mfa = verify.jwt_data.mfa.clone();
    let auth_time = verify
        .auth_time
        .unwrap_or_else(|| Timestamp::now().as_second() as usize);

    match tenant.auth_grant_find(&user_id, &client_id).await {
        Ok(Some(grant)) if scopes_cover(&grant.scope, &requested_scope) => {
            match issue_authorization_code(
                &mut tenant,
                &client_id,
                &callback_uri,
                &user_id,
                &requested_scope,
                nonce.as_deref(),
                pkce,
                &mfa,
                auth_time,
            )
            .await
            {
                Ok(code) => render_redirect_json(
                    res,
                    StatusCode::OK,
                    callback_url_with_code(
                        &callback_uri,
                        &code,
                        rp_state.as_deref(),
                        Some(&requested_scope),
                    ),
                ),
                Err(msg) => render_redirect_json(
                    res,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    oauth2_error_url("/error", "server_error", &msg, rp_state.as_deref()),
                ),
            }
        }
        Ok(_) => {
            // server-random key, bound to the resuming session's user.
            let csrf = random_urlsafe_string();
            if store_auth_pending(
                &csrf,
                &client_id,
                &callback_uri,
                &requested_scope,
                rp_state.as_deref(),
                nonce.as_deref(),
                pkce.as_ref(),
                "consent",
                Some(&user_id),
            )
            .await
            .is_err()
            {
                render_redirect_json(
                    res,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    oauth2_error_url(
                        "/error",
                        "server_error",
                        "Failed to store pending consent request",
                        rp_state.as_deref(),
                    ),
                );
                return;
            }
            render_redirect_json(
                res,
                StatusCode::OK,
                format!("/consent?state={}", urlencoding::encode(&csrf)),
            );
        }
        Err(e) => render_redirect_json(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            oauth2_error_url(
                "/error",
                "server_error",
                &format!("Failed to query consent grants: {e}"),
                rp_state.as_deref(),
            ),
        ),
    }
}

#[endpoint(
    summary = "Consent screen data for a parked /authorize request (SPA, Bearer JWT)",
    responses(
        (status_code = 200, description = "Client id + requested scopes", body = ApiResponse<ConsentRequestInfo>),
        (status_code = 400, description = "Unknown or expired state", body = ApiProblem),
        (status_code = 401, description = "No valid session JWT", body = ApiProblem)
    )
)]
pub async fn consent_info(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let verify = match crate::utils::validate_jwt(req, depot).await {
        Some(v) => v,
        None => {
            res.status_code(StatusCode::UNAUTHORIZED);
            res.render(Json(ApiProblem::unauthorized()));
            return;
        }
    };
    let csrf_state = match req.query::<String>("state").filter(|s| !s.is_empty()) {
        Some(s) => s,
        None => {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(ApiProblem::bad_request("Missing state")));
            return;
        }
    };
    let pending = match OIDC_AUTH_PENDING_CACHE
        .get(&format!("auth_pending:{csrf_state}"))
        .await
    {
        Some(p) => p,
        None => {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(ApiProblem::bad_request(
                "Unknown or expired consent state",
            )));
            return;
        }
    };
    // a consent entry parked with a session is bound to that
    // session's user; probing it with another session reveals nothing.
    if !pending_user_matches(&pending, &verify.jwt_data.user) {
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Json(ApiProblem::bad_request(
            "Unknown or expired consent state",
        )));
        return;
    }
    let scopes: Vec<ScopeDetail> = pending["scope"]
        .as_str()
        .unwrap_or_default()
        .split_whitespace()
        .map(|s| ScopeDetail {
            scope: s.to_string(),
            label: scope_label(s).to_string(),
        })
        .collect();
    res.status_code(StatusCode::OK);
    res.render(Json(ApiResponse::ok(ConsentRequestInfo {
        client_id: pending["client_id"]
            .as_str()
            .unwrap_or_default()
            .to_string(),
        scopes,
    })));
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ConsentDecision {
    pub state: String,
    pub decision: String,
}

#[endpoint(
    summary = "Submit the consent decision (SPA, Bearer JWT)",
    responses(
        (status_code = 200, description = "Next hop URL (RP callback with code)", body = OidcRedirectResponse),
        (status_code = 400, description = "Unknown or expired state", body = OidcRedirectResponse),
        (status_code = 401, description = "No valid session JWT", body = OidcRedirectResponse),
    )
)]
pub async fn consent_submit(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let verify = match crate::utils::validate_jwt(req, depot).await {
        Some(v) => v,
        None => {
            render_redirect_json(
                res,
                StatusCode::UNAUTHORIZED,
                "/login?error=session_expired".to_string(),
            );
            return;
        }
    };
    let body: ConsentDecision = match crate::utils::extract(req, None).await {
        Some(b) => b,
        None => {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(ApiProblem::validation_error(
                "Expected form/JSON body with 'state' and 'decision'",
            )));
            return;
        }
    };

    let pending = match OIDC_AUTH_PENDING_CACHE
        .get_one_shot(&format!("auth_pending:{}", body.state))
        .await
    {
        Some(p) => p,
        None => {
            render_redirect_json(
                res,
                StatusCode::BAD_REQUEST,
                "/login?error=invalid_state".to_string(),
            );
            return;
        }
    };

    // a consent entry parked with a session is bound to that
    // session's user — another session cannot consume it (the entry is
    // already gone, so the rightful user simply restarts the flow).
    if !pending_user_matches(&pending, &verify.jwt_data.user) {
        render_redirect_json(
            res,
            StatusCode::BAD_REQUEST,
            "/login?error=invalid_state".to_string(),
        );
        return;
    }

    let client_id = pending["client_id"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let callback_uri = pending["callback_uri"]
        .as_str()
        .unwrap_or_default()
        .to_string();
    let requested_scope = pending["scope"].as_str().unwrap_or_default().to_string();
    let rp_state = pending["state"].as_str().map(str::to_string);
    let nonce = pending["nonce"].as_str().map(str::to_string);
    let pkce = pending["code_challenge"].as_str().map(|c| {
        let method = if pending["code_challenge_method"].as_str() == Some("plain") {
            "plain"
        } else {
            "s256"
        };
        (method, c.to_string())
    });

    if body.decision != "accept" {
        render_redirect_json(
            res,
            StatusCode::OK,
            oauth2_error_url(
                &callback_uri,
                "access_denied",
                "User denied consent for this client.",
                rp_state.as_deref(),
            ),
        );
        return;
    }

    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let mut tenant = match continuation_tenant(req, state) {
        Some(t) => t,
        None => {
            render_redirect_json(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                oauth2_error_url("/error", "server_error", "Tenant unavailable", None),
            );
            return;
        }
    };

    match tenant.oauth2client_get(&client_id).await {
        Ok(c) if c.domain_id == tenant.name => {}
        _ => {
            render_redirect_json(
                res,
                StatusCode::BAD_REQUEST,
                oauth2_error_url(
                    "/error",
                    "invalid_client",
                    &format!("Unknown client '{}'", client_id),
                    rp_state.as_deref(),
                ),
            );
            return;
        }
    };

    let user_id = verify.jwt_data.user.clone();
    let mfa = verify.jwt_data.mfa.clone();
    let auth_time = verify
        .auth_time
        .unwrap_or_else(|| Timestamp::now().as_second() as usize);

    if let Err(e) = tenant.auth_grant_revoke_for(&user_id, &client_id).await {
        render_redirect_json(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            oauth2_error_url(
                "/error",
                "server_error",
                &format!("Failed to update consent grants: {e}"),
                rp_state.as_deref(),
            ),
        );
        return;
    }

    match issue_authorization_code(
        &mut tenant,
        &client_id,
        &callback_uri,
        &user_id,
        &requested_scope,
        nonce.as_deref(),
        pkce,
        &mfa,
        auth_time,
    )
    .await
    {
        Ok(code) => render_redirect_json(
            res,
            StatusCode::OK,
            callback_url_with_code(
                &callback_uri,
                &code,
                rp_state.as_deref(),
                Some(&requested_scope),
            ),
        ),
        Err(msg) => render_redirect_json(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            oauth2_error_url("/error", "server_error", &msg, rp_state.as_deref()),
        ),
    }
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct TokenRequest {
    #[serde(rename = "grant_type")]
    pub grant_type: String,
    #[serde(default)]
    pub code: Option<String>,
    pub redirect_uri: Option<String>,
    #[serde(default)]
    pub client_id: String,
    #[serde(rename = "client_secret")]
    pub client_secret: Option<String>,
    #[serde(rename = "code_verifier")]
    pub code_verifier: Option<String>,
    pub scope: Option<String>,
    #[serde(rename = "refresh_token")]
    pub refresh_token: Option<String>,
    #[serde(rename = "device_code")]
    pub device_code: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_token: Option<String>,
}

#[endpoint(
    summary = "OIDC/OAuth2 Token endpoint — exchange a grant for access + ID tokens",
    request_body = TokenRequest,
    responses(
        (status_code = 200, description = "Token response", body = TokenResponse),
        (status_code = 401, description = "Unauthorized / invalid client", body = OAuth2TokenError),
        (status_code = 400, description = "Invalid request", body = OAuth2TokenError),
    )
)]
pub async fn token(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let params: TokenRequest = match req.parse_form::<Vec<(String, String)>>().await {
        Ok(pairs) => {
            let map: std::collections::HashMap<String, String> = pairs.into_iter().collect();
            TokenRequest {
                grant_type: map.get("grant_type").cloned().unwrap_or_default(),
                code: map.get("code").cloned(),
                redirect_uri: map.get("redirect_uri").cloned(),
                client_id: map.get("client_id").cloned().unwrap_or_default(),
                client_secret: map.get("client_secret").cloned(),
                code_verifier: map.get("code_verifier").cloned(),
                scope: map.get("scope").cloned(),
                refresh_token: map.get("refresh_token").cloned(),
                device_code: map.get("device_code").cloned(),
            }
        }
        Err(_) => match crate::utils::extract::<TokenRequest>(req, None).await {
            Some(p) => p,
            None => {
                token_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Malformed request",
                );
                return;
            }
        },
    };

    if params.grant_type.is_empty() {
        token_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "Missing required parameter: grant_type",
        );
        return;
    }

    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");

    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    let issuer = crate::utils::get_issuer(req, state).unwrap_or_default();

    let mut tenant = match state.storage.tenant_by_domain(domain) {
        Some(t) => t,
        None => {
            token_error(
                res,
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Unknown tenant",
            );
            return;
        }
    };

    let client = match authenticate_client(&mut tenant, &params, req).await {
        Ok(c) => c,
        Err(e) => {
            token_error(res, StatusCode::UNAUTHORIZED, "invalid_client", &e);
            return;
        }
    };

    // server-side support first (unknown grants get the precise
    // `unsupported_grant_type`), then the per-client allowlist — a client
    // may only use the grant types it is registered for (RFC 6749 §5.2
    // `unauthorized_client`).
    if !SUPPORTED_GRANT_TYPES.contains(&params.grant_type.as_str()) {
        token_error(
            res,
            StatusCode::BAD_REQUEST,
            "unsupported_grant_type",
            &format!("Unsupported grant_type: {}", params.grant_type),
        );
        return;
    }
    if !client.get_grant_types().contains(&params.grant_type) {
        token_error(
            res,
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            &format!(
                "client '{}' is not registered for grant_type '{}'",
                client.id, params.grant_type
            ),
        );
        return;
    }

    match params.grant_type.as_str() {
        "authorization_code" => {
            handle_auth_code(&mut tenant, &client, &issuer, domain, &params, res).await
        }

        "refresh_token" => {
            handle_refresh(&mut tenant, &client, &issuer, domain, &params, res).await
        }

        "urn:ietf:params:oauth:grant-type:device_code" => {
            // RFC 8628 §3.4: the token request carries the grant in the
            // `device_code` parameter (not `code`, which belongs to the
            // authorization_code grant).
            let device_code = match params.device_code {
                Some(c) if !c.is_empty() => c,
                _ => {
                    token_error(
                        res,
                        StatusCode::BAD_REQUEST,
                        "invalid_request",
                        "Missing required parameter: device_code",
                    );
                    return;
                }
            };

            // the entire poll — client binding, expiry, interval,
            // status transition — runs in ONE atomic cache compute. The old
            // get → mutate → remove+insert sequence let racing pollers
            // re-insert a stale copy over an approval, double-mint an
            // approved entry, and bypass the polling interval.
            let key = format!("device:{}", device_code);
            let now = Timestamp::now().as_second();
            enum Poll {
                ForeignClient,
                Expired,
                SlowDown,
                Pending,
                Denied,
                Approved { user_id: String, scope: String },
                Invalid,
            }
            let poll = match OIDC_DEVICE_CACHE
                .codes
                .get_mut(&key, |entry| {
                    // a foreign client neither learns the status nor
                    // mutates the polling state.
                    if entry["client_id"].as_str() != Some(client.id.as_str()) {
                        return Poll::ForeignClient;
                    }
                    if now > entry["expires_at"].as_u64().unwrap_or(0) as i64 {
                        return Poll::Expired;
                    }
                    let last_polled = entry["last_polled_at"].as_i64().unwrap_or(0);
                    let interval =
                        entry.get("interval").and_then(|v| v.as_u64()).unwrap_or(5) as i64;
                    if last_polled > 0 && now - last_polled < interval {
                        entry["last_polled_at"] = serde_json::json!(now);
                        // RFC 8628 §3.5: slow_down raises the interval by 5 s.
                        entry["interval"] = serde_json::json!(interval + 5);
                        return Poll::SlowDown;
                    }
                    entry["last_polled_at"] = serde_json::json!(now);
                    match entry["status"].as_str() {
                        // "approving": a user decision is in flight — keep
                        // the RP polling.
                        Some("pending") | Some("approving") => Poll::Pending,
                        Some("denied") => Poll::Denied,
                        Some("approved") => {
                            // The flip to "consumed" is the atomic commit
                            // point: exactly one poller can ever observe
                            // "approved", so exactly one token is minted.
                            entry["status"] = serde_json::json!("consumed");
                            let user_id = entry["user_id"].as_str().unwrap_or_default().to_string();
                            let scope = entry["scope"].as_str().unwrap_or_default().to_string();
                            Poll::Approved { user_id, scope }
                        }
                        _ => Poll::Invalid,
                    }
                })
                .await
            {
                Some(p) => p,
                None => {
                    token_error(
                        res,
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "device_code is invalid",
                    );
                    return;
                }
            };

            match poll {
                Poll::ForeignClient => {
                    token_error(
                        res,
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "device_code was issued to another client",
                    );
                    return;
                }
                Poll::Expired => {
                    token_error(
                        res,
                        StatusCode::BAD_REQUEST,
                        "expired_token",
                        "device_code has expired",
                    );
                    return;
                }
                Poll::SlowDown => {
                    token_error(
                        res,
                        StatusCode::BAD_REQUEST,
                        "slow_down",
                        "polling too fast",
                    );
                    return;
                }
                Poll::Pending => {
                    token_error(
                        res,
                        StatusCode::BAD_REQUEST,
                        "authorization_pending",
                        "user has not yet completed authorization",
                    );
                    return;
                }
                Poll::Denied => {
                    token_error(
                        res,
                        StatusCode::BAD_REQUEST,
                        "access_denied",
                        "user denied authorization",
                    );
                    return;
                }
                Poll::Invalid => {
                    token_error(
                        res,
                        StatusCode::BAD_REQUEST,
                        "invalid_grant",
                        "device_code is invalid",
                    );
                    return;
                }
                Poll::Approved { user_id, scope } => {
                    // Cleanup only — the status flip above already made a
                    // second mint impossible.
                    OIDC_DEVICE_CACHE.codes.remove(&key).await;

                    // a malformed approval carries no identity — fail
                    // closed instead of minting for a placeholder user.
                    if user_id.is_empty() {
                        token_error(
                            res,
                            StatusCode::BAD_REQUEST,
                            "invalid_grant",
                            "device_code approval is malformed",
                        );
                        return;
                    }

                    // the approval can be up to 1800 s old and the
                    // session check at approval time is stateless — an
                    // admin deactivation in between must void the exchange.
                    if let Err(e) = require_active_user(&mut tenant, &user_id).await {
                        token_error(res, StatusCode::BAD_REQUEST, "invalid_grant", &e);
                        return;
                    }

                    match mint_token_response(
                        &mut tenant,
                        &client,
                        &issuer,
                        domain,
                        &user_id,
                        scope,
                        None,
                        None,
                    )
                    .await
                    {
                        Ok(token_resp) => {
                            res.status_code(StatusCode::OK);
                            res.render(Json(token_resp));
                        }
                        Err(e) => {
                            token_error(res, StatusCode::INTERNAL_SERVER_ERROR, "server_error", &e);
                        }
                    }
                }
            }
        }
        "client_credentials" => {
            handle_client_credentials(&mut tenant, &client, &issuer, domain, res).await
        }
        _ => {
            token_error(
                res,
                StatusCode::BAD_REQUEST,
                "unsupported_grant_type",
                &format!("Unsupported grant_type: {}", params.grant_type),
            );
        }
    }
}

/// Percent-decode one half of a HTTP Basic credential per RFC 6749 §2.3.1.
/// Uses plain percent-decoding (not full form-urlencoded parsing) so literal
/// `+` and trailing `=` in secrets survive; inputs that are not valid
/// percent-encoded UTF-8 are returned unchanged.
pub(crate) fn basic_credential_decode(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8()
        .map(|c| c.into_owned())
        .unwrap_or_else(|_| s.to_string())
}

/// Verify a client secret, trying the (percent-decoded) value first and
/// falling back to the raw header value when it differs. The fallback keeps
/// secrets registered before §2.3.1 decoding was implemented — e.g. secrets
/// containing a literal `%XX` sequence — working during the transition.
fn verify_client_secret(
    client: &OAuth2Client,
    secret: &str,
    raw: Option<&str>,
) -> Result<bool, String> {
    if client.verify_password(secret).map_err(|e| e.to_string())? {
        return Ok(true);
    }
    match raw {
        Some(r) if r != secret => client.verify_password(r).map_err(|e| e.to_string()),
        _ => Ok(false),
    }
}

/// Verify a client registered with `client_secret_basic`. Shared by every
/// endpoint that authenticates clients so the behavior cannot drift between
/// them: the Basic header's client_id must not contradict the request's
/// client_id (an empty header id is treated as absent), and the secret may
/// come from the header or fall back to the request body. Both the raw and
/// the RFC 6749 §2.3.1 percent-decoded halves are kept so verification can
/// fall back to the raw value for secrets registered before decoding existed.
fn verify_client_secret_basic(
    client: &OAuth2Client,
    client_id: &str,
    body_secret: Option<&str>,
    req: &Request,
) -> Result<(), String> {
    let (basic_id, basic_id_raw, basic_secret, basic_secret_raw) = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .filter(|h| h.starts_with("Basic "))
        .and_then(|h| {
            base64::engine::general_purpose::STANDARD
                .decode(&h[6..])
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok())
                .and_then(|s| {
                    s.split_once(':').map(|(id, sec)| {
                        (
                            basic_credential_decode(id),
                            id.to_string(),
                            basic_credential_decode(sec),
                            sec.to_string(),
                        )
                    })
                })
        })
        .unwrap_or_default();

    // The request client_id is already form-decoded; accept either the
    // decoded or the raw header value for legacy clients.
    if !basic_id.is_empty() && basic_id != client_id && basic_id_raw != client_id {
        return Err("client_id mismatch between body and Basic auth header".into());
    }

    let (secret, secret_raw) = if !basic_secret.is_empty() {
        (basic_secret, Some(basic_secret_raw))
    } else {
        (body_secret.unwrap_or_default().to_string(), None)
    };
    if secret.is_empty() {
        return Err("Missing required parameter: client_secret".into());
    }
    if !verify_client_secret(client, &secret, secret_raw.as_deref())? {
        return Err("Invalid client_credentials".into());
    }
    Ok(())
}

async fn authenticate_client(
    tenant: &mut crate::db::Tenant,
    params: &TokenRequest,
    req: &Request,
) -> Result<OAuth2Client, String> {
    let client_id = params.client_id.clone();
    if client_id.is_empty() {
        return Err("Missing required parameter: client_id".into());
    }

    let client = tenant
        .oauth2client_get(&client_id)
        .await
        .map_err(|e| e.to_string())?;
    let auth_method = &client.token_endpoint_auth_method;

    match auth_method.as_str() {
        "client_secret_post" => {
            let secret = params
                .client_secret
                .as_deref()
                .ok_or("Missing required parameter: client_secret")?;
            if !client.verify_password(secret).map_err(|e| e.to_string())? {
                return Err("Invalid client_credentials".into());
            }
        }
        "client_secret_basic" => {
            verify_client_secret_basic(
                &client,
                &params.client_id,
                params.client_secret.as_deref(),
                req,
            )?;
        }
        "none" => { /* public client — no secret needed */ }
        other => return Err(format!("Unsupported token_endpoint_auth_method: {}", other)),
    };

    Ok(client)
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct OidcAccessTokenData {
    pub scope: String,
    pub jti: String,
    pub client_id: String,
}

/// Claims carried inside a refresh-token JWT. The original `auth_time` lives
/// in the surrounding `Claim` envelope (set via `JwtOidcParams`), exactly as
/// the internal `/auth/refresh` mechanism carries it through `JwtVerify`.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct OidcRefreshTokenData {
    /// Distinguishes refresh tokens from access-token JWTs on decode.
    pub typ: String,
    pub scope: String,
    pub client_id: String,
    /// Factor set from the original authentication; amr/acr are re-derived
    /// from it on every rotation (same as `Tenant::refresh_jwt`).
    pub mfa: std::collections::HashSet<String>,
    /// All tokens rotated from the same root share one family id; replay of
    /// any revoked member revokes the family (RFC 9700 §4.14.2).
    pub family: String,
    /// Unix time the family started; bounds its absolute lifetime so a
    /// refresh chain never outlives its revocation window.
    pub family_created_at: i64,
}

/// Absolute lifetime of a refresh-token family. Bounding the chain forces
/// periodic re-authentication and guarantees every revocation record stays
/// valid until the whole family is dead. Shared by issuance, rotation, and
/// revocation — these MUST agree, or revocation markers outlive (or die
/// before) the window `handle_refresh` enforces.
const OIDC_REFRESH_FAMILY_LIFETIME: i64 = 30 * 24 * 3600;

/// The InvalidJwt-store marker covering a whole refresh-token family: every
/// member fails `handle_refresh`'s family check once it is poisoned. Shared
/// by the writers (`handle_refresh` replay response, `revoke`) and the
/// reader (`handle_refresh`) — the format is a write/read contract.
fn refresh_family_marker(family: &str) -> String {
    format!("oidc_refresh_family:{family}")
}

/// Unix time at which the family — and its revocation marker — expires.
fn refresh_family_end(family_created_at: i64) -> i64 {
    family_created_at + OIDC_REFRESH_FAMILY_LIFETIME
}

/// Issue a refresh token as a signed JWT via the same mechanism the internal
/// `/auth/refresh` flow uses: verification happens through `jwt_decode`
/// (signature + expiry) and revocation through the persistent `InvalidJwt`
/// store — no opaque server-side token registry. `issuer` is the canonical
/// issuer URL (`crate::utils::get_issuer`) and becomes the `iss` claim.
#[allow(clippy::too_many_arguments)]
fn issue_refresh_token_jwt(
    issuer: &str,
    key: &crate::key::Key,
    user_id: &str,
    client_id: &str,
    scope: &str,
    mfa: &std::collections::HashSet<String>,
    auth_time: usize,
    family: &str,
    family_created_at: i64,
    minutes: i32,
) -> anyhow::Result<String> {
    let data = OidcRefreshTokenData {
        typ: "refresh".into(),
        scope: scope.to_string(),
        client_id: client_id.to_string(),
        mfa: mfa.clone(),
        family: family.to_string(),
        family_created_at,
    };
    jwt_authenticate(
        issuer,
        user_id,
        &data,
        key,
        minutes,
        JwtOidcParams {
            client_id: client_id.to_string(),
            nonce: None,
            amr: amr_values(mfa),
            acr: acr_value(mfa),
            access_token: None,
            // A refresh token is not a re-authentication: carry the original
            // authentication time (OIDC Core §2), as Tenant::refresh_jwt does.
            auth_time: Some(auth_time),
        },
    )
}

async fn handle_auth_code(
    tenant: &mut crate::db::Tenant,
    client: &OAuth2Client,
    issuer: &str,
    domain: &str,
    params: &TokenRequest,
    res: &mut Response,
) {
    let code = match &params.code {
        Some(c) if !c.is_empty() => c.clone(),
        _ => {
            token_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Missing required parameter: code",
            );
            return;
        }
    };

    // the client came from a bare `get_by_id` — its `redirect_uris`
    // deferred is unloaded; query the relation explicitly (pattern).
    let registered: Vec<String> = match tenant.oauth2client_redirect_uris(&client.id).await {
        Ok(uris) => uris.into_iter().map(|r| r.id).collect(),
        Err(e) => {
            token_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                &format!("Failed to load redirect URIs: {e}"),
            );
            return;
        }
    };
    match &params.redirect_uri {
        None => {
            // RFC 6749 §4.1.3: redirect_uri may be omitted only when
            // exactly one is registered.
            if registered.len() != 1 {
                token_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "redirect_uri missing",
                );
                return;
            }
        }
        Some(provided) => {
            if !registered.contains(provided) {
                token_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "redirect_uri does not match",
                );
                return;
            }
        }
    }

    let entry = match OIDC_AUTH_CODE_CACHE
        .get_one_shot(&format!("auth_code:{code}"))
        .await
    {
        Some(e) => e,
        None => {
            token_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Authorization code has expired or was already used",
            );
            return;
        }
    };

    if entry["client_id"].as_str() != Some(client.id.as_str()) {
        token_error(
            res,
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "Authorization code was issued to a different client",
        );
        return;
    }

    let now = Timestamp::now().as_second();
    if now > entry["expires_at"].as_i64().unwrap_or(0) {
        token_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Authorization code has expired",
        );
        return;
    }

    if let Some(provided) = &params.redirect_uri
        && entry["callback_uri"].as_str() != Some(provided.as_str())
    {
        token_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "redirect_uri does not match the authorization request",
        );
        return;
    }

    let user_id = entry["user_id"].as_str().unwrap_or_default().to_string();
    if user_id.is_empty() {
        token_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Authorization code entry is malformed",
        );
        return;
    }
    // the code can be up to 600 s old and the user may have been
    // deactivated (or deleted) since /authorize — re-check before minting.
    if let Err(e) = require_active_user(tenant, &user_id).await {
        token_error(res, StatusCode::BAD_REQUEST, "invalid_grant", &e);
        return;
    }
    let scope = entry["scope"].as_str().unwrap_or_default().to_string();
    let nonce = entry["nonce"].as_str().map(String::from);
    let jti = entry["jti"]
        .as_str()
        .map(String::from)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let auth_time = entry["auth_time"].as_u64().unwrap_or(now as u64) as usize;
    let mfa: std::collections::HashSet<String> = entry["mfa"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    let code_challenge_method = entry["code_challenge_method"].as_str().map(String::from);

    let pkce_entry = OIDC_PKCE_CACHE.get_one_shot(&format!("pkce:{code}")).await;
    if let Some(method) = code_challenge_method.as_deref() {
        let verifier = match params.code_verifier.as_deref() {
            Some(v) if !v.is_empty() => v,
            _ => {
                token_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "invalid_grant",
                    "Missing required parameter: code_verifier",
                );
                return;
            }
        };
        let stored_challenge = pkce_entry
            .as_ref()
            .and_then(|e| e["challenge"].as_str())
            .unwrap_or_default();
        let verified = match method {
            "s256" => {
                let computed = base64::engine::general_purpose::URL_SAFE_NO_PAD
                    .encode(sha2::Sha256::digest(verifier.as_bytes()));
                constant_time_eq(computed.as_bytes(), stored_challenge.as_bytes())
            }
            "plain" => constant_time_eq(verifier.as_bytes(), stored_challenge.as_bytes()),
            _ => false,
        };
        if pkce_entry.is_none() || !verified {
            token_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "PKCE code_verifier does not match the challenge",
            );
            return;
        }
    }

    let key = match tenant.current_key(domain) {
        Ok(k) => k,
        Err(_) => {
            token_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "No active signing key for this tenant",
            );
            return;
        }
    };
    let amr = amr_values(&mfa);
    let acr = acr_value(&mfa);

    let at_data = OidcAccessTokenData {
        scope: scope.clone(),
        jti: jti.clone(),
        client_id: client.id.clone(),
    };
    let access_token = match jwt_authenticate(
        issuer,
        &user_id,
        &at_data,
        &key,
        60,
        JwtOidcParams {
            client_id: client.id.clone(),
            nonce: None,
            amr: amr.clone(),
            acr: acr.clone(),
            access_token: None,
            auth_time: Some(auth_time),
        },
    ) {
        Ok(t) => t,
        Err(_) => {
            token_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to sign access token",
            );
            return;
        }
    };

    let id_token = if scope.split_whitespace().any(|s| s == "openid") {
        match jwt_authenticate(
            issuer,
            &user_id,
            &serde_json::json!({}),
            &key,
            15,
            JwtOidcParams {
                client_id: client.id.clone(),
                nonce: nonce.clone(),
                amr: amr.clone(),
                acr: acr.clone(),
                access_token: Some(access_token.clone()),
                auth_time: Some(auth_time),
            },
        ) {
            Ok(t) => Some(t),
            Err(_) => {
                token_error(
                    res,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "Failed to sign ID token",
                );
                return;
            }
        }
    } else {
        None
    };

    let refresh_token = if scope.split_whitespace().any(|s| s == "offline_access") {
        let family = uuid::Uuid::new_v4().to_string();
        match issue_refresh_token_jwt(
            issuer,
            &key,
            &user_id,
            client.id.as_str(),
            scope.as_str(),
            &mfa,
            auth_time,
            &family,
            // The family starts NOW, not at the original authentication:
            // auth_time can be arbitrarily old for reused sessions, and a
            // backdated family window would expire the token on arrival.
            now,
            (OIDC_REFRESH_FAMILY_LIFETIME / 60) as i32,
        ) {
            Ok(rt) => Some(rt),
            Err(_) => {
                token_error(
                    res,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "Failed to sign refresh token",
                );
                return;
            }
        }
    } else {
        None
    };

    let at_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(&sha2::Sha256::digest(access_token.as_bytes())[..16]);
    let at_entry = serde_json::json!({
        "type": "access",
        "client_id": client.id.as_str(),
        "user_id": user_id.as_str(),
        "scope": scope.as_str(),
        "jti": jti.as_str(),
        "at_hash": at_hash.as_str(),
        "nonce": nonce.as_deref(),
        "amr": &amr,
        "acr": &acr,
        "iat": now,
        "exp": now + 3600,
    });
    OIDC_TOKEN_CACHE
        .insert(format!("token:access:{access_token}"), at_entry)
        .await
        .ok();

    tracing::info!(
        target: "oidc::token",
        client_id = client.id.as_str(),
        user_id = user_id.as_str(),
        scope = scope.as_str(),
        jti = jti.as_str(),
        at_hash = at_hash.as_str(),
        "issued tokens via authorization_code grant"
    );
    crate::ops::token_issued("oidc");

    res.status_code(StatusCode::OK);
    res.render(Json(TokenResponse {
        access_token,
        token_type: "Bearer".into(),
        expires_in: 3600,
        scope: if scope.is_empty() { None } else { Some(scope) },
        id_token,
        refresh_token,
    }));
}

async fn handle_refresh(
    tenant: &mut crate::db::Tenant,
    client: &OAuth2Client,
    issuer: &str,
    domain: &str,
    params: &TokenRequest,
    res: &mut Response,
) {
    let invalid_jwt = crate::jwt::InvalidJwt::global();
    let rt = match &params.refresh_token {
        Some(rt) if !rt.is_empty() => rt.clone(),
        _ => {
            token_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Missing required parameter: refresh_token",
            );
            return;
        }
    };

    // STEP A: verify the refresh token through the existing JWT machinery —
    // jwt_decode checks this tenant's signature and the expiry, mirroring the
    // internal /auth/refresh flow (Tenant::refresh_jwt). Nothing is mutated
    // before the commit point, so a rejected request cannot consume the
    // token.
    let tkn = match crate::jwt::jwt_decode::<OidcRefreshTokenData>(&rt, 2, tenant).await {
        Ok(t) => t,
        Err(_) => {
            token_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Unknown or expired refresh token",
            );
            return;
        }
    };
    let data = &tkn.claims.data;
    if tkn.claims.iss != issuer || data.typ != "refresh" || data.client_id != client.id.as_str() {
        token_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Refresh token was issued to a different client",
        );
        return;
    }

    let now = Timestamp::now().as_second();
    let user_id = tkn.claims.sub.clone();
    // The ORIGINAL authentication time travels in the claim envelope; a
    // refresh is not a re-authentication (OIDC Core §2), same as
    // Tenant::refresh_jwt preserving jwt_verify.auth_time.
    let auth_time = tkn.claims.auth_time.unwrap_or(now as usize);
    let mfa = data.mfa.clone();
    let original_scope = data.scope.clone();
    let family = data.family.clone();
    let family_created_at = data.family_created_at;
    // A family lives at most 30 days: bounding the chain's absolute lifetime
    // forces periodic re-authentication and guarantees every revocation
    // record stays valid until the whole family is dead.
    let family_end = refresh_family_end(family_created_at);
    if now >= family_end {
        token_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Refresh token family has expired; re-authentication required",
        );
        return;
    }

    // Replay detection: the persistent InvalidJwt store records every rotated
    // token plus a family-wide marker. Presenting an already-revoked token
    // indicates theft — poison the whole family (OAuth 2.0 Security BCP /
    // RFC 9700 §4.14.2). The marker persists, so every further replay keeps
    // being rejected.
    let family_marker = refresh_family_marker(&family);
    if invalid_jwt.is_valid(&rt).await || invalid_jwt.is_valid(&family_marker).await {
        revoke_refresh_token_family(&family_marker, family_end).await;
        tracing::warn!(
            target: "oidc::token",
            client_id = client.id.as_str(),
            "refresh token reuse detected; token family revoked"
        );
        token_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_grant",
            "Refresh token reuse detected; the token family has been revoked",
        );
        return;
    }

    // boundary: refresh is a central round-trip and the only point where
    // an OIDC session can be EXTENDED, so the user's live state is re-checked
    // here — never at token-verification time, which must stay stateless. A
    // deactivated user's current tokens run out their lifetime, but the
    // family can never be rotated again. Placed after replay detection so a
    // stolen-token replay still poisons the family, and before any mutation
    // so the presented token is not consumed. A DELETED user fails closed
    // too (via `require_active_user`): deletion cascades every
    // credential, so no new login is possible and the family must not keep
    // extending the old session.
    if let Err(e) = require_active_user(&mut *tenant, &user_id).await {
        token_error(res, StatusCode::BAD_REQUEST, "invalid_grant", &e);
        return;
    }

    // STEP C: scope narrowing (RFC 6749 §6) — validated before any state is
    // mutated so a bad scope request does not consume the refresh token.
    let scope = match params.scope.as_deref() {
        Some(requested) if !requested.trim().is_empty() => {
            if !scopes_cover(&original_scope, requested) {
                token_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "invalid_scope",
                    "Requested scope exceeds the scope granted to the refresh token",
                );
                return;
            }
            requested.to_string()
        }
        _ => original_scope,
    };

    // STEPS D/E before STEP B: fetch the signing key and sign both tokens
    // BEFORE consuming the refresh token, so a failure here cannot strand the
    // client with a revoked token and no response (a retry would then trip
    // replay detection and revoke the whole family).
    let key = match tenant.current_key(domain) {
        Ok(k) => k,
        Err(_) => {
            token_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "No active signing key for this tenant",
            );
            return;
        }
    };
    let amr = amr_values(&mfa);
    let acr = acr_value(&mfa);
    let jti = uuid::Uuid::new_v4().to_string();

    let at_data = OidcAccessTokenData {
        scope: scope.clone(),
        jti: jti.clone(),
        client_id: client.id.clone(),
    };
    let access_token = match jwt_authenticate(
        issuer,
        &user_id,
        &at_data,
        &key,
        60,
        JwtOidcParams {
            client_id: client.id.clone(),
            nonce: None,
            amr: amr.clone(),
            acr: acr.clone(),
            access_token: None,
            auth_time: Some(auth_time),
        },
    ) {
        Ok(t) => t,
        Err(_) => {
            token_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to sign access token",
            );
            return;
        }
    };

    let id_token = match generate_id_token(
        tenant,
        issuer,
        domain,
        &client.id,
        &user_id,
        &scope,
        &mfa,
        auth_time,
        Some(access_token.clone()),
    )
    .await
    {
        Ok(t) => t,
        Err(_) => {
            token_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to sign ID token",
            );
            return;
        }
    };

    // Sign the rotated refresh_token BEFORE the commit point too — a failure
    // after rotation must never strand the client with a revoked token and no
    // response. The successor stays in the same family, capped so the family
    // never outlives its absolute 30-day lifetime.
    let successor_minutes =
        ((std::cmp::min(now + OIDC_REFRESH_FAMILY_LIFETIME, family_end) - now) / 60) as i32;
    let mut new_rt: Option<String> = None;
    if scope.split_whitespace().any(|s| s == "offline_access") && successor_minutes > 0 {
        match issue_refresh_token_jwt(
            issuer,
            &key,
            &user_id,
            client.id.as_str(),
            &scope,
            &mfa,
            auth_time,
            &family,
            family_created_at,
            successor_minutes,
        ) {
            Ok(t) => new_rt = Some(t),
            Err(_) => {
                token_error(
                    res,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "server_error",
                    "Failed to sign refresh token",
                );
                return;
            }
        }
    }

    // STEP B: token rotation (OAuth 2.0 Security BCP / RFC 9700 §4.14.2) —
    // the atomic commit point, through the shared revocation primitive
    // (Step 1.2). Revoking the presented token in the persistent InvalidJwt
    // store is insert-wins, so exactly one concurrent presenter of the same
    // token rotates it; every loser is treated as reuse and the whole family
    // is revoked. The expiry from the decode above is passed through so the
    // token is not decoded (and re-verified) again.
    let rt_expires = jiff::Timestamp::from_second(tkn.claims.exp as i64)
        .expect("a JWT expiry validated by jwt_decode is a valid timestamp");
    match crate::utils::revoke_token(tenant, &rt, Some(rt_expires), "oidc refresh rotation").await {
        Ok(true) => {
            crate::ops::token_refreshed("oidc");
        }
        Ok(false) => {
            revoke_refresh_token_family(&family_marker, family_end).await;
            tracing::warn!(
                target: "oidc::token",
                client_id = client.id.as_str(),
                "refresh token reuse detected; token family revoked"
            );
            token_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_grant",
                "Refresh token reuse detected; the token family has been revoked",
            );
            return;
        }
        Err(_) => {
            token_error(
                res,
                StatusCode::INTERNAL_SERVER_ERROR,
                "server_error",
                "Failed to revoke refresh token",
            );
            return;
        }
    }

    let at_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .encode(&sha2::Sha256::digest(access_token.as_bytes())[..16]);
    let at_entry = serde_json::json!({
        "type": "access",
        "client_id": client.id.as_str(),
        "user_id": user_id.as_str(),
        "scope": scope.as_str(),
        "jti": jti.as_str(),
        "at_hash": at_hash.as_str(),
        "nonce": null,
        "amr": &amr,
        "acr": &acr,
        "iat": now,
        "exp": now + 3600,
    });
    OIDC_TOKEN_CACHE
        .insert(format!("token:access:{access_token}"), at_entry)
        .await
        .ok();

    tracing::info!(
        target: "oidc::token",
        client_id = client.id.as_str(),
        user_id = user_id.as_str(),
        scope = scope.as_str(),
        jti = jti.as_str(),
        at_hash = at_hash.as_str(),
        "issued tokens via refresh_token grant"
    );

    // STEP F: TokenResponse with the rotated refresh_token.
    res.status_code(StatusCode::OK);
    res.render(Json(TokenResponse {
        access_token,
        token_type: "Bearer".into(),
        expires_in: 3600,
        scope: if scope.is_empty() { None } else { Some(scope) },
        id_token,
        refresh_token: new_rt,
    }));
}

/// Poison a refresh-token family in the persistent InvalidJwt store (OAuth
/// 2.0 Security BCP / RFC 9700 §4.14.2 replay response): every member —
/// current and future — fails the family-marker check on its next refresh.
async fn revoke_refresh_token_family(family_marker: &str, family_end: i64) {
    let exp = jiff::Timestamp::from_second(family_end).unwrap_or_else(|_| jiff::Timestamp::now());
    crate::jwt::InvalidJwt::global()
        .invalid_raw(family_marker, exp)
        .await
        .ok();
}

/// Sign an OIDC ID token for the `/token` endpoint (OIDC Core §3.3.2.10).
/// Returns `Ok(None)` when the scope does not include "openid". `mfa` and
/// `auth_time` MUST come from the grant cache entry (refresh flows pass the
/// ORIGINAL auth_time through), and `access_token` the freshly issued access
/// token so at_hash is computed over it. Per OIDC Core §12.2 a refreshed ID
/// token carries no nonce.
#[allow(clippy::too_many_arguments)]
async fn generate_id_token(
    tenant: &mut crate::db::Tenant,
    issuer: &str,
    domain: &str,
    client_id: &str,
    user_id: &str,
    scope: &str,
    mfa: &std::collections::HashSet<String>,
    auth_time: usize,
    access_token: Option<String>,
) -> Result<Option<String>> {
    if !scope.split_whitespace().any(|s| s == "openid") {
        return Ok(None); // OIDC requires "openid" in scope
    }

    let key = tenant.current_key(domain)?;
    let params = JwtOidcParams {
        client_id: client_id.to_string(),
        nonce: None,
        amr: amr_values(mfa),
        acr: acr_value(mfa),
        access_token,
        auth_time: Some(auth_time),
    };
    let id_token = jwt_authenticate(issuer, user_id, &serde_json::json!({}), &key, 15, params)?;
    Ok(Some(id_token))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct UserInfoResponse {
    pub sub: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub given_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub family_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred_username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_verified: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub picture: Option<String>,
}

/// RFC 6750 §3.1 — Bearer token errors are reported in the WWW-Authenticate
/// challenge; OIDC Core §5.3.3 maps invalid/expired/revoked tokens to
/// `invalid_token` (401) and a missing openid scope to `insufficient_scope`
/// (403).
fn userinfo_error(res: &mut Response, status: StatusCode, error: &str, description: &str) {
    res.status_code(status);
    res.render(Json(ApiProblem {
        status: status.as_u16(),
        r#type: "unauthorized".into(),
        detail: Some(description.into()),
    }));
    let _ = res.add_header(
        "WWW-Authenticate",
        format!(r#"Bearer error="{error}",error_description="{description}",realm="auth""#),
        true,
    );
}

#[endpoint(
    summary = "OIDC UserInfo endpoint — retrieve claims about the authenticated user",
    responses(
        (status_code = 200, description = "User info", body = UserInfoResponse),
        (status_code = 401, description = "Unauthorized", body = serde_json::Value),
        (status_code = 403, description = "Insufficient scope", body = serde_json::Value),
    )
)]
pub async fn userinfo(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let bearer = match get_bearer_token(req) {
        Some(t) => t.to_string(),
        None => {
            res.status_code(StatusCode::UNAUTHORIZED);
            res.render(Json(ApiProblem::unauthorized()));
            // RFC 6750 §3.1 — challenge even when no credentials were presented
            let _ = res.add_header("WWW-Authenticate", r#"Bearer realm="auth""#, true);
            return;
        }
    };

    // STEP 1: resolve tenant from Host/X-Forwarded-Host (same pattern as token()).
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    let issuer = crate::utils::get_issuer(req, state).unwrap_or_default();
    let mut tenant = match state.storage.tenant_by_domain(domain) {
        Some(t) => t,
        None => {
            userinfo_error(
                res,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "Unknown tenant",
            );
            return;
        }
    };

    // STEP 2: validate through the shared primitive (Step 1.1) — signature,
    // expiry, issuer and revocation in one place. Decoded as Value with
    // refresh tokens rejected by type, so a refresh token (typ="refresh")
    // can never pass as an access token; an ID token fails the scope check
    // below. No policy engine: userinfo serves claims, not authorization.
    let decision = match crate::utils::validate_token::<serde_json::Value>(
        &mut tenant,
        &issuer,
        domain,
        &bearer,
        crate::utils::ValidateOpts {
            reject_typ: Some("refresh"),
            ..Default::default()
        },
    )
    .await
    {
        Ok(d) => d,
        Err(crate::utils::TokenReject::Revoked) => {
            userinfo_error(
                res,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "The access token has been revoked",
            );
            return;
        }
        Err(crate::utils::TokenReject::Invalid) => {
            userinfo_error(
                res,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "The access token is invalid or expired",
            );
            return;
        }
        Err(_) => {
            userinfo_error(
                res,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "The access token is invalid",
            );
            return;
        }
    };
    let scope = match decision
        .claims
        .data
        .get("scope")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
    {
        Some(s) => s,
        None => {
            userinfo_error(
                res,
                StatusCode::UNAUTHORIZED,
                "invalid_token",
                "The access token is invalid",
            );
            return;
        }
    };
    if !scope.split_whitespace().any(|s| s == "openid") {
        userinfo_error(
            res,
            StatusCode::FORBIDDEN,
            "insufficient_scope",
            "The access token does not contain the openid scope",
        );
        return;
    }

    // STEP 3: claims. No profile store exists yet, so sub is served with the
    // user's verified emails (only added through the magic-link verify flow,
    // hence email_verified=true); the earliest-registered email is primary.
    let sub = decision.claims.sub.clone();
    // sub is the user's surrogate key (UUID); resolve it for name-based
    // claims and the email lookup.
    let username = match uuid::Uuid::try_parse(&sub) {
        Ok(id) => match tenant.user_by_id(id).await {
            Ok(u) => u.name,
            Err(_) => sub.clone(),
        },
        Err(_) => sub.clone(),
    };
    let has_profile = scope.split_whitespace().any(|s| s == "profile");
    let has_email = scope.split_whitespace().any(|s| s == "email");

    let (email, email_verified) = if has_email {
        match tenant.all_emails(Some(&username)).await {
            Ok(mut emails) => {
                emails.sort_by_key(|e| e.created_at);
                match emails.first() {
                    Some(e) => (Some(e.id.clone()), Some(true)),
                    None => (None, None),
                }
            }
            Err(_) => (None, None),
        }
    } else {
        (None, None)
    };

    // STEP 4: OIDC Core §5.1 scope semantics — "profile" gates the profile
    // claims (only preferred_username is known without a profile store) and
    // "email" gates email/email_verified; None fields are omitted by serde.
    let resp = UserInfoResponse {
        sub: sub.clone(),
        name: None,
        given_name: None,
        family_name: None,
        preferred_username: if has_profile { Some(username) } else { None },
        email,
        email_verified,
        picture: None,
    };

    // STEP 5: 200 with application/json per OIDC Core §5.3.2.
    res.status_code(StatusCode::OK);
    res.render(Json(resp));
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct RevokeRequest {
    pub token: String,
    #[serde(rename = "token_type_hint")]
    #[serde(default)]
    pub token_type_hint: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
}

#[endpoint(
    summary = "Token revocation endpoint (RFC 7009)",
    request_body = RevokeRequest,
    responses(
        (status_code = 200, description = "Token revoked — always 200 with an empty body, even for unknown tokens (RFC 7009 §2.2)"),
        (status_code = 400, description = "Invalid request", body = serde_json::Value),
        (status_code = 401, description = "Unauthorized / invalid client", body = serde_json::Value),
    )
)]
pub async fn revoke(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let params = match req.parse_form::<Vec<(String, String)>>().await {
        Ok(pairs) => {
            let map: std::collections::HashMap<String, String> = pairs.into_iter().collect();
            RevokeRequest {
                token: map.get("token").cloned().unwrap_or_default(),
                token_type_hint: map.get("token_type_hint").cloned(),
                client_id: map.get("client_id").cloned(),
                client_secret: map.get("client_secret").cloned(),
            }
        }
        Err(_) => match crate::utils::extract::<RevokeRequest>(req, None).await {
            Some(p) => p,
            None => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ApiProblem::validation_error("Malformed request")));
                return;
            }
        },
    };

    if params.token.is_empty() {
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Json(ApiProblem::validation_error(
            "Missing required parameter: token",
        )));
        return;
    }

    // STEP 1: resolve the tenant and authenticate the calling client (same
    // pattern as token()). RFC 7009 §2.1 REQUIRES client authentication —
    // without it anyone could revoke tokens by guessing.
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    let issuer = crate::utils::get_issuer(req, state).unwrap_or_default();
    let mut tenant = match state.storage.tenant_by_domain(domain) {
        Some(t) => t,
        None => {
            token_error(
                res,
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Unknown tenant",
            );
            return;
        }
    };

    let auth_params = TokenRequest {
        grant_type: String::new(),
        code: None,
        redirect_uri: None,
        client_id: params.client_id.clone().unwrap_or_default(),
        client_secret: params.client_secret.clone(),
        code_verifier: None,
        scope: None,
        refresh_token: None,
        device_code: None,
    };
    let client = match authenticate_client(&mut tenant, &auth_params, req).await {
        Ok(c) => c,
        Err(e) => {
            token_error(res, StatusCode::UNAUTHORIZED, "invalid_client", &e);
            return;
        }
    };

    // RFC 7009 §2.1 requires client authentication. A public client
    // ("none") has no credential, so accepting it would let ANY anonymous
    // caller revoke this client's tokens — including poisoning an entire
    // refresh family below.
    if client.token_endpoint_auth_method == "none" {
        token_error(
            res,
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "public clients are not allowed on this endpoint",
        );
        return;
    }

    // STEP 2: identify the token through the existing JWT machinery.
    // jwt_decode is type-agnostic (signature + expiry) and the claims say
    // which kind it is (typ="refresh" vs. access-token data), so one decode
    // covers the hinted lookup plus the RFC 7009 §2.1 fallback to the other
    // token type — token_type_hint needs no special handling. An undecodable
    // or expired token is indistinguishable from an unknown one → 200
    // (RFC 7009 §2.2).
    let _hint = params.token_type_hint.as_deref();
    let tkn = match crate::jwt::jwt_decode::<serde_json::Value>(&params.token, 2, &mut tenant).await
    {
        Ok(t) => t,
        Err(_) => {
            revoke_ok(res);
            return;
        }
    };
    let data = &tkn.claims.data;

    // STEP 3: a token issued to another client (or another issuer) is treated
    // as not found — a client MUST NOT revoke another client's token, and the
    // response must not leak that the token exists (RFC 7009 §2.1).
    let token_client_id = data.get("client_id").and_then(|v| v.as_str()).unwrap_or("");
    if tkn.claims.iss != issuer || token_client_id != client.id.as_str() {
        revoke_ok(res);
        return;
    }

    // STEP 4: revoke through the persistent InvalidJwt store. For a refresh
    // token also poison the family marker exactly as handle_refresh does on
    // reuse, so every rotated sibling and successor dies with it.
    if data.get("typ").and_then(|v| v.as_str()) == Some("refresh") {
        if let (Some(family), Some(created_at)) = (
            data.get("family").and_then(|v| v.as_str()),
            data.get("family_created_at").and_then(|v| v.as_i64()),
        ) {
            let family_marker = refresh_family_marker(family);
            let family_end = refresh_family_end(created_at);
            revoke_refresh_token_family(&family_marker, family_end).await;
        }
    } else {
        OIDC_TOKEN_CACHE
            .remove(&format!("token:access:{}", params.token))
            .await;
    }
    // Revocation goes through the shared primitive (Step 1.2) — the same
    // store write `auth/logout` uses. The expiry from the decode above is
    // passed through so the token is not decoded (and re-verified) twice.
    let Ok(expires) = jiff::Timestamp::from_second(tkn.claims.exp as i64) else {
        revoke_ok(res);
        return;
    };
    if let Err(e) =
        crate::utils::revoke_token(&mut tenant, &params.token, Some(expires), "rfc7009 revoke")
            .await
    {
        tracing::warn!(
            target: "oidc::revoke",
            client_id = client.id.as_str(),
            error = %e,
            "failed to record token revocation"
        );
    }

    revoke_ok(res);
}

/// RFC 7009 §2.2: the revocation response is ALWAYS HTTP 200 with an empty
/// body — for revoked and for unknown/invalid tokens alike, so the response
/// never leaks which tokens exist.
fn revoke_ok(res: &mut Response) {
    res.status_code(StatusCode::OK);
    res.headers_mut().insert(
        salvo::http::header::CACHE_CONTROL,
        salvo::http::HeaderValue::from_static("no-store"),
    );
    res.headers_mut().insert(
        salvo::http::header::PRAGMA,
        salvo::http::HeaderValue::from_static("no-cache"),
    );
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct IntrospectRequest {
    pub token: String,
    #[serde(rename = "token_type_hint")]
    #[serde(default)]
    pub token_type_hint: Option<String>,
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct IntrospectResponse {
    pub active: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub token_type: Option<String>,
}

impl Default for IntrospectResponse {
    fn default() -> Self {
        Self {
            active: false,
            client_id: None,
            scope: None,
            sub: None,
            aud: None,
            iss: None,
            exp: None,
            iat: None,
            username: None,
            token_type: None,
        }
    }
}

#[endpoint(
    summary = "Token introspection endpoint (RFC 7662)",
    request_body = IntrospectRequest,
    responses(
        (status_code = 200, description = "Introspection response", body = IntrospectResponse),
        (status_code = 401, description = "Unauthorized", body = serde_json::Value),
        (status_code = 400, description = "Invalid request", body = serde_json::Value),
    )
)]
pub async fn introspect(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let params = match req.parse_form::<Vec<(String, String)>>().await {
        Ok(pairs) => {
            let map: std::collections::HashMap<String, String> = pairs.into_iter().collect();
            IntrospectRequest {
                token: map.get("token").cloned().unwrap_or_default(),
                token_type_hint: map.get("token_type_hint").cloned(),
                client_id: map.get("client_id").cloned(),
                client_secret: map.get("client_secret").cloned(),
            }
        }
        Err(_) => match crate::utils::extract::<IntrospectRequest>(req, None).await {
            Some(p) => p,
            None => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ApiProblem::validation_error("Malformed request")));
                return;
            }
        },
    };

    if params.token.is_empty() {
        introspect_ok(res, IntrospectResponse::default());
        return;
    }

    // STEP 1: resolve the tenant and authenticate the calling client (same
    // pattern as revoke()). RFC 7662 §2.1 REQUIRES client authentication —
    // the endpoint exists for protected resources only, so unauthenticated
    // callers get 401 without learning anything about any token.
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    let issuer = crate::utils::get_issuer(req, state).unwrap_or_default();
    let mut tenant = match state.storage.tenant_by_domain(domain) {
        Some(t) => t,
        None => {
            token_error(
                res,
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "Unknown tenant",
            );
            return;
        }
    };

    let auth_params = TokenRequest {
        grant_type: String::new(),
        code: None,
        redirect_uri: None,
        client_id: params.client_id.clone().unwrap_or_default(),
        client_secret: params.client_secret.clone(),
        code_verifier: None,
        scope: None,
        refresh_token: None,
        device_code: None,
    };
    let client = match authenticate_client(&mut tenant, &auth_params, req).await {
        Ok(c) => c,
        Err(e) => {
            token_error(res, StatusCode::UNAUTHORIZED, "invalid_client", &e);
            return;
        }
    };

    // RFC 7662 §2.1 requires client authentication — introspection
    // exists for protected resources. A public client ("none") has no
    // credential, so accepting it would let ANY anonymous caller probe
    // this client's tokens and learn active/sub/username/scope.
    if client.token_endpoint_auth_method == "none" {
        token_error(
            res,
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "public clients are not allowed on this endpoint",
        );
        return;
    }

    // STEP 2: identify the token — the oidc_tokens cache first (access
    // tokens issued by this process), then the shared validation primitive
    // (Step 1.1) as the stateless fallback that survives restarts and also
    // covers refresh tokens (JWTs carrying OidcRefreshTokenData). The
    // primitive is type-agnostic unless told otherwise (signature, expiry,
    // issuer, revocation) and the claims say which kind it is, so
    // token_type_hint needs no special handling — the RFC 7662 §2.1
    // fallback to the other token type is automatic. The cache fast path
    // keeps its own revocation lookup because its entries never reach a
    // decode. No policy engine here: introspection reports token validity
    // to relying parties, it does not authorize requests.
    let _hint = params.token_type_hint.as_deref();
    let invalid_jwt = crate::jwt::InvalidJwt::global();

    if let Some(entry) = OIDC_TOKEN_CACHE
        .get(&format!("token:access:{}", params.token))
        .await
    {
        let now = Timestamp::now().as_second();
        let exp = entry.get("exp").and_then(|v| v.as_i64()).unwrap_or(0);
        let entry_client_id = entry
            .get("client_id")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        if now >= exp
            || entry_client_id != client.id.as_str()
            || invalid_jwt.is_valid(&params.token).await
        {
            introspect_ok(res, IntrospectResponse::default());
            return;
        }
        let user_id = entry
            .get("user_id")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        introspect_ok(
            res,
            IntrospectResponse {
                active: true,
                client_id: Some(entry_client_id.to_string()),
                scope: entry
                    .get("scope")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string()),
                sub: Some(user_id.clone()),
                aud: Some(vec![entry_client_id.to_string()]),
                iss: Some(issuer.clone()),
                exp: entry.get("exp").and_then(|v| v.as_u64()),
                iat: entry.get("iat").and_then(|v| v.as_u64()),
                username: Some(user_id),
                token_type: Some("Bearer".into()),
            },
        );
        return;
    }

    let decision = match crate::utils::validate_token::<serde_json::Value>(
        &mut tenant,
        &issuer,
        domain,
        &params.token,
        crate::utils::ValidateOpts::default(),
    )
    .await
    {
        Ok(d) => d,
        // Unknown, expired, foreign-issuer and revoked tokens are all
        // reported the same way: active=false (RFC 7662 §2.2).
        Err(_) => {
            introspect_ok(res, IntrospectResponse::default());
            return;
        }
    };
    let data = &decision.claims.data;

    // STEP 3: a token issued to another client is reported as inactive —
    // the caller must be the token's audience (RFC 7662 §2.1), and the
    // response must not leak that someone else's token exists. (The issuer
    // was already matched by the validation primitive.)
    let token_client_id = data.get("client_id").and_then(|v| v.as_str()).unwrap_or("");
    if token_client_id != client.id.as_str() {
        introspect_ok(res, IntrospectResponse::default());
        return;
    }

    // STEP 4: refresh-token family liveness. Token-level revocation was
    // already enforced by the validation primitive; for a refresh token the
    // family marker additionally covers every rotated sibling and successor,
    // and the family's absolute lifetime bounds the chain exactly as
    // handle_refresh does.
    if data.get("typ").and_then(|v| v.as_str()) == Some("refresh") {
        let family_dead = match (
            data.get("family").and_then(|v| v.as_str()),
            data.get("family_created_at").and_then(|v| v.as_i64()),
        ) {
            (Some(family), Some(created_at)) => {
                invalid_jwt.is_valid(&refresh_family_marker(family)).await
                    || Timestamp::now().as_second() >= refresh_family_end(created_at)
            }
            // No family claims — this refresh token was not issued by this
            // flow; treat it as unknown.
            _ => true,
        };
        if family_dead {
            introspect_ok(res, IntrospectResponse::default());
            return;
        }
    }

    // STEP 5: RFC 7662 §2.2 — active=true with the token's metadata.
    introspect_ok(
        res,
        IntrospectResponse {
            active: true,
            client_id: Some(token_client_id.to_string()),
            scope: data
                .get("scope")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            sub: Some(decision.claims.sub.clone()),
            aud: Some(vec![decision.claims.aud.clone()]),
            iss: Some(decision.claims.iss.clone()),
            exp: Some(decision.claims.exp as u64),
            iat: Some(decision.claims.iat as u64),
            username: Some(decision.claims.sub.clone()),
            token_type: Some("Bearer".into()),
        },
    );
}

/// RFC 7662 §2.2: the introspection response is ALWAYS HTTP 200 with a JSON
/// body — unknown, expired and revoked tokens are reported with active=false
/// so the response never leaks which tokens exist. no-store keeps token
/// metadata out of intermediate caches.
fn introspect_ok(res: &mut Response, body: IntrospectResponse) {
    res.status_code(StatusCode::OK);
    res.headers_mut().insert(
        salvo::http::header::CACHE_CONTROL,
        salvo::http::HeaderValue::from_static("no-store"),
    );
    res.headers_mut().insert(
        salvo::http::header::PRAGMA,
        salvo::http::HeaderValue::from_static("no-cache"),
    );
    res.render(Json(body));
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DeviceAuthRequest {
    #[serde(default)]
    pub client_id: Option<String>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub client_secret: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DeviceAuthResponse {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub verification_uri_complete: Option<String>,
    pub expires_in: u64,
    pub interval: u64,
}

#[endpoint(
    summary = "Device authorization endpoint (RFC 8628) — for TV / CLI flows",
    request_body = DeviceAuthRequest,
    responses(
        (status_code = 200, description = "Device auth response", body = DeviceAuthResponse),
        (status_code = 401, description = "Unauthorized / invalid client", body = OAuth2TokenError),
        (status_code = 400, description = "Invalid request", body = OAuth2TokenError),
    )
)]
pub async fn device_authorization(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let params = match req.parse_form::<Vec<(String, String)>>().await {
        Ok(pairs) => {
            let map: std::collections::HashMap<String, String> = pairs.into_iter().collect();
            DeviceAuthRequest {
                client_id: map.get("client_id").cloned(),
                scope: map.get("scope").cloned(),
                client_secret: map.get("client_secret").cloned(),
            }
        }
        Err(_) => match crate::utils::extract::<DeviceAuthRequest>(req, None).await {
            Some(p) => p,
            None => {
                token_error(
                    res,
                    StatusCode::BAD_REQUEST,
                    "invalid_request",
                    "Malformed request",
                );
                return;
            }
        },
    };

    let client_id = match params.client_id {
        Some(id) if !id.is_empty() => id,
        _ => {
            token_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Missing required parameter: client_id",
            );
            return;
        }
    };

    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    let issuer = crate::utils::get_issuer(req, state).unwrap_or_default();
    let mut tenant = match state.storage.tenant_by_domain(domain) {
        Some(t) => t,
        None => {
            token_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "Unknown domain/tenant",
            );
            return;
        }
    };

    let client = match authenticate_client_by_id_secret(
        &mut tenant,
        &client_id,
        params.client_secret.as_deref(),
        req,
    )
    .await
    {
        Ok(c) => c,
        Err(e) => {
            token_error(res, StatusCode::UNAUTHORIZED, "invalid_client", &e);
            return;
        }
    };

    // / RFC 8628 §3.2.1: the device authorization grant must be
    // registered for this client.
    if !client
        .get_grant_types()
        .iter()
        .any(|g| g == GRANT_TYPE_DEVICE_CODE)
    {
        token_error(
            res,
            StatusCode::BAD_REQUEST,
            "unauthorized_client",
            "client is not registered for the device authorization grant",
        );
        return;
    }

    // same bounds as /authorize. An absent scope falls back to the
    // client's registered scope (RFC 8628 leaves an omitted scope to the
    // server) instead of defaulting to whatever the RP sent unchecked.
    let scope = params
        .scope
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| client.scope.clone());
    if let Err(e) = validate_requested_scope(&scope, &client.get_scope()) {
        token_error(res, StatusCode::BAD_REQUEST, "invalid_scope", &e);
        return;
    }
    let device_code = generate_device_code();
    let user_code = generate_user_code();
    let now = Timestamp::now();
    let expires_at = now
        .checked_add(1800_i32.seconds())
        .unwrap_or(now)
        .as_second();

    let device_entry = serde_json::json!({
        "client_id": client.id,
        "scope": scope,
        "user_code": user_code,
        "status": "pending",
        "user_id": serde_json::Value::Null,
        "expires_at": expires_at,
        "last_polled_at": 0,
    });

    if let Err(e) = OIDC_DEVICE_CACHE
        .codes
        .insert(format!("device:{}", device_code), device_entry.clone())
        .await
    {
        token_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            &format!("Failed to create device code: {}", e),
        );
        return;
    }
    if let Err(e) = OIDC_DEVICE_CACHE
        .by_user_code
        .insert(format!("user_code:{}", user_code), device_code.clone())
        .await
    {
        OIDC_DEVICE_CACHE
            .codes
            .remove(&format!("device:{}", device_code))
            .await;
        token_error(
            res,
            StatusCode::INTERNAL_SERVER_ERROR,
            "server_error",
            &format!("Failed to create device code: {}", e),
        );
        return;
    }

    let verification_uri = format!("{}/device-login", issuer);
    let verification_uri_complete = format!("{}/device-login?user_code={}", issuer, user_code);

    let resp = DeviceAuthResponse {
        device_code,
        user_code,
        verification_uri,
        verification_uri_complete: Some(verification_uri_complete),
        expires_in: 1800,
        interval: 5,
    };

    res.status_code(StatusCode::OK);
    res.headers_mut().insert(
        salvo::http::header::CACHE_CONTROL,
        salvo::http::HeaderValue::from_static("no-store"),
    );
    res.headers_mut().insert(
        salvo::http::header::PRAGMA,
        salvo::http::HeaderValue::from_static("no-cache"),
    );
    res.render(Json(resp));
}

#[endpoint(
    summary = "Device authorization request details for a user_code (client + scopes)",
    responses(
        (status_code = 200, description = "Client id + requested scopes", body = ApiResponse<ConsentRequestInfo>),
        (status_code = 400, description = "Missing, unknown or expired user_code", body = ApiProblem),
    )
)]
pub async fn device_login_info(req: &mut Request, _depot: &mut Depot, res: &mut Response) {
    let user_code = match req.query::<String>("user_code").filter(|s| !s.is_empty()) {
        Some(c) => c,
        None => {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(ApiProblem::bad_request("Missing user_code")));
            return;
        }
    };

    let device_code = match OIDC_DEVICE_CACHE
        .by_user_code
        .get(&format!("user_code:{user_code}"))
        .await
    {
        Some(code) => code,
        None => {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(ApiProblem::validation_error(
                "User code not found or expired",
            )));
            return;
        }
    };

    let entry = match OIDC_DEVICE_CACHE
        .codes
        .get(&format!("device:{device_code}"))
        .await
    {
        Some(e) => e,
        None => {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(ApiProblem::validation_error(
                "User code not found or expired",
            )));
            return;
        }
    };

    let scopes: Vec<ScopeDetail> = entry["scope"]
        .as_str()
        .unwrap_or_default()
        .split_whitespace()
        .map(|s| ScopeDetail {
            scope: s.to_string(),
            label: scope_label(s).to_string(),
        })
        .collect();
    res.status_code(StatusCode::OK);
    res.render(Json(ApiResponse::ok(ConsentRequestInfo {
        client_id: entry["client_id"].as_str().unwrap_or_default().to_string(),
        scopes,
    })));
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct DeviceLoginApproveRequest {
    pub user_code: String,
    pub action: String,
}

#[endpoint(
    summary = "Process device login approval/denial (SPA, Bearer JWT)",
    request_body = DeviceLoginApproveRequest,
    responses(
        (status_code = 200, description = "Decision recorded", body = DeviceApproveResult),
        (status_code = 400, description = "Invalid request", body = ApiProblem),
        (status_code = 401, description = "No valid session JWT", body = OidcRedirectResponse),
    )
)]
pub async fn device_login_approve(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let params = match crate::utils::extract::<DeviceLoginApproveRequest>(req, None).await {
        Some(p) => p,
        None => {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(ApiProblem::validation_error("Malformed request")));
            return;
        }
    };

    if params.user_code.is_empty() {
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Json(ApiProblem::validation_error(
            "Missing required parameter: user_code",
        )));
        return;
    }

    if params.action != "approve" && params.action != "deny" {
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Json(ApiProblem::validation_error(
            "Invalid action: must be 'approve' or 'deny'",
        )));
        return;
    }

    // The approving identity comes from the authenticated session — never
    // from user-supplied request data. Policy-free session check: approval
    // is a consent act on the caller's own account and no policy rows exist
    // for this path, so the default-deny engine would reject every session.
    let verify = match crate::utils::validate_session(req, depot).await {
        Some(v) => v,
        None => {
            let back = format!(
                "/device-login?user_code={}",
                urlencoding::encode(&params.user_code)
            );
            render_redirect_json(
                res,
                StatusCode::UNAUTHORIZED,
                format!("/login?redirect_uri={}", urlencoding::encode(&back)),
            );
            return;
        }
    };
    let user_id = verify.jwt_data.user.clone();

    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    let mut tenant = match state.storage.tenant_by_domain(domain) {
        Some(t) => t,
        None => {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(ApiProblem::not_found("Unknown domain/tenant")));
            return;
        }
    };

    let device_code = match OIDC_DEVICE_CACHE
        .by_user_code
        .get(&format!("user_code:{}", params.user_code))
        .await
    {
        Some(code) => code,
        None => {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(ApiProblem::validation_error(
                "User code not found or expired",
            )));
            return;
        }
    };

    let key = format!("device:{}", device_code);

    if params.action == "approve" {
        // claim the pending entry atomically BEFORE touching the DB.
        // The old get → mutate → remove+insert let two racing approvals
        // both pass the status check and double-record consent, and let a
        // concurrent poller re-insert a stale "pending" copy over the
        // decision. The claim flips pending → approving; exactly one
        // caller can win it.
        enum Claim {
            Already(String),
            Ready {
                client_id: String,
                scope: String,
                expires_at: i64,
            },
        }
        let claim = OIDC_DEVICE_CACHE
            .codes
            .get_mut(&key, |entry| {
                let status = entry["status"].as_str().unwrap_or("processed").to_string();
                if status != "pending" {
                    return Claim::Already(status);
                }
                entry["status"] = serde_json::json!("approving");
                Claim::Ready {
                    client_id: entry["client_id"].as_str().unwrap_or_default().to_string(),
                    scope: entry["scope"].as_str().unwrap_or_default().to_string(),
                    expires_at: entry["expires_at"].as_i64().unwrap_or(0),
                }
            })
            .await;
        let (client_id, scope, expires_at) = match claim {
            Some(Claim::Ready {
                client_id,
                scope,
                expires_at,
            }) => (client_id, scope, expires_at),
            Some(Claim::Already(status)) => {
                res.status_code(StatusCode::OK);
                res.render(Json(DeviceApproveResult {
                    status,
                    user: None,
                    already_processed: Some(true),
                }));
                return;
            }
            None => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ApiProblem::validation_error(
                    "Device code expired or not found",
                )));
                return;
            }
        };

        // Roll the claim back to pending so the user can retry; used when
        // the DB work below fails.
        macro_rules! rollback_claim {
            () => {
                OIDC_DEVICE_CACHE
                    .codes
                    .get_mut(&key, |entry| {
                        entry["status"] = serde_json::json!("pending");
                    })
                    .await;
            };
        }

        match tenant.oauth2client_get(&client_id).await {
            Ok(c) if c.domain_id == tenant.name => {}
            _ => {
                rollback_claim!();
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ApiProblem::not_found(
                    "OAuth2 client is not registered with this provider",
                )));
                return;
            }
        };

        // Record consent like the /authorize flow: REPLACE semantics — revoke
        // prior grants for (user, client), then write the new one. The raw
        // device code is never persisted; only its hash (AuthGrant.code_hash).
        if let Err(e) = tenant.auth_grant_revoke_for(&user_id, &client_id).await {
            rollback_claim!();
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            res.render(Json(ApiProblem {
                status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                r#type: "server_error".into(),
                detail: Some(format!("Failed to update consent grants: {e}")),
            }));
            return;
        }
        let grant_expires = match jiff::Timestamp::from_second(expires_at) {
            Ok(ts) => ts,
            Err(_) => {
                rollback_claim!();
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ApiProblem::validation_error(
                    "Device code expired or not found",
                )));
                return;
            }
        };
        let jti = uuid::Uuid::new_v4().to_string();
        let code_hash = hex::encode(sha2::Sha256::digest(device_code.as_bytes()));
        if let Err(e) = tenant
            .auth_grant_create(
                &jti,
                &client_id,
                &user_id,
                &scope,
                &code_hash,
                grant_expires,
            )
            .await
        {
            rollback_claim!();
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            res.render(Json(ApiProblem {
                status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
                r#type: "server_error".into(),
                detail: Some(format!("Failed to record authorization grant: {e}")),
            }));
            return;
        }

        // Commit the decision atomically.
        OIDC_DEVICE_CACHE
            .codes
            .get_mut(&key, |entry| {
                entry["status"] = serde_json::json!("approved");
                entry["user_id"] = serde_json::json!(user_id);
            })
            .await;
    } else {
        // Deny: a single atomic pending → denied transition.
        let status = OIDC_DEVICE_CACHE
            .codes
            .get_mut(&key, |entry| {
                let status = entry["status"].as_str().unwrap_or("processed").to_string();
                if status != "pending" {
                    return status;
                }
                entry["status"] = serde_json::json!("denied");
                entry["user_id"] = serde_json::Value::Null;
                "denied".to_string()
            })
            .await;
        match status {
            Some(s) if s == "denied" => {}
            Some(status) => {
                res.status_code(StatusCode::OK);
                res.render(Json(DeviceApproveResult {
                    status,
                    user: None,
                    already_processed: Some(true),
                }));
                return;
            }
            None => {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ApiProblem::validation_error(
                    "Device code expired or not found",
                )));
                return;
            }
        }
    }

    // The decision was committed atomically above — no separate
    // remove+insert write-back.
    let status = if params.action == "approve" {
        "approved"
    } else {
        "denied"
    };
    res.status_code(StatusCode::OK);
    res.render(Json(DeviceApproveResult {
        status: status.to_string(),
        user: Some(user_id),
        already_processed: None,
    }));
}

fn generate_user_code() -> String {
    // / RFC 8628 §6.1: no vowels, no ambiguous characters (0/O, 1/I).
    const CODES: [char; 20] = [
        'B', 'C', 'D', 'F', 'G', 'H', 'J', 'K', 'L', 'M', 'N', 'P', 'Q', 'R', 'S', 'T', 'V', 'W',
        'X', 'Z',
    ];
    // Rejection sampling: 256 is not divisible by 20, so `% 20` would bias
    // the first 16 characters. Accept only bytes below the largest
    // multiple of 20 that fits in a u8.
    const LIMIT: u8 = 240;
    let mut s = String::with_capacity(8);
    while s.len() < 8 {
        let mut buf = [0u8; 16];
        rand::fill(&mut buf);
        for b in buf {
            if b < LIMIT {
                s.push(CODES[b as usize % CODES.len()]);
                if s.len() == 8 {
                    break;
                }
            }
        }
    }
    format!("{}-{}", &s[..4], &s[4..])
}

#[cfg(test)]
mod tests {
    use super::*;
    use salvo::test::ResponseExt;

    #[test]
    fn scopes_cover_subset_semantics() {
        assert!(scopes_cover("openid profile email", "openid email"));
        assert!(scopes_cover("openid profile", "openid profile"));
        assert!(!scopes_cover("openid", "openid email"));
        assert!(!scopes_cover("", "openid"));
        assert!(scopes_cover("openid", ""));
        assert!(scopes_cover("openid", "   "));
    }

    /// requested scopes must be server-known AND registered for the
    /// client.
    #[test]
    fn requested_scope_must_be_known_and_registered() {
        let registered: Vec<String> = vec!["openid".into(), "offline_access".into()];
        assert!(validate_requested_scope("openid", &registered).is_ok());
        assert!(validate_requested_scope("openid offline_access", &registered).is_ok());
        assert!(validate_requested_scope("", &registered).is_ok());
        assert!(
            validate_requested_scope("openid email", &registered).is_err(),
            "known but unregistered scope must be refused"
        );
        assert!(
            validate_requested_scope("openid admin", &registered).is_err(),
            "unknown scope must be refused"
        );
        assert!(
            validate_requested_scope("openid", &[]).is_err(),
            "nothing registered means nothing may be requested"
        );
    }

    #[test]
    fn oauth2_error_url_encodes_and_preserves_state() {
        let url = oauth2_error_url("/callback", "access_denied", "User said no", Some("s p&x"));
        assert!(url.starts_with("/callback?error=access_denied"));
        assert!(url.contains("error_description=User%20said%20no"));
        assert!(url.contains("state=s%20p%26x"));
    }

    #[test]
    fn oauth2_error_url_omits_empty_description() {
        let url = oauth2_error_url("/e", "invalid_request", "", None);
        assert_eq!(url, "/e?error=invalid_request");
    }

    #[test]
    fn callback_url_carries_code_state_scope() {
        let url = callback_url_with_code(
            "https://rp/cb",
            "code123",
            Some("st&ate"),
            Some("openid profile"),
        );
        assert!(url.starts_with("https://rp/cb?code=code123"));
        assert!(url.contains("state=st%26ate"));
        assert!(url.contains("scope=openid%20profile"));
    }

    #[test]
    fn callback_url_without_optional_params() {
        let url = callback_url_with_code("https://rp/cb", "code123", None, None);
        assert_eq!(url, "https://rp/cb?code=code123");
    }

    #[test]
    fn random_urlsafe_string_shape_and_uniqueness() {
        let a = random_urlsafe_string();
        let b = random_urlsafe_string();
        assert_ne!(a, b);
        assert_eq!(a.len(), 43);
        assert!(
            a.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        );
    }

    #[test]
    fn constant_time_eq_matches_and_rejects() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(constant_time_eq(b"", b""));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(!constant_time_eq(b"ab", b"abc"));
    }

    #[test]
    fn scope_labels_known_and_unknown() {
        assert_eq!(scope_label("openid"), "Sign in with your identity");
        assert_eq!(scope_label("profile"), "Read your profile information");
        assert_eq!(scope_label("email"), "Read your email address");
        assert_eq!(
            scope_label("offline_access"),
            "Retain access while you are not present"
        );
        assert_eq!(scope_label("custom_scope"), "Additional access");
    }

    #[test]
    fn basic_credential_decode_percent_decodes_rfc6749() {
        assert_eq!(basic_credential_decode("abc%20def"), "abc def");
        assert_eq!(basic_credential_decode("a%2Bb"), "a+b");
        assert_eq!(basic_credential_decode("%3D%3D"), "==");
    }

    #[test]
    fn basic_credential_decode_preserves_literal_reserved_chars() {
        // Literal '+' and trailing '=' must survive (secrets are not
        // form-urlencoded key=value pairs).
        assert_eq!(basic_credential_decode("a+b"), "a+b");
        assert_eq!(basic_credential_decode("abc="), "abc=");
        assert_eq!(basic_credential_decode("plain"), "plain");
        assert_eq!(basic_credential_decode(""), "");
    }

    #[test]
    fn basic_credential_decode_invalid_sequences_fall_back_to_raw() {
        // A lone '%' or an invalid UTF-8 result must not destroy the secret.
        assert_eq!(basic_credential_decode("100%"), "100%");
        assert_eq!(basic_credential_decode("x%ZZy"), "x%ZZy");
        assert_eq!(basic_credential_decode("%ff"), "%ff");
    }

    // ── revoke endpoint (RFC 7009) integration tests ──────────────────────────

    /// The revocation store is a process-wide singleton, so all tests share one
    /// backing directory that must outlive every individual test's TempDir.
    /// Tokens/family ids are unique per test, so the shared store doesn't
    /// cross-contaminate assertions.
    static TEST_STORE_DIR: LazyLock<tempfile::TempDir> =
        LazyLock::new(|| tempfile::tempdir().expect("tempdir"));

    /// toasty spawns the store's connection task on whichever runtime is
    /// current during `init_global`. A `#[tokio::test]` runtime dies with its
    /// test and takes the connection down with it — every later store access
    /// from another test then panics with RecvError. So the store is
    /// initialized once on a dedicated multi-thread runtime whose workers
    /// outlive every individual test.
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

    /// In-process tenant with a signing key and two registered clients.
    async fn revoke_test_env() -> (crate::server::ServerState, tempfile::TempDir) {
        // First call wins; later Storage::init re-inits are no-ops, so the
        // store stays on the stable process-lifetime directory.
        init_revocation_store().await;
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = crate::db::Storage::init(tmp.path())
            .await
            .expect("storage init");
        storage.new_tenant("test-tenant").await.expect("tenant");
        storage
            .add_domain("localhost", "test-tenant")
            .await
            .expect("domain");
        {
            let mut tenant = storage.tenant_by_id("test-tenant").expect("tenant");
            tenant
                .key_create("localhost", "key1")
                .await
                .expect("signing key");
            for (id, secret) in [("client-a", "secret-a"), ("client-b", "secret-b")] {
                let redirect = format!("http://localhost/{id}/callback");
                tenant
                    .oauth2client_create(
                        id,
                        secret,
                        &[redirect.as_str()],
                        &format!("authorization_code refresh_token {GRANT_TYPE_DEVICE_CODE}"),
                        "code",
                        "client_secret_post",
                        "openid offline_access",
                    )
                    .await
                    .expect("oauth2 client");
            }
        }
        let state = crate::server::ServerState::create(storage, false)
            .await
            .expect("server state");
        (state, tmp)
    }

    fn revoke_service(state: crate::server::ServerState) -> Service {
        Service::new(
            Router::with_path("revoke")
                .post(crate::oidc::revoke)
                .hoop(salvo::affix_state::inject(state)),
        )
    }

    /// The issuer URL the endpoints derive for these test requests
    /// (`http://localhost/...`, `Host: localhost`).
    const TEST_ISSUER: &str = "http://localhost";

    /// Mint an access token exactly the way the /token endpoint does.
    fn mint_access_token(key: &crate::key::Key, client_id: &str) -> String {
        let data = OidcAccessTokenData {
            scope: "openid".into(),
            jti: uuid::Uuid::new_v4().to_string(),
            client_id: client_id.to_string(),
        };
        jwt_authenticate(
            TEST_ISSUER,
            "user1",
            &data,
            key,
            60,
            JwtOidcParams {
                client_id: client_id.to_string(),
                nonce: None,
                amr: None,
                acr: None,
                access_token: None,
                auth_time: None,
            },
        )
        .expect("sign access token")
    }

    async fn post_revoke(service: &Service, form: &str) -> (StatusCode, String) {
        let mut res = salvo::test::TestClient::post("http://localhost/revoke")
            .add_header("Host", "localhost", true)
            .raw_form(form.to_string())
            .send(service)
            .await;
        let status = res.status_code.expect("status code");
        let body = res.take_string().await.unwrap_or_default();
        (status, body)
    }

    #[tokio::test]
    async fn revoke_access_token_invalidates_it() {
        let (state, _tmp) = revoke_test_env().await;
        let service = revoke_service(state.clone());
        let access_token = {
            let tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            let key = tenant.current_key("localhost").expect("key");
            mint_access_token(&key, "client-a")
        };

        let (status, body) = post_revoke(
            &service,
            &format!("token={access_token}&client_id=client-a&client_secret=secret-a"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(
            body.is_empty(),
            "RFC 7009 §2.2 expects an empty body, got {body:?}"
        );
        assert!(
            crate::jwt::InvalidJwt::global()
                .is_valid(&access_token)
                .await,
            "revoked access token must be recorded in the InvalidJwt store"
        );
    }

    #[tokio::test]
    async fn revoke_refresh_token_poisons_its_family() {
        let (state, _tmp) = revoke_test_env().await;
        let service = revoke_service(state.clone());
        let family = uuid::Uuid::new_v4().to_string();
        let now = Timestamp::now().as_second();
        let rt = {
            let tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            let key = tenant.current_key("localhost").expect("key");
            issue_refresh_token_jwt(
                TEST_ISSUER,
                &key,
                "user1",
                "client-a",
                "openid offline_access",
                &std::collections::HashSet::new(),
                now as usize,
                &family,
                now,
                600,
            )
            .expect("sign refresh token")
        };

        let (status, body) = post_revoke(
            &service,
            &format!(
                "token={rt}&token_type_hint=refresh_token&client_id=client-a&client_secret=secret-a"
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.is_empty());
        assert!(
            crate::jwt::InvalidJwt::global().is_valid(&rt).await,
            "revoked refresh token must be recorded in the InvalidJwt store"
        );
        assert!(
            crate::jwt::InvalidJwt::global()
                .is_valid(&refresh_family_marker(&family))
                .await,
            "the refresh token family marker must be poisoned"
        );
    }

    #[tokio::test]
    async fn revoke_foreign_client_token_is_a_silent_noop() {
        let (state, _tmp) = revoke_test_env().await;
        let service = revoke_service(state.clone());
        let access_token = {
            let tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            let key = tenant.current_key("localhost").expect("key");
            mint_access_token(&key, "client-a")
        };

        // client-b attempts to revoke a token issued to client-a
        let (status, body) = post_revoke(
            &service,
            &format!("token={access_token}&client_id=client-b&client_secret=secret-b"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "RFC 7009 §2.1: never leak");
        assert!(body.is_empty());
        assert!(
            !crate::jwt::InvalidJwt::global()
                .is_valid(&access_token)
                .await,
            "a client must not revoke another client's token"
        );
    }

    #[tokio::test]
    async fn revoke_unknown_token_returns_200_empty() {
        let (state, _tmp) = revoke_test_env().await;
        let service = revoke_service(state.clone());

        let (status, body) = post_revoke(
            &service,
            "token=not-a-jwt&client_id=client-a&client_secret=secret-a",
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "RFC 7009 §2.2: invalid tokens get 200"
        );
        assert!(body.is_empty());
    }

    // ── introspect endpoint (RFC 7662) integration tests ────────────────────

    fn introspect_service(state: crate::server::ServerState) -> Service {
        Service::new(
            Router::with_path("introspect")
                .post(crate::oidc::introspect)
                .hoop(salvo::affix_state::inject(state)),
        )
    }

    async fn post_introspect(service: &Service, form: &str) -> (StatusCode, serde_json::Value) {
        let mut res = salvo::test::TestClient::post("http://localhost/introspect")
            .add_header("Host", "localhost", true)
            .raw_form(form.to_string())
            .send(service)
            .await;
        let status = res.status_code.expect("status code");
        let body = res.take_string().await.unwrap_or_default();
        let json = serde_json::from_str(&body).expect("introspection response must be JSON");
        (status, json)
    }

    #[tokio::test]
    async fn introspect_active_access_token() {
        let (state, _tmp) = revoke_test_env().await;
        let service = introspect_service(state.clone());
        let access_token = {
            let tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            let key = tenant.current_key("localhost").expect("key");
            mint_access_token(&key, "client-a")
        };

        let (status, body) = post_introspect(
            &service,
            &format!("token={access_token}&client_id=client-a&client_secret=secret-a"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["active"], true, "a live access token must be active");
        assert_eq!(body["client_id"], "client-a");
        assert_eq!(body["sub"], "user1");
        assert_eq!(body["username"], "user1");
        assert_eq!(body["scope"], "openid");
        assert_eq!(body["iss"], TEST_ISSUER);
        assert_eq!(body["aud"], serde_json::json!(["client-a"]));
        assert_eq!(body["token_type"], "Bearer");
        assert!(body["exp"].is_u64() && body["iat"].is_u64());
    }

    #[tokio::test]
    async fn introspect_active_refresh_token() {
        let (state, _tmp) = revoke_test_env().await;
        let service = introspect_service(state.clone());
        let now = Timestamp::now().as_second();
        let rt = {
            let tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            let key = tenant.current_key("localhost").expect("key");
            issue_refresh_token_jwt(
                TEST_ISSUER,
                &key,
                "user1",
                "client-a",
                "openid offline_access",
                &std::collections::HashSet::new(),
                now as usize,
                &uuid::Uuid::new_v4().to_string(),
                now,
                600,
            )
            .expect("sign refresh token")
        };

        let (status, body) = post_introspect(
            &service,
            &format!(
                "token={rt}&token_type_hint=refresh_token&client_id=client-a&client_secret=secret-a"
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["active"], true, "a live refresh token must be active");
        assert_eq!(body["client_id"], "client-a");
        assert_eq!(body["sub"], "user1");
        assert_eq!(body["scope"], "openid offline_access");
        assert_eq!(body["token_type"], "Bearer");
    }

    #[tokio::test]
    async fn introspect_requires_client_authentication() {
        let (state, _tmp) = revoke_test_env().await;
        let service = introspect_service(state.clone());
        let access_token = {
            let tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            let key = tenant.current_key("localhost").expect("key");
            mint_access_token(&key, "client-a")
        };

        // RFC 7662 §2.1: no credentials → 401, no token information
        let (status, body) = post_introspect(&service, &format!("token={access_token}")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "invalid_client");

        let (status, body) = post_introspect(
            &service,
            &format!("token={access_token}&client_id=client-a&client_secret=wrong"),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "invalid_client");
    }

    #[tokio::test]
    async fn introspect_foreign_client_token_is_inactive() {
        let (state, _tmp) = revoke_test_env().await;
        let service = introspect_service(state.clone());
        let access_token = {
            let tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            let key = tenant.current_key("localhost").expect("key");
            mint_access_token(&key, "client-a")
        };

        // client-b must not learn anything about client-a's token
        let (status, body) = post_introspect(
            &service,
            &format!("token={access_token}&client_id=client-b&client_secret=secret-b"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "RFC 7662 §2.1: never leak");
        assert_eq!(body["active"], false);
        assert!(
            body.get("client_id").is_none(),
            "an inactive response must not carry token metadata"
        );
    }

    #[tokio::test]
    async fn introspect_revoked_token_is_inactive() {
        let (state, _tmp) = revoke_test_env().await;
        let service = introspect_service(state.clone());
        let access_token = {
            let tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            let key = tenant.current_key("localhost").expect("key");
            mint_access_token(&key, "client-a")
        };
        let expires =
            jiff::Timestamp::from_second(Timestamp::now().as_second() + 3600).expect("exp");
        crate::jwt::InvalidJwt::global()
            .invalid_raw(&access_token, expires)
            .await
            .expect("record revocation");

        let (status, body) = post_introspect(
            &service,
            &format!("token={access_token}&client_id=client-a&client_secret=secret-a"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["active"], false, "a revoked token must be inactive");
    }

    #[tokio::test]
    async fn introspect_expired_refresh_family_is_inactive() {
        let (state, _tmp) = revoke_test_env().await;
        let service = introspect_service(state.clone());
        let now = Timestamp::now().as_second();
        // The JWT itself is still valid (10 min expiry) but the family
        // started after the absolute family window has already elapsed.
        let rt = {
            let tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            let key = tenant.current_key("localhost").expect("key");
            issue_refresh_token_jwt(
                TEST_ISSUER,
                &key,
                "user1",
                "client-a",
                "openid offline_access",
                &std::collections::HashSet::new(),
                now as usize,
                &uuid::Uuid::new_v4().to_string(),
                now - OIDC_REFRESH_FAMILY_LIFETIME - 1,
                600,
            )
            .expect("sign refresh token")
        };

        let (status, body) = post_introspect(
            &service,
            &format!("token={rt}&client_id=client-a&client_secret=secret-a"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(
            body["active"], false,
            "a token whose refresh family has expired must be inactive"
        );
    }

    #[tokio::test]
    async fn introspect_unknown_token_is_inactive() {
        let (state, _tmp) = revoke_test_env().await;
        let service = introspect_service(state.clone());

        let (status, body) = post_introspect(
            &service,
            "token=not-a-jwt&client_id=client-a&client_secret=secret-a",
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "RFC 7662 §2.2: invalid tokens get 200"
        );
        assert_eq!(body, serde_json::json!({"active": false}));
    }

    #[tokio::test]
    async fn introspect_cached_opaque_access_token_is_active() {
        let (state, _tmp) = revoke_test_env().await;
        let service = introspect_service(state.clone());
        // An opaque token known only to the oidc_tokens cache (never a JWT),
        // exactly as the /token endpoint records its access tokens.
        let opaque = format!("opaque-{}", uuid::Uuid::new_v4());
        let now = Timestamp::now().as_second();
        OIDC_TOKEN_CACHE
            .insert(
                format!("token:access:{opaque}"),
                serde_json::json!({
                    "type": "access",
                    "client_id": "client-a",
                    "user_id": "user1",
                    "scope": "openid",
                    "jti": uuid::Uuid::new_v4().to_string(),
                    "iat": now,
                    "exp": now + 3600,
                }),
            )
            .await
            .expect("cache insert");

        let (status, body) = post_introspect(
            &service,
            &format!("token={opaque}&client_id=client-a&client_secret=secret-a"),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["active"], true, "a cached access token must be active");
        assert_eq!(body["client_id"], "client-a");
        assert_eq!(body["sub"], "user1");
        assert_eq!(body["username"], "user1");
        assert_eq!(body["scope"], "openid");
        assert_eq!(body["iss"], TEST_ISSUER);
        assert_eq!(body["token_type"], "Bearer");
    }

    // ── refresh grant re-checks user.active ────────────────────────────
    //
    // OIDC refresh is a central round-trip and the only point where a session
    // is EXTENDED, so the live `active` state is enforced here (never at
    // stateless token verification). A deactivated user's family stops
    // rotating; the reject happens before the commit point so the presented
    // token is not consumed.

    fn token_service(state: crate::server::ServerState) -> Service {
        Service::new(
            Router::with_path("token")
                .post(crate::oidc::token)
                .hoop(salvo::affix_state::inject(state)),
        )
    }

    async fn post_token(service: &Service, form: &str) -> (StatusCode, serde_json::Value) {
        let mut res = salvo::test::TestClient::post("http://localhost/token")
            .add_header("Host", "localhost", true)
            .raw_form(form.to_string())
            .send(service)
            .await;
        let status = res.status_code.expect("status code");
        let body = res.take_string().await.unwrap_or_default();
        (
            status,
            serde_json::from_str(&body).unwrap_or(serde_json::Value::Null),
        )
    }

    /// Mint a refresh token for `user1` and return (token, family).
    async fn mint_user1_refresh(state: &crate::server::ServerState) -> (String, String) {
        let family = uuid::Uuid::new_v4().to_string();
        let now = Timestamp::now().as_second();
        let user_id = {
            let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            tenant.user("user1").await.expect("user1").id.to_string()
        };
        let tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
        let key = tenant.current_key("localhost").expect("key");
        let rt = issue_refresh_token_jwt(
            TEST_ISSUER,
            &key,
            &user_id,
            "client-a",
            "openid offline_access",
            &std::collections::HashSet::new(),
            now as usize,
            &family,
            now,
            600,
        )
        .expect("sign refresh token");
        (rt, family)
    }

    #[tokio::test]
    async fn refresh_grant_rejects_deactivated_user() {
        let (state, _tmp) = revoke_test_env().await;
        // revoke_test_env has no users; create user1 and then deactivate.
        {
            let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            tenant.user_create("user1").await.expect("user");
            tenant
                .user_deactivate(&crate::role::Caller::Bootstrap, "user1")
                .await
                .expect("deactivate");
        }
        let service = token_service(state.clone());
        let (rt, _family) = mint_user1_refresh(&state).await;

        let (status, body) = post_token(
            &service,
            &format!(
                "grant_type=refresh_token&refresh_token={rt}&client_id=client-a&client_secret=secret-a"
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a deactivated user must not rotate their refresh family"
        );
        assert_eq!(body["error"], "invalid_grant");
    }

    /// deletion cascades every credential, so no new login is
    /// possible — the refresh family must fail closed too instead of
    /// extending the deleted user's session.
    #[tokio::test]
    async fn refresh_grant_rejects_deleted_user() {
        let (state, _tmp) = revoke_test_env().await;
        {
            let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            tenant.user_create("user1").await.expect("user");
        }
        let service = token_service(state.clone());
        let (rt, _family) = mint_user1_refresh(&state).await;

        // Delete the user AFTER the refresh token was minted.
        {
            let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            tenant
                .user_delete(&crate::role::Caller::Bootstrap, "user1")
                .await
                .expect("delete");
        }

        let (status, body) = post_token(
            &service,
            &format!(
                "grant_type=refresh_token&refresh_token={rt}&client_id=client-a&client_secret=secret-a"
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a deleted user must not rotate their refresh family"
        );
        assert_eq!(body["error"], "invalid_grant");
    }

    /// The active-check reject must happen BEFORE the commit point: the
    /// presented token is not consumed, so reactivation lets the very same
    /// token rotate.
    #[tokio::test]
    async fn refresh_reject_for_deactivated_user_does_not_consume_token() {
        let (state, _tmp) = revoke_test_env().await;
        {
            let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            tenant.user_create("user1").await.expect("user");
            tenant
                .user_deactivate(&crate::role::Caller::Bootstrap, "user1")
                .await
                .expect("deactivate");
        }
        let service = token_service(state.clone());
        let (rt, _family) = mint_user1_refresh(&state).await;
        let form = format!(
            "grant_type=refresh_token&refresh_token={rt}&client_id=client-a&client_secret=secret-a"
        );

        let (status, _) = post_token(&service, &form).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        // Reactivate: the SAME token must now rotate, proving the earlier
        // reject did not revoke it.
        {
            let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            tenant
                .user_activate(&crate::role::Caller::Bootstrap, "user1")
                .await
                .expect("activate");
        }
        let (status, body) = post_token(&service, &form).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "reactivation must let the same refresh token rotate"
        );
        assert!(body["access_token"].is_string());
        assert!(
            body["refresh_token"].is_string(),
            "offline_access must rotate"
        );
    }

    /// Baseline: an active user's refresh grant rotates normally (guards
    /// against the active check rejecting legitimate users).
    #[tokio::test]
    async fn refresh_grant_works_for_active_user() {
        let (state, _tmp) = revoke_test_env().await;
        {
            let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            tenant.user_create("user1").await.expect("user");
        }
        let service = token_service(state.clone());
        let (rt, _family) = mint_user1_refresh(&state).await;

        let (status, body) = post_token(
            &service,
            &format!(
                "grant_type=refresh_token&refresh_token={rt}&client_id=client-a&client_secret=secret-a"
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "an active user must refresh: {body}"
        );
        assert!(body["access_token"].is_string());
        assert!(body["refresh_token"].is_string());
    }

    // ── client_credentials grant (RFC 6749 §4.4) ───────────────────────────

    /// The grant mints a long-lived session-shaped JWT bound to the
    /// client's service identity and carrying the `scim` role — the
    /// machine principal SCIM provisioning runs under.
    #[tokio::test]
    async fn client_credentials_mints_scim_service_token() {
        let (state, _tmp) = revoke_test_env().await;
        {
            let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            tenant
                .oauth2client_create(
                    "scim-client",
                    "scim-secret",
                    &[],
                    "client_credentials",
                    "",
                    "client_secret_post",
                    "",
                )
                .await
                .expect("client");
        }
        let service = token_service(state.clone());

        let (status, body) = post_token(
            &service,
            "grant_type=client_credentials&client_id=scim-client&client_secret=scim-secret",
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "client_credentials must mint: {body}"
        );
        let service_token = body["access_token"]
            .as_str()
            .expect("access_token")
            .to_string();
        assert_eq!(body["token_type"], "Bearer");
        assert!(body["refresh_token"].is_null(), "no refresh token for now");

        let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
        let client = tenant
            .oauth2client_get("scim-client")
            .await
            .expect("client");
        let data: crate::db::JwtData = tenant
            .jwt_verify(TEST_ISSUER, &client.uuid.to_string(), &service_token)
            .await
            .expect("token verifies against the client's service id");
        assert!(
            data.roles.contains("scim"),
            "the service token must carry the scim role"
        );
        assert_eq!(data.username, "client:scim-client");
    }

    /// A client is bound to its registered grant list (unauthorized_client),
    /// and the grant itself requires a confidential client (invalid_client).
    #[tokio::test]
    async fn client_credentials_refuses_unregistered_grant_and_public_clients() {
        let (state, _tmp) = revoke_test_env().await;
        {
            let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            tenant
                .oauth2client_create("public-cc", "x", &[], "client_credentials", "", "none", "")
                .await
                .expect("client");
        }
        let service = token_service(state.clone());

        // client-a is registered for authorization_code only.
        let (status, body) = post_token(
            &service,
            "grant_type=client_credentials&client_id=client-a&client_secret=secret-a",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "unauthorized_client");

        // A public client cannot use the grant even when registered for it.
        let (status, body) = post_token(
            &service,
            "grant_type=client_credentials&client_id=public-cc",
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert_eq!(body["error"], "invalid_client");
    }

    // ── device grant (RFC 8628) integration tests ──────────────────────────

    fn device_service(state: crate::server::ServerState) -> Service {
        Service::new(
            Router::new()
                .push(
                    Router::with_path("device_authorization")
                        .post(crate::oidc::device_authorization)
                        .hoop(salvo::affix_state::inject(state.clone())),
                )
                .push(
                    Router::with_path("device-login/approve")
                        .post(crate::oidc::device_login_approve)
                        .hoop(salvo::affix_state::inject(state.clone())),
                )
                .push(
                    Router::with_path("authorize")
                        .get(crate::oidc::authorize)
                        .hoop(salvo::affix_state::inject(state.clone())),
                )
                .push(
                    Router::with_path("token")
                        .post(crate::oidc::token)
                        .hoop(salvo::affix_state::inject(state)),
                ),
        )
    }

    /// Start a device flow for client-a and approve it via the real
    /// approval ceremony (session JWT for `user`); returns the
    /// device_authorization response.
    async fn start_and_approve_device_flow(
        service: &Service,
        state: &crate::server::ServerState,
        user: &str,
    ) -> serde_json::Value {
        let mut res = salvo::test::TestClient::post("http://localhost/device_authorization")
            .add_header("Host", "localhost", true)
            .raw_form("client_id=client-a&client_secret=secret-a&scope=openid".to_string())
            .send(service)
            .await;
        assert_eq!(res.status_code.expect("status code"), StatusCode::OK);
        let body = res.take_string().await.unwrap_or_default();
        let auth: serde_json::Value =
            serde_json::from_str(&body).expect("device authorization response");

        let session = {
            let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            tenant
                .authenticate_jwt(
                    &std::collections::HashSet::new(),
                    TEST_ISSUER,
                    "localhost",
                    user,
                    15,
                )
                .await
                .expect("session token")
        };
        let res = salvo::test::TestClient::post("http://localhost/device-login/approve")
            .add_header("Host", "localhost", true)
            .add_header("Authorization", format!("Bearer {session}"), true)
            .json(&serde_json::json!({
                "user_code": auth["user_code"].as_str().expect("user_code"),
                "action": "approve",
            }))
            .send(service)
            .await;
        assert_eq!(
            res.status_code.expect("status code"),
            StatusCode::OK,
            "approval ceremony must succeed"
        );
        auth
    }

    /// regression: a device_code is bound to the client it was issued
    /// to. Another registered (properly authenticated) client must not
    /// redeem an approved device_code, and the rejection must neither
    /// consume the entry nor poison the rightful client's polling interval.
    #[tokio::test]
    async fn device_code_is_bound_to_issuing_client() {
        let (state, _tmp) = revoke_test_env().await;
        {
            let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            tenant.user_create("alice").await.expect("user");
        }
        let service = device_service(state.clone());
        let auth = start_and_approve_device_flow(&service, &state, "alice").await;
        let device_code = auth["device_code"].as_str().expect("device_code");
        let grant = "urn:ietf:params:oauth:grant-type:device_code";

        let (status, body) = post_token(
            &service,
            &format!(
                "grant_type={grant}&device_code={device_code}&client_id=client-b&client_secret=secret-b"
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a foreign client must not redeem another client's device_code: {body}"
        );
        assert_eq!(body["error"], "invalid_grant");

        let (status, body) = post_token(
            &service,
            &format!(
                "grant_type={grant}&device_code={device_code}&client_id=client-a&client_secret=secret-a"
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "rightful client must still redeem: {body}"
        );
        assert!(body["access_token"].is_string());
        assert!(
            body["id_token"].is_string(),
            "scope=openid must mint an ID token"
        );
    }

    /// regression: the device grant reads the RFC 8628 §3.4
    /// `device_code` parameter. The authorization-code grant's `code`
    /// parameter must not be accepted, and a request carrying only `code`
    /// must leave the entry redeemable via the correct parameter.
    #[tokio::test]
    async fn device_grant_requires_device_code_parameter() {
        let (state, _tmp) = revoke_test_env().await;
        {
            let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            tenant.user_create("alice").await.expect("user");
        }
        let service = device_service(state.clone());
        let auth = start_and_approve_device_flow(&service, &state, "alice").await;
        let device_code = auth["device_code"].as_str().expect("device_code");
        let grant = "urn:ietf:params:oauth:grant-type:device_code";

        let (status, body) = post_token(
            &service,
            &format!(
                "grant_type={grant}&code={device_code}&client_id=client-a&client_secret=secret-a"
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the auth-code `code` parameter must not carry a device grant: {body}"
        );
        assert_eq!(body["error"], "invalid_request");

        let (status, body) = post_token(
            &service,
            &format!(
                "grant_type={grant}&device_code={device_code}&client_id=client-a&client_secret=secret-a"
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "the RFC 8628 parameter must redeem: {body}"
        );
        assert!(body["access_token"].is_string());
    }

    // ── device-flow and pending-auth hardening ────────────────────────

    /// User codes use the RFC 8628 §6.1 alphabet: no vowels, no ambiguous
    /// 0/O/1/I, shape XXXX-XXXX.
    #[test]
    fn user_code_uses_rfc8628_alphabet() {
        const ALLOWED: &str = "BCDFGHJKLMNPQRSTVWXZ";
        for _ in 0..100 {
            let code = generate_user_code();
            assert_eq!(code.len(), 9, "XXXX-XXXX shape");
            assert_eq!(&code[4..5], "-");
            assert!(
                code.chars()
                    .filter(|c| *c != '-')
                    .all(|c| ALLOWED.contains(c)),
                "code {code} must stay within the RFC 8628 alphabet"
            );
        }
    }

    /// A redeemed approval is consumed atomically: the second poller gets
    /// `invalid_grant` instead of a second token set (double-mint).
    #[tokio::test]
    async fn device_exchange_is_one_shot() {
        let (state, _tmp) = revoke_test_env().await;
        {
            let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            tenant.user_create("alice").await.expect("user");
        }
        let service = device_service(state.clone());
        let auth = start_and_approve_device_flow(&service, &state, "alice").await;
        let device_code = auth["device_code"].as_str().expect("device_code");
        let grant = "urn:ietf:params:oauth:grant-type:device_code";

        let (status, body) = post_token(
            &service,
            &format!(
                "grant_type={grant}&device_code={device_code}&client_id=client-a&client_secret=secret-a"
            ),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "first exchange must mint: {body}");

        let (status, body) = post_token(
            &service,
            &format!(
                "grant_type={grant}&device_code={device_code}&client_id=client-a&client_secret=secret-a"
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the approval is one-shot: {body}"
        );
        assert_eq!(body["error"], "invalid_grant");
    }

    /// `slow_down` raises the polling interval by 5 s (RFC 8628 §3.5).
    #[tokio::test]
    async fn device_slow_down_bumps_interval() {
        let (state, _tmp) = revoke_test_env().await;
        let service = device_service(state.clone());

        let mut res = salvo::test::TestClient::post("http://localhost/device_authorization")
            .add_header("Host", "localhost", true)
            .raw_form("client_id=client-a&client_secret=secret-a&scope=openid".to_string())
            .send(&service)
            .await;
        let body = res.take_string().await.unwrap_or_default();
        let auth: serde_json::Value = serde_json::from_str(&body).expect("device auth response");
        let device_code = auth["device_code"].as_str().expect("device_code");
        let grant = "urn:ietf:params:oauth:grant-type:device_code";

        // First poll records the timestamp; the immediate second poll trips
        // slow_down and must bump the stored interval 5 → 10.
        let (status, _) = post_token(
            &service,
            &format!(
                "grant_type={grant}&device_code={device_code}&client_id=client-a&client_secret=secret-a"
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);

        let (status, body) = post_token(
            &service,
            &format!(
                "grant_type={grant}&device_code={device_code}&client_id=client-a&client_secret=secret-a"
            ),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "slow_down");

        let entry = OIDC_DEVICE_CACHE
            .codes
            .get(&format!("device:{device_code}"))
            .await
            .expect("device entry");
        assert_eq!(
            entry["interval"].as_u64(),
            Some(10),
            "slow_down must raise the interval by 5 s (RFC 8628 §3.5)"
        );
    }

    /// A malformed approval carrying no identity fails closed instead of
    /// minting tokens for a placeholder user (`todo_user`).
    #[tokio::test]
    async fn device_exchange_refuses_approval_without_user() {
        let (state, _tmp) = revoke_test_env().await;
        let service = device_service(state.clone());

        let device_code = format!("g74-{}", uuid::Uuid::new_v4());
        let now = Timestamp::now().as_second();
        OIDC_DEVICE_CACHE
            .codes
            .insert(
                format!("device:{device_code}"),
                serde_json::json!({
                    "client_id": "client-a",
                    "scope": "openid",
                    "status": "approved",
                    "expires_at": now + 600,
                    "interval": 5,
                    "last_polled_at": 0,
                }),
            )
            .await
            .expect("seed malformed approval");

        let grant = "urn:ietf:params:oauth:grant-type:device_code";
        let (status, body) = post_token(
            &service,
            &format!(
                "grant_type={grant}&device_code={device_code}&client_id=client-a&client_secret=secret-a"
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "an approval without user_id must fail closed: {body}"
        );
        assert_eq!(body["error"], "invalid_grant");
    }

    /// The pending-authorization key is server-random — never the
    /// RP-supplied state — and the RP state rides inside the entry to be
    /// echoed on the callback (login-CSRF).
    #[tokio::test]
    async fn authorize_pending_key_is_server_random_not_rp_state() {
        let (state, _tmp) = revoke_test_env().await;
        let service = device_service(state.clone());

        let res = salvo::test::TestClient::get(
            "http://localhost/authorize?response_type=code&client_id=client-a&redirect_uri=http://localhost/client-a/callback&scope=openid&state=rp-state-123",
        )
        .add_header("Host", "localhost", true)
        .send(&service)
        .await;
        assert_eq!(res.status_code.expect("status code"), StatusCode::FOUND);
        let loc = location_header(&res);
        assert!(loc.starts_with("/login?client_id=client-a"), "{loc}");

        let key = loc
            .split("state=")
            .nth(1)
            .expect("state param in redirect")
            .split('&')
            .next()
            .expect("state value");
        let key = urlencoding::decode(key)
            .expect("urlencoded key")
            .to_string();
        assert_ne!(
            key, "rp-state-123",
            "the pending key must not be the RP-supplied state"
        );

        // The RP state is NOT a valid key...
        assert!(
            OIDC_AUTH_PENDING_CACHE
                .get("auth_pending:rp-state-123")
                .await
                .is_none()
        );
        // ...but rides inside the entry keyed by the server-random value.
        let entry = OIDC_AUTH_PENDING_CACHE
            .get(&format!("auth_pending:{key}"))
            .await
            .expect("pending entry under the server key");
        assert_eq!(
            entry["state"].as_str(),
            Some("rp-state-123"),
            "the RP state must be preserved inside the entry"
        );
    }

    fn consent_service(state: crate::server::ServerState) -> Service {
        Service::new(
            Router::new()
                .push(
                    Router::with_path("consent")
                        .post(crate::oidc::consent_submit)
                        .hoop(salvo::affix_state::inject(state.clone())),
                )
                .push(
                    Router::with_path("consent/info")
                        .get(crate::oidc::consent_info)
                        .hoop(salvo::affix_state::inject(state)),
                ),
        )
    }

    /// A consent entry parked while a session existed is bound to that
    /// session's user: another session can neither probe nor
    /// consume it; the rightful user still can.
    #[tokio::test]
    async fn consent_entry_is_bound_to_the_parking_session_user() {
        let (state, _tmp) = revoke_test_env().await;
        {
            let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            let bootstrap = crate::role::Caller::Bootstrap;
            tenant.user_create("alice").await.expect("alice");
            tenant.user_create("bob").await.expect("bob");
            // validate_jwt runs the policy engine (default-deny), so the
            // consent endpoints need allow rows before the binding is
            // what's under test.
            tenant
                .role_create(&bootstrap, "user", 0)
                .await
                .expect("role");
            tenant
                .user_add_role(&bootstrap, "alice", "user")
                .await
                .expect("grant");
            tenant
                .user_add_role(&bootstrap, "bob", "user")
                .await
                .expect("grant");
            for (method, resource) in [
                (Some(crate::db::HttpMethod::GET), "/consent/info"),
                (Some(crate::db::HttpMethod::POST), "/consent"),
            ] {
                tenant
                    .policy_create(
                        &bootstrap,
                        "localhost",
                        method,
                        resource,
                        "user",
                        &crate::policy::SourceResolver::Nothing,
                        &crate::policy::TargetResolver::Nothing,
                        false,
                        true,
                    )
                    .await
                    .expect("policy");
            }
        }
        let service = consent_service(state.clone());

        let alice_id = {
            let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            tenant.user("alice").await.expect("alice").id.to_string()
        };
        let key = format!("g74-bound-{}", uuid::Uuid::new_v4());
        let now = Timestamp::now().as_second();
        OIDC_AUTH_PENDING_CACHE
            .insert(
                format!("auth_pending:{key}"),
                serde_json::json!({
                    "client_id": "client-a",
                    "callback_uri": "http://localhost/client-a/callback",
                    "scope": "openid",
                    "state": "rp-1",
                    "nonce": null,
                    "stage": "consent",
                    "park_user": alice_id,
                    "created_at": now,
                }),
            )
            .await
            .expect("seed bound consent entry");

        let session_for = |user: &str| {
            let state = state.clone();
            let user = user.to_string();
            async move {
                let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
                tenant
                    .authenticate_jwt(
                        &std::collections::HashSet::new(),
                        TEST_ISSUER,
                        "localhost",
                        &user,
                        15,
                    )
                    .await
                    .expect("session token")
            }
        };
        let bob = session_for("bob").await;
        let alice = session_for("alice").await;

        // validate_jwt reads `local_addr`, which TestClient leaves empty —
        // build requests by hand instead.
        let build =
            |method: salvo::http::Method, uri: &str, jwt: &str, body: Option<serde_json::Value>| {
                let mut req = Request::new();
                *req.method_mut() = method;
                req.set_uri(uri.parse().unwrap());
                req.headers_mut()
                    .insert(salvo::http::header::HOST, "localhost".parse().unwrap());
                req.headers_mut().insert(
                    salvo::http::header::AUTHORIZATION,
                    format!("Bearer {jwt}").parse().unwrap(),
                );
                *req.remote_addr_mut() = "127.0.0.1:9999"
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
                    .into();
                *req.local_addr_mut() = "127.0.0.1:8080"
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
                    .into();
                if let Some(body) = body {
                    req.headers_mut().insert(
                        salvo::http::header::CONTENT_TYPE,
                        "application/json".parse().unwrap(),
                    );
                    *req.body_mut() =
                        salvo::http::ReqBody::from(serde_json::to_string(&body).unwrap());
                }
                req
            };

        // bob probes → refused, entry intact.
        let res = service
            .handle(build(
                salvo::http::Method::GET,
                &format!("http://localhost/consent/info?state={key}"),
                &bob,
                None,
            ))
            .await;
        assert_eq!(
            res.status_code,
            Some(StatusCode::BAD_REQUEST),
            "a foreign session must not probe the entry"
        );

        // alice (the parking session's user) probes successfully.
        let mut res = service
            .handle(build(
                salvo::http::Method::GET,
                &format!("http://localhost/consent/info?state={key}"),
                &alice,
                None,
            ))
            .await;
        assert_eq!(
            res.status_code,
            Some(StatusCode::OK),
            "the parking session's user must still see the entry"
        );
        let body = res.take_string().await.unwrap_or_default();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        assert_eq!(body["data"]["client_id"], "client-a");

        // bob consumes → refused. The entry is consumed fail-closed, so
        // even alice must restart the flow afterwards.
        let res = service
            .handle(build(
                salvo::http::Method::POST,
                "http://localhost/consent",
                &bob,
                Some(serde_json::json!({ "state": key, "decision": "accept" })),
            ))
            .await;
        assert_eq!(
            res.status_code,
            Some(StatusCode::BAD_REQUEST),
            "a foreign session must not consume the entry"
        );
        let res = service
            .handle(build(
                salvo::http::Method::GET,
                &format!("http://localhost/consent/info?state={key}"),
                &alice,
                None,
            ))
            .await;
        assert_eq!(
            res.status_code,
            Some(StatusCode::BAD_REQUEST),
            "a failed foreign consume burns the entry fail-closed"
        );
    }

    /// Introspection and revocation require real client authentication:
    /// public clients (`token_endpoint_auth_method = "none"`) are refused,
    /// so an anonymous caller can neither probe nor revoke — including
    /// poisoning a refresh family.
    #[tokio::test]
    async fn introspect_and_revoke_refuse_public_clients() {
        let (state, _tmp) = revoke_test_env().await;
        {
            let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            tenant
                .oauth2client_create(
                    "client-pub",
                    "unused",
                    &["http://localhost/client-pub/callback"],
                    "authorization_code",
                    "code",
                    "none",
                    "openid",
                )
                .await
                .expect("public client");
        }

        let (status, body) = post_introspect(
            &introspect_service(state.clone()),
            "token=anything&client_id=client-pub",
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "introspection must refuse public clients: {body}"
        );
        assert_eq!(body["error"], "invalid_client");

        let (status, body) = post_revoke(
            &revoke_service(state.clone()),
            "token=anything&client_id=client-pub",
        )
        .await;
        assert_eq!(
            status,
            StatusCode::UNAUTHORIZED,
            "revocation must refuse public clients: {body}"
        );
        let body: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        assert_eq!(body["error"], "invalid_client");
    }

    /// regression: an approved device entry stays redeemable for up
    /// to 1800 s and the approval-time session check is stateless — an
    /// admin deactivation in between must void the token exchange.
    #[tokio::test]
    async fn device_grant_refuses_deactivated_user_at_exchange() {
        let (state, _tmp) = revoke_test_env().await;
        {
            let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            tenant.user_create("alice").await.expect("user");
        }
        let service = device_service(state.clone());
        let auth = start_and_approve_device_flow(&service, &state, "alice").await;
        let device_code = auth["device_code"].as_str().expect("device_code");
        let grant = "urn:ietf:params:oauth:grant-type:device_code";

        // Deactivate after approval, before the RP redeems the code.
        {
            let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            tenant
                .user_deactivate(&crate::role::Caller::Bootstrap, "alice")
                .await
                .expect("deactivate");
        }

        let (status, body) = post_token(
            &service,
            &format!(
                "grant_type={grant}&device_code={device_code}&client_id=client-a&client_secret=secret-a"
            ),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a deactivated user must not receive tokens: {body}"
        );
        assert_eq!(body["error"], "invalid_grant");
    }

    /// Seed a one-shot auth-code cache entry the way
    /// `issue_authorization_code` does (minus the AuthGrant/PKCE side
    /// effects, which the exchange does not need for this probe).
    async fn seed_auth_code(code: &str, user: &str) {
        let now = Timestamp::now().as_second();
        let entry = serde_json::json!({
            "client_id": "client-a",
            "callback_uri": "http://localhost/client-a/callback",
            "user_id": user,
            "scope": "openid",
            "nonce": null,
            "code_challenge_method": null,
            "mfa": [],
            "auth_time": now,
            "jti": uuid::Uuid::new_v4().to_string(),
            "created_at": now,
            "expires_at": now + 600,
        });
        OIDC_AUTH_CODE_CACHE
            .insert(format!("auth_code:{code}"), entry)
            .await
            .expect("seed auth code");
    }

    /// regression: a parked auth code can outlive an admin
    /// deactivation — the exchange must re-check `user.active` and refuse
    /// to mint.
    #[tokio::test]
    async fn auth_code_exchange_refuses_deactivated_user() {
        let (state, _tmp) = revoke_test_env().await;
        let alice_id = {
            let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            tenant.user_create("alice").await.expect("user");
            tenant.user("alice").await.expect("alice").id.to_string()
        };
        let service = device_service(state.clone());

        // Positive control: an active user redeems the code.
        seed_auth_code("code-active", &alice_id).await;
        let (status, body) = post_token(
            &service,
            "grant_type=authorization_code&code=code-active&client_id=client-a&client_secret=secret-a",
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "an active user must redeem the code: {body}"
        );
        assert!(body["access_token"].is_string());

        // Deactivate, then a second parked code for the same user must be
        // refused at issuance.
        {
            let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            tenant
                .user_deactivate(&crate::role::Caller::Bootstrap, "alice")
                .await
                .expect("deactivate");
        }
        seed_auth_code("code-stale", &alice_id).await;
        let (status, body) = post_token(
            &service,
            "grant_type=authorization_code&code=code-stale&client_id=client-a&client_secret=secret-a",
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a deactivated user must not receive tokens: {body}"
        );
        assert_eq!(body["error"], "invalid_grant");
    }

    /// regression: the per-client `grant_types`/`response_types`
    /// allowlists are enforced. A client registered only for
    /// `refresh_token` (response_types without "code") must be refused
    /// with `unauthorized_client` on every other flow, while a
    /// fully-registered client passes the allowlists.
    #[tokio::test]
    async fn client_grant_and_response_type_allowlists_are_enforced() {
        let (state, _tmp) = revoke_test_env().await;
        {
            let mut tenant = state.storage.tenant_by_domain("localhost").expect("tenant");
            tenant.user_create("alice").await.expect("user");
            tenant
                .oauth2client_create(
                    "client-c",
                    "secret-c",
                    &["http://localhost/client-c/callback"],
                    "refresh_token",
                    "token",
                    "client_secret_post",
                    "openid",
                )
                .await
                .expect("oauth2 client");
        }
        let service = device_service(state.clone());

        // /token: grant types client-c is not registered for.
        for grant in ["authorization_code", GRANT_TYPE_DEVICE_CODE] {
            let (status, body) = post_token(
                &service,
                &format!("grant_type={grant}&client_id=client-c&client_secret=secret-c"),
            )
            .await;
            assert_eq!(
                status,
                StatusCode::BAD_REQUEST,
                "grant_type {grant} must be refused for client-c: {body}"
            );
            assert_eq!(body["error"], "unauthorized_client");
        }

        // Server-unknown grant types stay `unsupported_grant_type` even for
        // a fully registered client.
        let (status, body) = post_token(
            &service,
            "grant_type=password&client_id=client-a&client_secret=secret-a",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "unsupported_grant_type");

        // device_authorization: client-c lacks the device grant.
        let mut res = salvo::test::TestClient::post("http://localhost/device_authorization")
            .add_header("Host", "localhost", true)
            .raw_form("client_id=client-c&client_secret=secret-c".to_string())
            .send(&service)
            .await;
        assert_eq!(
            res.status_code.expect("status code"),
            StatusCode::BAD_REQUEST,
            "device_authorization must refuse unregistered clients"
        );
        let body = res.take_string().await.unwrap_or_default();
        assert!(body.contains("unauthorized_client"), "{body}");

        // /authorize: client-c's response_types do not include "code".
        let res = salvo::test::TestClient::get(
            "http://localhost/authorize?response_type=code&client_id=client-c&redirect_uri=http://localhost/client-c/callback&state=st1",
        )
        .add_header("Host", "localhost", true)
        .send(&service)
        .await;
        assert_eq!(res.status_code.expect("status code"), StatusCode::FOUND);
        let loc = res
            .headers()
            .get(salvo::http::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(
            loc.contains("error=unauthorized_client"),
            "authorize must refuse an unregistered response_type: {loc}"
        );

        // Positive control: fully registered client-a passes the allowlist
        // AND the redirect-URI check (fixed the unloaded deferred),
        // parking at the session gate: 302 to /login with the OIDC context.
        let res = salvo::test::TestClient::get(
            "http://localhost/authorize?response_type=code&client_id=client-a&redirect_uri=http://localhost/client-a/callback&state=st2",
        )
        .add_header("Host", "localhost", true)
        .send(&service)
        .await;
        assert_eq!(res.status_code.expect("status code"), StatusCode::FOUND);
        let loc = location_header(&res);
        assert!(
            loc.starts_with("/login?client_id=client-a"),
            "a registered client must reach the session gate: {loc}"
        );
    }

    fn location_header(res: &salvo::http::Response) -> String {
        res.headers()
            .get(salvo::http::header::LOCATION)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string()
    }

    /// regression: `/authorize` must validate `redirect_uri` against
    /// the client's registered URIs via the explicit relation query. Before
    /// the fix the unloaded `redirect_uris` deferred panicked for EVERY
    /// registered client, so the mismatch branch was unreachable dead code
    /// and the happy path was a 500.
    #[tokio::test]
    async fn authorize_checks_redirect_uri_without_panicking() {
        let (state, _tmp) = revoke_test_env().await;
        let service = device_service(state.clone());

        // Unregistered URI → invalid_redirect_uri (formerly dead code
        // behind the panic).
        let res = salvo::test::TestClient::get(
            "http://localhost/authorize?response_type=code&client_id=client-a&redirect_uri=https://evil.example/cb&state=st1",
        )
        .add_header("Host", "localhost", true)
        .send(&service)
        .await;
        assert_eq!(res.status_code.expect("status code"), StatusCode::FOUND);
        let loc = location_header(&res);
        assert!(
            loc.contains("error=invalid_redirect_uri"),
            "an unregistered redirect_uri must be refused: {loc}"
        );

        // Registered URI → the flow parks at the session gate instead of
        // panicking (formerly a 500 for every real client).
        let res = salvo::test::TestClient::get(
            "http://localhost/authorize?response_type=code&client_id=client-a&redirect_uri=http://localhost/client-a/callback&state=st2",
        )
        .add_header("Host", "localhost", true)
        .send(&service)
        .await;
        assert_eq!(res.status_code.expect("status code"), StatusCode::FOUND);
        let loc = location_header(&res);
        assert!(
            loc.starts_with("/login?client_id=client-a"),
            "a registered redirect_uri must reach the session gate: {loc}"
        );
    }

    /// regression: `/authorize` bounds the requested scope by the
    /// server's vocabulary and the client's registered scope BEFORE
    /// parking/consent. client-a is registered for "openid offline_access".
    #[tokio::test]
    async fn authorize_rejects_unregistered_or_unknown_scope() {
        let (state, _tmp) = revoke_test_env().await;
        let service = device_service(state.clone());

        // Known but unregistered scope (email) → invalid_scope.
        let res = salvo::test::TestClient::get(
            "http://localhost/authorize?response_type=code&client_id=client-a&redirect_uri=http://localhost/client-a/callback&scope=openid%20email&state=st1",
        )
        .add_header("Host", "localhost", true)
        .send(&service)
        .await;
        assert_eq!(res.status_code.expect("status code"), StatusCode::FOUND);
        let loc = location_header(&res);
        assert!(
            loc.starts_with("/error?error=invalid_scope"),
            "an unregistered scope must be refused before parking: {loc}"
        );

        // Unknown scope → invalid_scope.
        let res = salvo::test::TestClient::get(
            "http://localhost/authorize?response_type=code&client_id=client-a&redirect_uri=http://localhost/client-a/callback&scope=openid%20admin&state=st2",
        )
        .add_header("Host", "localhost", true)
        .send(&service)
        .await;
        assert_eq!(res.status_code.expect("status code"), StatusCode::FOUND);
        let loc = location_header(&res);
        assert!(
            loc.starts_with("/error?error=invalid_scope"),
            "an unknown scope must be refused: {loc}"
        );

        // Positive control: the registered scope reaches the session gate.
        let res = salvo::test::TestClient::get(
            "http://localhost/authorize?response_type=code&client_id=client-a&redirect_uri=http://localhost/client-a/callback&scope=openid%20offline_access&state=st3",
        )
        .add_header("Host", "localhost", true)
        .send(&service)
        .await;
        assert_eq!(res.status_code.expect("status code"), StatusCode::FOUND);
        let loc = location_header(&res);
        assert!(
            loc.starts_with("/login?client_id=client-a"),
            "a registered scope must reach the session gate: {loc}"
        );
    }

    /// regression: `device_authorization` applies the same scope
    /// bounds (RFC 8628 §3.2.2 `invalid_scope`).
    #[tokio::test]
    async fn device_authorization_rejects_unregistered_or_unknown_scope() {
        let (state, _tmp) = revoke_test_env().await;
        let service = device_service(state.clone());

        for scope in ["openid+email", "openid+admin"] {
            let mut res = salvo::test::TestClient::post("http://localhost/device_authorization")
                .add_header("Host", "localhost", true)
                .raw_form(format!(
                    "client_id=client-a&client_secret=secret-a&scope={scope}"
                ))
                .send(&service)
                .await;
            assert_eq!(
                res.status_code.expect("status code"),
                StatusCode::BAD_REQUEST,
                "scope '{scope}' must be refused"
            );
            let body = res.take_string().await.unwrap_or_default();
            let body: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
            assert_eq!(body["error"], "invalid_scope", "{body}");
        }

        // Positive control: the registered scope starts the flow.
        let mut res = salvo::test::TestClient::post("http://localhost/device_authorization")
            .add_header("Host", "localhost", true)
            .raw_form("client_id=client-a&client_secret=secret-a&scope=openid".to_string())
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("status code"), StatusCode::OK);
        let body = res.take_string().await.unwrap_or_default();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap_or_default();
        assert!(body["device_code"].is_string(), "{body}");
    }

    /// regression: the auth-code exchange loads `redirect_uris`
    /// explicitly. A mismatched URI is `invalid_grant` (formerly a panic),
    /// and an omitted URI with exactly one registered URI passes the check
    /// (formerly always 400 "redirect_uri missing" because the deferred
    /// was never loaded).
    #[tokio::test]
    async fn auth_code_exchange_loads_redirect_uris() {
        let (state, _tmp) = revoke_test_env().await;
        let service = device_service(state.clone());

        // Mismatched redirect_uri → invalid_grant, no panic.
        let (status, body) = post_token(
            &service,
            "grant_type=authorization_code&code=whatever&client_id=client-a&client_secret=secret-a&redirect_uri=https://evil.example/cb",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert_eq!(body["error"], "invalid_grant");
        assert!(
            body["error_description"]
                .as_str()
                .unwrap_or_default()
                .contains("redirect_uri"),
            "{body}"
        );

        // Omitted redirect_uri with exactly one registered URI → passes
        // the check and reaches code validation (unknown code), NOT the
        // old "redirect_uri missing" 400.
        let (status, body) = post_token(
            &service,
            "grant_type=authorization_code&code=whatever&client_id=client-a&client_secret=secret-a",
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_grant");
        assert!(
            body["error_description"]
                .as_str()
                .unwrap_or_default()
                .contains("expired or was already used"),
            "a single registered URI must satisfy the omitted-redirect_uri rule: {body}"
        );
    }
}
