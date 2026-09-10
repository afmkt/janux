//! OIDC profiles beyond Basic and Config:
//!
//! - **Dynamic Client Registration** — RFC 7591 `POST /register` and the
//!   RFC 7592 §4 read operation `GET /register/{client_id}`. Gated by a
//!   per-tenant switch (`oidc.dcr` in the tenant config store); default
//!   off because open registration lets anyone mint client rows.
//! - **RP-Initiated Logout 1.0** — `GET|POST /end_session`.
//! - **Back-Channel Logout 1.0** — logout-token fan-out triggered from
//!   `/end_session` and the first-party `auth/logout`.
//!
//! Janux sessions are stateless JWTs (README §2) with no server-side
//! session registry, so two spec mechanisms adapt accordingly:
//!
//! - Logout tokens carry `sub` but never `sid`
//!   (`backchannel_logout_session_supported` is false in discovery); the
//!   set of RPs to notify comes from the user's non-revoked consent
//!   grants (`AuthGrant`), which is the only durable record of where a
//!   user holds an active OIDC authorization.
//! - `/end_session` terminates the session presented to it (Bearer JWT)
//!   rather than a cookie it cannot name — login factors set cookies
//!   under client-chosen names, so no fixed session cookie exists.
//!
//! Extended client metadata (logout URIs, client name, provenance) lives
//! in the tenant `Config` store, not the `OAuth2Client` table — see
//! [`crate::idp::ClientMeta`] for why.

use crate::db::Tenant;
use crate::idp::ClientMeta;
use crate::utils::{ApiProblem, ApiResponse};
use base64::Engine;
use jiff::ToSpan;
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use std::sync::LazyLock;

/// Back-Channel Logout 1.0 §2.4 — the `events` claim value marking a JWT
/// as a logout token.
const BACKCHANNEL_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// Logout token lifetime: long enough for delivery + retries, short
/// enough that a leaked token cannot be replayed later.
const LOGOUT_TOKEN_SECONDS: i64 = 120;

/// Give-up bound for durable back-channel delivery (G-126): with the
/// exponential backoff below this covers ~5 hours of RP outage.
const BACKCHANNEL_MAX_ATTEMPTS: i32 = 10;

// ── Validation primitives (shared by DCR and the admin meta endpoint) ────────

/// Redirect/post-logout URI rules: absolute, no fragment (RFC 7591 §2
/// forbids fragments on `redirect_uris`), https everywhere except plain
/// http on loopback hosts (RFC 8252 §7.1 native-app pattern).
pub(crate) fn validate_client_uri(uri: &str) -> Result<(), String> {
    let parsed = url::Url::parse(uri).map_err(|e| format!("invalid URI '{uri}': {e}"))?;
    if parsed.fragment().is_some() {
        return Err(format!("URI must not contain a fragment: '{uri}'"));
    }
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_host(parsed.host_str()) => Ok(()),
        other => Err(format!(
            "URI scheme '{other}' not allowed (https, or http on loopback): '{uri}'"
        )),
    }
}

fn is_loopback_host(host: Option<&str>) -> bool {
    matches!(
        host,
        Some("127.0.0.1") | Some("localhost") | Some("[::1]") | Some("::1")
    )
}

/// Grant types a dynamically registered client may request. Machine
/// grants (`client_credentials`) are deliberately excluded — a self-service
/// registration must not mint itself a service identity.
const DCR_GRANT_TYPES: &[&str] = &[
    "authorization_code",
    "refresh_token",
    crate::oidc::GRANT_TYPE_DEVICE_CODE,
];

pub(crate) fn validate_dcr_grant_types(grant_types: &[String]) -> Result<Vec<String>, String> {
    if grant_types.is_empty() {
        return Ok(vec!["authorization_code".to_string()]);
    }
    for g in grant_types {
        if !DCR_GRANT_TYPES.contains(&g.as_str()) {
            return Err(format!("unsupported grant_type: '{g}'"));
        }
    }
    // redirect_uris are mandatory at registration, which only makes sense
    // together with the authorization_code grant.
    if !grant_types.iter().any(|g| g == "authorization_code") {
        return Err("grant_types must include 'authorization_code'".to_string());
    }
    Ok(grant_types.to_vec())
}

pub(crate) fn validate_dcr_response_types(
    response_types: &[String],
) -> Result<Vec<String>, String> {
    if response_types.is_empty() {
        return Ok(vec!["code".to_string()]);
    }
    // The server only implements the authorization-code flow; implicit and
    // hybrid response types are deprecated (OAuth 2.1 BCP) and never get
    // registered.
    for r in response_types {
        if r != "code" {
            return Err(format!("unsupported response_type: '{r}'"));
        }
    }
    Ok(vec!["code".to_string()])
}

/// Requested default scope must stay inside the server's known vocabulary
/// (`KNOWN_SCOPES`) — scope decides what a consent round can offer, so a
/// self-registering client must not widen it.
pub(crate) fn validate_dcr_scope(scope: Option<&str>) -> Result<String, String> {
    let scope = scope.unwrap_or("openid").trim();
    if scope.is_empty() {
        return Ok("openid".to_string());
    }
    for s in scope.split_whitespace() {
        if !crate::oidc::KNOWN_SCOPES.contains(&s) {
            return Err(format!("unknown scope: '{s}'"));
        }
    }
    Ok(scope.split_whitespace().collect::<Vec<_>>().join(" "))
}

// ── Dynamic Client Registration (RFC 7591) ──────────────────────────────────

#[derive(Debug, Deserialize, ToSchema)]
pub struct RegisterRequest {
    pub redirect_uris: Vec<String>,
    #[serde(default)]
    pub token_endpoint_auth_method: Option<String>,
    #[serde(default)]
    pub grant_types: Option<Vec<String>>,
    #[serde(default)]
    pub response_types: Option<Vec<String>>,
    #[serde(default)]
    pub scope: Option<String>,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Option<Vec<String>>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct RegisterResponse {
    pub client_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_secret: Option<String>,
    pub client_id_issued_at: i64,
    /// 0 = the client secret never expires (RFC 7591 §3.2.1).
    pub client_secret_expires_at: i64,
    pub redirect_uris: Vec<String>,
    pub token_endpoint_auth_method: String,
    pub grant_types: Vec<String>,
    pub response_types: Vec<String>,
    pub scope: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub backchannel_logout_uri: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub post_logout_redirect_uris: Vec<String>,
    /// RFC 7592 §3 (G-125): the management credential for GET/PUT/DELETE
    /// on `registration_client_uri`. Rotated on every update.
    pub registration_access_token: String,
    pub registration_client_uri: String,
}

/// RFC 7591 §3.2.2 error response shape (OAuth 2.0-style JSON).
fn registration_error(res: &mut Response, error: &str, description: &str) {
    crate::oidc::token_error(res, StatusCode::BAD_REQUEST, error, description);
}

/// The validated, normalized form of a registration body — shared by the
/// initial registration (RFC 7591) and the update path (RFC 7592 §4,
/// G-125) so both enforce identical metadata rules.
struct ValidatedRegistration {
    auth_method: String,
    grant_types: Vec<String>,
    response_types: Vec<String>,
    scope: String,
    post_logout_uris: Vec<String>,
}

fn validate_registration(
    body: &RegisterRequest,
) -> Result<ValidatedRegistration, (&'static str, String)> {
    // ── redirect_uris (RFC 7591 §2: REQUIRED, no fragments) ────────────
    if body.redirect_uris.is_empty() {
        return Err(("invalid_redirect_uri", "redirect_uris is required".into()));
    }
    for uri in &body.redirect_uris {
        if let Err(e) = validate_client_uri(uri) {
            return Err(("invalid_redirect_uri", e));
        }
    }

    // ── token_endpoint_auth_method ─────────────────────────────────────
    let auth_method = body
        .token_endpoint_auth_method
        .clone()
        .unwrap_or_else(|| "client_secret_basic".to_string());
    if !matches!(
        auth_method.as_str(),
        "client_secret_basic" | "client_secret_post" | "none"
    ) {
        return Err((
            "invalid_client_metadata",
            format!("unsupported token_endpoint_auth_method: '{auth_method}'"),
        ));
    }

    // ── grant_types / response_types / scope ───────────────────────────
    let grant_types = validate_dcr_grant_types(body.grant_types.as_deref().unwrap_or(&[]))
        .map_err(|e| ("invalid_client_metadata", e))?;
    let response_types = validate_dcr_response_types(body.response_types.as_deref().unwrap_or(&[]))
        .map_err(|e| ("invalid_client_metadata", e))?;
    let scope =
        validate_dcr_scope(body.scope.as_deref()).map_err(|e| ("invalid_client_metadata", e))?;

    // ── optional metadata ──────────────────────────────────────────────
    if let Some(name) = &body.client_name
        && name.chars().count() > 200
    {
        return Err(("invalid_client_metadata", "client_name too long".into()));
    }
    if let Some(uri) = &body.backchannel_logout_uri {
        if let Err(e) = validate_client_uri(uri) {
            return Err(("invalid_client_metadata", e));
        }
        if !uri.starts_with("https://") {
            return Err((
                "invalid_client_metadata",
                "backchannel_logout_uri must be https".into(),
            ));
        }
    }
    let mut post_logout_uris = Vec::new();
    if let Some(uris) = &body.post_logout_redirect_uris {
        for uri in uris {
            if let Err(e) = validate_client_uri(uri) {
                return Err(("invalid_client_metadata", e));
            }
            post_logout_uris.push(uri.clone());
        }
    }

    Ok(ValidatedRegistration {
        auth_method,
        grant_types,
        response_types,
        scope,
        post_logout_uris,
    })
}

/// RFC 7592 §3 registration access token lifetime. Janux clients do not
/// expire, and the RFC wants the RAT to live at least as long as the
/// client, so it gets a ten-year horizon; the effective kill switch is
/// the client row itself — every management call re-resolves the client,
/// so a deleted client's RAT dies immediately (and the delete also
/// poisons its machine tokens, G-123).
const REGISTRATION_TOKEN_LIFETIME_MINUTES: i32 = 10 * 365 * 24 * 60;

fn mint_registration_token(
    tenant: &mut crate::db::Tenant,
    issuer: &str,
    domain: &str,
    client_id: &str,
) -> anyhow::Result<String> {
    let key = tenant.current_key(domain)?;
    crate::jwt::jwt_authenticate(
        issuer,
        client_id,
        // jti makes every mint unique — the PUT rotation must be
        // observable even within the same whole-second iat.
        &serde_json::json!({
            "typ": "client_registration",
            "jti": uuid::Uuid::now_v7().to_string(),
        }),
        &key,
        REGISTRATION_TOKEN_LIFETIME_MINUTES,
        crate::jwt::JwtOidcParams {
            client_id: client_id.to_string(),
            nonce: None,
            amr: None,
            acr: None,
            access_token: None,
            auth_time: None,
        },
    )
}

async fn verify_registration_token(
    tenant: &mut crate::db::Tenant,
    issuer: &str,
    client_id: &str,
    token: &str,
) -> bool {
    let Ok(decoded) = crate::jwt::jwt_decode::<serde_json::Value>(
        token,
        crate::jwt::VERIFICATION_GRACE_MINUTES,
        tenant,
    )
    .await
    else {
        return false;
    };
    decoded.claims.iss == issuer
        && decoded.claims.sub == client_id
        && decoded.claims.aud == client_id
        && decoded.claims.data.get("typ").and_then(|v| v.as_str()) == Some("client_registration")
}

/// RFC 7592 §2.1: management requests authenticate with the registration
/// access token (Bearer). The client's own secret (Basic/post) is also
/// accepted — the pre-7592 behavior of the read endpoint, kept so
/// admin-created clients remain manageable. Public clients (`none`) can
/// only use the RAT.
async fn authenticate_management(
    req: &mut Request,
    tenant: &mut crate::db::Tenant,
    client: &crate::idp::OAuth2Client,
    issuer: &str,
) -> bool {
    if let Some(header) = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        && let Some(token) = header
            .strip_prefix("Bearer ")
            .or_else(|| header.strip_prefix("bearer "))
        && verify_registration_token(tenant, issuer, &client.id, token.trim()).await
    {
        return true;
    }
    let secret = presented_client_secret(req).await;
    match (client.token_endpoint_auth_method.as_str(), secret) {
        ("none", _) => false,
        (_, None) => false,
        (_, Some(attempt)) => client.verify_password(&attempt).unwrap_or(false),
    }
}

#[endpoint(
    summary = "OIDC Dynamic Client Registration (RFC 7591)",
    responses(
        (status_code = 201, description = "Client registered", body = RegisterResponse),
        (status_code = 400, description = "Registration rejected", body = serde_json::Value),
    )
)]
pub async fn register(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    // Owned String: `get_domain` borrows `req`, and the body parse below
    // needs it mutably while `domain` stays live until the client row is
    // written.
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or_default()
        .to_string();
    let issuer = crate::utils::get_issuer(req, state)
        .unwrap_or_default()
        .to_string();
    let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_str()) else {
        registration_error(res, "invalid_client_metadata", "unknown tenant domain");
        return;
    };

    // Tenant opt-in gate: open registration is an abuse vector, so the
    // default is closed and an admin flips `oidc.dcr` per tenant.
    if !tenant.dcr_enabled().await {
        registration_error(
            res,
            "invalid_client_metadata",
            "dynamic client registration is not enabled for this tenant",
        );
        return;
    }

    let body = match req.parse_json::<RegisterRequest>().await {
        Ok(b) => b,
        Err(_) => {
            registration_error(res, "invalid_client_metadata", "request body must be JSON");
            return;
        }
    };

    // Shared with the RFC 7592 update path (G-125) so both enforce
    // identical metadata rules.
    let validated = match validate_registration(&body) {
        Ok(v) => v,
        Err((error, desc)) => {
            registration_error(res, error, &desc);
            return;
        }
    };

    // ── create ─────────────────────────────────────────────────────────
    let client_id = uuid::Uuid::now_v7().to_string();
    // Public clients still get a stored secret hash: the model requires
    // one and it is never returned, so "none" stays secret-less in effect.
    let secret = crate::oidc::random_urlsafe_string();
    let redirect_refs: Vec<&str> = body.redirect_uris.iter().map(|s| s.as_str()).collect();
    if let Err(e) = tenant
        .oauth2client_create(
            &domain,
            &client_id,
            &secret,
            &redirect_refs,
            &validated.grant_types.join(" "),
            &validated.response_types.join(" "),
            &validated.auth_method,
            &validated.scope,
        )
        .await
    {
        registration_error(res, "invalid_client_metadata", &e.to_string());
        return;
    }
    let meta = ClientMeta {
        client_name: body.client_name.clone(),
        backchannel_logout_uri: body.backchannel_logout_uri.clone(),
        post_logout_redirect_uris: validated.post_logout_uris.clone(),
        dynamic: true,
    };
    if let Err(e) = tenant.client_meta_save(&client_id, &meta).await {
        // The client row exists but its extended metadata did not persist:
        // roll the registration back rather than leaving a half-registered
        // client behind.
        let _ = tenant.oauth2client_delete(&domain, &client_id).await;
        registration_error(res, "invalid_client_metadata", &e.to_string());
        return;
    }

    // G-125 (RFC 7592 §3): issue the initial management credential. A
    // tenant without a signing key cannot mint it — roll the registration
    // back rather than leaving an unmanageable client behind.
    let registration_access_token =
        match mint_registration_token(&mut tenant, &issuer, &domain, &client_id) {
            Ok(token) => token,
            Err(_) => {
                let _ = tenant.oauth2client_delete(&domain, &client_id).await;
                registration_error(
                    res,
                    "invalid_client_metadata",
                    "failed to issue the registration access token",
                );
                return;
            }
        };
    let registration_client_uri = format!("{issuer}/register/{client_id}");

    let issued_at = jiff::Timestamp::now().as_second();
    res.status_code(StatusCode::CREATED);
    res.render(Json(RegisterResponse {
        client_id,
        client_secret: if validated.auth_method == "none" {
            None
        } else {
            Some(secret)
        },
        client_id_issued_at: issued_at,
        client_secret_expires_at: 0,
        redirect_uris: body.redirect_uris,
        token_endpoint_auth_method: validated.auth_method,
        grant_types: validated.grant_types,
        response_types: validated.response_types,
        scope: validated.scope,
        client_name: body.client_name,
        backchannel_logout_uri: body.backchannel_logout_uri,
        post_logout_redirect_uris: validated.post_logout_uris,
        registration_access_token,
        registration_client_uri,
    }));
}

/// Extract the client secret for the registration read endpoint: HTTP
/// Basic (RFC 6749 §2.3.1) first, then a `client_secret` form/query
/// parameter (client_secret_post style).
async fn presented_client_secret(req: &mut Request) -> Option<String> {
    if let Some(header) = req
        .headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        && let Some(b64) = header.strip_prefix("Basic ")
        && let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(b64)
        && let Ok(decoded) = String::from_utf8(bytes)
        && let Some((id, secret)) = decoded.split_once(':')
    {
        let _ = id; // client_id is taken from the path
        if !secret.is_empty() {
            return Some(crate::oidc::basic_credential_decode(secret));
        }
    }
    #[derive(Deserialize)]
    struct SecretParam {
        #[serde(default)]
        client_secret: Option<String>,
    }
    crate::utils::extract::<SecretParam>(req, None)
        .await
        .and_then(|p| p.client_secret.filter(|s| !s.is_empty()))
}

#[endpoint(
    summary = "Read registered client metadata (RFC 7592 §4)",
    responses(
        (status_code = 200, description = "Client metadata", body = serde_json::Value),
        (status_code = 401, description = "Client authentication failed", body = serde_json::Value),
    )
)]
pub async fn register_read(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or_default();
    let issuer = crate::utils::get_issuer(req, state)
        .unwrap_or_default()
        .to_string();
    let client_id = match req.param::<String>("client_id") {
        Some(id) if !id.is_empty() => id,
        _ => {
            crate::oidc::token_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing client_id",
            );
            return;
        }
    };
    let Some(mut tenant) = state.storage.tenant_by_domain(domain) else {
        crate::oidc::token_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "unknown tenant domain",
        );
        return;
    };

    let client = match tenant.oauth2client_get(&client_id).await {
        // Domain-scoped: a client registered on another domain of the
        // tenant is unknown to this endpoint.
        Ok(c) if c.domain_id == domain => c,
        _ => {
            crate::oidc::token_error(
                res,
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "unknown client",
            );
            return;
        }
    };
    // G-125 (RFC 7592 §2.1): the registration access token is the
    // standard management credential; the client's own secret is still
    // accepted (the pre-7592 behavior) so admin-created clients remain
    // readable. Public clients can only use the RAT.
    if !authenticate_management(req, &mut tenant, &client, &issuer).await {
        crate::oidc::token_error(
            res,
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client authentication failed",
        );
        return;
    }

    let meta = tenant
        .client_meta_load(&client_id)
        .await
        .unwrap_or_default();
    let uris = tenant
        .oauth2client_redirect_uris(&client_id)
        .await
        .map(|rows| rows.into_iter().map(|r| r.uri).collect::<Vec<_>>())
        .unwrap_or_default();
    res.status_code(StatusCode::OK);
    res.render(Json(serde_json::json!({
        "client_id": client.id,
        "redirect_uris": uris,
        "token_endpoint_auth_method": client.token_endpoint_auth_method,
        "grant_types": client.get_grant_types(),
        "response_types": client.get_response_types(),
        "scope": client.scope,
        "client_name": meta.client_name,
        "backchannel_logout_uri": meta.backchannel_logout_uri,
        "post_logout_redirect_uris": meta.post_logout_redirect_uris,
    })));
}

#[endpoint(
    summary = "Update registered client metadata (RFC 7592 §4)",
    request_body = RegisterRequest,
    responses(
        (status_code = 200, description = "Updated metadata with a rotated registration_access_token", body = RegisterResponse),
        (status_code = 400, description = "Invalid metadata", body = serde_json::Value),
        (status_code = 401, description = "Client authentication failed", body = serde_json::Value),
    )
)]
pub async fn register_update(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or_default()
        .to_string();
    let issuer = crate::utils::get_issuer(req, state)
        .unwrap_or_default()
        .to_string();
    let client_id = match req.param::<String>("client_id") {
        Some(id) if !id.is_empty() => id,
        _ => {
            crate::oidc::token_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing client_id",
            );
            return;
        }
    };
    let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_str()) else {
        crate::oidc::token_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "unknown tenant domain",
        );
        return;
    };
    let client = match tenant.oauth2client_get(&client_id).await {
        Ok(c) if c.domain_id == domain => c,
        _ => {
            crate::oidc::token_error(
                res,
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "unknown client",
            );
            return;
        }
    };
    if !authenticate_management(req, &mut tenant, &client, &issuer).await {
        crate::oidc::token_error(
            res,
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client authentication failed",
        );
        return;
    }
    let body = match req.parse_json::<RegisterRequest>().await {
        Ok(b) => b,
        Err(_) => {
            registration_error(res, "invalid_client_metadata", "request body must be JSON");
            return;
        }
    };
    let validated = match validate_registration(&body) {
        Ok(v) => v,
        Err((error, desc)) => {
            registration_error(res, error, &desc);
            return;
        }
    };
    crate::audit::record_target_detail(res, "client", &client_id, "dcr-update");
    if let Err(e) = tenant
        .oauth2client_update(
            &domain,
            &client_id,
            &validated.grant_types.join(" "),
            &validated.response_types.join(" "),
            &validated.auth_method,
            &validated.scope,
            &body.redirect_uris,
        )
        .await
    {
        registration_error(res, "invalid_client_metadata", &e.to_string());
        return;
    }
    let meta = ClientMeta {
        client_name: body.client_name.clone(),
        backchannel_logout_uri: body.backchannel_logout_uri.clone(),
        post_logout_redirect_uris: validated.post_logout_uris.clone(),
        dynamic: true,
    };
    if let Err(e) = tenant.client_meta_save(&client_id, &meta).await {
        registration_error(res, "invalid_client_metadata", &e.to_string());
        return;
    }
    // RFC 7592 §4: the response carries the current credential — rotate
    // it on every update so a leaked token's usable window is bounded by
    // the client's own update cadence.
    let registration_access_token =
        match mint_registration_token(&mut tenant, &issuer, &domain, &client_id) {
            Ok(token) => token,
            Err(e) => {
                registration_error(
                    res,
                    "invalid_client_metadata",
                    &format!(
                        "metadata updated, but rotating the registration access token failed: {e}"
                    ),
                );
                return;
            }
        };
    res.status_code(StatusCode::OK);
    res.render(Json(RegisterResponse {
        client_id: client_id.clone(),
        // The secret is never re-exposed; rotation stays an admin surface.
        client_secret: None,
        client_id_issued_at: client.created_at.as_second(),
        client_secret_expires_at: 0,
        redirect_uris: body.redirect_uris,
        token_endpoint_auth_method: validated.auth_method,
        grant_types: validated.grant_types,
        response_types: validated.response_types,
        scope: validated.scope,
        client_name: body.client_name,
        backchannel_logout_uri: body.backchannel_logout_uri,
        post_logout_redirect_uris: validated.post_logout_uris,
        registration_access_token,
        registration_client_uri: format!("{issuer}/register/{client_id}"),
    }));
}

#[endpoint(
    summary = "Delete a registered client (RFC 7592 §5)",
    responses(
        (status_code = 204, description = "Client deleted (its machine tokens are revoked, G-123)"),
        (status_code = 400, description = "Bad request", body = serde_json::Value),
        (status_code = 401, description = "Client authentication failed", body = serde_json::Value),
    )
)]
pub async fn register_delete(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state)
        .unwrap_or_default()
        .to_string();
    let issuer = crate::utils::get_issuer(req, state)
        .unwrap_or_default()
        .to_string();
    let client_id = match req.param::<String>("client_id") {
        Some(id) if !id.is_empty() => id,
        _ => {
            crate::oidc::token_error(
                res,
                StatusCode::BAD_REQUEST,
                "invalid_request",
                "missing client_id",
            );
            return;
        }
    };
    let Some(mut tenant) = state.storage.tenant_by_domain(domain.as_str()) else {
        crate::oidc::token_error(
            res,
            StatusCode::BAD_REQUEST,
            "invalid_request",
            "unknown tenant domain",
        );
        return;
    };
    let client = match tenant.oauth2client_get(&client_id).await {
        Ok(c) if c.domain_id == domain => c,
        _ => {
            crate::oidc::token_error(
                res,
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "unknown client",
            );
            return;
        }
    };
    if !authenticate_management(req, &mut tenant, &client, &issuer).await {
        crate::oidc::token_error(
            res,
            StatusCode::UNAUTHORIZED,
            "invalid_client",
            "client authentication failed",
        );
        return;
    }
    crate::audit::record_target_detail(res, "client", &client_id, "dcr-delete");
    // The soft delete also poisons the client's machine tokens (G-123),
    // and future management calls fail at the client lookup above — the
    // registration access token dies with the client row.
    match tenant.oauth2client_delete(&domain, &client_id).await {
        Ok(_) => {
            res.status_code(StatusCode::NO_CONTENT);
        }
        Err(e) => registration_error(res, "invalid_client_metadata", &e.to_string()),
    }
}

// ── Back-Channel Logout 1.0 ─────────────────────────────────────────────────

/// Flattened payload of a logout token: the `jti` and the `events` claim
/// (Back-Channel Logout 1.0 §2.4 requires both; `sid` is never included —
/// discovery advertises `backchannel_logout_session_supported: false`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutTokenData {
    pub jti: String,
    pub events: serde_json::Value,
}

/// The RPs a logout must fan out to: `(backchannel_logout_uri, client_id)`
/// per distinct client with a non-revoked consent grant and a configured
/// URI. The caller hands them to [`queue_backchannel_deliveries`] (G-126),
/// which persists durable tasks — the worker re-mints a fresh logout token
/// for every delivery attempt.
///
/// The RP set is the user's non-revoked consent grants — the only durable
/// record of where the user holds an active OIDC authorization. Failures
/// (missing client, no URI) skip that RP: logout must never fail because
/// one RP is misconfigured.
pub async fn backchannel_logout_targets(
    tenant: &mut Tenant,
    user_id: &str,
) -> Vec<(String, String)> {
    let mut targets: Vec<(String, String)> = Vec::new();
    let Ok(grants) = tenant.auth_grant_all_for_user(user_id).await else {
        return targets;
    };
    let mut seen = std::collections::HashSet::new();
    for grant in grants {
        if !seen.insert(grant.client_id.clone()) {
            continue;
        }
        let Ok(client) = tenant.oauth2client_get(&grant.client_id).await else {
            continue;
        };
        let Some(meta) = tenant.client_meta_load(&client.id).await else {
            continue;
        };
        let Some(uri) = meta.backchannel_logout_uri.filter(|u| !u.is_empty()) else {
            continue;
        };
        targets.push((uri, client.id));
    }
    targets
}

/// A pending back-channel logout delivery (G-126). The old path was a
/// detached task with 3 in-memory attempts across ~16 seconds — a restart
/// or an RP outage longer than a few seconds dropped the notification
/// permanently, and the pre-minted logout token expired after 120 s
/// anyway. Task rows live in the tenant database and survive both: the
/// worker RE-MINTS a fresh logout token for every attempt (the 120 s
/// expiry bounds each try, not the retry window) and backs off
/// exponentially until `BACKCHANNEL_MAX_ATTEMPTS`.
#[derive(Debug, toasty::Model, Clone)]
pub struct BackchannelTask {
    #[key]
    pub id: String,
    /// Where to POST the logout token.
    pub uri: String,
    /// Issuer for the re-minted logout token.
    pub issuer: String,
    /// Domain whose signing key mints the token.
    pub domain_id: String,
    /// The logging-out user (logout token `sub`).
    pub sub: String,
    /// The RP (logout token `aud`).
    pub client_id: String,
    #[default(0)]
    pub attempts: i32,
    pub next_attempt_at: jiff::Timestamp,
    #[auto]
    pub created_at: jiff::Timestamp,
}

/// Wakeup for the back-channel worker: queued deliveries are attempted
/// immediately instead of waiting for the next sweep tick.
pub static BACKCHANNEL_NOTIFY: LazyLock<tokio::sync::Notify> =
    LazyLock::new(tokio::sync::Notify::new);

/// Queue durable back-channel deliveries for one logout event and wake
/// the worker. Insert failures are logged, not fatal — the logout itself
/// already succeeded.
pub async fn queue_backchannel_deliveries(
    tenant: &mut Tenant,
    issuer: &str,
    domain: &str,
    user_id: &str,
    targets: Vec<(String, String)>,
) {
    let now = jiff::Timestamp::now();
    for (uri, client_id) in targets {
        if let Err(e) = toasty::create!(BackchannelTask {
            id: uuid::Uuid::now_v7().to_string(),
            uri,
            issuer: issuer.to_string(),
            domain_id: domain.to_string(),
            sub: user_id.to_string(),
            client_id,
            attempts: 0,
            next_attempt_at: now,
        })
        .exec(&mut tenant.database)
        .await
        {
            tracing::warn!(target: "auth::oidc", "failed to queue back-channel delivery: {e:#}");
        }
    }
    BACKCHANNEL_NOTIFY.notify_one();
}

/// The back-channel worker loop: sweep every 60 s, plus an immediate
/// sweep whenever deliveries are queued. Started once from `main`.
pub async fn run_backchannel_worker(state: crate::server::ServerState) {
    let mut ticker = tokio::time::interval(std::time::Duration::from_secs(60));
    loop {
        tokio::select! {
            _ = ticker.tick() => {}
            _ = BACKCHANNEL_NOTIFY.notified() => {}
        }
        backchannel_pass(&state.storage).await;
    }
}

/// One durable-delivery sweep across every loaded tenant. Tasks run
/// under the tenant write guard like any other mutation, so deliveries
/// serialize against requests for the same tenant.
pub async fn backchannel_pass(storage: &crate::db::Storage) {
    let now = jiff::Timestamp::now();
    for id in storage.tenant_ids() {
        let Some(mut tenant) = storage.tenant_by_id(&id) else {
            continue;
        };
        // Task volume is tiny (one row per RP per logout, deleted on
        // success) — a full scan beats a timestamp-filter dependency.
        let Ok(tasks) = BackchannelTask::all().exec(&mut tenant.database).await else {
            continue;
        };
        for task in tasks {
            if task.next_attempt_at > now {
                continue;
            }
            deliver_backchannel_task(&mut tenant, &task, now).await;
        }
    }
}

async fn deliver_backchannel_task(
    tenant: &mut Tenant,
    task: &BackchannelTask,
    now: jiff::Timestamp,
) {
    // Re-mint per attempt: the 120 s logout-token expiry bounds a single
    // try, never the retry window.
    let Ok(key) = tenant.current_key(&task.domain_id) else {
        return; // no signing key right now — the next sweep retries
    };
    let data = LogoutTokenData {
        jti: uuid::Uuid::new_v4().to_string(),
        events: serde_json::json!({ BACKCHANNEL_EVENT: {} }),
    };
    let Ok(token) = crate::jwt::jwt_logout(
        &task.issuer,
        &task.sub,
        &task.client_id,
        &key,
        LOGOUT_TOKEN_SECONDS,
        &data,
    ) else {
        return;
    };
    let delivered = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(10))
        .build()
    {
        Ok(client) => client
            .post(&task.uri)
            .form(&[("logout_token", token.as_str())])
            .send()
            .await
            .map(|r| r.status().is_success())
            .unwrap_or(false),
        Err(_) => false,
    };
    if delivered {
        BackchannelTask::delete_by_id(&mut tenant.database, task.id.as_str())
            .await
            .ok();
        tracing::info!(
            target: "auth::oidc",
            uri = %task.uri,
            client_id = %task.client_id,
            attempts = task.attempts + 1,
            "back-channel logout delivered"
        );
        return;
    }
    let attempts = task.attempts + 1;
    if attempts >= BACKCHANNEL_MAX_ATTEMPTS {
        BackchannelTask::delete_by_id(&mut tenant.database, task.id.as_str())
            .await
            .ok();
        tracing::warn!(
            target: "auth::oidc",
            uri = %task.uri,
            client_id = %task.client_id,
            attempts,
            "back-channel logout GAVE UP — the RP never acknowledged; \
             its local session may outlive the SLO"
        );
        return;
    }
    // Exponential backoff: 2, 4, 8, 16, 32, 64, 64, 64, 64 minutes —
    // ~5 hours of coverage for an RP outage, bounded per attempt.
    let backoff_secs = (1i64 << attempts.min(6)) * 60;
    let next = now.checked_add(backoff_secs.seconds()).unwrap_or(now);
    BackchannelTask::update_by_id(task.id.as_str())
        .attempts(attempts)
        .next_attempt_at(next)
        .exec(&mut tenant.database)
        .await
        .ok();
    tracing::debug!(
        target: "auth::oidc",
        uri = %task.uri,
        client_id = %task.client_id,
        attempts,
        "back-channel logout delivery failed; scheduled retry"
    );
}

// ── RP-Initiated Logout 1.0 ─────────────────────────────────────────────────

#[derive(Debug, Default, Deserialize, ToSchema)]
pub struct EndSessionRequest {
    pub id_token_hint: Option<String>,
    pub client_id: Option<String>,
    pub post_logout_redirect_uri: Option<String>,
    pub state: Option<String>,
}

/// Decode an `id_token_hint` for identification only. Expiry is not
/// enforced: a stale-but-genuine hint still names the client and user it
/// was issued for, and the hint grants no capability on its own — the
/// redirect target must be registered for the client it names regardless.
/// Signature and issuer are enforced.
async fn decode_id_token_hint(
    tenant: &mut Tenant,
    issuer: &str,
    hint: &str,
) -> Option<crate::jwt::Claim<serde_json::Value>> {
    let header = jsonwebtoken::decode_header(hint).ok()?;
    let kid = header.kid?;
    let key = tenant.key(&kid).await.ok()?;
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.validate_exp = false;
    validation.validate_aud = false;
    let decoding = jsonwebtoken::DecodingKey::from_rsa_pem(&key.public).ok()?;
    let data =
        jsonwebtoken::decode::<crate::jwt::Claim<serde_json::Value>>(hint, &decoding, &validation)
            .ok()?;
    if data.claims.iss != issuer {
        return None;
    }
    Some(data.claims)
}

#[endpoint(
    summary = "OIDC RP-Initiated Logout 1.0 — end the presented session",
    responses(
        (status_code = 200, description = "Session ended (no redirect URI)"),
        (status_code = 302, description = "Redirect to post_logout_redirect_uri"),
        (status_code = 400, description = "Invalid request", body = ApiProblem),
    )
)]
pub async fn end_session(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let params = crate::utils::extract::<EndSessionRequest>(req, None)
        .await
        .unwrap_or_default();

    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let Some(domain) = crate::utils::get_domain(req, state) else {
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Json(ApiProblem::bad_request("unknown tenant domain")));
        return;
    };
    let domain = domain.to_string();
    let Some(issuer) = crate::utils::get_issuer(req, state) else {
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Json(ApiProblem::bad_request("unknown issuer")));
        return;
    };
    let Some(mut tenant) = state.storage.tenant_by_domain(&domain) else {
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Json(ApiProblem::bad_request("unknown tenant domain")));
        return;
    };

    // ── Identify the client: id_token_hint wins over the client_id param ─
    let mut client_id: Option<String> = params.client_id.clone().filter(|s| !s.is_empty());
    let mut user_id: Option<String> = None;
    if let Some(hint) = params.id_token_hint.clone().filter(|s| !s.is_empty())
        && let Some(claims) = decode_id_token_hint(&mut tenant, &issuer, &hint).await
    {
        client_id = Some(claims.aud.clone());
        user_id = Some(claims.sub.clone());
    }

    // ── Validate post_logout_redirect_uri (must be previously registered) ─
    let mut redirect_target: Option<String> = None;
    if let Some(uri) = params
        .post_logout_redirect_uri
        .clone()
        .filter(|s| !s.is_empty())
    {
        let registered = if let Some(cid) = &client_id {
            match tenant.oauth2client_get(cid).await {
                // Domain-scoped: only a client of THIS domain can have its
                // redirect URIs honored for post-logout redirection.
                Ok(c) if c.domain_id == domain => {
                    let mut allowed: Vec<String> = tenant
                        .oauth2client_redirect_uris(cid)
                        .await
                        .map(|rows| rows.into_iter().map(|r| r.uri).collect())
                        .unwrap_or_default();
                    if let Some(meta) = tenant.client_meta_load(cid).await {
                        allowed.extend(meta.post_logout_redirect_uris);
                    }
                    allowed.iter().any(|u| u == &uri)
                }
                // Unknown OR registered on another domain: not redirectable.
                _ => false,
            }
        } else {
            false
        };
        if !registered {
            // Never redirect to an unvalidated URI — report the error
            // directly instead (RP-Initiated Logout 1.0 §2).
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(ApiProblem::validation_error(
                "post_logout_redirect_uri is not registered for this client",
            )));
            return;
        }
        redirect_target = Some(uri);
    }

    // ── Terminate the presented session (Bearer JWT) ───────────────────
    if let Some(jwt) = crate::utils::get_jwt(req).map(str::to_string)
        && let Ok(tkn) = crate::jwt::jwt_decode::<crate::db::JwtData>(
            &jwt,
            crate::jwt::VERIFICATION_GRACE_MINUTES,
            &mut tenant,
        )
        .await
        && tkn.claims.iss == issuer
        && tkn.claims.aud == domain
        && let Ok(exp) = jiff::Timestamp::from_second(tkn.claims.exp as i64)
        && crate::utils::revoke_token(&mut tenant, &jwt, Some(exp), "rp-initiated logout")
            .await
            .is_ok()
    {
        user_id = Some(tkn.claims.sub.clone());
    }

    // ── Back-channel fan-out to the user's RPs ─────────────────────────
    if let Some(uid) = &user_id {
        let targets = backchannel_logout_targets(&mut tenant, uid).await;
        queue_backchannel_deliveries(&mut tenant, &issuer, &domain, uid, targets).await;
    }

    // G-139: the canonical session cookie is HttpOnly — only the server
    // can remove it from the jar, so RP-initiated logout expires it on
    // both response paths (harmless when no cookie was ever set).
    crate::verify::set_session_cookie(res, None);

    // ── Respond ────────────────────────────────────────────────────────
    match redirect_target {
        Some(uri) => {
            let mut loc = uri;
            if let Some(s) = params.state.filter(|s| !s.is_empty()) {
                loc.push_str(if loc.contains('?') { "&" } else { "?" });
                loc.push_str("state=");
                loc.push_str(&urlencoding::encode(&s));
            }
            crate::oidc::redirect_to(res, &loc);
        }
        None => {
            res.status_code(StatusCode::OK);
            res.render(Json(ApiResponse::ok("logged out")));
        }
    }
}

// ── Admin surface ───────────────────────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct OidcTenantConfig {
    pub dcr_enabled: bool,
}

#[endpoint(
    summary = "Read tenant OIDC feature configuration",
    responses(
        (status_code = 200, description = "Current configuration", body = ApiResponse<OidcTenantConfig>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
    )
)]
pub async fn oidc_config(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    let Some(mut tenant) = state.storage.tenant_by_domain(domain) else {
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Json(ApiProblem::not_found("Unknown domain")));
        return;
    };
    let cfg = OidcTenantConfig {
        dcr_enabled: tenant.dcr_enabled().await,
    };
    res.status_code(StatusCode::OK);
    res.render(Json(ApiResponse::ok(cfg)));
}

#[endpoint(
    summary = "Update tenant OIDC feature configuration",
    request_body = OidcTenantConfig,
    responses(
        (status_code = 200, description = "Configuration updated", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
    )
)]
pub async fn set_oidc_config(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Some(body) = crate::utils::extract::<OidcTenantConfig>(req, None).await else {
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Json(ApiProblem::validation_error(
            "Failed to parse request body",
        )));
        return;
    };
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    let Some(mut tenant) = state.storage.tenant_by_domain(domain) else {
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Json(ApiProblem::not_found("Unknown domain")));
        return;
    };
    if let Err(e) = tenant.dcr_set_enabled(body.dcr_enabled).await {
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Json(ApiProblem::validation_error(&e.to_string())));
        return;
    }
    res.status_code(StatusCode::OK);
    res.render(Json(ApiResponse::ok(())));
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct ClientMetaRequest {
    pub client_id: String,
    #[serde(default)]
    pub client_name: Option<String>,
    #[serde(default)]
    pub backchannel_logout_uri: Option<String>,
    #[serde(default)]
    pub post_logout_redirect_uris: Option<Vec<String>>,
}

#[endpoint(
    summary = "Set extended OIDC metadata for an OAuth2 client",
    request_body = ClientMetaRequest,
    responses(
        (status_code = 200, description = "Metadata saved", body = ApiResponse<()>),
        (status_code = 400, description = "Bad request", body = ApiProblem),
    )
)]
pub async fn set_client_meta(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let Some(body) = crate::utils::extract::<ClientMetaRequest>(req, None).await else {
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Json(ApiProblem::validation_error(
            "Failed to parse request body",
        )));
        return;
    };
    let state = depot
        .obtain_mut::<crate::server::ServerState>()
        .expect("ServerState not found");
    let domain = crate::utils::get_domain(req, state).unwrap_or("");
    let Some(mut tenant) = state.storage.tenant_by_domain(domain) else {
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Json(ApiProblem::not_found("Unknown domain")));
        return;
    };
    // Domain-scoped: metadata of a client registered on another domain of
    // the tenant is out of reach for this domain's admin surface.
    let client_on_domain = matches!(
        tenant.oauth2client_get(&body.client_id).await,
        Ok(c) if c.domain_id == domain
    );
    if !client_on_domain {
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Json(ApiProblem::not_found("Unknown OAuth2 client")));
        return;
    }
    let mut meta = tenant
        .client_meta_load(&body.client_id)
        .await
        .unwrap_or_default();
    if let Some(name) = body.client_name {
        meta.client_name = Some(name);
    }
    if let Some(uri) = body.backchannel_logout_uri {
        if uri.is_empty() {
            meta.backchannel_logout_uri = None;
        } else {
            if let Err(e) = validate_client_uri(&uri) {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ApiProblem::validation_error(&e)));
                return;
            }
            if !uri.starts_with("https://") {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ApiProblem::validation_error(
                    "backchannel_logout_uri must be https",
                )));
                return;
            }
            meta.backchannel_logout_uri = Some(uri);
        }
    }
    if let Some(uris) = body.post_logout_redirect_uris {
        for uri in &uris {
            if let Err(e) = validate_client_uri(uri) {
                res.status_code(StatusCode::BAD_REQUEST);
                res.render(Json(ApiProblem::validation_error(&e)));
                return;
            }
        }
        meta.post_logout_redirect_uris = uris;
    }
    if let Err(e) = tenant.client_meta_save(&body.client_id, &meta).await {
        res.status_code(StatusCode::BAD_REQUEST);
        res.render(Json(ApiProblem::validation_error(&e.to_string())));
        return;
    }
    res.status_code(StatusCode::OK);
    res.render(Json(ApiResponse::ok(())));
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_uri_validation_rules() {
        assert!(validate_client_uri("https://rp.example.com/callback").is_ok());
        // loopback http is the native-app exception (RFC 8252 §7.1)
        assert!(validate_client_uri("http://127.0.0.1:8080/cb").is_ok());
        assert!(validate_client_uri("http://localhost/cb").is_ok());
        assert!(validate_client_uri("http://[::1]:8080/cb").is_ok());
        // plain http elsewhere is rejected
        assert!(validate_client_uri("http://rp.example.com/callback").is_err());
        // fragments are forbidden (RFC 7591 §2)
        assert!(validate_client_uri("https://rp.example.com/cb#frag").is_err());
        // garbage is rejected
        assert!(validate_client_uri("not a uri").is_err());
        assert!(validate_client_uri("ftp://rp.example.com/cb").is_err());
    }

    #[test]
    fn dcr_grant_type_validation() {
        // default when omitted
        let g = validate_dcr_grant_types(&[]).unwrap();
        assert_eq!(g, vec!["authorization_code".to_string()]);
        // supported set accepted
        let g = validate_dcr_grant_types(&[
            "authorization_code".to_string(),
            "refresh_token".to_string(),
        ])
        .unwrap();
        assert_eq!(g.len(), 2);
        // machine grants are not self-service
        assert!(validate_dcr_grant_types(&["client_credentials".to_string()]).is_err());
        // redirect-based registration requires authorization_code
        assert!(validate_dcr_grant_types(&["refresh_token".to_string()]).is_err());
    }

    #[test]
    fn dcr_response_type_validation() {
        let r = validate_dcr_response_types(&[]).unwrap();
        assert_eq!(r, vec!["code".to_string()]);
        assert!(validate_dcr_response_types(&["code".to_string()]).is_ok());
        // implicit/hybrid are deprecated and never registered
        assert!(validate_dcr_response_types(&["id_token".to_string()]).is_err());
        assert!(validate_dcr_response_types(&["code id_token".to_string()]).is_err());
    }

    #[test]
    fn dcr_scope_stays_inside_known_vocabulary() {
        assert_eq!(validate_dcr_scope(None).unwrap(), "openid");
        assert_eq!(validate_dcr_scope(Some("")).unwrap(), "openid");
        assert_eq!(
            validate_dcr_scope(Some("openid profile")).unwrap(),
            "openid profile"
        );
        assert!(validate_dcr_scope(Some("admin")).is_err());
        // regression C2: the machine-provisioning scope lives outside the
        // user-consent vocabulary, so a self-service DCR registration can
        // never grant itself the `scim` role.
        assert!(validate_dcr_scope(Some("scim")).is_err());
    }

    fn test_key() -> crate::key::Key {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).expect("keygen");
        crate::key::Key {
            id: "test-key".to_string(),
            public: kp.public_key_pem().into_bytes(),
            private: kp.serialize_pem().into_bytes(),
            domain_id: "example.com".to_string(),
            retired: false,
            domain: Default::default(),
        }
    }

    /// Back-Channel Logout 1.0 §2.4: the logout token carries iss/sub/aud/
    /// iat/exp/jti/events, must NOT carry a nonce, and `sub` (not `sid`)
    /// identifies the user — discovery advertises session support as false.
    #[test]
    fn logout_token_round_trip_matches_spec_shape() {
        let key = test_key();
        let data = LogoutTokenData {
            jti: "unique-token-id".to_string(),
            events: serde_json::json!({ BACKCHANNEL_EVENT: {} }),
        };
        let token = crate::jwt::jwt_logout(
            "https://op.example.com",
            "user-uuid",
            "the-client",
            &key,
            LOGOUT_TOKEN_SECONDS,
            &data,
        )
        .expect("logout token signing must succeed");

        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
        validation.validate_aud = false;
        let decoded = jsonwebtoken::decode::<crate::jwt::Claim<LogoutTokenData>>(
            &token,
            &jsonwebtoken::DecodingKey::from_rsa_pem(&key.public).unwrap(),
            &validation,
        )
        .expect("logout token must decode with the public key");

        let claims = decoded.claims;
        assert_eq!(claims.iss, "https://op.example.com");
        assert_eq!(claims.sub, "user-uuid");
        assert_eq!(claims.aud, "the-client");
        assert_eq!(claims.data.jti, "unique-token-id");
        assert_eq!(claims.data.events[BACKCHANNEL_EVENT], serde_json::json!({}));
        // spec: no nonce in logout tokens; no session-bound claims either
        assert!(claims.nonce.is_none());
        assert!(claims.auth_time.is_none());
        assert!(claims.amr.is_none());
        assert!(claims.acr.is_none());
        assert!(claims.at_hash.is_none());
        // short-lived: exp == iat + LOGOUT_TOKEN_SECONDS
        assert_eq!(claims.exp, claims.iat + LOGOUT_TOKEN_SECONDS as usize);
    }

    /// Storage-backed environment for the fan-out tests: one tenant, one
    /// domain, one signing key (same pattern as `email.rs` tests).
    async fn fanout_env() -> (
        crate::db::Storage,
        tempfile::TempDir,
        &'static str,
        &'static str,
    ) {
        const TENANT: &str = "fanout-tenant";
        const DOMAIN: &str = "fanout.local";
        // Signing keys are encrypted at rest (H2); the process-wide
        // encryption key is first-call-wins across test envs.
        let _ = crate::crypto::setup_encryption_key(&"0".repeat(64));
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = crate::db::Storage::init(tmp.path())
            .await
            .expect("storage init");
        storage.new_tenant(TENANT).await.expect("tenant");
        storage.add_domain(DOMAIN, TENANT).await.expect("domain");
        {
            let mut tenant = storage.tenant_by_id(TENANT).expect("tenant");
            tenant
                .key_create(DOMAIN, "key1")
                .await
                .expect("signing key");
        }
        (storage, tmp, TENANT, DOMAIN)
    }

    /// Fan-out selects exactly the clients that (a) hold a non-revoked
    /// grant for the user and (b) registered a backchannel_logout_uri.
    /// Token minting moved into the durable worker (G-126) and is pinned
    /// by `backchannel_worker_delivers_form_encoded_and_deletes_the_task`.
    #[tokio::test]
    async fn backchannel_fanout_selects_registered_clients() {
        let (storage, _tmp, tenant_name, domain) = fanout_env().await;
        let user_id = "user-uuid-1";

        {
            let mut tenant = storage.tenant_by_id(tenant_name).expect("tenant");
            tenant
                .oauth2client_create(
                    domain,
                    "client-with-uri",
                    "secret-a",
                    &["https://a.example/cb"],
                    "authorization_code",
                    "code",
                    "client_secret_basic",
                    "openid",
                )
                .await
                .expect("client A");
            tenant
                .client_meta_save(
                    "client-with-uri",
                    &ClientMeta {
                        backchannel_logout_uri: Some("https://a.example/backchannel".into()),
                        ..Default::default()
                    },
                )
                .await
                .expect("meta A");
            tenant
                .oauth2client_create(
                    domain,
                    "client-without-uri",
                    "secret-b",
                    &["https://b.example/cb"],
                    "authorization_code",
                    "code",
                    "client_secret_basic",
                    "openid",
                )
                .await
                .expect("client B");
            tenant
                .oauth2client_create(
                    domain,
                    "client-revoked",
                    "secret-c",
                    &["https://c.example/cb"],
                    "authorization_code",
                    "code",
                    "client_secret_basic",
                    "openid",
                )
                .await
                .expect("client C");
            tenant
                .client_meta_save(
                    "client-revoked",
                    &ClientMeta {
                        backchannel_logout_uri: Some("https://c.example/backchannel".into()),
                        ..Default::default()
                    },
                )
                .await
                .expect("meta C");

            let exp = jiff::Timestamp::now()
                .checked_add(jiff::Span::new().hours(1))
                .expect("expiry");
            tenant
                .auth_grant_create("jti-a", "client-with-uri", user_id, "openid", "h", exp)
                .await
                .expect("grant A");
            tenant
                .auth_grant_create("jti-b", "client-without-uri", user_id, "openid", "h", exp)
                .await
                .expect("grant B");
            tenant
                .auth_grant_create("jti-c", "client-revoked", user_id, "openid", "h", exp)
                .await
                .expect("grant C");
            // consent revocation removes the client from the logout set
            tenant
                .auth_grant_revoke_for(user_id, "client-revoked")
                .await
                .expect("revoke C");
        }

        let mut tenant = storage.tenant_by_id(tenant_name).expect("tenant");
        let targets = backchannel_logout_targets(&mut tenant, user_id).await;
        assert_eq!(
            targets.len(),
            1,
            "only the client with a grant AND a backchannel_logout_uri is notified"
        );
        let (uri, client_id) = &targets[0];
        assert_eq!(uri, "https://a.example/backchannel");
        assert_eq!(
            client_id, "client-with-uri",
            "G-126: targets carry the client id — the worker re-mints the token per attempt"
        );

        // A user with no grants gets no notifications.
        let none = backchannel_logout_targets(&mut tenant, "stranger").await;
        assert!(none.is_empty());
    }

    /// G-126: delivery is a DURABLE task — the worker re-mints a fresh
    /// spec-shaped logout token per attempt, POSTs it form-encoded
    /// (Back-Channel Logout 1.0 §2.5), treats a 2xx as success and deletes
    /// the task.
    #[tokio::test]
    async fn backchannel_worker_delivers_form_encoded_and_deletes_the_task() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let (storage, _tmp, tenant_name, domain) = fanout_env().await;
        let issuer = format!("http://{domain}");
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let uri = format!("http://{addr}/backchannel");

        {
            let mut tenant = storage.tenant_by_id(tenant_name).expect("tenant");
            queue_backchannel_deliveries(
                &mut tenant,
                &issuer,
                domain,
                "user-uuid-1",
                vec![(uri, "client-a".to_string())],
            )
            .await;
        }

        // The responder must run CONCURRENTLY with the sweep: the worker
        // waits for the HTTP response while the responder waits for the
        // request body.
        let responder = tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.expect("delivery connects");
            let mut buf = vec![0u8; 8192];
            let mut data = Vec::new();
            loop {
                let n = sock.read(&mut buf).await.expect("read");
                if n == 0 {
                    break;
                }
                data.extend_from_slice(&buf[..n]);
                if String::from_utf8_lossy(&data).contains("logout_token=") {
                    break;
                }
            }
            sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .expect("ack");
            String::from_utf8_lossy(&data).to_string()
        });
        backchannel_pass(&storage).await;
        let text = responder.await.expect("responder");

        assert!(
            text.starts_with("POST /backchannel"),
            "delivery must be a POST to the registered URI: {text}"
        );
        assert!(
            text.contains("application/x-www-form-urlencoded"),
            "logout_token is form-encoded: {text}"
        );
        let token = text
            .split("logout_token=")
            .nth(1)
            .expect("logout_token param")
            .split(['&', '\r'])
            .next()
            .unwrap_or_default()
            .trim()
            .to_string();

        // The worker-minted token verifies against the tenant key and
        // carries the spec claims (aud = client, sub = user, events marker).
        let mut tenant = storage.tenant_by_id(tenant_name).expect("tenant");
        let decoded = crate::jwt::jwt_decode::<LogoutTokenData>(&token, 0, &mut tenant)
            .await
            .expect("worker-minted logout token must verify against the tenant JWKS");
        assert_eq!(decoded.claims.iss, issuer);
        assert_eq!(decoded.claims.sub, "user-uuid-1");
        assert_eq!(decoded.claims.aud, "client-a");
        assert_eq!(
            decoded.claims.data.events[BACKCHANNEL_EVENT],
            serde_json::json!({})
        );

        let tasks = BackchannelTask::all()
            .exec(&mut tenant.database)
            .await
            .expect("tasks");
        assert!(tasks.is_empty(), "a delivered task is deleted");
    }

    /// G-126: a failing RP is retried with backoff — the task is a DB row,
    /// so it survives restarts — a not-yet-due task is skipped, and the
    /// attempt bound eventually gives up and purges the task.
    #[tokio::test]
    async fn backchannel_worker_retries_with_backoff_and_gives_up() {
        let (storage, _tmp, tenant_name, domain) = fanout_env().await;
        let issuer = format!("http://{domain}");
        {
            let mut tenant = storage.tenant_by_id(tenant_name).expect("tenant");
            // Port 1: connection refused, immediately.
            queue_backchannel_deliveries(
                &mut tenant,
                &issuer,
                domain,
                "user-uuid-1",
                vec![(
                    "http://127.0.0.1:1/backchannel".to_string(),
                    "client-a".to_string(),
                )],
            )
            .await;
        }

        backchannel_pass(&storage).await;
        let task_id = {
            let mut tenant = storage.tenant_by_id(tenant_name).expect("tenant");
            let tasks = BackchannelTask::all()
                .exec(&mut tenant.database)
                .await
                .expect("tasks");
            assert_eq!(tasks.len(), 1, "a failed delivery keeps its task");
            assert_eq!(tasks[0].attempts, 1);
            assert!(
                tasks[0].next_attempt_at > jiff::Timestamp::now(),
                "the retry is scheduled into the future (backoff)"
            );
            tasks[0].id.clone()
        };

        // Not due yet: the next sweep is a no-op.
        backchannel_pass(&storage).await;
        {
            let mut tenant = storage.tenant_by_id(tenant_name).expect("tenant");
            let tasks = BackchannelTask::all()
                .exec(&mut tenant.database)
                .await
                .expect("tasks");
            assert_eq!(tasks[0].attempts, 1, "a not-yet-due task is untouched");
        }

        // Force the task to its last allowed attempt, due now.
        {
            let mut tenant = storage.tenant_by_id(tenant_name).expect("tenant");
            let past = jiff::Timestamp::now()
                .checked_sub(1.minutes())
                .expect("past");
            BackchannelTask::update_by_id(task_id.as_str())
                .attempts(BACKCHANNEL_MAX_ATTEMPTS - 1)
                .next_attempt_at(past)
                .exec(&mut tenant.database)
                .await
                .expect("force due");
        }
        backchannel_pass(&storage).await;
        {
            let mut tenant = storage.tenant_by_id(tenant_name).expect("tenant");
            let tasks = BackchannelTask::all()
                .exec(&mut tenant.database)
                .await
                .expect("tasks");
            assert!(
                tasks.is_empty(),
                "the attempt bound purges the task (the give-up is logged)"
            );
        }
    }

    // ── HTTP-level endpoint tests (Salvo TestClient) ──────────────────────

    const HTTP_DOMAIN: &str = "oidcext.local";

    /// The revocation store is a process-wide singleton shared by every
    /// test module — one backing dir outliving all per-test TempDirs,
    /// initialized on a runtime that outlives each `#[tokio::test]`
    /// (same pattern as the email.rs endpoint tests).
    static TEST_STORE_DIR: std::sync::LazyLock<tempfile::TempDir> =
        std::sync::LazyLock::new(|| tempfile::tempdir().expect("tempdir"));
    static TEST_STORE_RT: std::sync::LazyLock<tokio::runtime::Runtime> =
        std::sync::LazyLock::new(|| {
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

    async fn http_env() -> (crate::server::ServerState, tempfile::TempDir) {
        init_revocation_store().await;
        // Signing keys are encrypted at rest (H2); the process-wide
        // encryption key is first-call-wins across test envs.
        let _ = crate::crypto::setup_encryption_key(&"0".repeat(64));
        let tmp = tempfile::tempdir().expect("tempdir");
        let storage = crate::db::Storage::init(tmp.path())
            .await
            .expect("storage init");
        storage.new_tenant("ext-tenant").await.expect("tenant");
        storage
            .add_domain(HTTP_DOMAIN, "ext-tenant")
            .await
            .expect("domain");
        {
            let mut tenant = storage.tenant_by_id("ext-tenant").expect("tenant");
            tenant.key_create(HTTP_DOMAIN, "key1").await.expect("key");
        }
        let state = crate::server::ServerState::create_with(storage, false, &[])
            .await
            .expect("server state");
        (state, tmp)
    }

    fn ext_service(state: crate::server::ServerState) -> salvo::Router {
        Router::new()
            .hoop(salvo::affix_state::inject(state))
            .push(
                Router::with_path("register").post(register).push(
                    Router::with_path("{client_id}")
                        .get(register_read)
                        .put(register_update)
                        .delete(register_delete),
                ),
            )
            .push(
                Router::with_path("end_session")
                    .get(end_session)
                    .post(end_session),
            )
    }

    /// G-125 (RFC 7592): registration issues the management credential
    /// (`registration_access_token` + `registration_client_uri`); GET/PUT/
    /// DELETE accept it as a Bearer token; PUT replaces the metadata and
    /// ROTATES the credential; DELETE removes the client.
    #[tokio::test]
    async fn registration_management_round_trip_rfc7592() {
        use salvo::test::ResponseExt;
        let (state, _tmp) = http_env().await;
        {
            let mut tenant = state.storage.tenant_by_id("ext-tenant").expect("tenant");
            tenant.dcr_set_enabled(true).await.expect("enable DCR");
        }
        let service = salvo::Service::new(ext_service(state));

        // ── Register: the 201 carries the RFC 7592 §3 credentials.
        let mut res = salvo::test::TestClient::post("http://oidcext.local/register")
            .add_header("Host", HTTP_DOMAIN, true)
            .json(&serde_json::json!({
                "redirect_uris": ["https://rp.example.com/cb"],
                "client_name": "example rp",
            }))
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("status"), StatusCode::CREATED);
        let body: serde_json::Value =
            serde_json::from_str(&res.take_string().await.unwrap_or_default()).expect("json");
        let client_id = body["client_id"].as_str().expect("client_id").to_string();
        let rat = body["registration_access_token"]
            .as_str()
            .expect("registration_access_token must be issued")
            .to_string();
        let config_uri = body["registration_client_uri"]
            .as_str()
            .expect("registration_client_uri")
            .to_string();
        assert!(
            config_uri.ends_with(&format!("/register/{client_id}")),
            "{config_uri}"
        );

        // ── GET with the RAT as Bearer.
        let res =
            salvo::test::TestClient::get(format!("http://oidcext.local/register/{client_id}"))
                .add_header("Host", HTTP_DOMAIN, true)
                .add_header("Authorization", format!("Bearer {rat}"), true)
                .send(&service)
                .await;
        assert_eq!(res.status_code.expect("status"), StatusCode::OK);

        // ── PUT replaces the metadata and rotates the credential.
        let mut res =
            salvo::test::TestClient::put(format!("http://oidcext.local/register/{client_id}"))
                .add_header("Host", HTTP_DOMAIN, true)
                .add_header("Authorization", format!("Bearer {rat}"), true)
                .json(&serde_json::json!({
                    "redirect_uris": ["https://rp.example.com/cb2"],
                    "client_name": "updated rp",
                }))
                .send(&service)
                .await;
        assert_eq!(res.status_code.expect("status"), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&res.take_string().await.unwrap_or_default()).expect("json");
        assert_eq!(
            body["redirect_uris"],
            serde_json::json!(["https://rp.example.com/cb2"])
        );
        assert_eq!(body["client_name"], "updated rp");
        assert!(
            body["client_secret"].is_null(),
            "the secret is never re-exposed on update"
        );
        let rat2 = body["registration_access_token"]
            .as_str()
            .expect("rotated RAT")
            .to_string();
        assert_ne!(rat2, rat, "the credential rotates on update");

        // The read reflects the update (with the rotated RAT).
        let mut res =
            salvo::test::TestClient::get(format!("http://oidcext.local/register/{client_id}"))
                .add_header("Host", HTTP_DOMAIN, true)
                .add_header("Authorization", format!("Bearer {rat2}"), true)
                .send(&service)
                .await;
        assert_eq!(res.status_code.expect("status"), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&res.take_string().await.unwrap_or_default()).expect("json");
        assert_eq!(
            body["redirect_uris"],
            serde_json::json!(["https://rp.example.com/cb2"])
        );

        // ── PUT with invalid metadata → 400 (plain-http redirect).
        let res =
            salvo::test::TestClient::put(format!("http://oidcext.local/register/{client_id}"))
                .add_header("Host", HTTP_DOMAIN, true)
                .add_header("Authorization", format!("Bearer {rat2}"), true)
                .json(&serde_json::json!({ "redirect_uris": ["http://insecure.example/cb"] }))
                .send(&service)
                .await;
        assert_eq!(res.status_code.expect("status"), StatusCode::BAD_REQUEST);

        // ── A garbage Bearer is not the credential.
        let res =
            salvo::test::TestClient::put(format!("http://oidcext.local/register/{client_id}"))
                .add_header("Host", HTTP_DOMAIN, true)
                .add_header("Authorization", "Bearer not-a-jwt", true)
                .json(&serde_json::json!({ "redirect_uris": ["https://rp.example.com/cb3"] }))
                .send(&service)
                .await;
        assert_eq!(res.status_code.expect("status"), StatusCode::UNAUTHORIZED);

        // ── DELETE with the RAT → 204, and the client is gone.
        let res =
            salvo::test::TestClient::delete(format!("http://oidcext.local/register/{client_id}"))
                .add_header("Host", HTTP_DOMAIN, true)
                .add_header("Authorization", format!("Bearer {rat2}"), true)
                .send(&service)
                .await;
        assert_eq!(res.status_code.expect("status"), StatusCode::NO_CONTENT);

        let res =
            salvo::test::TestClient::get(format!("http://oidcext.local/register/{client_id}"))
                .add_header("Host", HTTP_DOMAIN, true)
                .add_header("Authorization", format!("Bearer {rat2}"), true)
                .send(&service)
                .await;
        assert_eq!(
            res.status_code.expect("status"),
            StatusCode::UNAUTHORIZED,
            "the RAT dies with the client row"
        );
    }

    /// RFC 7591 round-trip: registration answers 201 with credentials,
    /// the client becomes usable, and the RFC 7592 §4 read returns the
    /// registered metadata to an authenticated client only.
    #[tokio::test]
    async fn register_and_read_round_trip() {
        use salvo::test::ResponseExt;
        let (state, _tmp) = http_env().await;
        {
            let mut tenant = state.storage.tenant_by_id("ext-tenant").expect("tenant");
            tenant.dcr_set_enabled(true).await.expect("enable DCR");
        }
        let service = salvo::Service::new(ext_service(state));

        let mut res = salvo::test::TestClient::post("http://oidcext.local/register")
            .add_header("Host", HTTP_DOMAIN, true)
            .json(&serde_json::json!({
                "redirect_uris": ["https://rp.example.com/callback"],
                "client_name": "example rp",
                "scope": "openid profile",
                "post_logout_redirect_uris": ["https://rp.example.com/logged-out"],
            }))
            .send(&service)
            .await;
        assert_eq!(
            res.status_code.expect("status"),
            StatusCode::CREATED,
            "a valid registration must answer 201"
        );
        let body: serde_json::Value =
            serde_json::from_str(&res.take_string().await.unwrap_or_default())
                .expect("registration response JSON");
        let client_id = body["client_id"].as_str().expect("client_id").to_string();
        let secret = body["client_secret"]
            .as_str()
            .expect("client_secret for a confidential client")
            .to_string();
        assert_eq!(body["client_secret_expires_at"], 0);
        assert_eq!(
            body["grant_types"],
            serde_json::json!(["authorization_code"])
        );
        assert_eq!(body["scope"], "openid profile");

        // RFC 7592 §4 read with client_secret_basic
        let basic =
            base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:{secret}"));
        let mut res =
            salvo::test::TestClient::get(format!("http://oidcext.local/register/{client_id}"))
                .add_header("Host", HTTP_DOMAIN, true)
                .add_header("Authorization", format!("Basic {basic}"), true)
                .send(&service)
                .await;
        assert_eq!(res.status_code.expect("status"), StatusCode::OK);
        let body: serde_json::Value =
            serde_json::from_str(&res.take_string().await.unwrap_or_default())
                .expect("read response JSON");
        assert_eq!(body["client_id"], client_id);
        assert_eq!(
            body["redirect_uris"],
            serde_json::json!(["https://rp.example.com/callback"])
        );
        assert_eq!(body["client_name"], "example rp");
        assert_eq!(
            body["post_logout_redirect_uris"],
            serde_json::json!(["https://rp.example.com/logged-out"])
        );

        // a wrong secret gets invalid_client, never metadata
        let bad =
            base64::engine::general_purpose::STANDARD.encode(format!("{client_id}:wrong-secret"));
        let res =
            salvo::test::TestClient::get(format!("http://oidcext.local/register/{client_id}"))
                .add_header("Host", HTTP_DOMAIN, true)
                .add_header("Authorization", format!("Basic {bad}"), true)
                .send(&service)
                .await;
        assert_eq!(res.status_code.expect("status"), StatusCode::UNAUTHORIZED);
    }

    /// Redirect-URI validation fires before any client state is created.
    #[tokio::test]
    async fn register_rejects_invalid_redirect_uri() {
        use salvo::test::ResponseExt;
        let (state, _tmp) = http_env().await;
        {
            let mut tenant = state.storage.tenant_by_id("ext-tenant").expect("tenant");
            tenant.dcr_set_enabled(true).await.expect("enable DCR");
        }
        let service = salvo::Service::new(ext_service(state));

        let mut res = salvo::test::TestClient::post("http://oidcext.local/register")
            .add_header("Host", HTTP_DOMAIN, true)
            .json(&serde_json::json!({
                "redirect_uris": ["http://rp.example.com/callback#frag"],
            }))
            .send(&service)
            .await;
        assert_eq!(res.status_code.expect("status"), StatusCode::BAD_REQUEST);
        let body: serde_json::Value =
            serde_json::from_str(&res.take_string().await.unwrap_or_default()).expect("error JSON");
        assert_eq!(body["error"], "invalid_redirect_uri");
    }

    /// RP-Initiated Logout: the presented session JWT is revoked and the
    /// browser is redirected to the registered post-logout URI with the
    /// RP's state preserved.
    #[tokio::test]
    async fn end_session_revokes_session_and_redirects() {
        let (state, _tmp) = http_env().await;
        let issuer = format!("http://{HTTP_DOMAIN}");
        let session_jwt = {
            let mut tenant = state.storage.tenant_by_id("ext-tenant").expect("tenant");
            tenant
                .signup_user_email("dave", "dave@example.com")
                .await
                .expect("user");
            tenant
                .oauth2client_create(
                    HTTP_DOMAIN,
                    "rp-client",
                    "rp-secret",
                    &["https://rp.example.com/callback"],
                    "authorization_code",
                    "code",
                    "client_secret_basic",
                    "openid",
                )
                .await
                .expect("client");
            tenant
                .client_meta_save(
                    "rp-client",
                    &ClientMeta {
                        post_logout_redirect_uris: vec![
                            "https://rp.example.com/logged-out".to_string(),
                        ],
                        ..Default::default()
                    },
                )
                .await
                .expect("meta");
            tenant
                .authenticate_jwt(
                    &std::collections::HashSet::new(),
                    &issuer,
                    HTTP_DOMAIN,
                    "dave",
                    15,
                )
                .await
                .expect("session JWT")
        };
        let service = salvo::Service::new(ext_service(state));

        let res = salvo::test::TestClient::get(format!(
            "http://oidcext.local/end_session?client_id=rp-client&post_logout_redirect_uri={}&state=xyz",
            urlencoding::encode("https://rp.example.com/logged-out")
        ))
        .add_header("Host", HTTP_DOMAIN, true)
        .add_header("Authorization", format!("Bearer {session_jwt}"), true)
        .send(&service)
        .await;
        assert_eq!(
            res.status_code.expect("status"),
            StatusCode::FOUND,
            "a valid post_logout_redirect_uri must end in a redirect"
        );
        let loc = res
            .headers
            .get("location")
            .expect("Location header")
            .to_str()
            .expect("header value")
            .to_string();
        assert_eq!(loc, "https://rp.example.com/logged-out?state=xyz");

        // the presented session is revoked — the store reports it invalid
        assert!(
            crate::jwt::InvalidJwt::global()
                .is_valid(&session_jwt)
                .await,
            "end_session must revoke the presented session token"
        );
    }
}
