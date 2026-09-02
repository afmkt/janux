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
use salvo::http::StatusCode;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

/// Back-Channel Logout 1.0 §2.4 — the `events` claim value marking a JWT
/// as a logout token.
const BACKCHANNEL_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// Logout token lifetime: long enough for delivery + retries, short
/// enough that a leaked token cannot be replayed later.
const LOGOUT_TOKEN_SECONDS: i64 = 120;

/// Delivery attempts per back-channel target (initial + retries).
const BACKCHANNEL_ATTEMPTS: u32 = 3;

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
}

/// RFC 7591 §3.2.2 error response shape (OAuth 2.0-style JSON).
fn registration_error(res: &mut Response, error: &str, description: &str) {
    crate::oidc::token_error(res, StatusCode::BAD_REQUEST, error, description);
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
    let domain = crate::utils::get_domain(req, state).unwrap_or_default();
    let Some(mut tenant) = state.storage.tenant_by_domain(domain) else {
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

    // ── redirect_uris (RFC 7591 §2: REQUIRED, no fragments) ────────────
    if body.redirect_uris.is_empty() {
        registration_error(res, "invalid_redirect_uri", "redirect_uris is required");
        return;
    }
    for uri in &body.redirect_uris {
        if let Err(e) = validate_client_uri(uri) {
            registration_error(res, "invalid_redirect_uri", &e);
            return;
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
        registration_error(
            res,
            "invalid_client_metadata",
            &format!("unsupported token_endpoint_auth_method: '{auth_method}'"),
        );
        return;
    }

    // ── grant_types / response_types / scope ───────────────────────────
    let grant_types = match validate_dcr_grant_types(body.grant_types.as_deref().unwrap_or(&[])) {
        Ok(g) => g,
        Err(e) => return registration_error(res, "invalid_client_metadata", &e),
    };
    let response_types =
        match validate_dcr_response_types(body.response_types.as_deref().unwrap_or(&[])) {
            Ok(r) => r,
            Err(e) => return registration_error(res, "invalid_client_metadata", &e),
        };
    let scope = match validate_dcr_scope(body.scope.as_deref()) {
        Ok(s) => s,
        Err(e) => return registration_error(res, "invalid_client_metadata", &e),
    };

    // ── optional metadata ──────────────────────────────────────────────
    if let Some(name) = &body.client_name
        && name.chars().count() > 200
    {
        return registration_error(res, "invalid_client_metadata", "client_name too long");
    }
    if let Some(uri) = &body.backchannel_logout_uri {
        if let Err(e) = validate_client_uri(uri) {
            return registration_error(res, "invalid_client_metadata", &e);
        }
        if !uri.starts_with("https://") {
            return registration_error(
                res,
                "invalid_client_metadata",
                "backchannel_logout_uri must be https",
            );
        }
    }
    let mut post_logout_uris = Vec::new();
    if let Some(uris) = &body.post_logout_redirect_uris {
        for uri in uris {
            if let Err(e) = validate_client_uri(uri) {
                return registration_error(res, "invalid_client_metadata", &e);
            }
            post_logout_uris.push(uri.clone());
        }
    }

    // ── create ─────────────────────────────────────────────────────────
    let client_id = uuid::Uuid::now_v7().to_string();
    // Public clients still get a stored secret hash: the model requires
    // one and it is never returned, so "none" stays secret-less in effect.
    let secret = crate::oidc::random_urlsafe_string();
    let redirect_refs: Vec<&str> = body.redirect_uris.iter().map(|s| s.as_str()).collect();
    if let Err(e) = tenant
        .oauth2client_create(
            &client_id,
            &secret,
            &redirect_refs,
            &grant_types.join(" "),
            &response_types.join(" "),
            &auth_method,
            &scope,
        )
        .await
    {
        registration_error(res, "invalid_client_metadata", &e.to_string());
        return;
    }
    let meta = ClientMeta {
        client_name: body.client_name.clone(),
        backchannel_logout_uri: body.backchannel_logout_uri.clone(),
        post_logout_redirect_uris: post_logout_uris.clone(),
        dynamic: true,
    };
    if let Err(e) = tenant.client_meta_save(&client_id, &meta).await {
        // The client row exists but its extended metadata did not persist:
        // roll the registration back rather than leaving a half-registered
        // client behind.
        let _ = tenant.oauth2client_delete(&client_id).await;
        registration_error(res, "invalid_client_metadata", &e.to_string());
        return;
    }

    let issued_at = jiff::Timestamp::now().as_second();
    res.status_code(StatusCode::CREATED);
    res.render(Json(RegisterResponse {
        client_id,
        client_secret: if auth_method == "none" {
            None
        } else {
            Some(secret)
        },
        client_id_issued_at: issued_at,
        client_secret_expires_at: 0,
        redirect_uris: body.redirect_uris,
        token_endpoint_auth_method: auth_method,
        grant_types,
        response_types,
        scope,
        client_name: body.client_name,
        backchannel_logout_uri: body.backchannel_logout_uri,
        post_logout_redirect_uris: post_logout_uris,
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
        Ok(c) => c,
        Err(_) => {
            crate::oidc::token_error(
                res,
                StatusCode::UNAUTHORIZED,
                "invalid_client",
                "unknown client",
            );
            return;
        }
    };
    // Public clients cannot authenticate a read request; RFC 7592 would
    // hand them a registration_access_token, which this server does not
    // issue — reject rather than expose metadata unauthenticated.
    let secret = presented_client_secret(req).await;
    let authenticated = match (client.token_endpoint_auth_method.as_str(), secret) {
        ("none", _) => false,
        (_, None) => false,
        (_, Some(attempt)) => client.verify_password(&attempt).unwrap_or(false),
    };
    if !authenticated {
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
        .map(|rows| rows.into_iter().map(|r| r.id).collect::<Vec<_>>())
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

// ── Back-Channel Logout 1.0 ─────────────────────────────────────────────────

/// Flattened payload of a logout token: the `jti` and the `events` claim
/// (Back-Channel Logout 1.0 §2.4 requires both; `sid` is never included —
/// discovery advertises `backchannel_logout_session_supported: false`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogoutTokenData {
    pub jti: String,
    pub events: serde_json::Value,
}

/// Mint one logout token per RP of `user_id` that registered a
/// `backchannel_logout_uri`. Returns `(uri, logout_token)` pairs; the
/// caller hands them to [`spawn_backchannel_delivery`].
///
/// The RP set is the user's non-revoked consent grants — the only durable
/// record of where the user holds an active OIDC authorization. Failures
/// (missing client, no signing key) skip that RP: logout must never fail
/// because one RP is misconfigured.
pub async fn backchannel_logout_targets(
    tenant: &mut Tenant,
    issuer: &str,
    domain: &str,
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
        let Ok(key) = tenant.current_key(domain) else {
            continue;
        };
        let data = LogoutTokenData {
            jti: uuid::Uuid::new_v4().to_string(),
            events: serde_json::json!({ BACKCHANNEL_EVENT: {} }),
        };
        let Ok(token) = crate::jwt::jwt_logout(
            issuer,
            user_id,
            &client.id,
            &key,
            LOGOUT_TOKEN_SECONDS,
            &data,
        ) else {
            continue;
        };
        targets.push((uri, token));
    }
    targets
}

/// Fire-and-forget delivery of logout tokens: `POST logout_token=…`
/// (form-encoded, Back-Channel Logout 1.0 §2.5) with a short timeout and
/// bounded retries. Runs detached — the logout response never waits on
/// RP reachability.
pub fn spawn_backchannel_delivery(targets: Vec<(String, String)>) {
    if targets.is_empty() {
        return;
    }
    tokio::spawn(async move {
        let Ok(client) = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(10))
            .build()
        else {
            return;
        };
        for (uri, token) in targets {
            let mut delivered = false;
            for attempt in 0..BACKCHANNEL_ATTEMPTS {
                if attempt > 0 {
                    tokio::time::sleep(std::time::Duration::from_secs(1 << attempt)).await;
                }
                let ok = client
                    .post(&uri)
                    .form(&[("logout_token", token.as_str())])
                    .send()
                    .await
                    .map(|r| r.status().is_success())
                    .unwrap_or(false);
                if ok {
                    delivered = true;
                    break;
                }
            }
            tracing::debug!(
                target: "auth::oidc",
                uri = %uri,
                delivered,
                "back-channel logout delivery"
            );
        }
    });
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
    if let Some(hint) = params.id_token_hint.clone().filter(|s| !s.is_empty()) {
        if let Some(claims) = decode_id_token_hint(&mut tenant, &issuer, &hint).await {
            client_id = Some(claims.aud.clone());
            user_id = Some(claims.sub.clone());
        }
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
                Ok(_) => {
                    let mut allowed: Vec<String> = tenant
                        .oauth2client_redirect_uris(cid)
                        .await
                        .map(|rows| rows.into_iter().map(|r| r.id).collect())
                        .unwrap_or_default();
                    if let Some(meta) = tenant.client_meta_load(cid).await {
                        allowed.extend(meta.post_logout_redirect_uris);
                    }
                    allowed.iter().any(|u| u == &uri)
                }
                Err(_) => false,
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
    if let Some(jwt) = crate::utils::get_jwt(req).map(str::to_string) {
        if let Ok(tkn) = crate::jwt::jwt_decode::<crate::db::JwtData>(&jwt, 2, &mut tenant).await
            && tkn.claims.iss == issuer
            && tkn.claims.aud == domain
        {
            if let Ok(exp) = jiff::Timestamp::from_second(tkn.claims.exp as i64) {
                if crate::utils::revoke_token(&mut tenant, &jwt, Some(exp), "rp-initiated logout")
                    .await
                    .is_ok()
                {
                    user_id = Some(tkn.claims.sub.clone());
                }
            }
        }
    }

    // ── Back-channel fan-out to the user's RPs ─────────────────────────
    if let Some(uid) = &user_id {
        let targets = backchannel_logout_targets(&mut tenant, &issuer, &domain, uid).await;
        spawn_backchannel_delivery(targets);
    }

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
    if tenant.oauth2client_get(&body.client_id).await.is_err() {
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
    }

    fn test_key() -> crate::key::Key {
        let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).expect("keygen");
        crate::key::Key {
            id: "test-key".to_string(),
            public: kp.public_key_pem().into_bytes(),
            private: kp.serialize_pem().into_bytes(),
            domain_id: "example.com".to_string(),
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
    /// The minted token must be verifiable against the tenant JWKS and
    /// carry the user/client identities.
    #[tokio::test]
    async fn backchannel_fanout_selects_registered_clients() {
        let (storage, _tmp, tenant_name, domain) = fanout_env().await;
        let issuer = format!("http://{domain}");
        let user_id = "user-uuid-1";

        {
            let mut tenant = storage.tenant_by_id(tenant_name).expect("tenant");
            tenant
                .oauth2client_create(
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
        let targets = backchannel_logout_targets(&mut tenant, &issuer, domain, user_id).await;
        assert_eq!(
            targets.len(),
            1,
            "only the client with a grant AND a backchannel_logout_uri is notified"
        );
        let (uri, token) = &targets[0];
        assert_eq!(uri, "https://a.example/backchannel");

        // The token verifies against the tenant key and carries the spec
        // claims (aud = client, sub = user, events marker present).
        let decoded = crate::jwt::jwt_decode::<LogoutTokenData>(token, 0, &mut tenant)
            .await
            .expect("logout token must verify against the tenant JWKS");
        assert_eq!(decoded.claims.iss, issuer);
        assert_eq!(decoded.claims.sub, user_id);
        assert_eq!(decoded.claims.aud, "client-with-uri");
        assert_eq!(
            decoded.claims.data.events[BACKCHANNEL_EVENT],
            serde_json::json!({})
        );

        // A user with no grants gets no notifications.
        let none = backchannel_logout_targets(&mut tenant, &issuer, domain, "stranger").await;
        assert!(none.is_empty());
    }

    /// Delivery posts a form-encoded `logout_token` (Back-Channel Logout
    /// 1.0 §2.5) and treats a 2xx as success.
    #[tokio::test]
    async fn backchannel_delivery_posts_form_encoded_logout_token() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let uri = format!("http://{addr}/backchannel");

        spawn_backchannel_delivery(vec![(uri, "the-logout-token".to_string())]);

        let (mut sock, _) = listener.accept().await.expect("delivery connects");
        let mut buf = vec![0u8; 4096];
        let mut data = Vec::new();
        // read until the end of the (small) request body
        loop {
            let n = sock.read(&mut buf).await.expect("read");
            if n == 0 {
                break;
            }
            data.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&data);
            if text.contains("the-logout-token") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&data).to_string();
        assert!(
            text.starts_with("POST /backchannel"),
            "delivery must be a POST to the registered URI: {text}"
        );
        assert!(
            text.contains("application/x-www-form-urlencoded"),
            "logout_token is form-encoded: {text}"
        );
        assert!(text.contains("logout_token=the-logout-token"));
        sock.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
            .await
            .expect("ack");
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
        let state = crate::server::ServerState::create(storage, false)
            .await
            .expect("server state");
        (state, tmp)
    }

    fn ext_service(state: crate::server::ServerState) -> salvo::Router {
        Router::new()
            .hoop(salvo::affix_state::inject(state))
            .push(
                Router::with_path("register")
                    .post(register)
                    .push(Router::with_path("{client_id}").get(register_read)),
            )
            .push(
                Router::with_path("end_session")
                    .get(end_session)
                    .post(end_session),
            )
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
