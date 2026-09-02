use crate::db::HttpMethod;
use crate::db::JwtVerify;

use crate::server::ServerState;

use serde::{Deserialize, Serialize};

use salvo::http::Method;
use salvo::prelude::*;
use salvo::rate_limiter::RateIssuer;
use serde::de::DeserializeOwned;
use std::collections::HashMap;
use std::sync::LazyLock;

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiProblem {
    pub status: u16,
    #[serde(rename = "type")]
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl ApiProblem {
    pub fn bad_request(msg: &str) -> Self {
        ApiProblem {
            status: StatusCode::BAD_REQUEST.as_u16(),
            r#type: "bad request".into(),
            detail: Some(msg.into()),
        }
    }
    pub fn not_found(msg: &str) -> Self {
        ApiProblem {
            status: StatusCode::NOT_FOUND.as_u16(),
            r#type: "not_found".into(),
            detail: Some(msg.into()),
        }
    }
    pub fn validation_error(detail: &str) -> Self {
        ApiProblem {
            status: StatusCode::UNPROCESSABLE_ENTITY.as_u16(),
            r#type: "validation_error".into(),
            detail: Some(detail.into()),
        }
    }
    pub fn unauthorized() -> Self {
        ApiProblem {
            status: StatusCode::UNAUTHORIZED.as_u16(),
            r#type: "unauthorized".into(),
            detail: None,
        }
    }
    pub fn forbidden() -> Self {
        ApiProblem {
            status: StatusCode::FORBIDDEN.as_u16(),
            r#type: "forbidden".into(),
            detail: None,
        }
    }
    pub fn conflict(msg: &str) -> Self {
        ApiProblem {
            status: StatusCode::CONFLICT.as_u16(),
            r#type: "conflict".into(),
            detail: Some(msg.into()),
        }
    }
    pub fn server_error(msg: &str) -> Self {
        ApiProblem {
            status: StatusCode::INTERNAL_SERVER_ERROR.as_u16(),
            r#type: "server_error".into(),
            detail: Some(msg.into()),
        }
    }
}

/// Build the role-administration [`Caller`](crate::role::Caller) from the
/// session the `protect` hoop injected into the depot. Returns `None`
/// when no verified session is present — handlers must fail closed.
pub fn caller_from_depot(depot: &Depot) -> Option<crate::role::Caller> {
    depot
        .obtain::<JwtVerify>()
        .ok()
        .map(|v| crate::role::Caller::Jwt(v.jwt_data.clone()))
}

/// Render a role-administration failure with its proper status: 403 for the
/// level gate, 409 for role-name conflicts, 400 for everything else.
pub fn render_admin_error(res: &mut Response, err: anyhow::Error) {
    match err.downcast::<crate::role::AdminError>() {
        Ok(crate::role::AdminError::Forbidden) => {
            res.status_code(StatusCode::FORBIDDEN);
            res.render(Json(ApiProblem::forbidden()));
        }
        Ok(crate::role::AdminError::Conflict(msg)) => {
            res.status_code(StatusCode::CONFLICT);
            res.render(Json(ApiProblem::conflict(&msg)));
        }
        Err(other) => {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(ApiProblem::validation_error(&other.to_string())));
        }
    }
}

#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct ApiResponse<T> {
    pub ok: bool,
    pub data: T,
}

impl<T> ApiResponse<T> {
    pub fn ok(data: T) -> Self {
        ApiResponse { ok: true, data }
    }
}

pub fn get_method(req: &Request) -> HttpMethod {
    match *req.method() {
        Method::GET => HttpMethod::GET,
        Method::CONNECT => HttpMethod::CONNECT,
        Method::DELETE => HttpMethod::DELETE,
        Method::HEAD => HttpMethod::HEAD,
        Method::OPTIONS => HttpMethod::OPTIONS,
        Method::PATCH => HttpMethod::PATCH,
        Method::POST => HttpMethod::POST,
        Method::PUT => HttpMethod::PUT,
        Method::TRACE => HttpMethod::TRACE,
        _ => HttpMethod::GET,
    }
}

/// Parse an HTTP method name (e.g. from `X-Forwarded-Method`).
pub fn parse_http_method(s: &str) -> Option<HttpMethod> {
    match s.trim().to_ascii_uppercase().as_str() {
        "GET" => Some(HttpMethod::GET),
        "CONNECT" => Some(HttpMethod::CONNECT),
        "DELETE" => Some(HttpMethod::DELETE),
        "HEAD" => Some(HttpMethod::HEAD),
        "OPTIONS" => Some(HttpMethod::OPTIONS),
        "PATCH" => Some(HttpMethod::PATCH),
        "POST" => Some(HttpMethod::POST),
        "PUT" => Some(HttpMethod::PUT),
        "TRACE" => Some(HttpMethod::TRACE),
        _ => None,
    }
}

/// The path used for authorization decisions: always the real request path.
///
/// The router already routed on this path, so authorizing against anything
/// else (a client-supplied `X-Forwarded-Uri`) would let a caller choose which
/// policy applies to their request. The only legitimate consumer of
/// `X-Forwarded-Uri` is the forward-auth `verify` endpoint, which opts in
/// explicitly via [`forwarded_origin`].
pub fn get_path(req: &Request) -> &str {
    req.uri().path()
}

/// Split a host value into `(host, port)` sub-slices of the input.
fn split_port(host: &str) -> Option<(&str, &str)> {
    if let Some(end) = host.find(']') {
        // Bracketed IPv6 literal: "[::1]:8080" -> ("[::1]", "8080").
        let rest = &host[end + 1..];
        return if !rest.is_empty() && rest.starts_with(':') {
            Some((&host[..end + 1], &rest[1..]))
        } else {
            None
        };
    }
    let idx = host.rfind(':')?;
    let port = &host[idx + 1..];
    if idx > 0 && !port.is_empty() && port.chars().all(|c| c.is_ascii_digit()) {
        Some((&host[..idx], port))
    } else {
        None
    }
}

/// Strip the port from a host value, returning a sub-slice of the input.
fn strip_port(host: &str) -> Option<&str> {
    split_port(host).map(|(bare, _)| bare)
}

/// Drop the port from a host when it is the scheme's default port
/// (`80`/http, `443`/https); non-default ports are preserved.
fn strip_default_port<'a>(host: &'a str, scheme: &str) -> &'a str {
    let default = if scheme == "https" { "443" } else { "80" };
    match split_port(host) {
        Some((bare, port)) if port == default => bare,
        _ => host,
    }
}

/// Unified tenant-domain resolution — the single place where a tenant is
/// derived from a request. Every endpoint and code path must use this.
///
/// - `trust_forwarded_headers = false` (default): only the raw `Host` header is used.
/// - `trust_forwarded_headers = true`: `X-Forwarded-Host` (first entry) is preferred,
/// falling back to `Host`. Enable only behind a reverse proxy that owns
/// these headers (e.g. Caddy with `header_up X-Forwarded-Host {host}`).
///
/// Candidates are validated against the registered tenant domains; a
/// port-stripped fallback handles clients sending `Host: domain:port`.
/// Returns `(visible_host, registered_domain)`: the host value the client
/// used (port included, exactly as sent) and the registered tenant domain
/// it matched (port stripped). Returns `None` when no registered tenant
/// matches.
fn resolve_host<'a>(req: &'a Request, state: &ServerState) -> Option<(&'a str, &'a str)> {
    let mut candidates: Vec<&'a str> = Vec::new();
    if state.trust_forwarded_headers
        && let Some(first) = req
            .headers()
            .get("X-Forwarded-Host")
            .and_then(|v| v.to_str().ok())
            .and_then(|xfh| xfh.split(',').next())
            .map(str::trim)
        && !first.is_empty()
    {
        candidates.push(first);
    }
    if let Some(host) = req
        .headers()
        .get("Host")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        && !host.is_empty()
    {
        candidates.push(host);
    }
    for candidate in candidates {
        if state.storage.router.contains_key(candidate) {
            return Some((candidate, candidate));
        }
        if let Some(bare) = strip_port(candidate)
            && state.storage.router.contains_key(bare)
        {
            return Some((candidate, bare));
        }
    }
    None
}

/// The registered tenant domain for this request (see [`resolve_host`]).
pub fn get_domain<'a>(req: &'a Request, state: &ServerState) -> Option<&'a str> {
    resolve_host(req, state).map(|(_, domain)| domain)
}

/// The scheme the client used to reach this server: `X-Forwarded-Proto`
/// (first entry) when forwarded headers are trusted, otherwise the actual
/// connection scheme. Untrusted or malformed forwarding values fall back
/// to the connection scheme, so a forged header can never steer the issuer
/// (same trust model as [`get_domain`], /).
fn get_scheme(req: &Request, state: &ServerState) -> String {
    if state.trust_forwarded_headers
        && let Some(first) = req
            .headers()
            .get("X-Forwarded-Proto")
            .and_then(|v| v.to_str().ok())
            .and_then(|proto| proto.split(',').next())
            .map(|p| p.trim().to_ascii_lowercase())
        && (first == "http" || first == "https")
    {
        return first;
    }
    req.scheme().as_str().to_string()
}

/// Original (method, path) of the proxied request, for the forward-auth
/// `verify` endpoint only.
///
/// `None` unless `trust_forwarded_headers` is enabled. The path comes from
/// `X-Forwarded-Uri` (query stripped), the method from `X-Forwarded-Method`
/// (falling back to the actual request method — proxies such as Caddy always
/// send GET to the auth endpoint).
pub fn forwarded_origin<'a>(
    req: &'a Request,
    state: &ServerState,
) -> Option<(HttpMethod, &'a str)> {
    if !state.trust_forwarded_headers {
        return None;
    }
    let path = req
        .headers()
        .get("X-Forwarded-Uri")
        .and_then(|v| v.to_str().ok())?
        .split('?')
        .next()
        .filter(|p| !p.is_empty())?;
    let method = req
        .headers()
        .get("X-Forwarded-Method")
        .and_then(|v| v.to_str().ok())
        .and_then(parse_http_method)
        .unwrap_or_else(|| get_method(req));
    Some((method, path))
}

/// Canonical issuer URL for this request's tenant: `<scheme>://<host>[:<port>]`,
/// built on the unified domain resolver.
///
/// Derived from the request itself — connection scheme (or the trusted
/// proxy's `X-Forwarded-Proto`) and the client-visible host — so the same
/// binary works unchanged as `https://auth.example.com` in production and
/// `http://localhost:8080` in local development; no issuer configuration
/// exists. Non-default ports are kept because discovery builds every
/// endpoint URL from this value, so it must be exactly the URL clients
/// reach the server at. Discovery, token issuance and every `iss`
/// comparison MUST use this one function so the three always agree
/// (OIDC Core §3.1.3.7, RFC 8414 §2).
///
/// Returns `None` when no registered tenant matches the request.
pub fn get_issuer(req: &Request, state: &ServerState) -> Option<String> {
    let (host, _domain) = resolve_host(req, state)?;
    let scheme = get_scheme(req, state);
    let host = strip_default_port(host, scheme.as_str());
    Some(format!("{}://{}", scheme, host))
}

pub fn get_jwt(req: &Request) -> Option<&str> {
    req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| {
            // Check if the header starts with "Bearer " (case-insensitive)
            // and return the part after the prefix.
            if h.to_lowercase().starts_with("bearer ") {
                Some(&h["bearer ".len()..])
            } else {
                // If you support plain token strings without the prefix,
                // remove this block or return None if strictly "Bearer" is required.
                None
            }
        })
}

// ─────────────────────────────────────────────────────────────────────────────
// Token lifecycle primitives (Step 1 of the API consolidation plan)
//
// Every endpoint that validates or revokes a token goes through exactly one
// of the two primitives below. Before this consolidation the internal
// (`/api/v1/auth/*`) and OIDC (`/introspect`, `/userinfo`, `/revoke`) paths
// each carried their own revocation checks and divergent guarantees.
// ─────────────────────────────────────────────────────────────────────────────

/// Why a token failed [`validate_token`]. Endpoints map these to their wire
/// errors; the variants carry no token-derived data, so error responses
/// never leak which check failed beyond what the caller already knows.
#[derive(Debug)]
pub enum TokenReject {
    /// Structure, `kid` lookup, signature or expiry failed (`jwt_decode`).
    Invalid,
    /// The `iss` claim does not match this tenant's canonical issuer.
    IssuerMismatch,
    /// The token is recorded in the process-wide revocation store.
    Revoked,
    /// The token carries a rejected `typ` marker (e.g. a refresh token
    /// presented where only access tokens are accepted).
    TypeMismatch,
    /// The token is bound to a different tenant domain.
    DomainMismatch,
}

impl std::fmt::Display for TokenReject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let msg = match self {
            TokenReject::Invalid => "token is invalid or expired",
            TokenReject::IssuerMismatch => "token issuer does not match",
            TokenReject::Revoked => "token is revoked",
            TokenReject::TypeMismatch => "token type is not accepted here",
            TokenReject::DomainMismatch => "token is bound to another tenant domain",
        };
        f.write_str(msg)
    }
}

/// The request context the tenant policy engine evaluates against. Passing
/// this in [`ValidateOpts::policy`] opts the validation into RBAC; omitting
/// it keeps the decision at token validity alone.
#[derive(Clone, Copy)]
pub struct PolicyCtx<'a> {
    pub act: &'a HttpMethod,
    pub path: &'a str,
    pub query: &'a HashMap<String, String>,
    pub header: &'a HashMap<String, String>,
}

/// Options for [`validate_token`]. All fields default to off: a bare
/// `ValidateOpts::default()` validates signature, expiry, issuer and
/// revocation only — the semantics OIDC introspection/userinfo need.
#[derive(Default, Clone, Copy)]
pub struct ValidateOpts<'a> {
    /// Evaluate the tenant policy engine against this request context.
    /// `None` skips the engine entirely (session hoop, `/introspect`,
    /// `/userinfo`) — token validity alone decides.
    pub policy: Option<PolicyCtx<'a>>,
    /// Require the token's bound domain to equal the request's tenant
    /// domain (session tokens are tenant-bound).
    pub domain_bound: bool,
    /// Reject tokens whose `typ` marker equals this value (e.g. `"refresh"`
    /// at `/userinfo`, where a refresh token must never pass as an access
    /// token).
    pub reject_typ: Option<&'a str>,
}

/// The outcome of [`validate_token`]: the decoded claim envelope plus the
/// authorization decision. Without a policy check a valid token yields
/// `can_access = true`; with one, the engine decides (deny by default).
pub struct TokenDecision<T> {
    pub claims: crate::jwt::Claim<T>,
    pub can_access: bool,
    pub expect_mfa: bool,
}

/// The single token-validation primitive (Step 1.1): signature, expiry,
/// issuer, `typ`, tenant-domain binding, revocation — and, opt-in, the
/// tenant policy engine. Every validation path in the server calls this:
/// the `verify`/`protect`/`session` hoops through the request adapters
/// below, `/introspect` and `/userinfo` directly.
///
/// Policy evaluation is an opt-in flag so OIDC semantics are preserved:
/// introspection reports token validity to relying parties and never runs
/// the engine. When the engine runs it denies by default — a token whose
/// roles match no policy is rejected, exactly as before.
pub async fn validate_token<T>(
    tenant: &mut crate::db::Tenant,
    issuer: &str,
    domain: &str,
    jwt: &str,
    opts: ValidateOpts<'_>,
) -> Result<TokenDecision<T>, TokenReject>
where
    T: serde::de::DeserializeOwned + crate::db::TokenPayload,
{
    // Revocation gate first: the store is the only authority on
    // revocation state, and checking it before decoding keeps a revoked
    // token from being processed any further on every path.
    if crate::jwt::InvalidJwt::global().is_valid(jwt).await {
        return Err(TokenReject::Revoked);
    }
    let all_data = crate::jwt::jwt_decode::<T>(jwt, 2, tenant)
        .await
        .map_err(|_| TokenReject::Invalid)?;
    if all_data.claims.iss != issuer {
        return Err(TokenReject::IssuerMismatch);
    }
    if let Some(rejected) = opts.reject_typ
        && all_data.claims.data.typ() == Some(rejected)
    {
        return Err(TokenReject::TypeMismatch);
    }
    if opts.domain_bound && all_data.claims.data.bound_domain() != Some(domain) {
        return Err(TokenReject::DomainMismatch);
    }

    let (can_access, expect_mfa) = match opts.policy {
        // No policy engine requested: a token that survived the checks
        // above is a valid session.
        None => (true, false),
        Some(ctx) => {
            let mut permitted: Option<bool> = None;
            let mut expect_mfa: bool = false;
            // Only internal session claims carry roles the engine can
            // evaluate; any other payload is denied by default here.
            if let Some(data) = all_data.claims.data.jwt_data()
                && let Some(domain_map) = tenant.policies.get(domain)
            {
                let target_path: Vec<&str> = ctx.path.split("/").collect();
                'outer: for r in &data.roles {
                    if let Some(policies) = domain_map.get(r) {
                        let ps = policies.value();
                        for p in ps {
                            match p.can_access(
                                ctx.act,
                                domain,
                                data,
                                &target_path,
                                ctx.query,
                                ctx.header,
                            ) {
                                None => continue,
                                Some(tmp) => {
                                    expect_mfa |= tmp.expect_mfa;
                                    if tmp.can_access {
                                        if permitted.is_none() {
                                            permitted = Some(true);
                                        }
                                    } else {
                                        permitted = Some(false);
                                        break 'outer;
                                    }
                                }
                            }
                        }
                    }
                }
            }
            // Reject by default: no applicable policy means no access.
            (matches!(permitted, Some(true)), expect_mfa)
        }
    };

    Ok(TokenDecision {
        claims: all_data.claims,
        can_access,
        expect_mfa,
    })
}

/// The single revocation primitive (Step 1.2): record `jwt` in the
/// process-wide `InvalidJwt` store so every path that consults the store —
/// [`validate_token`], refresh rotation, `/introspect`, `/userinfo` —
/// rejects it from now on. `auth/logout`, RFC 7009 `/revoke` and (later)
/// RP-Initiated Logout are all callers of this one function, never separate
/// implementations.
///
/// `exp` is the token's expiry when the caller already holds a decoded
/// claim envelope; pass `None` to have the token decoded here (which also
/// refuses garbage input, matching the historical logout behavior).
///
/// Returns `true` when THIS call recorded the revocation and `false` when
/// the token was already revoked — the store's insert-wins atomicity makes
/// this the commit point for refresh rotation, exactly as `handle_refresh`
/// relies on it.
pub async fn revoke_token(
    tenant: &mut crate::db::Tenant,
    jwt: &str,
    exp: Option<jiff::Timestamp>,
    reason: &str,
) -> anyhow::Result<bool> {
    let store = crate::jwt::InvalidJwt::global();
    let newly = match exp {
        Some(exp) => store.invalid_raw(jwt, exp).await?,
        None => store.invalid(jwt, tenant).await?,
    };
    tracing::debug!(target: "auth::revoke", reason, newly, "token revocation recorded");
    Ok(newly)
}

fn jwt_verify_from(decision: TokenDecision<crate::db::JwtData>, domain: &str) -> JwtVerify {
    JwtVerify {
        can_access: decision.can_access,
        jwt_data: decision.claims.data,
        expect_mfa: decision.expect_mfa,
        domain: domain.to_string(),
        auth_time: decision.claims.auth_time,
    }
}

pub async fn validate_jwt(req: &Request, depot: &mut Depot) -> Option<JwtVerify> {
    validate_jwt_for(req, depot, None).await
}

/// Validate the bearer JWT and evaluate the tenant policy engine.
///
/// `at` optionally overrides the (method, path) the policy is evaluated
/// against. Only the forward-auth `verify` endpoint passes the original
/// proxied request here (via [`forwarded_origin`]); every in-process caller
/// passes `None`, which authorizes against the real request the router
/// matched.
pub async fn validate_jwt_for(
    req: &Request,
    depot: &mut Depot,
    at: Option<(HttpMethod, &str)>,
) -> Option<JwtVerify> {
    let jwt = get_jwt(req)?;
    let _port = req.local_addr().port()?;
    let state = depot.obtain_mut::<ServerState>().ok()?;
    let domain = get_domain(req, state)?;
    let issuer = get_issuer(req, state)?;
    let (method, path) = match at {
        Some((m, p)) => (m, p.to_string()),
        None => (get_method(req), get_path(req).to_string()),
    };
    let mut tenant = state.storage.tenant_by_domain(domain)?;
    let query_map: HashMap<String, String> = req
        .queries()
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let header_map: HashMap<String, String> = req
        .headers()
        .iter()
        .map(|(k, v)| {
            (
                k.as_str().to_lowercase().to_string(),
                v.to_str().unwrap_or_default().to_string(),
            )
        })
        .collect();
    let decision = validate_token::<crate::db::JwtData>(
        &mut tenant,
        &issuer,
        domain,
        jwt,
        ValidateOpts {
            policy: Some(PolicyCtx {
                act: &method,
                path: &path,
                query: &query_map,
                header: &header_map,
            }),
            ..Default::default()
        },
    )
    .await
    .ok()?;
    Some(jwt_verify_from(decision, domain))
}

/// Validate the bearer JWT as a *session* for the self-service auth
/// endpoints, skipping the policy engine: these endpoints are how a
/// session acquires factors, so RBAC-gating them is circular (a token
/// denied for missing MFA must still be able to complete MFA). Returns the
/// session when the token is cryptographically valid, unrevoked, and bound
/// to this tenant.
pub async fn validate_session(req: &Request, depot: &mut Depot) -> Option<JwtVerify> {
    let jwt = get_jwt(req)?;
    let state = depot.obtain_mut::<ServerState>().ok()?;
    let domain = get_domain(req, state)?;
    let issuer = get_issuer(req, state)?;
    let mut tenant = state.storage.tenant_by_domain(domain)?;
    let decision = validate_token::<crate::db::JwtData>(
        &mut tenant,
        &issuer,
        domain,
        jwt,
        ValidateOpts {
            domain_bound: true,
            ..Default::default()
        },
    )
    .await
    .ok()?;
    Some(jwt_verify_from(decision, domain))
}

pub async fn refresh_jwt(req: &Request, depot: &mut Depot) -> Option<String> {
    let jwt = get_jwt(req)?;

    let state = depot.obtain_mut::<ServerState>().ok()?;
    let domain = get_domain(req, state)?;
    let issuer = get_issuer(req, state)?;
    let mut tenant = state.storage.tenant_by_domain(domain)?;
    tenant.refresh_jwt(&issuer, domain, jwt, 15).await.ok()
}

pub enum ExtractSource {
    Form,
    Body,
    Query,
}

pub async fn extract<T>(req: &mut Request, source: Option<ExtractSource>) -> Option<T>
where
    T: DeserializeOwned,
{
    match source {
        None => {
            if let Ok(data) = req.parse_form::<T>().await {
                return Some(data);
            }
            if let Ok(data) = req.parse_json::<T>().await {
                return Some(data);
            }
            if let Ok(data) = req.parse_queries::<T>() {
                return Some(data);
            }
            None
        }
        Some(ExtractSource::Form) => {
            if let Ok(data) = req.parse_form::<T>().await {
                return Some(data);
            }
            None
        }
        Some(ExtractSource::Body) => {
            if let Ok(data) = req.parse_json::<T>().await {
                return Some(data);
            }
            None
        }
        Some(ExtractSource::Query) => {
            if let Ok(data) = req.parse_queries::<T>() {
                return Some(data);
            }
            None
        }
    }
}

/// Client identity for rate limiting: the client IP, nothing else.
///
/// The old key mixed the peer socket address — *including its ephemeral
/// port*, so every new TCP connection was already a fresh identity — with an
/// `X-User-ID` header or `name` query chosen by the caller, so rotating the
/// header bought a fresh budget. Both are gone; the key is now the bare IP.
///
/// Which IP depends on the same trust model as [`get_domain`]/[`get_issuer`]
///, because behind a forward-auth proxy (Caddy/Traefik) the TCP
/// peer is the proxy itself and keying on it would put **every** client
/// behind one shared budget:
///
/// - `trust_forwarded_headers = false` (default, direct connections): the
/// peer's IP.
/// - `trust_forwarded_headers = true`: the **rightmost** `X-Forwarded-For`
/// entry — the one written by the trusted proxy directly in front of this
/// server. Caddy's `forward_auth` (a `reverse_proxy`) discards client-sent
/// `X-Forwarded-For` unless `trusted_proxies` is configured and writes the
/// real client IP; Traefik's ForwardAuth sends the source IP the same way.
/// The *leftmost* entry is deliberately not used: with CDN/`trusted_proxies`
/// chains both proxies preserve client-supplied entries to the left of the
/// ones they append, so the left side is spoofable and would reintroduce
/// the identity-rotation bypass. The rightmost entry is always an address
/// observed by trusted infrastructure — in a multi-hop chain it may
/// identify the last proxy's peer rather than the end client (coarse, but
/// never attacker-chosen). Missing/unparseable values fall back to the peer.
fn client_ip(req: &Request, depot: &Depot) -> String {
    let trusted = depot
        .obtain::<ServerState>()
        .map(|state| state.trust_forwarded_headers)
        .unwrap_or(false);
    if trusted
        && let Some(xff) = req
            .headers()
            .get("X-Forwarded-For")
            .and_then(|v| v.to_str().ok())
        && let Some(last) = xff
            .rsplit(',')
            .next()
            .map(str::trim)
            .filter(|ip| !ip.is_empty())
    {
        return last.to_string();
    }
    req.remote_addr()
        .ip()
        .map(|ip| ip.to_string())
        .unwrap_or_else(|| req.remote_addr().to_string())
}

pub struct JanuxIssuer;

impl RateIssuer for JanuxIssuer {
    type Key = String;
    async fn issue(&self, req: &mut Request, depot: &Depot) -> Option<Self::Key> {
        Some(client_ip(req, depot))
    }
}

/// per-recipient dispatch throttle — `(window_start, count)` per
/// identifier, keyed `email:<addr>` / `mobile:<number>`. The per-IP quota
/// on `/api/v1/auth` only bounds single-source floods; distributed clients
/// could still SMS-bomb one phone or burn the mail quota. Entries die
/// shortly after their window closes.
static SEND_THROTTLE: LazyLock<crate::cache::EphemCache<String, (i64, u64)>> =
    LazyLock::new(|| crate::cache::EphemCache::new("send_throttle", Some(120)));

/// fixed-window budget per recipient identifier, independent of the
/// client IP. Returns `true` while `key` has sent fewer than `limit`
/// requests in the current 60 s window. The identifier is only known after
/// body extraction, so this runs inside the handlers (a hoop issuer cannot
/// read the body without consuming it).
pub async fn send_throttle_allows(key: &str, limit: u64) -> bool {
    let now = jiff::Timestamp::now().as_second();
    let window = now - now.rem_euclid(60);
    match SEND_THROTTLE
        .get_mut(key, |entry| {
            if entry.0 != window {
                *entry = (window, 1);
                return true;
            }
            if entry.1 >= limit {
                return false;
            }
            entry.1 += 1;
            true
        })
        .await
    {
        Some(allowed) => allowed,
        None => {
            // First hit in this window. A racing insert may overwrite
            // this one — the budget is approximate under concurrency by
            // design (the IP quota still bounds every single source).
            SEND_THROTTLE
                .insert(key.to_string(), (window, 1))
                .await
                .ok();
            true
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use salvo::http::header::HOST;
    use salvo::http::header::HeaderName;

    /// ServerState with an in-memory router table — no storage init, no
    /// revocation store, no runtime dependencies.
    async fn test_state(trust_forwarded_headers: bool, domains: &[&str]) -> ServerState {
        let storage = crate::db::Storage {
            raw_path: std::path::PathBuf::from("/tmp/janux-resolver-tests"),
            tenants: dashmap::DashMap::new(),
            router: dashmap::DashMap::new(),
            topology: tokio::sync::Mutex::new(()),
        };
        for d in domains {
            storage
                .router
                .insert((*d).to_string(), "test-tenant".to_string());
        }
        ServerState::create(storage, trust_forwarded_headers)
            .await
            .expect("server state")
    }

    fn req_with(
        host: Option<&str>,
        xfh: Option<&str>,
        xfu: Option<&str>,
        xfm: Option<&str>,
        path: &str,
    ) -> Request {
        let mut req = Request::new();
        if let Some(h) = host {
            req.headers_mut().insert(HOST, h.parse().unwrap());
        }
        if let Some(h) = xfh {
            req.headers_mut().insert(
                HeaderName::from_static("x-forwarded-host"),
                h.parse().unwrap(),
            );
        }
        if let Some(u) = xfu {
            req.headers_mut().insert(
                HeaderName::from_static("x-forwarded-uri"),
                u.parse().unwrap(),
            );
        }
        if let Some(m) = xfm {
            req.headers_mut().insert(
                HeaderName::from_static("x-forwarded-method"),
                m.parse().unwrap(),
            );
        }
        req.set_uri(path.parse().unwrap());
        req
    }

    // ── get_domain: untrusted mode (default) ────────────────────────────────

    #[tokio::test]
    async fn domain_untrusted_resolves_from_host_header() {
        let state = test_state(false, &["tenant.example.com"]).await;
        let req = req_with(Some("tenant.example.com"), None, None, None, "/");
        assert_eq!(get_domain(&req, &state), Some("tenant.example.com"));
    }

    #[tokio::test]
    async fn domain_untrusted_ignores_x_forwarded_host() {
        // regression: a spoofed X-Forwarded-Host must never steer tenant
        // resolution when forwarding headers are not trusted.
        let state = test_state(false, &["tenant.example.com", "victim.example.com"]).await;
        let req = req_with(
            Some("tenant.example.com"),
            Some("victim.example.com"),
            None,
            None,
            "/",
        );
        assert_eq!(get_domain(&req, &state), Some("tenant.example.com"));

        // Known XFH + unknown Host → rejection, not fallback to XFH.
        let req = req_with(
            Some("unknown.example.com"),
            Some("victim.example.com"),
            None,
            None,
            "/",
        );
        assert_eq!(get_domain(&req, &state), None);
    }

    #[tokio::test]
    async fn domain_untrusted_strips_port_from_host() {
        let state = test_state(false, &["tenant.example.com"]).await;
        let req = req_with(Some("tenant.example.com:8080"), None, None, None, "/");
        assert_eq!(get_domain(&req, &state), Some("tenant.example.com"));
    }

    #[tokio::test]
    async fn domain_unknown_or_missing_host_is_none() {
        let state = test_state(false, &["tenant.example.com"]).await;
        let req = req_with(Some("evil.example.com"), None, None, None, "/");
        assert_eq!(get_domain(&req, &state), None);
        let req = req_with(None, None, None, None, "/");
        assert_eq!(get_domain(&req, &state), None);
    }

    // ── get_domain: trusted mode ────────────────────────────────────────────

    #[tokio::test]
    async fn domain_trusted_prefers_x_forwarded_host() {
        let state = test_state(true, &["public.example.com", "internal.upstream"]).await;
        let req = req_with(
            Some("internal.upstream"),
            Some("public.example.com"),
            None,
            None,
            "/",
        );
        assert_eq!(get_domain(&req, &state), Some("public.example.com"));
    }

    #[tokio::test]
    async fn domain_trusted_falls_back_to_host() {
        let state = test_state(true, &["tenant.example.com"]).await;
        // Unknown XFH falls back to Host.
        let req = req_with(
            Some("tenant.example.com"),
            Some("unknown.example.com"),
            None,
            None,
            "/",
        );
        assert_eq!(get_domain(&req, &state), Some("tenant.example.com"));
        // Missing XFH uses Host.
        let req = req_with(Some("tenant.example.com"), None, None, None, "/");
        assert_eq!(get_domain(&req, &state), Some("tenant.example.com"));
    }

    #[tokio::test]
    async fn domain_trusted_uses_first_x_forwarded_host_entry_and_strips_port() {
        let state = test_state(true, &["tenant.example.com"]).await;
        let req = req_with(
            Some("other.example.com"),
            Some("tenant.example.com:8443, proxy.internal"),
            None,
            None,
            "/",
        );
        assert_eq!(get_domain(&req, &state), Some("tenant.example.com"));
    }

    // ── get_path: always the real path ────────────────────────────────

    #[tokio::test]
    async fn path_is_always_the_real_request_path() {
        let req = req_with(
            Some("tenant.example.com"),
            None,
            Some("/api/v1/some/allowed/path"),
            None,
            "/api/v1/admin/user/delete",
        );
        assert_eq!(get_path(&req), "/api/v1/admin/user/delete");
    }

    // ── forwarded_origin: forward-auth opt-in ───────────────────────────────

    #[tokio::test]
    async fn forwarded_origin_disabled_is_none() {
        let state = test_state(false, &["tenant.example.com"]).await;
        let req = req_with(
            Some("tenant.example.com"),
            None,
            Some("/orig"),
            Some("POST"),
            "/api/v1/auth/verify",
        );
        assert!(forwarded_origin(&req, &state).is_none());
    }

    #[tokio::test]
    async fn forwarded_origin_trusted_returns_original_method_and_path() {
        let state = test_state(true, &["tenant.example.com"]).await;
        let req = req_with(
            Some("tenant.example.com"),
            None,
            Some("/orig/path?with=query"),
            Some("delete"),
            "/api/v1/auth/verify",
        );
        let (method, path) = forwarded_origin(&req, &state).expect("forwarded origin");
        assert_eq!(method, HttpMethod::DELETE);
        assert_eq!(path, "/orig/path");
    }

    #[tokio::test]
    async fn forwarded_origin_trusted_falls_back_to_real_method() {
        let state = test_state(true, &["tenant.example.com"]).await;
        let req = req_with(
            Some("tenant.example.com"),
            None,
            Some("/orig"),
            None,
            "/api/v1/auth/verify",
        );
        let (method, path) = forwarded_origin(&req, &state).expect("forwarded origin");
        assert_eq!(method, HttpMethod::GET); // Request::new default
        assert_eq!(path, "/orig");
    }

    #[tokio::test]
    async fn forwarded_origin_without_uri_is_none() {
        let state = test_state(true, &["tenant.example.com"]).await;
        let req = req_with(Some("tenant.example.com"), None, None, Some("POST"), "/");
        assert!(forwarded_origin(&req, &state).is_none());
    }

    // ── get_issuer / parse_http_method ──────────────────────────────────────

    fn with_proto(mut req: Request, proto: &str) -> Request {
        req.headers_mut().insert(
            HeaderName::from_static("x-forwarded-proto"),
            proto.parse().unwrap(),
        );
        req
    }

    fn with_scheme(mut req: Request, scheme: salvo::http::uri::Scheme) -> Request {
        *req.scheme_mut() = scheme;
        req
    }

    #[tokio::test]
    async fn issuer_uses_connection_scheme_and_keeps_non_default_port() {
        // Request::new defaults to the http scheme — a local dev deployment
        // must advertise an http issuer that includes the port.
        let state = test_state(false, &["localhost"]).await;
        let req = req_with(Some("localhost:8080"), None, None, None, "/");
        assert_eq!(
            get_issuer(&req, &state),
            Some("http://localhost:8080".to_string())
        );
    }

    #[tokio::test]
    async fn issuer_uses_https_when_the_connection_is_tls() {
        let state = test_state(false, &["tenant.example.com"]).await;
        let req = with_scheme(
            req_with(Some("tenant.example.com"), None, None, None, "/"),
            salvo::http::uri::Scheme::HTTPS,
        );
        assert_eq!(
            get_issuer(&req, &state),
            Some("https://tenant.example.com".to_string())
        );
    }

    #[tokio::test]
    async fn issuer_strips_default_ports() {
        let state = test_state(false, &["tenant.example.com"]).await;
        let req = with_scheme(
            req_with(Some("tenant.example.com:443"), None, None, None, "/"),
            salvo::http::uri::Scheme::HTTPS,
        );
        assert_eq!(
            get_issuer(&req, &state),
            Some("https://tenant.example.com".to_string())
        );
        let req = req_with(Some("tenant.example.com:80"), None, None, None, "/");
        assert_eq!(
            get_issuer(&req, &state),
            Some("http://tenant.example.com".to_string())
        );
        // Non-default port for the scheme is preserved.
        let req = req_with(Some("tenant.example.com:8443"), None, None, None, "/");
        assert_eq!(
            get_issuer(&req, &state),
            Some("http://tenant.example.com:8443".to_string())
        );
    }

    #[tokio::test]
    async fn issuer_trusted_mode_uses_forwarded_proto_and_host() {
        let state = test_state(true, &["public.example.com"]).await;
        let req = with_proto(
            req_with(
                Some("internal.upstream"),
                Some("public.example.com"),
                None,
                None,
                "/",
            ),
            "https",
        );
        assert_eq!(
            get_issuer(&req, &state),
            Some("https://public.example.com".to_string())
        );
    }

    #[tokio::test]
    async fn issuer_untrusted_mode_ignores_forwarded_proto() {
        // /regression: a spoofed X-Forwarded-Proto must never steer
        // the issuer when forwarding headers are not trusted.
        let state = test_state(false, &["tenant.example.com"]).await;
        let req = with_proto(
            req_with(Some("tenant.example.com"), None, None, None, "/"),
            "https",
        );
        assert_eq!(
            get_issuer(&req, &state),
            Some("http://tenant.example.com".to_string())
        );
    }

    #[tokio::test]
    async fn issuer_trusted_mode_rejects_invalid_forwarded_proto() {
        let state = test_state(true, &["tenant.example.com"]).await;
        let req = with_proto(
            req_with(Some("tenant.example.com"), None, None, None, "/"),
            "ftp",
        );
        assert_eq!(
            get_issuer(&req, &state),
            Some("http://tenant.example.com".to_string())
        );
    }

    #[tokio::test]
    async fn issuer_unknown_tenant_is_none() {
        let state = test_state(false, &["tenant.example.com"]).await;
        let req = req_with(Some("unknown.example.com"), None, None, None, "/");
        assert_eq!(get_issuer(&req, &state), None);
    }

    #[test]
    fn parse_http_method_accepts_known_methods() {
        assert_eq!(parse_http_method("GET"), Some(HttpMethod::GET));
        assert_eq!(parse_http_method("post"), Some(HttpMethod::POST));
        assert_eq!(parse_http_method(" Delete "), Some(HttpMethod::DELETE));
        assert_eq!(parse_http_method(""), None);
        assert_eq!(parse_http_method("HACK"), None);
    }

    // ── rate-limit identity is the client IP, not spoofable ──────────

    fn with_xff(mut req: Request, xff: &str) -> Request {
        req.headers_mut().insert(
            HeaderName::from_static("x-forwarded-for"),
            xff.parse().unwrap(),
        );
        req
    }

    fn with_peer(mut req: Request, peer: &str) -> Request {
        *req.remote_addr_mut() = peer.parse::<std::net::SocketAddr>().unwrap().into();
        req
    }

    fn depot_with(state: ServerState) -> Depot {
        let mut depot = Depot::new();
        depot.inject(state);
        depot
    }

    #[tokio::test]
    async fn rate_key_untrusted_is_the_peer_ip_without_port() {
        let state = test_state(false, &["tenant.example.com"]).await;
        let depot = depot_with(state);
        // The ephemeral port must not be part of the key — otherwise every
        // new TCP connection is a fresh rate-limit identity.
        let req = with_peer(Request::new(), "203.0.113.7:55555");
        assert_eq!(client_ip(&req, &depot), "203.0.113.7");
    }

    #[tokio::test]
    async fn rate_key_untrusted_ignores_x_forwarded_for() {
        // /regression: without trusted forwarding headers a spoofed
        // XFF must not steer the rate-limit identity.
        let state = test_state(false, &["tenant.example.com"]).await;
        let depot = depot_with(state);
        let req = with_peer(with_xff(Request::new(), "1.2.3.4"), "203.0.113.7:55555");
        assert_eq!(client_ip(&req, &depot), "203.0.113.7");
    }

    #[tokio::test]
    async fn rate_key_trusted_uses_the_rightmost_xff_entry() {
        // Behind Caddy/Traefik the peer is the proxy; the trusted proxy
        // appends the address it observed. Entries further left can be
        // client-supplied (CDN/trusted_proxies chains preserve them), so only
        // the rightmost one is acceptable.
        let state = test_state(true, &["tenant.example.com"]).await;
        let depot = depot_with(state);
        let req = with_peer(
            with_xff(Request::new(), "6.6.6.6, 10.0.0.1, 203.0.113.9"),
            "127.0.0.1:1000",
        );
        assert_eq!(client_ip(&req, &depot), "203.0.113.9");
    }

    #[tokio::test]
    async fn rate_key_trusted_single_entry_is_the_client() {
        // The common forward-auth topology: the proxy writes exactly one
        // entry — the client IP.
        let state = test_state(true, &["tenant.example.com"]).await;
        let depot = depot_with(state);
        let req = with_peer(with_xff(Request::new(), "198.51.100.23"), "127.0.0.1:1000");
        assert_eq!(client_ip(&req, &depot), "198.51.100.23");
    }

    #[tokio::test]
    async fn rate_key_trusted_falls_back_to_the_peer() {
        let state = test_state(true, &["tenant.example.com"]).await;
        let depot = depot_with(state);
        let req = with_peer(Request::new(), "203.0.113.7:55555");
        assert_eq!(client_ip(&req, &depot), "203.0.113.7");
        // Whitespace-only header also falls back.
        let req = with_peer(with_xff(Request::new(), " , "), "203.0.113.7:55555");
        assert_eq!(client_ip(&req, &depot), "203.0.113.7");
    }

    // ── end-to-end: the real limiter, both deployment modes ───────────
    //
    // These run the actual `RateLimiter` + `JanuxIssuer` through a `Service`
    // wired like `main.rs`: affix (ServerState) hoop on the root router, the
    // limiter on a child router — which also proves ServerState reaches the
    // issuer's depot (without it, trusted mode would silently key on the
    // proxy's peer address and the "second client" assertions below fail).

    use salvo::rate_limiter::{BasicQuota, FixedGuard, MokaStore, RateLimiter};

    #[handler]
    async fn ok_handler(res: &mut Response) {
        res.render(Text::Plain("ok"));
    }

    fn limited_service(state: ServerState) -> Service {
        let limiter = RateLimiter::new(
            FixedGuard::new(),
            MokaStore::new(),
            JanuxIssuer,
            BasicQuota::per_minute(3),
        );
        Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(state))
                .push(Router::with_path("auth").hoop(limiter).get(ok_handler)),
        )
    }

    fn ip_request(peer: &str, xff: Option<&str>) -> Request {
        let mut req = Request::new();
        req.set_uri("http://tenant.example.com/auth".parse().unwrap());
        *req.remote_addr_mut() = peer.parse::<std::net::SocketAddr>().unwrap().into();
        if let Some(xff) = xff {
            req.headers_mut().insert(
                HeaderName::from_static("x-forwarded-for"),
                xff.parse().unwrap(),
            );
        }
        req
    }

    /// Mode 1: forward-auth behind a proxy (`trust_forwarded_headers = true`).
    /// Every request arrives from the proxy's peer address; the identity must
    /// come from the trusted proxy's `X-Forwarded-For` entry.
    #[tokio::test]
    async fn limiter_behind_a_proxy_keys_on_the_forwarded_client() {
        let state = test_state(true, &["tenant.example.com"]).await;
        let service = limited_service(state);
        const PROXY: &str = "127.0.0.1:1000";

        for _ in 0..3 {
            let res = service
                .handle(ip_request(PROXY, Some("203.0.113.10")))
                .await;
            assert_eq!(res.status_code, Some(StatusCode::OK));
        }
        // 4th request from the same client exhausts the budget…
        let res = service
            .handle(ip_request(PROXY, Some("203.0.113.10")))
            .await;
        assert_eq!(res.status_code, Some(StatusCode::TOO_MANY_REQUESTS));

        // …but a different client behind the SAME proxy still gets through:
        // the key is the forwarded client IP, not the shared proxy peer.
        let res = service
            .handle(ip_request(PROXY, Some("203.0.113.11")))
            .await;
        assert_eq!(res.status_code, Some(StatusCode::OK));

        // Rotating client-supplied entries to the LEFT of the trusted
        // proxy's entry buys nothing — the rightmost entry is the identity.
        let res = service
            .handle(ip_request(PROXY, Some("6.6.6.6, 203.0.113.10")))
            .await;
        assert_eq!(res.status_code, Some(StatusCode::TOO_MANY_REQUESTS));
    }

    /// Mode 2: stand-alone (`trust_forwarded_headers = false`). The identity
    /// is the TCP peer; client-sent `X-Forwarded-For` must be ignored.
    #[tokio::test]
    async fn limiter_standalone_keys_on_the_peer_and_ignores_xff() {
        let state = test_state(false, &["tenant.example.com"]).await;
        let service = limited_service(state);

        for _ in 0..3 {
            let res = service
                .handle(ip_request("203.0.113.20:4000", Some("6.6.6.6")))
                .await;
            assert_eq!(res.status_code, Some(StatusCode::OK));
        }
        // 4th request from the same peer exhausts the budget — the spoofed
        // XFF did not create a separate identity…
        let res = service
            .handle(ip_request("203.0.113.20:4000", Some("6.6.6.6")))
            .await;
        assert_eq!(res.status_code, Some(StatusCode::TOO_MANY_REQUESTS));

        // …and a different peer sending the SAME spoofed XFF is a fresh
        // identity: the key is the peer IP, not the header.
        let res = service
            .handle(ip_request("203.0.113.21:4000", Some("6.6.6.6")))
            .await;
        assert_eq!(res.status_code, Some(StatusCode::OK));
    }

    // ── per-recipient dispatch throttle ──────────────────────────────

    #[tokio::test]
    async fn send_throttle_enforces_the_window_budget() {
        let key = format!("g76:{}", uuid::Uuid::new_v4());
        for _ in 0..3 {
            assert!(send_throttle_allows(&key, 3).await);
        }
        assert!(
            !send_throttle_allows(&key, 3).await,
            "the budget must be exhausted after the limit"
        );

        // A different identifier has its own budget.
        let other = format!("g76:{}", uuid::Uuid::new_v4());
        assert!(send_throttle_allows(&other, 3).await);
    }

    #[tokio::test]
    async fn send_throttle_resets_on_a_new_window() {
        let key = format!("g76:{}", uuid::Uuid::new_v4());
        // Seed an exhausted budget from a long-gone window.
        SEND_THROTTLE
            .insert(key.clone(), (0, 999))
            .await
            .expect("seed");
        assert!(
            send_throttle_allows(&key, 3).await,
            "a new window must reset the budget"
        );
    }
}
