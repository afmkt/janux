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
    pub fn too_many_requests(detail: &str) -> Self {
        ApiProblem {
            status: StatusCode::TOO_MANY_REQUESTS.as_u16(),
            r#type: "too_many_requests".into(),
            detail: Some(detail.into()),
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

/// Default page size for paginated list endpoints.
pub const DEFAULT_PAGE_LIMIT: usize = 50;

/// Hard cap on page size, matching SCIM's `filter.maxResults`.
pub const MAX_PAGE_LIMIT: usize = 200;

/// Parse the `limit`/`offset` query parameters shared by all paginated list
/// endpoints. `limit` is clamped to `[1, MAX_PAGE_LIMIT]` (default
/// [`DEFAULT_PAGE_LIMIT`]); a missing or malformed `offset` falls back to 0.
/// `offset` is capped at `i64::MAX` because toasty's query builder panics on
/// larger values.
pub fn page_params(req: &Request) -> (usize, usize) {
    let limit = req
        .query::<usize>("limit")
        .unwrap_or(DEFAULT_PAGE_LIMIT)
        .clamp(1, MAX_PAGE_LIMIT);
    let offset = req
        .query::<usize>("offset")
        .unwrap_or(0)
        .min(i64::MAX as usize);
    (limit, offset)
}

/// Translate a client-facing page window into safe toasty query bounds:
/// fetch one extra row to probe for a next page (see [`Page::from_rows`]),
/// and keep both values within the `i64` range toasty's builder requires
/// (it panics above `i64::MAX`).
pub fn page_bounds(limit: usize, offset: usize) -> (usize, usize) {
    (
        limit.saturating_add(1).min(i64::MAX as usize),
        offset.min(i64::MAX as usize),
    )
}

/// Pagination envelope for list endpoints. `next_offset` is `Some` only when
/// more rows follow this page, so clients can loop without a total count.
#[derive(Debug, Serialize, Deserialize, ToSchema)]
pub struct Page<T> {
    pub items: Vec<T>,
    pub limit: usize,
    pub offset: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_offset: Option<usize>,
}

impl<T> Page<T> {
    /// Build a page from rows fetched with `limit + 1`: the extra probe row
    /// (when present) signals that more data follows and is dropped. This
    /// avoids a separate `COUNT(*)` query.
    pub fn from_rows(mut rows: Vec<T>, limit: usize, offset: usize) -> Self {
        let has_more = rows.len() > limit;
        if has_more {
            rows.truncate(limit);
        }
        Page {
            items: rows,
            limit,
            offset,
            next_offset: has_more.then_some(offset + limit),
        }
    }

    /// Page an already-loaded in-memory collection (used for the tenant
    /// directory, which lives in a `DashMap` rather than the DB).
    pub fn from_all(rows: Vec<T>, limit: usize, offset: usize) -> Self {
        let end = offset.saturating_add(limit);
        let has_more = rows.len() > end;
        let items = rows.into_iter().skip(offset).take(limit).collect();
        Page {
            items,
            limit,
            offset,
            next_offset: has_more.then_some(end),
        }
    }

    pub fn map<U>(self, f: impl FnMut(T) -> U) -> Page<U> {
        Page {
            items: self.items.into_iter().map(f).collect(),
            limit: self.limit,
            offset: self.offset,
            next_offset: self.next_offset,
        }
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

/// Client-visible host candidates in trust order: the proxy-forwarded host
/// first (only when forwarding headers are trusted), then the raw `Host`
/// header. Shared by tenant resolution ([`resolve_host`]) and the
/// registration-free issuer derivation ([`raw_issuer`]) so both always see
/// the same host the client used.
fn host_candidates<'a>(req: &'a Request, state: &ServerState) -> Vec<&'a str> {
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
    candidates
}

fn resolve_host<'a>(req: &'a Request, state: &ServerState) -> Option<(&'a str, &'a str)> {
    for candidate in host_candidates(req, state) {
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
    Some(issuer_url(host, req, state))
}

/// Issuer URL derived from the request WITHOUT requiring a registered
/// tenant — the Tier-A discovery fallback for unprovisioned hosts.
///
/// Same trust model as [`get_issuer`]: the host comes from the trusted
/// proxy's `X-Forwarded-Host` or the raw `Host` header, the scheme from
/// [`get_scheme`]. Unlike [`get_issuer`] it never consults the tenant
/// router, so any host the client visibly used yields a well-formed issuer.
/// Only used to render the skeleton discovery document
/// (`janux_provisioned: false`); token issuance still requires a tenant.
/// Returns `None` only when the request carries no host at all.
pub fn raw_issuer(req: &Request, state: &ServerState) -> Option<String> {
    let host = host_candidates(req, state).into_iter().next()?;
    Some(issuer_url(host, req, state))
}

/// The single issuer-URL assembly: `<scheme>://<host>[:<port>]` from a
/// client-visible host value. BOTH [`get_issuer`] and [`raw_issuer`] must
/// build through this helper so the provisioned and skeleton documents can
/// never drift apart in scheme, port or (future) normalization handling —
/// discovery, token issuance and every `iss` comparison rely on that
/// single-derivation invariant (OIDC Core §3.1.3.7, RFC 8414 §2).
fn issuer_url(host: &str, req: &Request, state: &ServerState) -> String {
    let scheme = get_scheme(req, state);
    let host = strip_default_port(host, scheme.as_str());
    format!("{}://{}", scheme, host)
}

/// Extract the bearer token from the `Authorization` header. The
/// auth-scheme is case-insensitive (RFC 6749 §2.1, RFC 6750 §2.1), so
/// `Bearer`, `bearer` and `BEARER` all match. This is the SINGLE bearer
/// extractor — the internal `/api/v1/*` paths and the OIDC resource
/// endpoints (`/userinfo`) both go through it so their scheme handling
/// can never drift apart. The `to_str()` filter guarantees visible
/// ASCII, so the 7-byte prefix slice is always char-boundary safe.
/// The canonical session cookie name (G-139). The verify endpoints set an
/// HttpOnly cookie under this name when the request carries
/// `cookie: "janux.session"`, and `get_jwt` reads it back — so browser
/// callers can keep the session JWT out of JS-readable storage entirely
/// (no sessionStorage/localStorage exfiltration surface for XSS). The
/// Authorization header takes precedence: non-browser clients and RPs keep
/// using Bearer, and SameSite=Strict means cross-site requests never carry
/// the cookie, so cookie auth adds no CSRF surface.
pub const SESSION_COOKIE: &str = "janux.session";

pub fn get_jwt(req: &Request) -> Option<&str> {
    req.headers()
        .get("Authorization")
        .and_then(|h| h.to_str().ok())
        .and_then(|h| {
            if h.len() >= 7 && h[..7].eq_ignore_ascii_case("bearer ") {
                Some(&h[7..])
            } else {
                None
            }
        })
        .or_else(|| session_cookie_jwt(req))
}

/// The session JWT from the canonical cookie, if present. Parsed from the
/// raw `Cookie` header because `get_jwt` takes `&Request` while salvo's
/// cookie-jar accessor needs `&mut`; JWTs are base64url, so there is no
/// quoting or escaping to undo. Public so `refresh` can tell whether the
/// rotated token must be re-set into the cookie (G-139).
pub fn session_cookie_jwt(req: &Request) -> Option<&str> {
    req.headers()
        .get(salvo::http::header::COOKIE)?
        .to_str()
        .ok()?
        .split(';')
        .find_map(|pair| {
            let (name, value) = pair.split_once('=')?;
            let value = value.trim();
            (name.trim() == SESSION_COOKIE && !value.is_empty()).then_some(value)
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
    let all_data = crate::jwt::jwt_decode::<T>(jwt, crate::jwt::VERIFICATION_GRACE_MINUTES, tenant)
        .await
        .map_err(|_| TokenReject::Invalid)?;
    if all_data.claims.iss != issuer {
        return Err(TokenReject::IssuerMismatch);
    }
    // G-123: a deleted OAuth2 client poisons a marker keyed by its service
    // identity (`sub` = `OAuth2Client.uuid`). Machine tokens are stateless
    // 90-day JWTs with no other kill switch, so every live principal of the
    // deleted client fails here from then on. Only machine-shaped tokens
    // (the mint-time `client:<id>` username) pay the extra store lookup;
    // user sessions never carry a client uuid as `sub`.
    if all_data.claims.data.machine_username().is_some()
        && crate::jwt::InvalidJwt::global()
            .is_valid(&client_machine_marker(&all_data.claims.sub))
            .await
    {
        return Err(TokenReject::Revoked);
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

/// Marker covering a whole internal session-rotation chain (H4). Every
/// token in a `/auth/refresh` chain shares its `sub` and ORIGINAL
/// `auth_time` (refresh preserves both), so the pair is a family key
/// without any token-shape change. Once poisoned, every surviving member
/// of the chain fails the family check on its next refresh attempt and
/// the chain dies out within one token lifetime — the RFC 9700 §4.14.2
/// replay response, mirroring the OIDC refresh-token family
/// (`oidc_refresh_family:*`). Two logins of the same user within the same
/// second share a family; poisoning then conservatively kills both.
pub fn session_family_marker(sub: &str, auth_time: usize) -> String {
    format!("session_family:{sub}:{auth_time}")
}

/// The poison marker only has to outlive the newest chain member minted
/// before the poisoning (session tokens live 15 minutes at every
/// `refresh_jwt`/`authenticate_jwt` call site); 24 h is ample headroom
/// and expired markers are gc'd by the revocation store.
const SESSION_FAMILY_POISON_TTL_SEC: i64 = 24 * 3600;

/// Poison an internal session family after refresh-token reuse (theft
/// indicator): successors of the stolen token stop rotating immediately.
pub async fn poison_session_family(sub: &str, auth_time: usize) {
    let exp = jiff::Timestamp::from_second(
        jiff::Timestamp::now().as_second() + SESSION_FAMILY_POISON_TTL_SEC,
    )
    .unwrap_or_else(|_| jiff::Timestamp::now());
    crate::jwt::InvalidJwt::global()
        .invalid_raw(&session_family_marker(sub, auth_time), exp)
        .await
        .ok();
}

/// Whether the internal session family has been poisoned.
pub async fn session_family_poisoned(sub: &str, auth_time: usize) -> bool {
    crate::jwt::InvalidJwt::global()
        .is_valid(&session_family_marker(sub, auth_time))
        .await
}

/// Marker covering every machine token of one OAuth2 client (G-123).
/// `client_credentials` tokens are stateless 90-day JWTs keyed by the
/// client's service identity (`sub` = `OAuth2Client.uuid`), so deleting a
/// client poisons this marker instead of enumerating tokens —
/// `validate_token` rejects every live principal of the deleted client
/// from then on. Mirrors the `session_family:*` / `oidc_refresh_family:*`
/// marker precedent.
pub fn client_machine_marker(client_uuid: &str) -> String {
    format!("machine_client:{client_uuid}")
}

/// Poison a deleted client's machine-token marker. The marker must outlive
/// the longest token that could have been minted before the deletion
/// (machine tokens live `CLIENT_CREDENTIALS_TOKEN_LIFETIME_MINUTES`);
/// expired markers are gc'd by the revocation store. The write result is
/// returned, not swallowed: a deletion whose kill switch failed to persist
/// would leave 90-day SCIM principals alive, and the caller must be able to
/// surface (and retry) that.
pub async fn poison_client_machine_tokens(client_uuid: &str) -> anyhow::Result<()> {
    let exp = jiff::Timestamp::from_second(
        jiff::Timestamp::now().as_second()
            + i64::from(crate::oidc::CLIENT_CREDENTIALS_TOKEN_LIFETIME_MINUTES) * 60,
    )
    .unwrap_or_else(|_| jiff::Timestamp::now());
    crate::jwt::InvalidJwt::global()
        .invalid_raw(&client_machine_marker(client_uuid), exp)
        .await?;
    Ok(())
}

/// Outbound HTTP client with bounded timeouts (H6). Every server-initiated
/// call (Aliyun SMS, Resend email, social IdP discovery/token/userinfo)
/// MUST use this: a hung peer otherwise pins the request handler — which
/// for the auth flows means pinning the tenant's `DashMap` write guard and
/// stalling every other caller for that domain until the peer gives up.
/// The bounds turn an indefinite freeze into a bounded, auditable failure.
/// One shared client keeps connection pooling; clones are `Arc`-cheap.
static OUTBOUND_HTTP_CLIENT: LazyLock<reqwest::Client> = LazyLock::new(|| {
    reqwest::Client::builder()
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15))
        .build()
        // The builder only fails on TLS-backend init; fall back to the
        // (unbounded) default rather than making every dispatch fail.
        .unwrap_or_else(|_| reqwest::Client::new())
});

pub fn outbound_http_client() -> reqwest::Client {
    OUTBOUND_HTTP_CLIENT.clone()
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

#[allow(dead_code)] // extraction sources accepted by `extract`
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
///
/// The cold-key path runs inside the same per-key compute as the update:
/// create-and-increment is one atomic step, so N concurrent first hits
/// (first ever, or after the TTL) cannot all observe absence and all pass
/// — the budget holds even for a coordinated burst on an idle key.
pub async fn send_throttle_allows(key: &str, limit: u64) -> bool {
    let now = jiff::Timestamp::now().as_second();
    let window = now - now.rem_euclid(60);
    SEND_THROTTLE
        .compute_or_insert(
            key,
            || (window, 0),
            |entry| {
                if entry.0 != window {
                    *entry = (window, 1);
                    return true;
                }
                if entry.1 >= limit {
                    return false;
                }
                entry.1 += 1;
                true
            },
        )
        .await
}

/// Per-account verify-failure state: the current fixed window and the
/// failures counted in it, the lockout deadline, and how many lockout
/// cycles have fired (drives the exponential backoff).
#[derive(Clone)]
struct VerifyFailures {
    window: i64,
    failures: u32,
    locked_until: i64,
    cycles: u32,
}

/// Per-account budget on the code-verify paths. The per-IP quota on
/// `/api/v1/auth` bounds a single source only; this budget binds to the
/// account, so a distributed attacker cannot multiply guesses by rotating
/// IPs. `VERIFY_FAILURE_LIMIT` failed verifies in a
/// `VERIFY_FAILURE_WINDOW_SEC` window lock the account's code ceremonies
/// (verify AND the matching code-issuing request) for
/// `VERIFY_LOCKOUT_BASE_SEC`, doubling per repeated cycle up to
/// `VERIFY_LOCKOUT_CAP_SEC`. A successful verify clears the state.
/// The lock covers only guessable-code ceremonies — magic links,
/// passkeys, and social dances are not gated — so a deliberate lockout
/// cannot deny the victim every factor.
const VERIFY_FAILURE_LIMIT: u32 = 5;
const VERIFY_FAILURE_WINDOW_SEC: i64 = 15 * 60;
const VERIFY_LOCKOUT_BASE_SEC: i64 = 15 * 60;
const VERIFY_LOCKOUT_CAP_SEC: i64 = 24 * 60 * 60;

static VERIFY_FAILURES: LazyLock<crate::cache::EphemCache<String, VerifyFailures>> =
    LazyLock::new(|| {
        // The TTL must outlive the longest lockout, or expiry would
        // silently lift the lock; every write refreshes it. The capacity
        // is sized well above the default so an attacker flooding junk
        // keys cannot evict a victim's live lockout (failures are also
        // only recorded for identities tied to a real ceremony, which
        // bounds how cheaply entries can be created).
        crate::cache::EphemCache::with_capacity("verify_failures", Some(25 * 3600), 200_000)
    });

/// The gate key: the account a code ceremony targets, scoped by tenant.
pub fn verify_gate_key(domain: &str, user: &str) -> String {
    format!("verify:{domain}:{user}")
}

/// Whether the account's code-verify path is open. Checked at handler
/// entry (the identity is only known after body extraction) BEFORE any
/// one-shot ceremony secret is consumed, so a locked-out attacker cannot
/// burn a code just issued to the legitimate user.
pub async fn verify_gate_allows(key: &str) -> bool {
    match VERIFY_FAILURES.get(key).await {
        Some(state) => jiff::Timestamp::now().as_second() >= state.locked_until,
        None => true,
    }
}

/// Record one failed code verify against the account. Failures count
/// across ceremonies within a fixed window; reaching the limit arms the
/// lockout and escalates the backoff for the next cycle. The
/// create-and-increment runs inside the cache's per-key compute, so
/// concurrent failures on a cold key cannot lose counts.
pub async fn record_verify_failure(key: &str) {
    let now = jiff::Timestamp::now().as_second();
    let window = now - now.rem_euclid(VERIFY_FAILURE_WINDOW_SEC);
    VERIFY_FAILURES
        .compute_or_insert(
            key,
            || VerifyFailures {
                window,
                failures: 0,
                locked_until: 0,
                cycles: 0,
            },
            |state| {
                if state.window != window {
                    state.window = window;
                    state.failures = 0;
                }
                state.failures += 1;
                if state.failures >= VERIFY_FAILURE_LIMIT {
                    // Exponential backoff per lockout cycle, capped; the
                    // shift is bounded so the multiply cannot overflow.
                    let backoff = VERIFY_LOCKOUT_BASE_SEC
                        .saturating_mul(1i64 << state.cycles.min(16))
                        .min(VERIFY_LOCKOUT_CAP_SEC);
                    state.locked_until = now + backoff;
                    state.cycles += 1;
                    state.failures = 0;
                }
            },
        )
        .await;
}

/// Clear the account's failure state after a successful verify.
pub async fn clear_verify_failures(key: &str) {
    VERIFY_FAILURES.remove(key).await;
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

    // ── get_jwt: Bearer first, canonical session cookie fallback (G-139) ──

    #[test]
    fn get_jwt_prefers_bearer_and_falls_back_to_the_session_cookie() {
        // Nothing at all.
        let req = Request::new();
        assert_eq!(get_jwt(&req), None);

        // The Authorization header wins.
        let mut req = Request::new();
        req.headers_mut().insert(
            salvo::http::header::AUTHORIZATION,
            "Bearer header-token".parse().unwrap(),
        );
        assert_eq!(get_jwt(&req), Some("header-token"));

        // Case-insensitive scheme (G-117) still wins over the cookie.
        let mut req = Request::new();
        req.headers_mut().insert(
            salvo::http::header::AUTHORIZATION,
            "bearer header-token".parse().unwrap(),
        );
        req.headers_mut().insert(
            salvo::http::header::COOKIE,
            format!("other=1; {SESSION_COOKIE}=cookie-token")
                .parse()
                .unwrap(),
        );
        assert_eq!(get_jwt(&req), Some("header-token"));

        // Without the header the canonical cookie is used, alongside
        // unrelated cookies.
        let mut req = Request::new();
        req.headers_mut().insert(
            salvo::http::header::COOKIE,
            format!("theme=dark; {SESSION_COOKIE}=cookie-token; other=x")
                .parse()
                .unwrap(),
        );
        assert_eq!(get_jwt(&req), Some("cookie-token"));

        // A non-canonical cookie is ignored.
        let mut req = Request::new();
        req.headers_mut().insert(
            salvo::http::header::COOKIE,
            "janux.other=nope".parse().unwrap(),
        );
        assert_eq!(get_jwt(&req), None);

        // An empty cookie value is ignored — that is the cleared state
        // `logout` leaves behind.
        let mut req = Request::new();
        req.headers_mut().insert(
            salvo::http::header::COOKIE,
            format!("{SESSION_COOKIE}=").parse().unwrap(),
        );
        assert_eq!(get_jwt(&req), None);
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

    // ── raw_issuer: Tier-A discovery fallback ───────────────────────────────

    #[tokio::test]
    async fn raw_issuer_derives_from_unregistered_host() {
        let state = test_state(false, &["tenant.example.com"]).await;
        let req = req_with(Some("fresh.example.com"), None, None, None, "/");
        assert_eq!(
            raw_issuer(&req, &state),
            Some("http://fresh.example.com".to_string())
        );
        // Registered hosts derive the same issuer through both paths.
        let req = req_with(Some("tenant.example.com"), None, None, None, "/");
        assert_eq!(raw_issuer(&req, &state), get_issuer(&req, &state));
    }

    #[tokio::test]
    async fn raw_issuer_strips_default_port_and_honors_scheme() {
        let state = test_state(false, &[]).await;
        let req = with_scheme(
            req_with(Some("fresh.example.com:443"), None, None, None, "/"),
            salvo::http::uri::Scheme::HTTPS,
        );
        assert_eq!(
            raw_issuer(&req, &state),
            Some("https://fresh.example.com".to_string())
        );
        let req = req_with(Some("fresh.example.com:8080"), None, None, None, "/");
        assert_eq!(
            raw_issuer(&req, &state),
            Some("http://fresh.example.com:8080".to_string())
        );
    }

    #[tokio::test]
    async fn raw_issuer_follows_the_same_header_trust_model() {
        // Untrusted: a spoofed XFH must not steer the skeleton issuer.
        let state = test_state(false, &[]).await;
        let req = req_with(
            Some("real.example.com"),
            Some("spoofed.example.com"),
            None,
            None,
            "/",
        );
        assert_eq!(
            raw_issuer(&req, &state),
            Some("http://real.example.com".to_string())
        );
        // Trusted: the proxy-forwarded host is the client-visible one.
        let state = test_state(true, &[]).await;
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
            raw_issuer(&req, &state),
            Some("https://public.example.com".to_string())
        );
    }

    #[tokio::test]
    async fn raw_issuer_without_any_host_is_none() {
        let state = test_state(false, &[]).await;
        let req = req_with(None, None, None, None, "/");
        assert_eq!(raw_issuer(&req, &state), None);
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

    /// regression: on a cold key (first ever hit, or after the TTL), N
    /// concurrent requests must not all observe absence and all pass —
    /// create-and-increment is one atomic per-key compute, so the budget
    /// holds even for a coordinated burst on an idle key.
    #[tokio::test]
    async fn send_throttle_cold_key_burst_respects_the_limit() {
        let key = format!("g119:{}", uuid::Uuid::new_v4());
        let mut handles = Vec::new();
        for _ in 0..10 {
            let key = key.clone();
            handles.push(tokio::spawn(
                async move { send_throttle_allows(&key, 3).await },
            ));
        }
        let mut allowed = 0;
        for h in handles {
            if h.await.expect("task") {
                allowed += 1;
            }
        }
        assert_eq!(
            allowed, 3,
            "a concurrent burst on a cold key must not exceed the budget"
        );
    }

    #[tokio::test]
    async fn verify_gate_locks_after_repeated_failures() {
        let key = verify_gate_key("localhost", &format!("g104-{}", uuid::Uuid::new_v4()));
        for _ in 0..(VERIFY_FAILURE_LIMIT - 1) {
            record_verify_failure(&key).await;
            assert!(
                verify_gate_allows(&key).await,
                "under the limit the gate stays open"
            );
        }
        record_verify_failure(&key).await;
        assert!(
            !verify_gate_allows(&key).await,
            "reaching the limit must lock the account's verify path"
        );

        // Another account has its own budget.
        let other = verify_gate_key("localhost", &format!("g104-{}", uuid::Uuid::new_v4()));
        assert!(verify_gate_allows(&other).await);

        // A successful verify clears the lock.
        clear_verify_failures(&key).await;
        assert!(verify_gate_allows(&key).await);
    }

    #[tokio::test]
    async fn verify_gate_backoff_escalates_per_cycle() {
        let key = verify_gate_key("localhost", &format!("g104-{}", uuid::Uuid::new_v4()));
        for _ in 0..VERIFY_FAILURE_LIMIT {
            record_verify_failure(&key).await;
        }
        let state = VERIFY_FAILURES.get(&key).await.expect("state");
        assert_eq!(state.cycles, 1);
        let now = jiff::Timestamp::now().as_second();
        assert!(
            (now + VERIFY_LOCKOUT_BASE_SEC - 5..=now + VERIFY_LOCKOUT_BASE_SEC + 5)
                .contains(&state.locked_until),
            "first lockout lasts the base backoff"
        );

        // Simulate the first lockout expiring, then trip the limit again.
        VERIFY_FAILURES
            .get_mut(&key, |s| {
                s.locked_until = 0;
            })
            .await;
        for _ in 0..VERIFY_FAILURE_LIMIT {
            record_verify_failure(&key).await;
        }
        let state = VERIFY_FAILURES.get(&key).await.expect("state");
        assert_eq!(state.cycles, 2, "each lockout cycle must escalate");
        assert!(
            (now + 2 * VERIFY_LOCKOUT_BASE_SEC - 5..=now + 2 * VERIFY_LOCKOUT_BASE_SEC + 5)
                .contains(&state.locked_until),
            "second lockout lasts twice the base backoff"
        );
        clear_verify_failures(&key).await;
    }

    #[tokio::test]
    async fn verify_gate_window_reset_drops_stale_failures() {
        let key = verify_gate_key("localhost", &format!("g104-{}", uuid::Uuid::new_v4()));
        // Seed a nearly-exhausted budget from a long-gone window.
        VERIFY_FAILURES
            .insert(
                key.clone(),
                VerifyFailures {
                    window: 0,
                    failures: VERIFY_FAILURE_LIMIT - 1,
                    locked_until: 0,
                    cycles: 0,
                },
            )
            .await
            .expect("seed");
        record_verify_failure(&key).await;
        assert!(
            verify_gate_allows(&key).await,
            "a new window must reset the failure count"
        );
        let state = VERIFY_FAILURES.get(&key).await.expect("state");
        assert_eq!(state.failures, 1);
        clear_verify_failures(&key).await;
    }

    /// regression: the auth-scheme is case-insensitive (RFC 6749 §2.1 /
    /// RFC 6750 §2.1) — `BEARER` must extract the token exactly like
    /// `Bearer`, and non-bearer schemes or short values must not match.
    #[test]
    fn get_jwt_matches_bearer_scheme_case_insensitively() {
        fn req_with_auth(value: &str) -> Request {
            let mut req = Request::new();
            req.headers_mut().insert(
                salvo::http::header::AUTHORIZATION,
                salvo::http::HeaderValue::from_str(value).expect("header value"),
            );
            req
        }

        for scheme in ["Bearer", "bearer", "BEARER", "BeArEr"] {
            let req = req_with_auth(&format!("{scheme} abc.def.ghi"));
            assert_eq!(
                get_jwt(&req),
                Some("abc.def.ghi"),
                "scheme `{scheme}` must match case-insensitively"
            );
        }
        assert_eq!(get_jwt(&req_with_auth("Basic dXNlcjpwYXNz")), None);
        assert_eq!(
            get_jwt(&req_with_auth("bearer")),
            None,
            "a scheme without the space and token must not match"
        );
        assert_eq!(get_jwt(&Request::new()), None, "a missing header");
    }

    // ── pagination (G-113) ──────────────────────────────────────────────────

    fn req_with_query(query: &str) -> Request {
        let mut req = Request::new();
        req.set_uri(format!("/list?{query}").parse().unwrap());
        req
    }

    #[test]
    fn page_params_defaults_and_clamping() {
        // defaults when absent
        let mut req = Request::new();
        req.set_uri("/list".parse().unwrap());
        assert_eq!(page_params(&req), (DEFAULT_PAGE_LIMIT, 0));

        // explicit values pass through
        assert_eq!(page_params(&req_with_query("limit=10&offset=20")), (10, 20));

        // limit is clamped into [1, MAX_PAGE_LIMIT]
        assert_eq!(page_params(&req_with_query("limit=0")).0, 1);
        assert_eq!(
            page_params(&req_with_query("limit=100000")).0,
            MAX_PAGE_LIMIT
        );

        // malformed values fall back to defaults
        assert_eq!(
            page_params(&req_with_query("limit=abc&offset=-1")),
            (DEFAULT_PAGE_LIMIT, 0)
        );

        // offset is capped at i64::MAX — toasty's builder panics above it
        assert_eq!(
            page_params(&req_with_query("offset=18446744073709551615")).1,
            i64::MAX as usize
        );
    }

    #[test]
    fn page_bounds_probes_one_extra_row_within_toasty_limits() {
        assert_eq!(page_bounds(50, 0), (51, 0));
        // the probe must not overflow usize or exceed toasty's i64 bound
        assert_eq!(page_bounds(usize::MAX, 0).0, i64::MAX as usize);
        assert_eq!(page_bounds(50, usize::MAX).1, i64::MAX as usize);
    }

    #[test]
    fn page_from_rows_uses_the_probe_row_to_detect_a_next_page() {
        // limit + 1 rows fetched → the extra row is dropped and next_offset set
        let page = Page::from_rows(vec![1, 2, 3], 2, 4);
        assert_eq!(page.items, vec![1, 2]);
        assert_eq!(page.limit, 2);
        assert_eq!(page.offset, 4);
        assert_eq!(page.next_offset, Some(6));

        // fewer rows than the limit → last page
        let page = Page::from_rows(vec![1, 2], 5, 0);
        assert_eq!(page.items, vec![1, 2]);
        assert_eq!(page.next_offset, None);

        // exactly `limit` rows (no probe row) → treated as last page
        let page = Page::from_rows(vec![1, 2], 2, 0);
        assert_eq!(page.next_offset, None);

        // empty result
        let page = Page::<i32>::from_rows(vec![], 2, 0);
        assert!(page.items.is_empty());
        assert_eq!(page.next_offset, None);
    }

    #[test]
    fn page_from_all_slices_in_memory_rows() {
        let rows: Vec<i32> = (0..7).collect();
        let page = Page::from_all(rows.clone(), 3, 0);
        assert_eq!(page.items, vec![0, 1, 2]);
        assert_eq!(page.next_offset, Some(3));

        let page = Page::from_all(rows.clone(), 3, 6);
        assert_eq!(page.items, vec![6]);
        assert_eq!(page.next_offset, None);

        // offset past the end yields an empty page, not a panic
        let page = Page::from_all(rows.clone(), 3, 100);
        assert!(page.items.is_empty());
        assert_eq!(page.next_offset, None);

        // extreme offsets saturate instead of overflowing `offset + limit`
        let page = Page::from_all(rows, 3, usize::MAX);
        assert!(page.items.is_empty());
        assert_eq!(page.next_offset, None);
    }

    #[test]
    fn page_map_preserves_pagination_metadata() {
        let page = Page::from_rows(vec![1, 2, 3], 2, 0).map(|n| n.to_string());
        assert_eq!(page.items, vec!["1", "2"]);
        assert_eq!(page.next_offset, Some(2));
    }

    #[test]
    fn page_serializes_without_next_offset_on_the_last_page() {
        let last = Page::from_rows(vec![1], 5, 0);
        let json = serde_json::to_value(&last).expect("serialize");
        assert_eq!(json["items"], serde_json::json!([1]));
        assert!(
            json.get("next_offset").is_none(),
            "next_offset must be omitted on the last page: {json}"
        );

        let more = Page::from_rows(vec![1, 2], 1, 0);
        let json = serde_json::to_value(&more).expect("serialize");
        assert_eq!(json["next_offset"], serde_json::json!(1));
    }
}
