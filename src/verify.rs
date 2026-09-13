use crate::db::JwtVerify;
use crate::utils::{ApiProblem, ApiResponse, refresh_jwt, validate_jwt, validate_jwt_for};
use crate::utils::{get_domain, get_jwt};
use salvo::prelude::*;
use serde::Serialize;

#[endpoint(
    summary = "Verify JWT, entry for forward-auth",
    responses(
        (status_code = 200, description = "Authorized"),
        (status_code = 401, description = "Unauthorized")
    )
)]
pub async fn verify(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    // Forward-auth mode: a reverse proxy (e.g. Caddy `forward_auth`) rewrites
    // the request line to this endpoint and reports the original request via
    // `X-Forwarded-Uri` / `X-Forwarded-Method`. Those headers are honored for
    // the policy decision only when `trust_forwarded_headers` is enabled; otherwise
    // (direct calls, untrusted deployments) the real request is evaluated, so
    // a forged header can never steer the authorization decision.
    let at = depot
        .obtain_mut::<crate::server::ServerState>()
        .ok()
        .and_then(|state| crate::utils::forwarded_origin(req, state));
    let (is_forwarded, want_redirect) = depot
        .obtain_mut::<crate::server::ServerState>()
        .ok()
        .map(|state| {
            let forwarded = crate::utils::forwarded_origin(req, state).is_some();
            (forwarded, state.forward_auth_redirect)
        })
        .unwrap_or((false, false));
    let result = match at {
        Some((method, path)) => validate_jwt_for(req, depot, Some((method, path))).await,
        None => validate_jwt(req, depot).await,
    };
    if let Some(d) = result {
        if d.can_access {
            res.status_code(StatusCode::OK);
            return;
        } else if d.expect_mfa {
            res.status_code(StatusCode::FORBIDDEN);
            let _ = res.add_header("X-MFA-Required", "true", true);
            return;
        }
    }
    if is_forwarded && want_redirect {
        // Browsers resolve the relative Location against their current
        // host; the proxy must forward /login to janux, which hosts it.
        let loc = auth_redirect(req, depot).await;
        let _ = res.add_header("Location", &loc, true);
        res.status_code(StatusCode::SEE_OTHER);
        return;
    }
    let err = ApiProblem::unauthorized();
    res.status_code(StatusCode::UNAUTHORIZED);
    res.render(Json(err));
    // RFC 6750 §3.1 — require WWW-Authenticate on Bearer auth failures
    let _ = res.add_header(
        "WWW-Authenticate",
        r#"Bearer error="invalid_token",realm="auth""#,
        true,
    );
}

#[endpoint(
    summary = "Logout, invalidate JWT",
    responses(
        (status_code = 200, description = "Authorized", body = ApiResponse<()>),
        (status_code = 401, description = "Unauthorized", body = ApiProblem)
    )
)]
pub async fn logout(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    if let Ok(state) = depot.obtain_mut::<crate::server::ServerState>()
        && let Some(domain) = get_domain(req, state)
        && let Some(jwt) = get_jwt(req)
        && let Some(mut tenant) = state.storage.tenant_by_domain(domain)
    {
        let issuer = crate::utils::get_issuer(req, state);
        let decoded = crate::jwt::jwt_decode::<crate::db::JwtData>(
            jwt,
            crate::jwt::VERIFICATION_GRACE_MINUTES,
            &mut tenant,
        )
        .await
        .ok();
        // G-89: attribute the logout to the session's owner when the
        // token decodes (revocation itself works regardless).
        if let Some(tkn) = &decoded {
            crate::audit::record_target_detail(res, "auth", &tkn.claims.data.username, "logout");
        }
        if crate::utils::revoke_token(&mut tenant, jwt, None, "logout")
            .await
            .is_ok()
        {
            if let (Some(issuer), Some(tkn)) = (&issuer, &decoded)
                && tkn.claims.iss == *issuer
                && tkn.claims.aud == domain
            {
                let targets =
                    crate::oidc_ext::backchannel_logout_targets(&mut tenant, &tkn.claims.sub).await;
                crate::oidc_ext::queue_backchannel_deliveries(
                    &mut tenant,
                    issuer,
                    domain,
                    &tkn.claims.sub,
                    targets,
                )
                .await;
            }

            // G-139: the session cookie is HttpOnly — only the server can
            // remove it from the jar, so logout must expire it explicitly.
            // #1: reuse the same Domain so the clear matches the jar entry.
            let scope = crate::config::SessionDTO::load(&mut tenant, domain)
                .await
                .cookie_scope;
            set_session_cookie(res, None, scope.as_deref());
            res.status_code(StatusCode::OK);
            res.render(Json(ApiResponse::ok(())));
            return;
        }
    }

    // No bearer token → 401, the contract this endpoint declares (and
    // what `refresh` renders); other failures (unknown domain, revoke
    // error) stay 400.
    if get_jwt(req).is_none() {
        res.status_code(StatusCode::UNAUTHORIZED);
        res.render(Json(ApiProblem::unauthorized()));
        return;
    }
    res.status_code(StatusCode::BAD_REQUEST);
    res.render(Json(ApiProblem::bad_request("")));
}

#[endpoint(
    summary = "Refresh JWT",
    responses(
        (status_code = 200, description = "Authorized", body = ApiResponse<String>),
        (status_code = 401, description = "Unauthorized", body = ApiProblem)
    )
)]
pub async fn refresh(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    // G-139: when the old token arrived in the canonical HttpOnly cookie,
    // the rotated token must be set back into it — the old one is revoked
    // by the rotation, so a browser left on the stale cookie would 401 on
    // its next request.
    let via_cookie = crate::utils::session_cookie_jwt(req).is_some();
    if let Some(new_jwt) = refresh_jwt(req, depot).await {
        if via_cookie {
            let scope = session_scope(req, depot).await;
            set_session_cookie(res, Some(&new_jwt), scope.as_deref());
        }
        res.status_code(StatusCode::OK);
        res.render(Json(ApiResponse::ok(new_jwt)));
        return;
    }
    let err = ApiProblem::unauthorized();
    res.status_code(StatusCode::UNAUTHORIZED);
    res.render(Json(err));
    // RFC 6750 §3.1 — Bearer token errors in the WWW-Authenticate header
    let _ = res.add_header(
        "WWW-Authenticate",
        r#"Bearer error="invalid_token",realm="auth""#,
        true,
    );
}

#[handler]
pub async fn protect(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    protect_at(req, depot, res, ctrl, None).await
}

/// `protect` with an explicit policy-evaluation target. `at` overrides the
/// (method, path) the policy engine sees — the SCIM surface uses it to
/// canonicalize the dynamic `/scim/v2/Users/{id}` segment into the literal
/// policy resource (matches exactly, no wildcards). `None` authorizes
/// against the real request, like `protect`.
pub async fn protect_at(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
    at: Option<(crate::db::HttpMethod, String)>,
) {
    // 1. Take ownership of the result
    let data = match at {
        Some((method, path)) => {
            crate::utils::validate_jwt_for(req, depot, Some((method, &path))).await
        }
        None => validate_jwt(req, depot).await,
    };
    if let Some(data) = data {
        if data.can_access {
            depot.inject(data);
            ctrl.call_next(req, depot, res).await;
            return;
        }
        if data.expect_mfa {
            // Valid session that lacks a required factor: tell the client to
            // step up instead of failing like a bad token — without this
            // signal the client cannot discover that an
            // MFA round via /api/v1/auth/* is what unlocks the resource.
            res.status_code(StatusCode::FORBIDDEN);
            let _ = res.add_header("X-MFA-Required", "true", true);
            return;
        }
        // G-28: a VALID session whose roles do not satisfy the policy set
        // is authenticated-but-forbidden → 403. The 401 below is reserved
        // for missing/invalid credentials; conflating the two made the
        // engine's deny path indistinguishable from a bad token.
        res.status_code(StatusCode::FORBIDDEN);
        res.render(Json(ApiProblem::forbidden()));
        return;
    }

    // Fallback if auth fails
    let err = ApiProblem::unauthorized();
    res.status_code(StatusCode::UNAUTHORIZED);
    res.render(Json(err));
    // RFC 6750 §3.1 — Bearer token errors in the WWW-Authenticate header
    let _ = res.add_header(
        "WWW-Authenticate",
        r#"Bearer error="invalid_token",realm="auth""#,
        true,
    );
}

#[handler]
pub async fn session(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    // Session gate for the self-service auth endpoints: inject a
    // *valid* session and always call next. Unlike `protect`, this does NOT
    // run the policy engine — these endpoints are how a session acquires
    // factors, so RBAC-gating them is circular (a token denied for missing
    // MFA must still be able to complete MFA). Handlers act only on the
    // session's own identity and reject a missing injection
    // themselves; unauthenticated first-time logins proceed without one.
    if let Some(data) = crate::utils::validate_session(req, depot).await {
        depot.inject(data);
    }
    ctrl.call_next(req, depot, res).await;
}

// ─── Session introspection (whoami) ──────────────────────────────────────────

/// The current session's identity, for first-party frontends that no
/// longer hold a readable JWT (G-139 moved it into an HttpOnly cookie):
/// the admin console's MFA/Account tabs and the step-up flows need to
/// know WHO the session belongs to (G-138/G-162).
#[derive(Serialize, ToSchema)]
pub struct SessionInfo {
    pub username: String,
    pub user: String,
    pub domain: String,
    pub roles: Vec<String>,
    /// Factors proven at `auth_time` (feeds amr/acr and the policy
    /// engine's MFA gate).
    pub mfa: Vec<String>,
    pub auth_time: Option<usize>,
}

#[endpoint(
    summary = "Describe the current session (whoami)",
    responses(
        (status_code = 200, description = "Session info", body = ApiResponse<SessionInfo>),
        (status_code = 401, description = "No valid session", body = ApiProblem),
    )
)]
pub async fn session_info(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    match crate::utils::validate_session(req, depot).await {
        Some(v) => {
            let mut roles: Vec<String> = v.jwt_data.roles.into_iter().collect();
            roles.sort();
            let mut mfa: Vec<String> = v.jwt_data.mfa.into_iter().collect();
            mfa.sort();
            res.status_code(StatusCode::OK);
            res.render(Json(ApiResponse::ok(SessionInfo {
                username: v.jwt_data.username,
                user: v.jwt_data.user,
                domain: v.domain,
                roles,
                mfa,
                auth_time: v.auth_time,
            })));
        }
        None => {
            res.status_code(StatusCode::UNAUTHORIZED);
            res.render(Json(ApiProblem::unauthorized()));
        }
    }
}

// ─── Canonical session cookie (G-139) ────────────────────────────────────────

/// Set — or, with `jwt: None`, expire — the canonical HttpOnly session
/// cookie. Same attributes as the per-ceremony `VerifyRequest.cookie` path
/// (H5/G-111): HttpOnly, Secure, SameSite=Strict, Path=/. Used by `logout`
/// (JS cannot remove an HttpOnly cookie itself) and `refresh` (the rotated
/// token must replace the revoked one in the jar).
pub fn set_session_cookie(res: &mut Response, jwt: Option<&str>, domain: Option<&str>) {
    use salvo::http::cookie::{Cookie, SameSite};
    let mut builder = Cookie::build((
        crate::utils::SESSION_COOKIE,
        jwt.unwrap_or_default().to_string(),
    ))
    .path("/")
    .http_only(true)
    .secure(true)
    .same_site(SameSite::Strict);
    // Sub-domain SSO (#1): widen the cookie's `Domain` attribute so a
    // browser shares one login across the sibling domains janux serves under
    // a registrable domain. Operator-declared + validated (never inferred
    // here); `None`/empty keeps host-only behavior. A CLEAR must reuse the
    // same `Domain`, or the browser will not match the old jar entry.
    if let Some(d) = domain {
        let d = d.trim();
        if !d.is_empty() {
            builder = builder.domain(d.to_string());
        }
    }
    if jwt.is_none() {
        builder = builder.expires(salvo::http::cookie::time::OffsetDateTime::UNIX_EPOCH);
    }
    res.add_cookie(builder.build());
}

/// The registrable domain this request's tenant scopes its session cookie to
/// (sub-domain SSO, #1). `None` = the host-only default. Reads the per-domain
/// `session.cookie_scope` from the tenant Config store.
async fn session_scope(req: &Request, depot: &mut Depot) -> Option<String> {
    let Ok(state) = depot.obtain_mut::<crate::server::ServerState>() else {
        return None;
    };
    let domain = get_domain(req, state)?;
    let mut tenant = match state.storage.tenant_by_domain(domain) {
        Some(t) => t,
        None => return None,
    };
    crate::config::SessionDTO::load(&mut tenant, domain)
        .await
        .cookie_scope
}

/// The tenant-scoped login origin to bounce an UNAUTHENTICATED forward-auth
/// probe to (#5): the domain's configured `session.redirect_url` + `/login`.
/// `None` (single-host) falls back to the bare relative `/login`.
async fn auth_redirect(req: &Request, depot: &mut Depot) -> String {
    let Ok(state) = depot.obtain_mut::<crate::server::ServerState>() else {
        return "/login".to_string();
    };
    let Some(domain) = get_domain(req, state) else {
        return "/login".to_string();
    };
    let mut tenant = match state.storage.tenant_by_domain(domain) {
        Some(t) => t,
        None => return "/login".to_string(),
    };
    let base = crate::config::SessionDTO::load(&mut tenant, domain)
        .await
        .redirect_url;
    if let Some(b) = base {
        let t = b.trim();
        if !t.is_empty() {
            return format!("{}/login", t.trim_end_matches('/'));
        }
    }
    "/login".to_string()
}

// ─── Sudo mode for credential mutations (G-132) ──────────────────────────────

/// Header on the 403 that gated credential mutations return when the
/// session is too old: a machine-readable "run a fresh authentication
/// ceremony, then retry" (mirrors the `X-MFA-Required` precedent).
pub const REAUTH_HEADER: &str = "X-Reauth-Required";

/// The sudo-mode window: credential mutations (attaching or removing
/// login factors) require the session to have been AUTHENTICATED — not
/// merely refreshed — within this window. Deliberately equal to the
/// internal session TTL (15 min): a session that has not been through
/// `refresh_jwt` since its ceremony is inside the window, everything older
/// is not. `refresh_jwt` preserves the original `auth_time`, so an
/// indefinitely rotated — possibly stolen — chain can never re-enter the
/// window, while the exfiltration window of a hijacked fresh session is
/// bounded by the same 15 minutes (and G-139's HttpOnly cookie removes
/// the XSS exfiltration path entirely).
pub const SUDO_WINDOW_SEC: usize = 15 * 60;

/// Whether the injected session was authenticated within the sudo window.
/// A missing `auth_time` fails closed: without it the authentication's
/// freshness cannot be proven.
pub fn session_is_fresh(data: &JwtVerify) -> bool {
    match data.auth_time {
        Some(auth_time) => {
            let now = jiff::Timestamp::now().as_second().max(0) as usize;
            // `saturating_sub` tolerates clock skew that put `auth_time`
            // slightly in the future (jwt verification allows the same
            // leeway).
            now.saturating_sub(auth_time) <= SUDO_WINDOW_SEC
        }
        None => false,
    }
}

/// Mark the response as a sudo-mode refusal: 403 plus the
/// `X-Reauth-Required` signal. Handlers render their factor-specific error
/// body afterwards (EmailResponse/MobileResponse/ApiProblem).
pub fn mark_reauth_required(res: &mut Response) {
    res.status_code(StatusCode::FORBIDDEN);
    let _ = res.add_header(REAUTH_HEADER, "true", true);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// Forward-auth UX: an unauthenticated PROXIED request (X-Forwarded-*)
    /// becomes a 303 -> /login when `forward_auth_redirect` is on, and the
    /// historical 401 problem+json when it is off. The 401 path is the
    /// backward-compatible default; the 303 path is what a browser behind
    /// Caddy `forward_auth` / nginx `auth_request` needs to reach login.
    #[tokio::test]
    async fn forward_auth_unauth_redirects_or_401() {
        async fn state_with_redirect(wants: bool) -> crate::server::ServerState {
            let tmp = tempfile::tempdir().expect("tempdir");
            let storage = crate::db::Storage::init(tmp.path())
                .await
                .expect("storage init");
            // trust forwarded headers, no proxy allow-list (trust all), toggle flag
            let state = crate::server::ServerState::create_with(storage, true, &[], wants)
                .await
                .expect("state");
            let _ = tmp; // keep the data dir alive for the test's duration
            state
        }

        // A forwarded request with NO session token, exactly as Caddy presents
        // it to /api/v1/auth/verify.
        let probe = || {
            salvo::test::TestClient::get("http://localhost/api/v1/auth/verify")
                .add_header("Host", "app.example.com", true)
                .add_header("X-Forwarded-Uri", "/app", true)
                .add_header("X-Forwarded-Method", "GET", true)
        };

        // Flag ON: unauthenticated + forwarded -> 303 to /login.
        let on = state_with_redirect(true).await;
        let service = Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(on))
                .push(Router::with_path("api/v1/auth/verify").get(super::verify)),
        );
        let res = probe().send(&service).await;
        assert_eq!(
            res.status_code.expect("status"),
            StatusCode::SEE_OTHER,
            "flag on must redirect an unauthenticated probe to login"
        );
        assert_eq!(
            res.headers().get("Location").unwrap().to_str().unwrap(),
            "/login",
            "the 303 must point at the hosted login page"
        );

        // Flag OFF: the same request keeps the historical 401 problem+json.
        let off = state_with_redirect(false).await;
        let service = Service::new(
            Router::new()
                .hoop(salvo::affix_state::inject(off))
                .push(Router::with_path("api/v1/auth/verify").get(super::verify)),
        );
        let res = probe().send(&service).await;
        assert_eq!(
            res.status_code.expect("status"),
            StatusCode::UNAUTHORIZED,
            "flag off must keep the historical 401 answer"
        );
    }

    fn verify_with_auth_time(auth_time: Option<usize>) -> JwtVerify {
        JwtVerify {
            can_access: true,
            jwt_data: crate::db::JwtData {
                user: uuid::Uuid::nil().to_string(),
                username: "alice".into(),
                domain: "example.com".into(),
                mfa: HashSet::new(),
                roles: HashSet::from(["user".to_string()]),
            },
            expect_mfa: false,
            domain: "example.com".into(),
            auth_time,
        }
    }

    fn now_sec() -> usize {
        jiff::Timestamp::now().as_second().max(0) as usize
    }

    /// G-132: only a recently AUTHENTICATED session passes the sudo gate.
    #[test]
    fn sudo_gate_accepts_only_fresh_auth_time() {
        assert!(
            session_is_fresh(&verify_with_auth_time(Some(now_sec()))),
            "a just-authenticated session is inside the window"
        );
        assert!(
            session_is_fresh(&verify_with_auth_time(Some(now_sec() - SUDO_WINDOW_SEC))),
            "the window edge is inclusive"
        );
        assert!(
            !session_is_fresh(&verify_with_auth_time(Some(
                now_sec() - SUDO_WINDOW_SEC - 60
            ))),
            "a session older than the window must re-authenticate"
        );
        assert!(
            !session_is_fresh(&verify_with_auth_time(None)),
            "a missing auth_time fails closed"
        );
        assert!(
            session_is_fresh(&verify_with_auth_time(Some(now_sec() + 120))),
            "clock skew into the future is tolerated like jwt verification does"
        );
    }

    /// G-139: the canonical session cookie carries the H5/G-111 attribute
    /// set, and the clear shape (logout) expires it with an empty value —
    /// which `get_jwt`'s parser ignores, so a cleared cookie never
    /// authenticates. Round-tripped through a real response: salvo renders
    /// the cookie jar into `Set-Cookie` headers at send time.
    #[handler]
    async fn set_cookie_probe(res: &mut Response) {
        set_session_cookie(res, Some("tok"), None);
    }

    #[handler]
    async fn clear_cookie_probe(res: &mut Response) {
        set_session_cookie(res, None, None);
    }

    // #1: an operator-declared `cookie_scope` widens the session cookie to
    // a registrable Domain, so a browser shares one login across the
    // sibling domains janux serves under it.
    #[handler]
    async fn set_domain_probe(res: &mut Response) {
        set_session_cookie(res, Some("tok"), Some("example.com"));
    }

    #[tokio::test]
    async fn session_cookie_domain_scope() {
        let service =
            Service::new(Router::new().push(Router::with_path("set").get(set_domain_probe)));
        let res = salvo::test::TestClient::get("http://localhost/set")
            .send(&service)
            .await;
        let set = res
            .headers()
            .get(salvo::http::header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .expect("set cookie")
            .to_string();
        assert!(
            set.contains(&format!("{}=tok", crate::utils::SESSION_COOKIE)),
            "{set}"
        );
        assert!(
            set.contains("Domain=example.com"),
            "scoped cookie must carry Domain=example.com: {set}"
        );
        for attr in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
            assert!(set.contains(attr), "missing {attr} in {set}");
        }
    }

    #[tokio::test]
    async fn session_cookie_set_and_clear_shapes() {
        let service = Service::new(
            Router::new()
                .push(Router::with_path("set").get(set_cookie_probe))
                .push(Router::with_path("clear").get(clear_cookie_probe)),
        );

        let res = salvo::test::TestClient::get("http://localhost/set")
            .send(&service)
            .await;
        let set = res
            .headers()
            .get_all(salvo::http::header::SET_COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            set.contains(&format!("{}=tok", crate::utils::SESSION_COOKIE)),
            "{set}"
        );
        for attr in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
            assert!(set.contains(attr), "missing {attr} in {set}");
        }

        let res = salvo::test::TestClient::get("http://localhost/clear")
            .send(&service)
            .await;
        let cleared = res
            .headers()
            .get(salvo::http::header::SET_COOKIE)
            .and_then(|v| v.to_str().ok())
            .expect("clear cookie")
            .to_string();
        assert!(
            cleared.contains(&format!("{}=", crate::utils::SESSION_COOKIE)),
            "{cleared}"
        );
        assert!(
            cleared.contains("Expires=Thu, 01 Jan 1970"),
            "the clear cookie must be expired: {cleared}"
        );

        // And the cleared shape never authenticates.
        let mut req = Request::new();
        req.headers_mut().insert(
            salvo::http::header::COOKIE,
            format!("{}=", crate::utils::SESSION_COOKIE)
                .parse()
                .unwrap(),
        );
        assert_eq!(crate::utils::get_jwt(&req), None);
    }
}
