use crate::utils::{ApiProblem, ApiResponse, refresh_jwt, validate_jwt, validate_jwt_for};
use crate::utils::{get_domain, get_jwt};
use salvo::prelude::*;

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
    if let Ok(state) = depot.obtain_mut::<crate::server::ServerState>() {
        if let Some(domain) = get_domain(req, state) {
            if let Some(jwt) = get_jwt(req) {
                if let Some(mut tenant) = state.storage.tenant_by_domain(domain) {
                    // Decode BEFORE revoking: the claims identify the user
                    // for the OIDC Back-Channel Logout fan-out. Only a
                    // session token bound to this tenant (iss + aud =
                    // domain) triggers notifications.
                    let issuer = crate::utils::get_issuer(req, state);
                    let decoded = crate::jwt::jwt_decode::<crate::db::JwtData>(jwt, 2, &mut tenant)
                        .await
                        .ok();
                    // Revocation goes through the shared primitive (Step 1.2)
                    // — same store, same guarantees as RFC 7009 `/revoke`.
                    if crate::utils::revoke_token(&mut tenant, jwt, None, "logout")
                        .await
                        .is_ok()
                    {
                        if let (Some(issuer), Some(tkn)) = (&issuer, &decoded) {
                            if tkn.claims.iss == *issuer && tkn.claims.aud == domain {
                                let targets = crate::oidc_ext::backchannel_logout_targets(
                                    &mut tenant,
                                    issuer,
                                    domain,
                                    &tkn.claims.sub,
                                )
                                .await;
                                crate::oidc_ext::spawn_backchannel_delivery(targets);
                            }
                        }
                        res.status_code(StatusCode::OK);
                        res.render(Json(ApiResponse::ok(())));
                        return;
                    }
                }
            }
        }
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
    if let Some(new_jwt) = refresh_jwt(req, depot).await {
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
