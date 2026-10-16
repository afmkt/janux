// ─── Long-lived API keys ────────────────────────────────────────────────────
//
// An API key is a session-shaped JWT stamped with `typ = "api_key+jwt"` in its
// payload. It carries the minting session's identity (with `mfa` frozen at mint
// time) and an optional role subset, is signed with the tenant's current key
// (so it verifies like every other Janux token), and lives until its `exp` or
// explicit revocation — it is NOT refreshed and must not drive session-only
// flows (credential add/remove, sudo/reauth). See `apikey.md`.

use crate::db::{API_KEY_TYP, JwtData, JwtVerify};
use crate::server::ServerState;
use crate::utils::{ApiProblem, ApiResponse, extract, get_domain, get_issuer};
use salvo::oapi::ToSchema;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Request body for `POST /api/v1/auth/api-key`.
#[derive(Deserialize, Debug, ToSchema)]
pub struct ApiKeyRequest {
    /// Requested lifetime in seconds. Clamped into
    /// `[API_KEY_MIN_LIFETIME_SECS, API_KEY_MAX_LIFETIME_SECS]`; the effective
    /// value is echoed back as `expires_in`. Omitted / non-positive → the
    /// minimum.
    #[serde(default)]
    pub lifetime_seconds: Option<i64>,
    /// Roles the key should carry. Omitted / null / empty → the full session
    /// role set. Non-empty → must be a subset of the session's roles (no
    /// escalation); any role the session does not hold is a 400.
    #[serde(default)]
    pub roles: Option<Vec<String>>,
}

/// `data` of the mint response.
#[derive(Serialize, Debug, ToSchema)]
pub struct ApiKeyData {
    /// The minted API-key JWT.
    pub access_token: String,
    /// Always `"Bearer"`.
    pub token_type: String,
    /// Effective lifetime in seconds, after clamping.
    pub expires_in: i64,
    /// The payload `typ` marker, `"api_key+jwt"`.
    pub typ: String,
}

/// Decide which roles an API key carries from a requested subset and the
/// minting session's roles.
///
/// `None` or an empty request copies the full session role set; a non-empty
/// request is accepted only when every entry is held by the session (the key
/// may NARROW, never escalate). A requested role the session does not hold
/// yields `None` — the caller renders a 400 — so privilege escalation is
/// impossible.
pub fn resolve_api_key_roles(
    requested: Option<Vec<String>>,
    session_roles: &HashSet<String>,
) -> Option<HashSet<String>> {
    match requested {
        None => Some(session_roles.clone()),
        Some(r) if r.is_empty() => Some(session_roles.clone()),
        Some(r) => {
            if r.iter().all(|role| session_roles.contains(role)) {
                Some(r.into_iter().collect())
            } else {
                None
            }
        }
    }
}

/// Refuse an API key presented as the session. Mounted (after the `session`
/// hoop) on the mint endpoint, so an API key cannot mint another API key: a
/// key that could self-mint before its `exp` would escape its own lifetime
/// bound — an unbounded rotation chain. API keys are otherwise accepted
/// wherever a session is (including credential add/remove); only self-mint is
/// refused. When no session is injected (a first-time login) there is nothing
/// to reject and the request proceeds.
#[handler]
pub async fn reject_if_apikey(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let is_apikey = match depot.obtain_mut::<JwtVerify>() {
        Ok(v) => v.jwt_data.typ.as_deref() == Some(API_KEY_TYP),
        Err(_) => false,
    };
    if is_apikey {
        res.status_code(StatusCode::FORBIDDEN);
        res.render(Json(ApiProblem::forbidden_reason(
            "API keys cannot mint other API keys",
        )));
        return;
    }
    ctrl.call_next(req, depot, res).await;
}

#[endpoint(
    summary = "Mint a long-lived API key for the current session",
    request_body = ApiKeyRequest,
    responses(
        (status_code = 200, description = "API key minted", body = ApiResponse<ApiKeyData>),
        (status_code = 400, description = "Bad request / role escalation", body = ApiProblem),
        (status_code = 401, description = "No valid session", body = ApiProblem),
        (status_code = 403, description = "API keys cannot mint other API keys", body = ApiProblem),
        (status_code = 500, description = "Signing failure", body = ApiProblem),
    )
)]
pub async fn mint(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    // 1. The minting session, injected by the `session` hoop. Absent → 401.
    //    Snapshot the identity out of the depot borrow before touching state.
    let identity: Option<JwtData> = match depot.obtain_mut::<JwtVerify>() {
        Ok(v) => Some(JwtData {
            user: v.jwt_data.user.clone(),
            username: v.jwt_data.username.clone(),
            domain: v.jwt_data.domain.clone(),
            mfa: v.jwt_data.mfa.clone(),
            roles: v.jwt_data.roles.clone(),
            typ: None,
        }),
        Err(_) => None,
    };
    let Some(identity) = identity else {
        res.status_code(StatusCode::UNAUTHORIZED);
        res.render(Json(ApiProblem::unauthorized()));
        return;
    };

    // 2. Request body.
    let body = match extract::<ApiKeyRequest>(req, None).await {
        Some(b) => b,
        None => {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(ApiProblem::bad_request("invalid request body")));
            return;
        }
    };

    // 3. Role subset — no privilege escalation.
    let roles = match resolve_api_key_roles(body.roles, &identity.roles) {
        Some(roles) => roles,
        None => {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(ApiProblem::bad_request(
                "requested roles must be a subset of the session's roles",
            )));
            return;
        }
    };

    // 4. Domain / issuer / tenant (mirrors the session-gated handlers).
    let state = match depot.obtain::<ServerState>() {
        Ok(s) => s,
        Err(_) => return,
    };
    let domain = match get_domain(req, state) {
        Some(d) => d.to_string(),
        None => return,
    };
    let issuer = match get_issuer(req, state) {
        Some(i) => i,
        None => return,
    };
    let mut tenant = match state.storage.tenant_by_domain(domain.as_str()) {
        Some(t) => t,
        None => {
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            res.render(Json(ApiProblem::server_error("no tenant for domain")));
            return;
        }
    };

    // 5. Mint: copy identity, freeze mfa, stamp the marker, clamp the lifetime.
    match tenant
        .mint_api_key(&issuer, &domain, &identity, body.lifetime_seconds, roles)
        .await
    {
        Ok((jwt, secs)) => {
            res.status_code(StatusCode::OK);
            res.render(Json(ApiResponse::ok(ApiKeyData {
                access_token: jwt,
                token_type: "Bearer".to_string(),
                expires_in: secs,
                typ: API_KEY_TYP.to_string(),
            })));
        }
        Err(e) => {
            tracing::warn!(
                target: "auth::apikey",
                error = %e,
                "failed to mint API key"
            );
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
            res.render(Json(ApiProblem::server_error("failed to mint API key")));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roles(name: &str, more: &[&str]) -> HashSet<String> {
        let mut set = HashSet::new();
        set.insert(name.to_string());
        for m in more {
            set.insert((*m).to_string());
        }
        set
    }

    #[test]
    fn omitted_roles_copy_the_full_session_set() {
        let session = roles("user", &["admin"]);
        assert_eq!(resolve_api_key_roles(None, &session), Some(session.clone()));
        assert_eq!(
            resolve_api_key_roles(Some(vec![]), &session),
            Some(session.clone()),
            "an empty request is the same as omitting it"
        );
    }

    #[test]
    fn legal_subset_is_kept() {
        let session = roles("user", &["admin", "scim"]);
        assert_eq!(
            resolve_api_key_roles(Some(vec!["user".into()]), &session),
            Some(roles("user", &[]))
        );
    }

    #[test]
    fn escalation_is_refused() {
        let session = roles("user", &[]);
        // A role the session does not hold must never appear on the key.
        assert_eq!(
            resolve_api_key_roles(Some(vec!["admin".into()]), &session),
            None,
            "a requested role absent from the session is rejected"
        );
        // A mix of held + unheld roles fails closed (the whole request, not a
        // partial grant).
        assert_eq!(
            resolve_api_key_roles(Some(vec!["user".into(), "admin".into()]), &session),
            None,
            "a partial escalation fails the entire request"
        );
    }
}
