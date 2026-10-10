//! Public JWT decode / inspection endpoint.
//!
//! `POST /api/v1/jwt/decode` accepts a JWT string and returns its header and
//! claims. No authentication is required: JWT payloads are not encrypted, so
//! anyone who already possesses the token can read the claims offline. This
//! endpoint adds signature verification against the tenant's keys, expiry
//! checking, and a revocation lookup.
//!
//! Always returns HTTP 200 with a structured body; only a missing `token`
//! field is a 400.

use crate::utils::{get_domain, ApiProblem};
use base64::Engine;
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

#[derive(Debug, Deserialize, ToSchema)]
pub struct DecodeRequest {
    /// The JWT string to decode and (when possible) verify.
    pub token: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DecodeResponse {
    /// True only when the token was issued by this tenant, the signature
    /// verifies, the token is within its lifetime (with leeway), and it has
    /// not been revoked.
    pub valid: bool,
    /// Whether the token appears in the revocation store. Independent of
    /// signature / expiry — a revoked token is always `valid: false`.
    pub revoked: bool,
    /// Human-readable reason when `valid` is false. Omitted when valid.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// JWT header (alg, kid, typ, …) when the first segment is parseable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub header: Option<serde_json::Value>,
    /// Full claims payload when the second segment is parseable — returned
    /// even when the signature is invalid, so callers can still inspect the
    /// contents of a token they already possess.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<serde_json::Value>,
}

fn decode_jwt_segment(part: &str) -> Option<serde_json::Value> {
    let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let bytes = engine
        .decode(part)
        .ok()
        .or_else(|| base64::engine::general_purpose::URL_SAFE.decode(part).ok())?;
    serde_json::from_slice(&bytes).ok()
}

/// Best-effort split of a compact JWT into (header, claims) JSON values.
/// Does not touch the signature.
fn insecure_parts(token: &str) -> (Option<serde_json::Value>, Option<serde_json::Value>) {
    let mut parts = token.split('.');
    let header = parts.next().and_then(decode_jwt_segment);
    let claims = parts.next().and_then(decode_jwt_segment);
    (header, claims)
}

fn map_decode_error(err: &anyhow::Error) -> String {
    let msg = err.to_string();
    let lower = msg.to_lowercase();
    if msg.contains("ExpiredSignature") || lower.contains("expired") {
        "expired".into()
    } else if msg.contains("ImmatureSignature") || lower.contains("immature") {
        "not_yet_valid".into()
    } else if lower.contains("missing kid") || lower.contains("broken, missing kid") {
        "unknown_kid".into()
    } else if lower.contains("key") && (lower.contains("not found") || lower.contains("unknown")) {
        "unknown_kid".into()
    } else {
        "invalid_signature".into()
    }
}

#[endpoint(
    summary = "Decode a JWT issued by this server",
    description = "Accepts a JWT string and returns its header and claims. \
No authentication is required: JWT payloads are not encrypted, so anyone who \
already possesses the token can read the claims offline. This endpoint adds \
signature verification against the tenant's keys, expiry checking, and a \
revocation lookup. Always returns HTTP 200 with a structured body; only a \
malformed request (missing token) is a 400.",
    request_body = DecodeRequest,
    responses(
        (status_code = 200, description = "Decode result", body = DecodeResponse),
        (status_code = 400, description = "Malformed request", body = ApiProblem),
    )
)]
pub async fn decode_jwt(req: &mut Request, depot: &mut Depot, res: &mut Response) {
    let params = match crate::utils::extract::<DecodeRequest>(req, None).await {
        Some(p) if !p.token.trim().is_empty() => p,
        _ => {
            res.status_code(StatusCode::BAD_REQUEST);
            res.render(Json(ApiProblem::bad_request("missing token")));
            return;
        }
    };
    let token = params.token.trim().to_string();

    let (header, claims) = insecure_parts(&token);

    // Malformed compact serialization — nothing further to report.
    if header.is_none() && claims.is_none() {
        res.status_code(StatusCode::OK);
        res.render(Json(DecodeResponse {
            valid: false,
            revoked: false,
            reason: Some("malformed".into()),
            header: None,
            claims: None,
        }));
        return;
    }

    // `InvalidJwt::is_valid` means "present in the revocation store".
    let revoked = match crate::jwt::InvalidJwt::try_global() {
        Some(store) => store.is_valid(&token).await,
        None => false,
    };

    let mut signature_ok = false;
    let mut reason: Option<String> = None;

    // Resolve the tenant from Host so we can verify against real keys.
    if let Ok(state) = depot.obtain_mut::<crate::server::ServerState>() {
        if let Some(domain) = get_domain(req, state) {
            if let Some(mut tenant) = state.storage.tenant_by_domain(domain) {
                match crate::jwt::jwt_decode::<serde_json::Value>(
                    &token,
                    crate::jwt::VERIFICATION_GRACE_MINUTES,
                    &mut tenant,
                )
                .await
                {
                    Ok(_data) => {
                        signature_ok = true;
                    }
                    Err(e) => {
                        reason = Some(map_decode_error(&e));
                    }
                }
            } else {
                reason = Some("unknown_issuer".into());
            }
        } else {
            reason = Some("unknown_issuer".into());
        }
    } else {
        reason = Some("unknown_issuer".into());
    }

    if revoked {
        reason = Some("revoked".into());
    }

    let valid = signature_ok && !revoked;
    if valid {
        reason = None;
    } else if reason.is_none() {
        reason = Some("invalid".into());
    }

    res.status_code(StatusCode::OK);
    res.render(Json(DecodeResponse {
        valid,
        revoked,
        reason,
        header,
        claims,
    }));
}
