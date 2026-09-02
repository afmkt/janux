//! Operational endpoints: health probes, Prometheus metrics, and request
//! correlation.
//!
//! Metric label sets are deliberately bounded: `route_label` collapses
//! dynamic path segments and `auth_attempt` only accepts known
//! factor/action names, so no client-supplied input can inflate series
//! cardinality.

use std::sync::LazyLock;
use std::time::{Duration, Instant};

use prometheus::{
    Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
    TextEncoder,
};
use salvo::prelude::*;
use serde::{Deserialize, Serialize};

use crate::server::ServerState;

// ── Health probes ────────────────────────────────────────────────────

#[derive(Serialize, Deserialize, ToSchema)]
pub struct HealthyResponse {
    pub ok: bool,
}

/// Shallow health check. Kept stable because the test harness and
/// container healthchecks use it as the "server is up" signal.
#[endpoint(
    summary = "Shallow health check",
    responses(
        (status_code = 200, description = "Server is up", body = HealthyResponse),
    )
)]
pub async fn healthy() -> Json<HealthyResponse> {
    Json(HealthyResponse { ok: true })
}

/// Liveness probe: the process is running and answering. Deliberately
/// dependency-free — losing a backend makes the server unready, not
/// dead, and restarting a live process on that basis would be wrong.
#[endpoint(
    summary = "Liveness probe",
    responses(
        (status_code = 200, description = "Process is alive", body = HealthyResponse),
    )
)]
pub async fn live() -> Json<HealthyResponse> {
    Json(HealthyResponse { ok: true })
}

/// Readiness probe: the server state is injected and the data
/// directory backing the tenant databases is still present.
///
/// Deliberately takes NO tenant guard (README §6): probes must not
/// serialize behind in-flight tenant requests, so this checks the
/// tenant map without borrowing any tenant.
#[endpoint(
    summary = "Readiness probe",
    responses(
        (status_code = 200, description = "Ready to serve", body = HealthyResponse),
        (status_code = 503, description = "Not ready", body = HealthyResponse),
    )
)]
pub async fn ready(depot: &mut Depot, res: &mut Response) {
    let ok = depot
        .obtain_mut::<ServerState>()
        .map(|state| state.storage.raw_path.is_dir())
        .unwrap_or(false);
    if !ok {
        res.status_code(StatusCode::SERVICE_UNAVAILABLE);
    }
    res.render(Json(HealthyResponse { ok }));
}

// ── Request correlation ──────────────────────────────────────────────

pub const REQUEST_ID_HEADER: &str = "x-request-id";
const REQUEST_ID_DEPOT_KEY: &str = "janux_request_id";

/// Edge hoop: adopt a caller-supplied `X-Request-Id` (validated ASCII,
/// <= 128 chars) or mint a UUIDv4, carry it through the depot for
/// logging, and echo it back on the response so clients can correlate
/// their side with server logs.
#[handler]
pub async fn request_id(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let id = req
        .headers()
        .get(REQUEST_ID_HEADER)
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .filter(|s| !s.is_empty() && s.len() <= 128 && s.bytes().all(|b| b.is_ascii_graphic()))
        .map(str::to_string)
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    depot.insert(REQUEST_ID_DEPOT_KEY, id.clone());
    ctrl.call_next(req, depot, res).await;
    res.headers_mut().insert(
        salvo::http::header::HeaderName::from_static(REQUEST_ID_HEADER),
        id.parse().expect("request id is validated ASCII"),
    );
}

/// The current request's correlation id, if the `request_id` hoop ran.
pub fn request_id_of(depot: &Depot) -> Option<&String> {
    depot.get::<String>(REQUEST_ID_DEPOT_KEY).ok()
}

// ── Metrics ──────────────────────────────────────────────────────────

static HTTP_REQUESTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "janux_http_requests_total",
            "HTTP requests by normalized route, method and status code",
        ),
        &["path", "method", "status"],
    )
    .expect("valid metric definition")
});

static HTTP_DURATION: LazyLock<HistogramVec> = LazyLock::new(|| {
    HistogramVec::new(
        HistogramOpts::new(
            "janux_http_request_duration_seconds",
            "HTTP request latency by normalized route and method",
        ),
        &["path", "method"],
    )
    .expect("valid metric definition")
});

static RATE_LIMITED: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "janux_http_rate_limited_total",
            "Requests rejected with 429 by the rate limiters",
        ),
        &["path"],
    )
    .expect("valid metric definition")
});

static AUTH_ATTEMPTS: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "janux_auth_attempts_total",
            "Passwordless factor attempts by factor, action and outcome",
        ),
        &["factor", "action", "outcome"],
    )
    .expect("valid metric definition")
});

static TOKENS_ISSUED: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "janux_tokens_issued_total",
            "JWTs minted (session = login factors, oidc = /token grants)",
        ),
        &["kind"],
    )
    .expect("valid metric definition")
});

static TOKENS_REFRESHED: LazyLock<IntCounterVec> = LazyLock::new(|| {
    IntCounterVec::new(
        Opts::new(
            "janux_tokens_refreshed_total",
            "Successful token rotations (session = /auth/refresh, oidc = refresh_token grant)",
        ),
        &["kind"],
    )
    .expect("valid metric definition")
});

static TOKENS_REVOKED: LazyLock<IntCounter> = LazyLock::new(|| {
    IntCounter::new(
        "janux_tokens_revoked_total",
        "Revocations committed to the InvalidJwt store (insert-wins, deduplicated)",
    )
    .expect("valid metric definition")
});

static REVOKED_STORED: LazyLock<IntGauge> = LazyLock::new(|| {
    IntGauge::new(
        "janux_revocation_records_stored",
        "Rows currently in the persistent revocation store",
    )
    .expect("valid metric definition")
});

static TENANTS_LOADED: LazyLock<IntGauge> = LazyLock::new(|| {
    IntGauge::new(
        "janux_tenants_loaded",
        "Tenants currently loaded in this process",
    )
    .expect("valid metric definition")
});

static TENANT_GUARD_WAIT: LazyLock<Histogram> = LazyLock::new(|| {
    Histogram::with_opts(
        HistogramOpts::new(
            "janux_tenant_guard_wait_seconds",
            "Time spent acquiring the per-tenant serialization guard (README §6 head-of-line cost)",
        )
        .buckets(vec![
            0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0,
        ]),
    )
    .expect("valid metric definition")
});

static REGISTRY: LazyLock<Registry> = LazyLock::new(|| {
    let r = Registry::new();
    r.register(Box::new(HTTP_REQUESTS.clone()))
        .expect("registration cannot fail");
    r.register(Box::new(HTTP_DURATION.clone()))
        .expect("registration cannot fail");
    r.register(Box::new(RATE_LIMITED.clone()))
        .expect("registration cannot fail");
    r.register(Box::new(AUTH_ATTEMPTS.clone()))
        .expect("registration cannot fail");
    r.register(Box::new(TOKENS_ISSUED.clone()))
        .expect("registration cannot fail");
    r.register(Box::new(TOKENS_REFRESHED.clone()))
        .expect("registration cannot fail");
    r.register(Box::new(TOKENS_REVOKED.clone()))
        .expect("registration cannot fail");
    r.register(Box::new(REVOKED_STORED.clone()))
        .expect("registration cannot fail");
    r.register(Box::new(TENANTS_LOADED.clone()))
        .expect("registration cannot fail");
    r.register(Box::new(TENANT_GUARD_WAIT.clone()))
        .expect("registration cannot fail");
    r
});

// Recording helpers called from the choke points (db.rs, jwt.rs, oidc.rs).

pub fn token_issued(kind: &'static str) {
    TOKENS_ISSUED.with_label_values(&[kind]).inc();
}

pub fn token_refreshed(kind: &'static str) {
    TOKENS_REFRESHED.with_label_values(&[kind]).inc();
}

pub fn record_revocation() {
    TOKENS_REVOKED.inc();
}

pub fn record_guard_wait(elapsed: Duration) {
    TENANT_GUARD_WAIT.observe(elapsed.as_secs_f64());
}

/// Collapse a request path into a bounded route label. Dynamic segments
/// are replaced (`social/{id}`) or dropped (frontend catch-all), so the
/// label set cannot grow with attacker-chosen URLs.
fn route_label(path: &str) -> String {
    let path = path.split('?').next().unwrap_or(path);
    let mut segs = path.split('/').filter(|s| !s.is_empty());
    match (segs.next(), segs.next()) {
        (Some("api"), Some("v1")) => {
            let area = segs.next().unwrap_or("");
            let rest: Vec<&str> = segs.collect();
            if area == "auth" {
                // /api/v1/auth/{factor}/{action}; social carries an {id}
                // segment between factor and action.
                let (factor, action) = if rest.first() == Some(&"social") {
                    ("social", rest[2..].join("/"))
                } else {
                    (rest.first().copied().unwrap_or(""), rest[1..].join("/"))
                };
                if action.is_empty() {
                    format!("/api/v1/auth/{factor}")
                } else {
                    format!("/api/v1/auth/{factor}/{action}")
                }
            } else {
                // admin/* and health routes are fixed names.
                let tail = rest.join("/");
                if tail.is_empty() {
                    format!("/api/v1/{area}")
                } else {
                    format!("/api/v1/{area}/{tail}")
                }
            }
        }
        (Some(".well-known"), _) => "discovery".into(),
        (Some("scim"), Some("v2")) => {
            // Bounded labels: the dynamic resource instance segment is
            // collapsed to the canonical `{id}` policy resource.
            let rest: Vec<&str> = segs.collect();
            match rest.as_slice() {
                ["Users"] => "/scim/v2/Users".into(),
                ["Users", _] => "/scim/v2/Users/{id}".into(),
                [page] => format!("/scim/v2/{page}"),
                _ => "/scim/v2".into(),
            }
        }
        (Some(first), _) => {
            const PROTOCOL: &[&str] = &[
                "authorize",
                "consent",
                "token",
                "userinfo",
                "revoke",
                "introspect",
                "device_authorization",
                "device-login",
            ];
            if PROTOCOL.contains(&first) {
                path.trim_start_matches('/').into()
            } else {
                // Hosted pages and the frontend catch-all.
                "static".into()
            }
        }
        _ => "static".into(),
    }
}

const KNOWN_FACTORS: &[&str] = &["email", "otp", "passkey", "social", "totp"];
const KNOWN_ACTIONS: &[&str] = &[
    "request",
    "verify",
    "add",
    "add/verify",
    "remove",
    "enroll",
    "link",
    "redeem",
];

/// Extract a bounded (factor, action, outcome) triple from a
/// `/api/v1/auth/*` path, or `None` for anything outside the known
/// factor/action catalog.
fn auth_attempt(path: &str, status: u16) -> Option<(&'static str, &'static str, &'static str)> {
    let mut segs = path.split('?').next()?.split('/').filter(|s| !s.is_empty());
    if segs.next()? != "api" || segs.next()? != "v1" || segs.next()? != "auth" {
        return None;
    }
    let rest: Vec<&str> = segs.collect();
    let factor = KNOWN_FACTORS
        .iter()
        .copied()
        .find(|f| rest.first() == Some(f))?;
    let action_str = if factor == "social" {
        rest[2..].join("/")
    } else {
        rest[1..].join("/")
    };
    let action = KNOWN_ACTIONS.iter().copied().find(|a| *a == action_str)?;
    let outcome = if (100..400).contains(&status) {
        "ok"
    } else {
        "fail"
    };
    Some((factor, action, outcome))
}

/// Outermost recording hoop: RED metrics, rate-limit rejections and
/// factor attempt counters for every request. Must sit OUTSIDE the
/// rate-limiter hoops to observe their 429s.
#[handler]
pub async fn metrics_hoop(
    req: &mut Request,
    depot: &mut Depot,
    res: &mut Response,
    ctrl: &mut FlowCtrl,
) {
    let path = req.uri().path().to_string();
    let method = req.method().to_string();
    let start = Instant::now();
    ctrl.call_next(req, depot, res).await;
    let elapsed = start.elapsed();
    let status = res.status_code.map(|s| s.as_u16()).unwrap_or(0);
    let label = route_label(&path);
    let status_str = status.to_string();
    HTTP_REQUESTS
        .with_label_values(&[&label, &method, &status_str])
        .inc();
    HTTP_DURATION
        .with_label_values(&[&label, &method])
        .observe(elapsed.as_secs_f64());
    if status == 429 {
        RATE_LIMITED.with_label_values(&[&label]).inc();
    }
    if let Some((factor, action, outcome)) = auth_attempt(&path, status) {
        AUTH_ATTEMPTS
            .with_label_values(&[factor, action, outcome])
            .inc();
    }
}

/// Prometheus scrape endpoint. Process-global telemetry (all tenants),
/// therefore admin-gated behind the default-deny `protect` hoop — it
/// must never sit on the public surface.
#[endpoint(
    summary = "Prometheus metrics (process-global, admin-gated)",
    responses(
        (status_code = 200, description = "Prometheus text exposition format", body = String),
    )
)]
pub async fn metrics(depot: &mut Depot, res: &mut Response) {
    if let Ok(state) = depot.obtain_mut::<ServerState>() {
        TENANTS_LOADED.set(state.storage.tenants.len() as i64);
    }
    if let Some(store) = crate::jwt::InvalidJwt::try_global() {
        if let Ok(n) = store.len().await {
            REVOKED_STORED.set(n as i64);
        }
    }
    match TextEncoder::new().encode_to_string(&REGISTRY.gather()) {
        Ok(out) => {
            res.headers_mut().insert(
                salvo::http::header::CONTENT_TYPE,
                salvo::http::HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
            );
            res.render(Text::Plain(out));
        }
        Err(e) => {
            tracing::error!(error = %e, "failed to encode prometheus metrics");
            res.status_code(StatusCode::INTERNAL_SERVER_ERROR);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_label_bounds_cardinality() {
        assert_eq!(route_label("/api/v1/healthy"), "/api/v1/healthy");
        assert_eq!(
            route_label("/api/v1/auth/email/verify"),
            "/api/v1/auth/email/verify"
        );
        // social's {id} segment is dropped
        assert_eq!(
            route_label("/api/v1/auth/social/google/request"),
            "/api/v1/auth/social/request"
        );
        assert_eq!(
            route_label("/api/v1/admin/oauth2client/create"),
            "/api/v1/admin/oauth2client/create"
        );
        assert_eq!(route_label("/.well-known/jwks.json"), "discovery");
        assert_eq!(route_label("/token"), "token");
        assert_eq!(route_label("/authorize/resume"), "authorize/resume");
        // SCIM labels stay bounded: instance ids collapse to `{id}`
        assert_eq!(route_label("/scim/v2/Users"), "/scim/v2/Users");
        assert_eq!(
            route_label("/scim/v2/Users/01a058ed-b318-7c50-90a7-74469a942bf8"),
            "/scim/v2/Users/{id}"
        );
        assert_eq!(
            route_label("/scim/v2/ServiceProviderConfig"),
            "/scim/v2/ServiceProviderConfig"
        );
        // frontend catch-all and hosted pages collapse to one label
        assert_eq!(route_label("/assets/login-DujkBr0F.js"), "static");
        assert_eq!(route_label("/login"), "static");
        assert_eq!(route_label("/../../etc/passwd"), "static");
    }

    #[test]
    fn auth_attempt_only_accepts_known_factors_and_actions() {
        assert_eq!(
            auth_attempt("/api/v1/auth/email/verify", 200),
            Some(("email", "verify", "ok"))
        );
        assert_eq!(
            auth_attempt("/api/v1/auth/otp/request", 429),
            Some(("otp", "request", "fail"))
        );
        assert_eq!(
            auth_attempt("/api/v1/auth/social/github/verify", 401),
            Some(("social", "verify", "fail"))
        );
        // unknown factor / action / non-auth paths are rejected
        assert_eq!(auth_attempt("/api/v1/auth/nuclear/verify", 200), None);
        assert_eq!(auth_attempt("/api/v1/auth/email/explode", 200), None);
        assert_eq!(auth_attempt("/api/v1/admin/user/list", 200), None);
    }

    #[test]
    fn registry_renders_prometheus_text() {
        token_issued("session");
        record_revocation();
        record_guard_wait(Duration::from_micros(42));
        let out = TextEncoder::new()
            .encode_to_string(&REGISTRY.gather())
            .expect("encoding cannot fail");
        assert!(out.contains("janux_tokens_issued_total"));
        assert!(out.contains("janux_tokens_revoked_total"));
        assert!(out.contains("janux_tenant_guard_wait_seconds"));
    }
}
