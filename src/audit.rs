use salvo::prelude::*;
use tracing::{error, info};

/// What a request acted ON (G-89). The audit hoop sees the route, the
/// actor and the outcome, but not the resource — handlers record it here
/// as soon as the target identity is parsed, BEFORE the action is
/// attempted, so denied and failed attempts are attributed too (that is
/// where the trail earns its keep: who TRIED what against whom).
///
/// `detail` carries cheap old→new-style facts where the handler has them
/// (`level=79`, `active=false`, `factor=email`). Full before/after diff
/// capture is a separate ambition (gaps.md G-166).
#[derive(Clone, Debug)]
pub struct AuditTarget {
    pub kind: &'static str,
    pub name: String,
    pub detail: Option<String>,
}

/// Record the target of this request (see [`AuditTarget`]). Carried on
/// the response extensions, not the depot: handlers typically hold a
/// long-lived `depot` borrow (the injected `ServerState`), while `res`
/// is free until the render calls.
pub fn record_target(res: &mut Response, kind: &'static str, name: &str) {
    res.extensions.insert(AuditTarget {
        kind,
        name: name.to_string(),
        detail: None,
    });
}

/// Record the target plus an old→new-style detail fact.
pub fn record_target_detail(res: &mut Response, kind: &'static str, name: &str, detail: &str) {
    res.extensions.insert(AuditTarget {
        kind,
        name: name.to_string(),
        detail: Some(detail.to_string()),
    });
}

/// The rendered `target`/`detail` pair for the audit line; "-" when the
/// handler recorded nothing (reads, unparseable bodies, uncovered routes).
fn audit_target(res: &Response) -> (String, String) {
    match res.extensions.get::<AuditTarget>() {
        Some(t) => (
            format!("{}:{}", t.kind, t.name),
            t.detail.clone().unwrap_or_else(|| "-".to_string()),
        ),
        None => ("-".to_string(), "-".to_string()),
    }
}

/// The actor/tenant context for an audit line (G-89). Read AFTER the
/// handler runs, so the `protect`/`session` hoop's injection is visible:
/// this upgrades the trail from a pure access log (method/URI/status) to
/// actor-attributed lines — who (username), as which principal (sub), on
/// which tenant (domain). Routes that ran without a session (public
/// ceremonies, unauthenticated refusals) report "-".
fn audit_actor(depot: &Depot) -> (String, String, String) {
    match depot.obtain::<crate::db::JwtVerify>() {
        Ok(v) => (
            v.jwt_data.username.clone(),
            v.jwt_data.user.clone(),
            v.domain.clone(),
        ),
        Err(_) => ("-".to_string(), "-".to_string(), "-".to_string()),
    }
}

/// Query parameters whose VALUES are one-shot secrets or credentials
/// (G-140). The audit hoop logs the request URI, and several ceremonies
/// accept their secret as a query parameter (GET-routed `totp/verify`,
/// magic-link landings, social callbacks, device flow) — logging those
/// verbatim writes live credentials into the log sink. Matched
/// case-insensitively; the parameter NAME is kept (it identifies the
/// flow), the value is not.
const SENSITIVE_QUERY_PARAMS: &[&str] = &[
    "token",
    "code",
    "jwt",
    "access_token",
    "refresh_token",
    "id_token",
    "id_token_hint",
    "logout_token",
    "assertion",
    "client_secret",
    "secret",
    "password",
    "user_code",
];

/// The request URI as it may be logged: path plus a query string whose
/// sensitive values are replaced with `[redacted]` (G-140). Non-secret
/// parameters (e.g. `state`, usernames) stay — they are what makes the
/// trail useful.
fn redacted_uri(uri: &salvo::http::uri::Uri) -> String {
    let Some(query) = uri.query() else {
        return uri.path().to_string();
    };
    let redacted = query
        .split('&')
        .map(|pair| match pair.split_once('=') {
            Some((key, _))
                if SENSITIVE_QUERY_PARAMS
                    .iter()
                    .any(|s| s.eq_ignore_ascii_case(key)) =>
            {
                format!("{key}=[redacted]")
            }
            _ => pair.to_string(),
        })
        .collect::<Vec<_>>()
        .join("&");
    format!("{}?{redacted}", uri.path())
}

#[handler]
pub async fn audit(req: &mut Request, depot: &mut Depot, res: &mut Response, ctrl: &mut FlowCtrl) {
    let method = req.method().clone();
    let uri = redacted_uri(req.uri());
    let start = std::time::Instant::now();

    // Run the next hop/handler in the chain

    ctrl.call_next(req, depot, res).await;

    let elapsed = start.elapsed();
    // Correlation id from the edge hoop (crate::ops::request_id); empty
    // when the route is exercised without it (e.g. isolated test setups).
    let request_id = crate::ops::request_id_of(depot)
        .cloned()
        .unwrap_or_default();
    let (actor, sub, domain) = audit_actor(depot);
    let (target, detail) = audit_target(res);
    if let Some(status_code) = res.status_code {
        // 3xx are successful redirects (e.g. the social callback's 303 to
        // the login page), not failures — logging them at error level
        // floods alerting pipelines with normal traffic.
        if status_code.as_u16() < 400 {
            info!(
                request_id = %request_id,
                actor = %actor,
                sub = %sub,
                domain = %domain,
                target = %target,
                detail = %detail,
                "OK {}, {}, {}, {duration_ms}",
                method,
                uri,
                status_code.as_u16(),
                duration_ms = elapsed.as_millis()
            );
        } else {
            error!(
                request_id = %request_id,
                actor = %actor,
                sub = %sub,
                domain = %domain,
                target = %target,
                detail = %detail,
                "FAILED {}, {}, {}, {duration_ms}",
                method,
                uri,
                status_code.as_u16(),
                duration_ms = elapsed.as_millis()
            );
        }
    } else {
        error!(
            request_id = %request_id,
            actor = %actor,
            sub = %sub,
            domain = %domain,
            target = %target,
            detail = %detail,
            "FAILED {}, {}, {}, {duration_ms}",
            method,
            uri,
            "Unknown status code",
            duration_ms = elapsed.as_millis()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[handler]
    async fn mutation_probe(res: &mut Response) {
        record_target_detail(res, "user", "alice", "active=false");
        res.status_code(StatusCode::OK);
        res.render(Json(crate::utils::ApiResponse::ok(())));
    }

    #[handler]
    async fn inject_session(
        req: &mut Request,
        depot: &mut Depot,
        res: &mut Response,
        ctrl: &mut FlowCtrl,
    ) {
        depot.inject(crate::db::JwtVerify {
            can_access: true,
            jwt_data: crate::db::JwtData {
                user: "uuid-1".to_string(),
                username: "alice".to_string(),
                domain: "example.com".to_string(),
                mfa: HashSet::new(),
                roles: HashSet::from(["admin".to_string()]),
            },
            expect_mfa: false,
            domain: "example.com".to_string(),
            auth_time: None,
        });
        ctrl.call_next(req, depot, res).await;
    }

    /// End-to-end shape check (G-89): a real request through the hoop
    /// renders actor, tenant, and the handler-recorded target into the
    /// log line — the contract log-based alerting and forensics rely on.
    #[tokio::test]
    async fn audit_hoop_renders_actor_and_target() {
        use std::io::Write;
        use std::sync::{Arc, Mutex};
        use tracing_subscriber::fmt::MakeWriter;

        #[derive(Clone, Default)]
        struct SharedBuf(Arc<Mutex<Vec<u8>>>);
        impl Write for SharedBuf {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().write(b)
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> MakeWriter<'a> for SharedBuf {
            type Writer = SharedBuf;
            fn make_writer(&self) -> SharedBuf {
                self.clone()
            }
        }

        let buf = SharedBuf::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(buf.clone())
            .with_ansi(false)
            .finish();
        let guard = tracing::subscriber::set_default(subscriber);

        let service = Service::new(
            Router::new().push(
                Router::with_path("probe")
                    .hoop(audit)
                    .hoop(inject_session)
                    .post(mutation_probe),
            ),
        );
        let res = salvo::test::TestClient::post("http://localhost/probe")
            .send(&service)
            .await;
        assert_eq!(res.status_code, Some(StatusCode::OK));
        drop(guard);

        let logged = String::from_utf8(buf.0.lock().unwrap().clone()).expect("utf8 log");
        assert!(logged.contains("actor=alice"), "{logged}");
        assert!(logged.contains("sub=uuid-1"), "{logged}");
        assert!(logged.contains("domain=example.com"), "{logged}");
        assert!(logged.contains("target=user:alice"), "{logged}");
        assert!(logged.contains("detail=active=false"), "{logged}");
        assert!(logged.contains("OK POST"), "{logged}");
    }

    /// G-89: the actor context comes from the injected session; without
    /// one every field degrades to "-" instead of panicking or lying.
    #[test]
    fn audit_actor_reads_the_injected_session() {
        let mut depot = Depot::new();
        assert_eq!(
            audit_actor(&depot),
            ("-".into(), "-".into(), "-".into()),
            "no session → placeholder actor"
        );

        depot.inject(crate::db::JwtVerify {
            can_access: true,
            jwt_data: crate::db::JwtData {
                user: "uuid-1".to_string(),
                username: "alice".to_string(),
                domain: "api.example.com".to_string(),
                mfa: HashSet::new(),
                roles: HashSet::from(["admin".to_string()]),
            },
            expect_mfa: false,
            domain: "api.example.com".to_string(),
            auth_time: None,
        });
        assert_eq!(
            audit_actor(&depot),
            ("alice".into(), "uuid-1".into(), "api.example.com".into())
        );
    }

    /// G-89: handlers record what the request acted ON; the hoop renders
    /// `kind:name` plus the optional detail, and "-" when nothing was
    /// recorded (reads, unparseable bodies, uncovered routes).
    #[test]
    fn audit_target_reads_the_recorded_context() {
        let mut res = Response::new();
        assert_eq!(audit_target(&res), ("-".into(), "-".into()));

        record_target(&mut res, "user", "alice");
        assert_eq!(audit_target(&res), ("user:alice".into(), "-".into()));

        record_target_detail(&mut res, "role", "ops", "level=79");
        assert_eq!(
            audit_target(&res),
            ("role:ops".into(), "level=79".into()),
            "the latest record wins"
        );
    }

    /// G-140: one-shot secrets riding in query strings must never reach
    /// the log sink; the rest of the URI stays useful.
    #[test]
    fn audit_uri_redacts_secret_query_values() {
        use salvo::http::uri::Uri;

        // No query → just the path.
        let uri: Uri = "/api/v1/admin/user/create".parse().unwrap();
        assert_eq!(redacted_uri(&uri), "/api/v1/admin/user/create");

        // Secret values redacted, names and innocent params kept.
        let uri: Uri = "/api/v1/auth/totp/verify?code=123456&jwt=eyJhbGci&state=abc&user=alice"
            .parse()
            .unwrap();
        let logged = redacted_uri(&uri);
        assert!(logged.contains("code=[redacted]"), "{logged}");
        assert!(logged.contains("jwt=[redacted]"), "{logged}");
        assert!(logged.contains("state=abc"), "{logged}");
        assert!(logged.contains("user=alice"), "{logged}");
        assert!(!logged.contains("123456"), "{logged}");
        assert!(!logged.contains("eyJhbGci"), "{logged}");

        // Case-insensitive parameter matching; magic-link landings.
        let uri: Uri = "/login?Token=sekrit&username=bob".parse().unwrap();
        let logged = redacted_uri(&uri);
        assert!(logged.contains("Token=[redacted]"), "{logged}");
        assert!(!logged.contains("sekrit"), "{logged}");

        // Valueless pairs and empty values survive unchanged.
        let uri: Uri = "/x?flag&code=".parse().unwrap();
        let logged = redacted_uri(&uri);
        assert!(logged.contains("flag"), "{logged}");
        assert!(logged.contains("code=[redacted]"), "{logged}");
    }
}
