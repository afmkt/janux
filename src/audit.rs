use salvo::prelude::*;
use sha2::{Digest, Sha256};
use std::sync::{Mutex, OnceLock};
use tracing::{error, info};

/// What a request acted ON (G-89). The audit hoop sees the route, the
/// actor and the outcome, but not the resource — handlers record it here
/// as soon as the target identity is parsed, BEFORE the action is
/// attempted, so denied and failed attempts are attributed too (that is
/// where the trail earns its keep: who TRIED what against whom).
///
/// `detail` carries a cheap old→new-style fact where the handler has the
/// requested change on hand (`level=79`, `active=false`, `factor=email`).
/// `diff` (G-166) carries a full before/after snapshot when the handler
/// read the prior state — `active=true->false` — so a mutation line shows
/// both sides of the change rather than only the requested value.
#[derive(Clone, Debug, Default)]
pub struct AuditTarget {
    pub kind: &'static str,
    pub name: String,
    pub detail: Option<String>,
    /// G-166: the full before→after snapshot of the mutated field, rendered
    /// as a dedicated `diff=` field when the handler captured both sides.
    pub diff: Option<String>,
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
        diff: None,
    });
}

/// Record the target plus an old→new-style detail fact.
pub fn record_target_detail(res: &mut Response, kind: &'static str, name: &str, detail: &str) {
    res.extensions.insert(AuditTarget {
        kind,
        name: name.to_string(),
        detail: Some(detail.to_string()),
        diff: None,
    });
}

/// Record the target plus a full before→after diff snapshot (G-166). The
/// handler must have read the prior state so it can name both ends; the
/// trail then renders `diff=old->new` alongside whatever `detail=` fact
/// was recorded, giving a mutation line its full shape even when a field
/// is set by many distinct callers.
pub fn record_target_diff(
    res: &mut Response,
    kind: &'static str,
    name: &str,
    before: &str,
    after: &str,
) {
    res.extensions.insert(AuditTarget {
        kind,
        name: name.to_string(),
        detail: None,
        diff: Some(format!("{before}->{after}")),
    });
}

/// Record the target with BOTH a `detail=` fact and a full before->after
/// `diff=` snapshot (G-166). Use where the handler reads the prior state
/// and wants the trail to show the requested change *and* both sides of
/// the transition in one line.
pub fn record_target_full(
    res: &mut Response,
    kind: &'static str,
    name: &str,
    detail: &str,
    before: &str,
    after: &str,
) {
    res.extensions.insert(AuditTarget {
        kind,
        name: name.to_string(),
        detail: Some(detail.to_string()),
        diff: Some(format!("{before}->{after}")),
    });
}

/// The rendered `target`/`detail`/`diff` triple for the audit line; "-" in
/// each slot when the handler did not record it (reads, unparseable
/// bodies, uncovered routes).
fn audit_target(res: &Response) -> (String, String, String) {
    match res.extensions.get::<AuditTarget>() {
        Some(t) => (
            format!("{}:{}", t.kind, t.name),
            t.detail.clone().unwrap_or_else(|| "-".to_string()),
            t.diff.clone().unwrap_or_else(|| "-".to_string()),
        ),
        None => ("-".to_string(), "-".to_string(), "-".to_string()),
    }
}

/// The actor/tenant context for an audit line (G-89). Read AFTER the
/// handler runs, so the `protect`/`session` hoop's injection is visible:
/// this upgrades the trail from a pure access log (method/URI/status) to
/// actor-attributed lines — who (username), as which principal (sub), on
/// which tenant (domain). Routes that ran without a session (public
/// mutations recorded via [`record_target`] with a subject in the target,
/// unauthenticated refusals) report "-".
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

// ── Tamper-evident hash chain (G-166) ─────────────────────────────────
//
// Every audit line is linked to the one before it: a monotonically
// increasing `seq` plus a `prev` holding the final hash of the prior
// line. A verifier who replays the trail recomputes
// sha256(prev_hash || "\n" || line) and checks the emitted `prev`; any
// insertion, deletion, or reorder of an already-persisted line breaks
// exactly one `prev` link, so the tampering is detectable. (Genesis is
// 32 zero bytes.) This bounds in-process and reordered tampering;
// surviving total host compromise additionally needs the trail shipped to
// an append-only external sink, which is an operator configuration outside
// the trail's own integrity property.
#[derive(Clone, Debug)]
pub struct AuditChain {
    /// 1-based sequence number of this line in the process's trail.
    pub seq: u64,
    /// Hex of the prior line's hash (genesis: 32 zero bytes = 64 `0`s).
    pub prev: String,
}

type H = [u8; 32];

/// A replayable hash-chain state. `Chain::new()` is the genesis (seq 0,
/// all-zero prev) so an isolated process or test can verify a stream from
/// a known start. The live trail's tail lives behind [`audit_chain_next`].
#[derive(Default)]
pub struct Chain {
    seq: u64,
    prev: H,
}

impl Chain {
    pub fn new() -> Self {
        Chain {
            seq: 0,
            prev: [0; 32],
        }
    }

    /// Advance the chain with one line, returning the `(seq, prev)` the
    /// caller writes alongside it. The line bytes are folded into the new
    /// running hash; a verifier re-derives the link from the persisted
    /// message plus the emitted `prev`.
    pub fn next(&mut self, line: &str) -> (u64, String) {
        self.seq += 1;
        let prev_hex = hex_of(&self.prev);
        let mut hasher = Sha256::new();
        hasher.update(self.prev);
        hasher.update(b"\n");
        hasher.update(line.as_bytes());
        self.prev = hasher.finalize().into();
        (self.seq, prev_hex)
    }
}

/// Verify a reconstructed trail (G-166): for each persisted `line`, the
/// `prev` the line claimed must equal the hash-link derived from the
/// genesis and every preceding line. Returns `false` on any broken link —
/// i.e. a detected insertion, deletion, or reorder.
///
/// This is the verification primitive for shipping the chain to an
/// append-only, externally-held store (the external-sink portion that
/// remains a residual: Janux writes lines in-process; the operator's sink
/// calls `verify_chain` over the imported lines to detect tampering). It is
/// not yet wired into the running binary, hence the `allow(dead_code)`.
#[allow(dead_code)]
pub fn verify_chain(lines: &[&str], claimed_prevs: &[String]) -> bool {
    if lines.len() != claimed_prevs.len() {
        return false;
    }
    let mut chain = Chain::new();
    for (line, claimed) in lines.iter().zip(claimed_prevs.iter()) {
        let (_seq, prev) = chain.next(line);
        if prev != *claimed {
            return false;
        }
    }
    true
}

fn hex_of(hash: &H) -> String {
    hash.iter().map(|b| format!("{b:02x}")).collect()
}

// The process-global tail of the trail. One chain, shared by every audit
// hoop; each advance is taken under the lock so concurrent requests cannot
// interleave two advances out of `seq` order.
static CHAIN: OnceLock<Mutex<Chain>> = OnceLock::new();

/// The `seq`/`prev` a new audit line must carry (G-166). Process-global
/// so the whole service is one ordered, tamper-evident sequence.
pub fn audit_chain_next(line: &str) -> AuditChain {
    let mut guard = CHAIN
        .get_or_init(|| Mutex::new(Chain::new()))
        .lock()
        .expect("audit chain");
    let (seq, prev) = guard.next(line);
    AuditChain { seq, prev }
}

/// The canonical, deterministic bytes an audit line is chained on (G-166).
/// Everything security-relevant goes in; nothing that the log formatter
/// adds (timestamps, level) does, so a verifier recomputing from the
/// persisted message reaches the same `prev` regardless of how the sink
/// formats it.
/// One material field per audit line; the ten-arg shape is the audit schema
/// itself, so the function is allowed over the arg-count heuristic.
#[allow(clippy::too_many_arguments)]
fn line_material(
    verdict: &str,
    method: &str,
    uri: &str,
    status: &str,
    actor: &str,
    sub: &str,
    domain: &str,
    target: &str,
    detail: &str,
    diff: &str,
) -> String {
    format!(
        "{verdict} {method} {uri} {status} actor={actor} sub={sub} domain={domain} target={target} detail={detail} diff={diff}"
    )
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
    let (target, detail, diff) = audit_target(res);

    // Tamper-evident chain advance (G-166): the canonical material becomes
    // the running hash, and the returned `seq`/`prev` ride the line so a
    // verifier can detect any post-hoc edit to the persisted trail.
    let status_str = res.status_code.map(|c| c.as_u16().to_string());
    let method_str = method.to_string();
    let verdict = |code: u16| if code < 400 { "OK" } else { "FAILED" };

    match &res.status_code {
        Some(status_code) => {
            let code = status_code.as_u16();
            let material = line_material(
                verdict(code),
                &method_str,
                &uri,
                status_str.as_deref().unwrap_or_default(),
                &actor,
                &sub,
                &domain,
                &target,
                &detail,
                &diff,
            );
            let chain = audit_chain_next(&material);
            if code < 400 {
                // 3xx are successful redirects (e.g. the social callback's
                // 303 to the login page), not failures — logging them at
                // error level floods alerting pipelines with normal
                // traffic.
                info!(
                    request_id = %request_id,
                    seq = chain.seq,
                    prev = %chain.prev,
                    actor = %actor,
                    sub = %sub,
                    domain = %domain,
                    target = %target,
                    detail = %detail,
                    diff = %diff,
                    "OK {}, {}, {}, {duration_ms}",
                    method,
                    uri,
                    code,
                    duration_ms = elapsed.as_millis()
                );
            } else {
                error!(
                    request_id = %request_id,
                    seq = chain.seq,
                    prev = %chain.prev,
                    actor = %actor,
                    sub = %sub,
                    domain = %domain,
                    target = %target,
                    detail = %detail,
                    diff = %diff,
                    "FAILED {}, {}, {}, {duration_ms}",
                    method,
                    uri,
                    code,
                    duration_ms = elapsed.as_millis()
                );
            }
        }
        None => {
            let material = line_material(
                "FAILED",
                &method_str,
                &uri,
                "0",
                &actor,
                &sub,
                &domain,
                &target,
                &detail,
                &diff,
            );
            let chain = audit_chain_next(&material);
            error!(
                request_id = %request_id,
                seq = chain.seq,
                prev = %chain.prev,
                actor = %actor,
                sub = %sub,
                domain = %domain,
                target = %target,
                detail = %detail,
                diff = %diff,
                "FAILED {}, {}, {}, {duration_ms}",
                method,
                uri,
                "Unknown status code",
                duration_ms = elapsed.as_millis()
            )
        }
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
    async fn diff_probe(res: &mut Response) {
        record_target_diff(res, "user", "bob", "true", "false");
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
        // G-166 tamper-evident fields ride every line.
        assert!(logged.contains("seq="), "{logged}");
        assert!(logged.contains("prev="), "{logged}");
    }

    /// G-166: a full before→after diff snapshot renders as its own
    /// `diff=` field, distinct from the single-value `detail=` fact.
    #[tokio::test]
    async fn audit_hoop_renders_diff_snapshot() {
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
            Router::new().push(Router::with_path("probe").hoop(audit).post(diff_probe)),
        );
        let res = salvo::test::TestClient::post("http://localhost/probe")
            .send(&service)
            .await;
        assert_eq!(res.status_code, Some(StatusCode::OK));
        drop(guard);

        let logged = String::from_utf8(buf.0.lock().unwrap().clone()).expect("utf8 log");
        assert!(logged.contains("target=user:bob"), "{logged}");
        assert!(logged.contains("diff=true->false"), "{logged}");
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
    /// `kind:name` plus the optional detail/diff, and "-" when nothing was
    /// recorded (reads, unparseable bodies, uncovered routes).
    #[test]
    fn audit_target_reads_the_recorded_context() {
        let mut res = Response::new();
        assert_eq!(audit_target(&res), ("-".into(), "-".into(), "-".into()));

        record_target(&mut res, "user", "alice");
        assert_eq!(
            audit_target(&res),
            ("user:alice".into(), "-".into(), "-".into())
        );

        record_target_detail(&mut res, "role", "ops", "level=79");
        assert_eq!(
            audit_target(&res),
            ("role:ops".into(), "level=79".into(), "-".into()),
            "the latest record wins"
        );

        record_target_diff(&mut res, "user", "bob", "true", "false");
        assert_eq!(
            audit_target(&res),
            ("user:bob".into(), "-".into(), "true->false".into()),
            "the diff is a separate slot from detail"
        );
    }

    /// G-166: an unbroken trail verifies, and any single edit — a changed
    /// line, a dropped line, or a reordered pair — is detected.
    #[test]
    fn audit_chain_detects_tampering() {
        let lines = [
            "OK POST /user/set 200 actor=admin target=user:bob detail=- diff=true->false",
            "OK POST /role/grant 200 actor=admin target=user:bob detail=grant role=ops diff=-",
            "OK POST /key/retire 200 actor=admin target=key:main detail=retire diff=-",
        ];

        // A fresh chain links every line; the emitted `prev` is the one
        // a verifier would recompute.
        let mut chain = Chain::new();
        let mut claimed_prevs = Vec::new();
        let mut seqs = Vec::new();
        for line in lines.iter() {
            let (seq, prev) = chain.next(line);
            claimed_prevs.push(prev);
            seqs.push(seq);
        }
        assert!(
            verify_chain(&lines, &claimed_prevs),
            "an unbroken trail must verify"
        );
        // seq is a monotonic 1-based counter.
        assert_eq!(seqs, vec![1, 2, 3]);

        // Genesis prev is 32 zero bytes → 64 '0' chars.
        assert_eq!(
            claimed_prevs[0],
            "0000000000000000000000000000000000000000000000000000000000000000"
        );

        // A modified line breaks its own link.
        let tampered = [
            lines[0],
            "OK POST /user/set 200 actor=admin target=user:bob detail=- diff=false->true",
            lines[2],
        ];
        let cp = claimed_prevs.clone();
        assert!(
            !verify_chain(&tampered, &cp),
            "a rewritten line must fail verification"
        );

        // A reordered pair breaks the link between them.
        let reordered = [lines[0], lines[2], lines[1]];
        assert!(
            !verify_chain(&reordered, &claimed_prevs),
            "a reordered trail must fail verification"
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

    /// A full before→after diff is captured when the handler reads the prior
    /// state and records both sides (G-166 #1).
    #[test]
    fn full_diff_captures_before_and_after() {
        let mut res = Response::new();
        record_target_full(
            &mut res,
            "user",
            "bob",
            "active=false",
            "active=true",
            "active=false",
        );
        let (t, detail, diff) = audit_target(&res);
        assert_eq!(t, "user:bob");
        assert_eq!(detail, "active=false");
        assert_eq!(diff, "active=true->active=false");
    }

    /// A sensitive admin read is attributed with a `read/<resource>` target so
    /// the enumeration itself is audited (G-166 #2).
    #[test]
    fn read_target_names_the_resource() {
        let mut res = Response::new();
        record_target(&mut res, "read", "user");
        let (t, _, _) = audit_target(&res);
        assert_eq!(t, "read:user");
    }

    /// A public mutation that failed before recording a target still leaves an
    /// audit line with an empty target placeholder — never an unlogged event
    /// (G-166 #4).
    #[test]
    fn no_target_renders_placeholders() {
        let res = Response::new();
        let (t, detail, diff) = audit_target(&res);
        assert_eq!(t, "-");
        assert_eq!(detail, "-");
        assert_eq!(diff, "-");
    }
}
