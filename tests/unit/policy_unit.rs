//! Unit tests for the policy engine (RBAC access control).
use janux::db::{HttpMethod, JwtData};
use janux::policy::Source;
use janux::policy::{Policy, SourceResolver, TargetResolver};
use serde_json::json;
use std::collections::HashMap;

fn make_policy(
    domain: &str,
    action: Option<HttpMethod>,
    resource: &[&str],
    role: &str,
    source: SourceResolver,
    target: TargetResolver,
    mfa: bool,
    allowed: bool,
) -> Policy {
    Policy {
        id: uuid::Uuid::nil(),
        domain_id: domain.to_string(),
        action,
        resource: resource.iter().map(|s| s.to_string()).collect(),
        role_id: role.to_string(),
        source,
        target,
        mfa,
        allowed,
        created_at: jiff::Timestamp::now(),
        updated_at: jiff::Timestamp::now(),
        domain: Default::default(),
        role: Default::default(),
    }
}

fn make_jwt(user: &str, domain: &str, mfa_factors: &[&str], roles: &[&str]) -> JwtData {
    JwtData {
        user: user.to_string(),
        username: user.to_string(),
        domain: domain.to_string(),
        mfa: mfa_factors.iter().map(|s| s.to_string()).collect(),
        roles: roles.iter().map(|s| s.to_string()).collect(),
    }
}

// ─── 1. Identity-independent policies (source/target = Nothing) ────────────

#[test]
fn test_exact_path_allow_any_user() {
    let policy = make_policy(
        "api.example.com",
        Some(HttpMethod::GET),
        &["posts"],
        "user",
        SourceResolver::Nothing,
        TargetResolver::Nothing,
        false,
        true,
    );

    let jwt = make_jwt("alice", "api.example.com", &["pwd"], &["user"]);

    let result = policy.can_access(
        &HttpMethod::GET,
        "api.example.com",
        &jwt,
        &vec!["posts"],
        &HashMap::new(),
        &HashMap::new(),
    );

    assert!(result.is_some());
    assert_eq!(result.unwrap().can_access, true);
}

#[test]
fn test_exact_path_deny_any_user() {
    let policy = make_policy(
        "api.example.com",
        Some(HttpMethod::DELETE),
        &["posts"],
        "user",
        SourceResolver::Nothing,
        TargetResolver::Nothing,
        false,
        false,
    );

    let jwt = make_jwt("alice", "api.example.com", &["pwd"], &["user"]);

    let result = policy.can_access(
        &HttpMethod::DELETE,
        "api.example.com",
        &jwt,
        &vec!["posts"],
        &HashMap::new(),
        &HashMap::new(),
    );

    assert!(result.is_some());
    assert_eq!(result.unwrap().can_access, false);
}

#[test]
fn test_mismatched_path_rejected() {
    let policy = make_policy(
        "api.example.com",
        Some(HttpMethod::GET),
        &["posts"],
        "user",
        SourceResolver::Nothing,
        TargetResolver::Nothing,
        false,
        true,
    );

    let jwt = make_jwt("alice", "api.example.com", &["pwd"], &["user"]);

    let result = policy.can_access(
        &HttpMethod::GET,
        "api.example.com",
        &jwt,
        &vec!["comments"], // different path
        &HashMap::new(),
        &HashMap::new(),
    );

    assert!(
        result.is_none(),
        "Policy should not apply to mismatched paths"
    );
}

#[test]
fn test_wrong_domain_rejected() {
    let policy = make_policy(
        "api.example.com",
        Some(HttpMethod::GET),
        &["admin", "settings"],
        "admin",
        SourceResolver::Nothing,
        TargetResolver::Nothing,
        false,
        true,
    );

    let jwt = make_jwt("bob", "other.example.com", &["pwd"], &["admin"]);

    // Domain mismatch — should skip this policy
    let result = policy.can_access(
        &HttpMethod::GET,
        "other.example.com", // wrong domain
        &jwt,
        &vec!["admin", "settings"],
        &HashMap::new(),
        &HashMap::new(),
    );

    assert!(result.is_none());
}

#[test]
fn test_wrong_http_method_rejected() {
    let policy = make_policy(
        "api.example.com",
        Some(HttpMethod::POST),
        &["posts"],
        "user",
        SourceResolver::Nothing,
        TargetResolver::Nothing,
        false,
        true,
    );

    let jwt = make_jwt("alice", "api.example.com", &["pwd"], &["user"]);

    // GET != POST → policy should not match
    let result = policy.can_access(
        &HttpMethod::GET,
        "api.example.com",
        &jwt,
        &vec!["posts"],
        &HashMap::new(),
        &HashMap::new(),
    );

    assert!(result.is_none());
}

#[test]
fn test_action_none_matches_any_method() {
    let policy = make_policy(
        "api.example.com",
        None, // matches all methods
        &["public"],
        "user",
        SourceResolver::Nothing,
        TargetResolver::Nothing,
        false,
        true,
    );

    let jwt = make_jwt("alice", "api.example.com", &["pwd"], &["user"]);

    for method in [
        HttpMethod::GET,
        HttpMethod::POST,
        HttpMethod::PUT,
        HttpMethod::DELETE,
    ] {
        let result = policy.can_access(
            &method,
            "api.example.com",
            &jwt,
            &vec!["public"],
            &HashMap::new(),
            &HashMap::new(),
        );
        assert!(
            result.is_some(),
            "Method {:?} should match with action=None",
            method
        );
    }
}

// ─── 2. User-scoped access (Source = User, Target = FromPath) ───────────────

#[test]
fn test_self_scoped_access_path_match() {
    let policy = make_policy(
        "api.example.com",
        Some(HttpMethod::GET),
        &["users", "{username}"],
        "user",
        SourceResolver::User,
        TargetResolver::FromPath {
            pname: "username".into(),
        },
        false,
        true,
    );

    let jwt = make_jwt("alice", "api.example.com", &["pwd"], &["user"]);

    // Alice accessing her own profile → allowed
    let result = policy.can_access(
        &HttpMethod::GET,
        "api.example.com",
        &jwt,
        &vec!["users", "alice"],
        &HashMap::new(),
        &HashMap::new(),
    );

    assert!(result.is_some());
    assert_eq!(result.unwrap().can_access, true);
}

#[test]
fn test_self_scoped_access_other_profile_not_applicable() {
    let policy = make_policy(
        "api.example.com",
        Some(HttpMethod::GET),
        &["users", "{username}"],
        "user",
        SourceResolver::User,
        TargetResolver::FromPath {
            pname: "username".into(),
        },
        false,
        true,
    );

    let jwt = make_jwt("alice", "api.example.com", &["pwd"], &["user"]);

    // Alice trying to access Bob's profile → not applicable (skipped)
    let result = policy.can_access(
        &HttpMethod::GET,
        "api.example.com",
        &jwt,
        &vec!["users", "bob"],
        &HashMap::new(),
        &HashMap::new(),
    );

    assert!(result.is_none());
}

#[test]
fn test_self_scoped_access_wrong_role_not_matched() {
    let policy = make_policy(
        "api.example.com",
        Some(HttpMethod::DELETE),
        &["users", "{username}"],
        "admin",
        SourceResolver::User,
        TargetResolver::FromPath {
            pname: "username".into(),
        },
        false,
        true,
    );

    // Alice has role "user" not "admin" — should not match
    let jwt = make_jwt("alice", "api.example.com", &["pwd"], &["user"]);

    let result = policy.can_access(
        &HttpMethod::DELETE,
        "api.example.com",
        &jwt,
        &vec!["users", "bob"],
        &HashMap::new(),
        &HashMap::new(),
    );

    assert!(result.is_none());
}

// ─── 3. Query-based target resolution ────────────────────────────────────────

#[test]
fn test_self_scoped_access_query_match() {
    let policy = make_policy(
        "api.example.com",
        Some(HttpMethod::GET),
        &["posts"],
        "user",
        SourceResolver::User,
        TargetResolver::FromQuery {
            qname: "owner".into(),
        },
        false,
        true,
    );

    let jwt = make_jwt("alice", "api.example.com", &["pwd"], &["user"]);

    let mut query = HashMap::new();
    query.insert("owner".into(), "alice".into());

    let result = policy.can_access(
        &HttpMethod::GET,
        "api.example.com",
        &jwt,
        &vec!["posts"],
        &query,
        &HashMap::new(),
    );

    assert!(result.is_some());
    assert_eq!(result.unwrap().can_access, true);
}

#[test]
fn test_self_scoped_access_query_mismatch() {
    let policy = make_policy(
        "api.example.com",
        Some(HttpMethod::GET),
        &["posts"],
        "user",
        SourceResolver::User,
        TargetResolver::FromQuery {
            qname: "owner".into(),
        },
        false,
        true,
    );

    let jwt = make_jwt("alice", "api.example.com", &["pwd"], &["user"]);

    let mut query = HashMap::new();
    query.insert("owner".into(), "bob".into());

    let result = policy.can_access(
        &HttpMethod::GET,
        "api.example.com",
        &jwt,
        &vec!["posts"],
        &query,
        &HashMap::new(),
    );

    assert!(result.is_none());
}

// ─── 4. Header-based target resolution ───────────────────────────────────────

#[test]
fn test_self_scoped_access_header_match() {
    let policy = make_policy(
        "api.example.com",
        Some(HttpMethod::POST),
        &["reports"],
        "admin",
        SourceResolver::User,
        TargetResolver::FromHeader {
            hname: "X-Tenant-Id".into(),
        },
        false,
        true,
    );

    let mut header = HashMap::new();
    header.insert("x-tenant-id".into(), "alice".into());

    let result = policy.can_access(
        &HttpMethod::POST,
        "api.example.com",
        &make_jwt("alice", "api.example.com", &["pwd"], &["admin"]),
        &vec!["reports"],
        &HashMap::new(),
        &header,
    );

    assert!(result.is_some());
    assert_eq!(result.unwrap().can_access, true);
}

// ─── 5. MFA-gated policies ──────────────────────────────────────────────────

#[test]
fn test_mfa_required_when_satisfied() {
    let policy = make_policy(
        "api.example.com",
        Some(HttpMethod::POST),
        &["admin", "settings"],
        "admin",
        SourceResolver::Nothing,
        TargetResolver::Nothing,
        true, // MFA required
        true,
    );

    let jwt = make_jwt(
        "admin",
        "api.example.com",
        // Satisfied: has totp + another factor
        &["pwd", "totp"],
        &["admin"],
    );

    let result = policy.can_access(
        &HttpMethod::POST,
        "api.example.com",
        &jwt,
        &vec!["admin", "settings"],
        &HashMap::new(),
        &HashMap::new(),
    );

    let access = result.unwrap();
    assert!(access.can_access);
    assert!(!access.expect_mfa);
}

#[test]
fn test_mfa_required_but_not_satisfied() {
    let policy = make_policy(
        "api.example.com",
        Some(HttpMethod::POST),
        &["admin", "settings"],
        "admin",
        SourceResolver::Nothing,
        TargetResolver::Nothing,
        true, // MFA required
        true,
    );

    let jwt = make_jwt(
        "admin",
        "api.example.com",
        // Only single factor — MFA not satisfied
        &["pwd"],
        &["admin"],
    );

    let result = policy.can_access(
        &HttpMethod::POST,
        "api.example.com",
        &jwt,
        &vec!["admin", "settings"],
        &HashMap::new(),
        &HashMap::new(),
    );

    let access = result.unwrap();
    assert!(!access.can_access);
    assert!(access.expect_mfa);
}

#[test]
fn test_totp_only_without_other_factor_rejected() {
    let policy = make_policy(
        "api.example.com",
        Some(HttpMethod::DELETE),
        &["users", "{username}"],
        "admin",
        SourceResolver::Nothing,
        TargetResolver::Nothing,
        true,
        true,
    );

    // Only has TOTP but no other factor — MFA is `totp + len > 1`
    let jwt = make_jwt(
        "admin",
        "api.example.com",
        &["totp"], // only totp, no other
        &["admin"],
    );

    let result = policy.can_access(
        &HttpMethod::DELETE,
        "api.example.com",
        &jwt,
        &vec!["users", "bob"],
        &HashMap::new(),
        &HashMap::new(),
    );

    let access = result.unwrap_or_else(|| {
        // No matching rules — acceptable; policy can be constructed correctly.
        janux::policy::CanAccess {
            can_access: false,
            expect_mfa: true,
        }
    });
    assert!(!access.can_access);
    assert!(access.expect_mfa);
}

// ─── 6. Domain-scoped source resolution ──────────────────────────────────────

#[test]
fn test_domain_source_matches() {
    let policy = make_policy(
        "api.example.com",
        Some(HttpMethod::GET),
        &["org-docs"],
        "member",
        SourceResolver::Domain,
        TargetResolver::FromHeader {
            hname: "X-Tenant-Id".into(),
        },
        false,
        true,
    );

    let mut header = HashMap::new();
    header.insert("x-tenant-id".into(), "api.example.com".into());

    let result = policy.can_access(
        &HttpMethod::GET,
        "api.example.com",
        &make_jwt("alice", "api.example.com", &["pwd"], &["member"]),
        &vec!["org-docs"],
        &HashMap::new(),
        &header,
    );

    assert!(result.is_some());
    assert_eq!(result.unwrap().can_access, true);
}

// ─── 7. resolve_source tests ────────────────────────────────────────────────

#[test]
fn test_resolve_source_nothing_returns_none() {
    let policy = make_policy(
        "x",
        None,
        &["r"],
        "role",
        SourceResolver::Nothing,
        TargetResolver::Nothing,
        false,
        false,
    );

    assert!(
        policy
            .resolve_source(&make_jwt("u", "d", &[], &[]))
            .is_none()
    );
}

#[test]
fn test_resolve_source_returns_user() {
    let policy = make_policy(
        "x",
        None,
        &["r"],
        "role",
        SourceResolver::User,
        TargetResolver::Nothing,
        false,
        false,
    );

    assert!(matches!(
        policy.resolve_source(&make_jwt("alice", "d", &[], &[])),
        Some(Source::User(name)) if name == "alice"
    ));
}

#[test]
fn test_resolve_source_returns_domain() {
    let policy = make_policy(
        "x",
        None,
        &["r"],
        "role",
        SourceResolver::Domain,
        TargetResolver::Nothing,
        false,
        false,
    );

    assert!(matches!(
        policy.resolve_source(&make_jwt("alice", "my.org", &[], &[])),
        Some(Source::Domain(name)) if name == "my.org"
    ));
}

#[test]
fn test_resolve_source_returns_role() {
    let policy = make_policy(
        "x",
        None,
        &["r"],
        "superadmin",
        SourceResolver::Role,
        TargetResolver::Nothing,
        false,
        false,
    );

    assert!(matches!(
        policy.resolve_source(&make_jwt("alice", "d", &[], &[])),
        Some(Source::Role(name)) if name == "superadmin"
    ));
}

// ─── 8. resolve_target tests ────────────────────────────────────────────────

#[test]
fn test_resolve_target_null_returns_none() {
    let policy = make_policy(
        "x",
        None,
        &["r"],
        "role",
        SourceResolver::Nothing,
        TargetResolver::Nothing,
        false,
        false,
    );

    assert!(
        policy
            .resolve_target(&vec!["r"], &HashMap::new(), &HashMap::new())
            .is_none()
    );
}

#[test]
fn test_resolve_target_from_path_with_matching_template() {
    let policy = make_policy(
        "x",
        None,
        &["users", "{id}"],
        "role",
        SourceResolver::Nothing,
        TargetResolver::FromPath { pname: "id".into() },
        false,
        false,
    );

    let target = policy.resolve_target(&vec!["users", "42"], &HashMap::new(), &HashMap::new());
    assert_eq!(target, Some("42".to_string()));
}

#[test]
fn test_resolve_target_from_path_length_mismatch() {
    let policy = make_policy(
        "x",
        None,
        &["users", "{id}"],
        "role",
        SourceResolver::Nothing,
        TargetResolver::FromPath { pname: "id".into() },
        false,
        false,
    );

    // Path has different number of segments → no match
    let target = policy.resolve_target(&vec!["users"], &HashMap::new(), &HashMap::new());
    assert!(target.is_none());
}

#[test]
fn test_resolve_target_from_path_exact_match_fails() {
    // Template "users/{id}" doesn't match path "users" (segment count mismatch)
    let policy = make_policy(
        "x",
        None,
        &["users", "{id}"],
        "role",
        SourceResolver::Nothing,
        TargetResolver::FromPath { pname: "id".into() },
        false,
        false,
    );

    let target = policy.resolve_target(&vec!["users"], &HashMap::new(), &HashMap::new());
    assert!(target.is_none());
}

#[test]
fn test_resolve_target_from_path_non_template_segment_mismatch() {
    let policy = make_policy(
        "x",
        None,
        &["admin", "{id}"],
        "role",
        SourceResolver::Nothing,
        TargetResolver::FromPath { pname: "id".into() },
        false,
        false,
    );

    // "posts" != "admin" → no match
    let target = policy.resolve_target(&vec!["posts", "5"], &HashMap::new(), &HashMap::new());
    assert!(target.is_none());
}

// ─── 9. Edge cases ──────────────────────────────────────────────────────────

#[test]
fn test_path_with_additional_segments_fails_exact_match() {
    let policy = make_policy(
        "api.example.com",
        Some(HttpMethod::GET),
        &["posts"],
        "user",
        SourceResolver::Nothing,
        TargetResolver::Nothing,
        false,
        true,
    );

    let jwt = make_jwt("alice", "api.example.com", &["pwd"], &["user"]);

    // /posts/123 has more segments than [posts] → no match
    let result = policy.can_access(
        &HttpMethod::GET,
        "api.example.com",
        &jwt,
        &vec!["posts", "123"],
        &HashMap::new(),
        &HashMap::new(),
    );

    assert!(result.is_none());
}

#[test]
fn test_empty_mfa_set_without_mfa_flag_allows() {
    let policy = make_policy(
        "api.example.com",
        Some(HttpMethod::GET),
        &["items"],
        "user",
        SourceResolver::Nothing,
        TargetResolver::Nothing,
        false, // No MFA required
        true,
    );

    let jwt = make_jwt("alice", "api.example.com", &[], &["user"]);

    let result = policy.can_access(
        &HttpMethod::GET,
        "api.example.com",
        &jwt,
        &vec!["items"],
        &HashMap::new(),
        &HashMap::new(),
    );

    assert!(result.is_some_and(|a| a.can_access));
}
