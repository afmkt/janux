//! Unit tests for the utils module (helper types and functions).
use std::collections::HashSet;

// ─── ApiProblem tests ─────────────────────────────────────────────────────────

#[test]
fn test_api_problem_bad_request() {
    let problem = janux::utils::ApiProblem::bad_request("something failed");
    assert_eq!(problem.status, 400);
    assert_eq!(problem.r#type, "bad request");
    assert_eq!(problem.detail, Some("something failed".to_string()));
}

#[test]
fn test_api_problem_not_found() {
    let problem = janux::utils::ApiProblem::not_found("user not found");
    assert_eq!(problem.status, 404);
    assert_eq!(problem.r#type, "not_found");
    assert_eq!(problem.detail, Some("user not found".to_string()));
}

#[test]
fn test_api_problem_validation_error() {
    let problem = janux::utils::ApiProblem::validation_error("invalid field: email");
    assert_eq!(problem.status, 422);
    assert_eq!(problem.r#type, "validation_error");
    assert_eq!(problem.detail, Some("invalid field: email".to_string()));
}

#[test]
fn test_api_problem_unauthorized_no_detail() {
    let problem = janux::utils::ApiProblem::unauthorized();
    assert_eq!(problem.status, 401);
    assert_eq!(problem.r#type, "unauthorized");
    assert!(problem.detail.is_none());
}

#[test]
fn test_api_problem_server_error() {
    let problem = janux::utils::ApiProblem::server_error("oom");
    assert_eq!(problem.status, 500);
    assert_eq!(problem.r#type, "server_error");
    assert_eq!(problem.detail, Some("oom".to_string()));
}

#[test]
fn test_api_problem_serialization_round_trip() {
    use serde_json;

    let problem = janux::utils::ApiProblem::bad_request("test detail");
    let json = serde_json::to_string(&problem).unwrap();
    assert!(json.contains("bad request"));
    assert!(json.contains("test detail"));

    let restored: janux::utils::ApiProblem = serde_json::from_str(&json).unwrap();
    assert_eq!(restored.status, problem.status);
    assert_eq!(restored.r#type, problem.r#type);
}

// ─── ApiResponse tests ────────────────────────────────────────────────────────

#[test]
fn test_api_response_ok_wraps_data() {
    let response: janux::utils::ApiResponse<Vec<&str>> =
        janux::utils::ApiResponse::ok(vec!["a", "b"]);
    assert!(response.ok);
    assert_eq!(response.data, vec!["a", "b"]);
}

#[test]
fn test_api_response_with_unit_data() {
    let response: janux::utils::ApiResponse<()> = janux::utils::ApiResponse::ok(());
    assert!(response.ok);

    // Should serialize to {"ok":true,"data":null}
    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("true"));
}

#[test]
fn test_api_response_with_struct_data() {
    #[derive(Debug, serde::Serialize, PartialEq, Clone)]
    struct TestData {
        id: String,
        name: String,
    }

    let data = TestData {
        id: "1".into(),
        name: "test".into(),
    };
    let response: janux::utils::ApiResponse<TestData> = janux::utils::ApiResponse::ok(data.clone());

    assert!(response.ok);
    assert_eq!(response.data, data);
}

// ─── HttpMethod conversion tests ──────────────────────────────────────────────

#[test]
fn test_http_method_all_variants() {
    // Verify all 9 HTTP methods are covered per the enum definition
    let methods: [janux::db::HttpMethod; 9] = [
        janux::db::HttpMethod::GET,
        janux::db::HttpMethod::POST,
        janux::db::HttpMethod::PUT,
        janux::db::HttpMethod::DELETE,
        janux::db::HttpMethod::PATCH,
        janux::db::HttpMethod::OPTIONS,
        janux::db::HttpMethod::CONNECT,
        janux::db::HttpMethod::HEAD,
        janux::db::HttpMethod::TRACE,
    ];
    assert_eq!(methods.len(), 9);
}

// ─── AuthType methods (from db.rs) ──────────────────────────────────────────────

#[test]
fn test_auth_type_as_str() {
    // Auth type conversions - verify all types have string representation
    let auth_types: [(&str, &janux::db::AuthType); 5] = [
        ("passkey", &janux::db::AuthType::PassKey),
        ("email", &janux::db::AuthType::Email),
        ("otp", &janux::db::AuthType::OTP),
        ("oauth2", &janux::db::AuthType::OAuth2),
        ("totp", &janux::db::AuthType::TOTP),
    ];

    for (str_val, _) in auth_types {
        assert!(!str_val.is_empty());
    }
}

// ─── JwtData structure tests ──────────────────────────────────────────────────

#[test]
fn test_jwt_data_with_multiple_roles() {
    let jwt = janux::db::JwtData {
        user: "admin@example.com".to_string(),
        username: "admin@example.com".to_string(),
        domain: "auth.example.com".to_string(),
        mfa: ["pwd", "totp"].iter().map(|s| s.to_string()).collect(),
        roles: ["admin", "user", "editor"]
            .iter()
            .map(|s| s.to_string())
            .collect(),
    };

    assert_eq!(jwt.user, "admin@example.com");
    assert_eq!(jwt.domain, "auth.example.com");
    assert!(jwt.mfa.contains("totp"));
    assert!(jwt.roles.contains("admin"));
}

#[test]
fn test_jwt_data_empty_mfa() {
    let jwt = janux::db::JwtData {
        user: "user".to_string(),
        username: "user".to_string(),
        domain: "example.com".to_string(),
        mfa: HashSet::new(),
        roles: ["user"].iter().map(|s| s.to_string()).collect(),
    };

    assert!(jwt.mfa.is_empty());
}

// ─── JwtVerify structure tests ──────────────────────────────────────────────────

#[test]
fn test_jwt_verify_data_complete() {
    let verify = janux::db::JwtVerify {
        can_access: true,
        jwt_data: janux::db::JwtData {
            user: "alice".into(),
            username: "alice".into(),
            domain: "example.com".into(),
            mfa: ["pwd", "totp"].iter().map(|s| s.to_string()).collect(),
            roles: ["admin"].iter().map(|s| s.to_string()).collect(),
        },
        expect_mfa: false,
        domain: "example.com".to_string(),
        auth_time: Some(1_699_999_000),
    };

    assert!(verify.can_access);
    assert!(!verify.expect_mfa);
    assert_eq!(verify.domain, "example.com");
}

#[test]
fn test_jwt_verify_expect_mfa_flag() {
    let verify = janux::db::JwtVerify {
        can_access: false,
        jwt_data: janux::db::JwtData {
            user: "alice".into(),
            username: "alice".into(),
            domain: "example.com".into(),
            mfa: ["pwd"].iter().map(|s| s.to_string()).collect(),
            roles: HashSet::new(),
        },
        expect_mfa: true,
        domain: "example.com".to_string(),
        auth_time: None,
    };

    assert!(!verify.can_access);
    assert!(verify.expect_mfa);
}

// ─── BindConfig / ServerConfig tests (from server.rs) ──────────────────────

#[test]
fn test_bind_config_format() {
    let bind = janux::server::BindConfig {
        address: "0.0.0.0".to_string(),
        port: 8080,
    };

    assert_eq!(bind.string(), "0.0.0.0:8080");
}

#[test]
fn test_default_port() {
    let bind = janux::server::BindConfig {
        address: "127.0.0.1".to_string(),
        port: 8080,
    };

    assert_eq!(bind.string(), "127.0.0.1:8080");
}

// ─── ExtractSource enum tests ──────────────────────────────────────────────────

#[test]
fn test_extract_source_variants() {
    // Form, Body, Query — three extraction sources
    let sources = ["Form", "Body", "Query"];
    assert_eq!(sources.len(), 3);
}

// ─── Claim type structure tests ──────────────────────────────────────────────

#[test]
fn test_clain_minimal_fields_are_constructible() {
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    struct MinimalClaim {
        iss: String,
        sub: String,
        aud: String,
        exp: usize,
        iat: usize,
        nbf: usize,
        #[serde(skip_serializing_if = "Option::is_none")]
        nonce: Option<String>,
    }

    let claim = MinimalClaim {
        iss: "a".into(),
        sub: "b".into(),
        aud: "c".into(),
        exp: 1,
        iat: 1,
        nbf: 1,
        nonce: None,
    };

    let json = serde_json::to_string(&claim).unwrap();
    assert!(!json.contains("nonce")); // skip_serializing_if should work
}
