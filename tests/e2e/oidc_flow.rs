//! E2E test: OpenID Connect / OAuth 2.0 wire contracts.
//!
//! G-158: the old "endpoint exists" tests asserted `resp.is_ok()` —
//! which passes on 500s and proved nothing. Each probe below pins the
//! real contract: discovery serves a provisioned document for a seeded
//! tenant, unauthenticated protocol calls fail closed with the RFC's
//! error status, and the JWKS carries the seeded signing key.

/// Discovery for a seeded tenant: 200, provisioned, with the endpoints
/// an RP needs.
#[tokio::test]
async fn test_well_known_openid_configuration() {
    let base_url = super::shared_server().await;

    let resp = reqwest::Client::new()
        .get(format!(
            "{}/.well-known/openid-configuration",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "localhost")
        .send()
        .await
        .expect("discovery request");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let doc: serde_json::Value = resp.json().await.expect("discovery json");
    assert_eq!(doc["janux_provisioned"], true, "seeded tenant: {doc}");
    assert_eq!(doc["issuer"], "http://localhost");
    for field in [
        "jwks_uri",
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "revocation_endpoint",
        "introspection_endpoint",
    ] {
        assert!(
            doc[field].as_str().is_some_and(|s| !s.is_empty()),
            "discovery must advertise {field}: {doc}"
        );
    }
}

/// Userinfo without a token fails closed — 401, never 200 or 500.
#[tokio::test]
async fn test_userinfo_requires_auth() {
    let base_url = super::shared_server().await;

    let resp = reqwest::Client::new()
        .get(format!("{}/userinfo", base_url.trim_end_matches('/')))
        .header("Host", "localhost")
        .send()
        .await
        .expect("userinfo request");

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
}

/// The token endpoint answers POST — and an authorization_code grant
/// without client authentication is rejected 401 invalid_client
/// (RFC 6749 §5.2), never 200 or 500.
#[tokio::test]
async fn test_token_endpoint_rejects_unauthenticated_client() {
    let base_url = super::shared_server().await;

    let resp = reqwest::Client::new()
        .post(format!("{}/token", base_url.trim_end_matches('/')))
        .header("Host", "localhost")
        .form(&[("grant_type", "authorization_code")])
        .send()
        .await
        .expect("token request");

    assert_eq!(resp.status(), reqwest::StatusCode::UNAUTHORIZED);
    let body: serde_json::Value = resp.json().await.expect("error body");
    assert_eq!(body["error"], "invalid_client");
}

/// A parameterless GET /authorize cannot be answered: the error is
/// rendered via a 302 to the hosted `/error` page (which does not exist
/// yet — a tracked Low finding in gaps.md, so the followed status would
/// be a bare 404). Pinned here WITHOUT following redirects: 302 with an
/// `invalid_request` error, never 500 and never a silent 200.
#[tokio::test]
async fn test_authorize_get_requires_parameters() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");
    let resp = client
        .get(format!("{}/authorize", base_url.trim_end_matches('/')))
        .header("Host", "localhost")
        .send()
        .await
        .expect("authorize GET");

    assert_eq!(resp.status(), reqwest::StatusCode::FOUND);
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("error redirect")
        .to_string();
    assert!(
        location.contains("error=invalid_request"),
        "the redirect must carry the RFC 6749 error code: {location}"
    );
}

/// POST /authorize with an UNKNOWN client must NEVER redirect to the
/// presented redirect_uri (RFC 6749 §4.1.2.1 — the URI is unvalidated
/// when the client is unknown): the redirect goes to the hosted error
/// page instead.
#[tokio::test]
async fn test_authorize_post_unknown_client_does_not_redirect() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("client");
    let resp = client
        .post(format!("{}/authorize", base_url.trim_end_matches('/')))
        .header("Host", "localhost")
        .form(&[
            ("client_id", "no-such-client"),
            ("redirect_uri", "http://localhost/callback"),
        ])
        .send()
        .await
        .expect("authorize POST");

    assert_eq!(resp.status(), reqwest::StatusCode::FOUND);
    let location = resp
        .headers()
        .get(reqwest::header::LOCATION)
        .and_then(|v| v.to_str().ok())
        .expect("error redirect")
        .to_string();
    assert!(
        !location.starts_with("http://localhost/callback"),
        "an unknown client must never redirect to the presented URI: {location}"
    );
    assert!(
        location.contains("error="),
        "the redirect must carry an error code: {location}"
    );
}

/// RFC 7009 error semantics: a revocation request without a token is an
/// invalid request (400); a request that presents a token but fails client
/// authentication is rejected with 401 `invalid_client` (§2.1) — never 200,
/// which is reserved for authenticated clients.
#[tokio::test]
async fn test_revoke_requires_client_authentication() {
    let base_url = super::shared_server().await;

    let client = reqwest::Client::new();

    // Missing token parameter → 400
    let resp = client
        .post(format!("{}/revoke", base_url.trim_end_matches('/')))
        .header("Host", "localhost")
        .form(&[("client_id", "some-client")])
        .send()
        .await
        .expect("request should succeed");
    assert_eq!(resp.status(), 400, "missing token must be a 400");

    // Token present but client unknown → 401 invalid_client
    let resp = client
        .post(format!("{}/revoke", base_url.trim_end_matches('/')))
        .header("Host", "localhost")
        .form(&[
            ("token", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig"),
            ("client_id", "no-such-client"),
        ])
        .send()
        .await
        .expect("request should succeed");
    assert_eq!(
        resp.status(),
        401,
        "unauthenticated revocation must be rejected"
    );
    let body: serde_json::Value = resp.json().await.expect("JSON error body");
    assert_eq!(body["error"], "invalid_client");

    // Token present but no client_id at all → 401 invalid_client
    let resp = client
        .post(format!("{}/revoke", base_url.trim_end_matches('/')))
        .header("Host", "localhost")
        .form(&[("token", "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.sig")])
        .send()
        .await
        .expect("request should succeed");
    assert_eq!(resp.status(), 401);
}

/// Introspection without a token parameter is an invalid request (400)
/// — the parameter check runs before client authentication. An
/// authenticated caller presenting an unknown token gets 200
/// {active:false} (RFC 7662 §2.2 — pinned by the lib-level introspect
/// tests).
#[tokio::test]
async fn test_introspect_rejects_missing_token() {
    let base_url = super::shared_server().await;

    let resp = reqwest::Client::new()
        .post(format!("{}/introspect", base_url.trim_end_matches('/')))
        .header("Host", "localhost")
        .send()
        .await
        .expect("introspect request");

    assert_eq!(resp.status(), reqwest::StatusCode::BAD_REQUEST);
}

/// JWKS is public and — with the seed now creating a signing key per
/// domain (G-136) — non-empty for a provisioned tenant.
#[tokio::test]
async fn test_jwks_is_public_and_populated() {
    let base_url = super::shared_server().await;

    let resp = reqwest::Client::new()
        .get(format!(
            "{}/.well-known/jwks.json",
            base_url.trim_end_matches('/')
        ))
        .header("Host", "localhost")
        .send()
        .await
        .expect("jwks request");

    assert_eq!(resp.status(), reqwest::StatusCode::OK);
    let body: serde_json::Value = resp.json().await.expect("jwks json");
    let keys = body["keys"]
        .as_array()
        .unwrap_or_else(|| panic!("jwks must carry a keys array: {body}"));
    assert!(
        !keys.is_empty(),
        "the seeded tenant must advertise its signing key: {body}"
    );
    assert!(
        keys.iter()
            .all(|k| k["kty"] == "RSA" && k["kid"].is_string()),
        "every advertised key is RSA with a kid: {body}"
    );
}
