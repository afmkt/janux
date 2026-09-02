//! Unit tests for OIDC `amr` / `acr` / `auth_time` handling (RFC 8176 / OIDC Core §2).
//!
//! Covers:
//! 1. Mapping internal factor labels to registered RFC 8176 `amr` values.
//! 2. Deriving the `acr` assurance level from the factor set.
//! 3. A real sign/decode round-trip proving the claims reach the JWT,
//!    including that a supplied `auth_time` is preserved (refresh semantics).

use janux::db::{JwtData, acr_value, amr_values};
use janux::jwt::{Claim, JwtOidcParams, jwt_authenticate};
use janux::key::Key;
use std::collections::HashSet;

fn set(labels: &[&str]) -> HashSet<String> {
    labels.iter().map(|s| s.to_string()).collect()
}

// ─── amr_values: RFC 8176 mapping ────────────────────────────────────────────

#[test]
fn test_amr_passkey_maps_to_hwk() {
    assert_eq!(amr_values(&set(&["passkey"])), Some(vec!["hwk".into()]));
}

#[test]
fn test_amr_email_maps_to_mca() {
    assert_eq!(amr_values(&set(&["email"])), Some(vec!["mca".into()]));
}

#[test]
fn test_amr_sms_otp_maps_to_sms() {
    assert_eq!(amr_values(&set(&["otp"])), Some(vec!["sms".into()]));
}

#[test]
fn test_amr_totp_maps_to_otp() {
    assert_eq!(amr_values(&set(&["totp"])), Some(vec!["otp".into()]));
}

#[test]
fn test_amr_oauth2_has_no_registered_value() {
    // Federated login: RFC 8176 registers no value; claim must be omitted.
    assert_eq!(amr_values(&set(&["oauth2"])), None);
}

#[test]
fn test_amr_legacy_social_label_is_ignored() {
    assert_eq!(amr_values(&set(&["Social"])), None);
}

#[test]
fn test_amr_empty_set_is_none() {
    assert_eq!(amr_values(&HashSet::new()), None);
}

#[test]
fn test_amr_multi_factor_sorted_and_deduped() {
    // Insertion order must not affect output.
    let a = amr_values(&set(&["totp", "email"]));
    let b = amr_values(&set(&["email", "totp"]));
    assert_eq!(a, b);
    assert_eq!(a, Some(vec!["mca".to_string(), "otp".to_string()]));
}

// ─── acr_value: assurance level derivation ───────────────────────────────────

#[test]
fn test_acr_empty_is_none() {
    assert_eq!(acr_value(&HashSet::new()), None);
}

#[test]
fn test_acr_single_factor_is_1() {
    assert_eq!(acr_value(&set(&["email"])), Some("1".into()));
    assert_eq!(acr_value(&set(&["passkey"])), Some("1".into()));
    assert_eq!(acr_value(&set(&["totp"])), Some("1".into())); // totp alone is not MFA per policy.rs
}

#[test]
fn test_acr_totp_plus_second_factor_is_2() {
    // Mirrors the policy engine's MFA definition (totp && len > 1).
    assert_eq!(acr_value(&set(&["totp", "email"])), Some("2".into()));
    assert_eq!(acr_value(&set(&["totp", "passkey"])), Some("2".into()));
}

// ─── JWT round-trip: claims actually land in the signed token ────────────────

fn test_key() -> Key {
    let kp = rcgen::KeyPair::generate_for(&rcgen::PKCS_RSA_SHA256).expect("keygen");
    Key {
        id: "test-key".to_string(),
        public: kp.public_key_pem().into_bytes(),
        private: kp.serialize_pem().into_bytes(),
        domain_id: "example.com".to_string(),
        domain: Default::default(),
    }
}

fn jwt_data(mfa: HashSet<String>) -> JwtData {
    JwtData {
        user: "alice".to_string(),
        username: "alice".to_string(),
        domain: "example.com".to_string(),
        mfa,
        roles: ["user"].iter().map(|s| s.to_string()).collect(),
    }
}

fn decode_claims(token: &str, key: &Key) -> Claim<JwtData> {
    let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::RS256);
    validation.validate_aud = false;
    let data = jsonwebtoken::decode::<Claim<JwtData>>(
        token,
        &jsonwebtoken::DecodingKey::from_rsa_pem(&key.public).unwrap(),
        &validation,
    )
    .expect("token should decode with the public key");
    data.claims
}

#[test]
fn test_fresh_auth_stamps_amr_acr_and_current_auth_time() {
    let key = test_key();
    let mfa = set(&["email", "totp"]);
    let before = jiff::Timestamp::now().as_second() as usize;

    let token = jwt_authenticate(
        "example.com",
        "alice",
        &jwt_data(mfa.clone()),
        &key,
        15,
        JwtOidcParams {
            client_id: "example.com".to_string(),
            nonce: None,
            amr: amr_values(&mfa),
            acr: acr_value(&mfa),
            access_token: None,
            auth_time: None, // fresh authentication → stamp now
        },
    )
    .expect("signing must succeed");

    let claims = decode_claims(&token, &key);
    assert_eq!(claims.amr, Some(vec!["mca".to_string(), "otp".to_string()]));
    assert_eq!(claims.acr, Some("2".to_string()));
    let at = claims.auth_time.expect("auth_time must be present");
    assert!(at >= before && at <= before + 5, "auth_time should be ~now");
    assert_eq!(claims.sub, "alice");
    assert_eq!(claims.aud, "example.com");
}

#[test]
fn test_supplied_auth_time_is_preserved() {
    // Refresh semantics: the ORIGINAL authentication instant must survive
    // re-issuance, otherwise max_age checks break (OIDC Core §2).
    let key = test_key();
    let mfa = set(&["passkey"]);
    let original_auth_time: usize = 1_600_000_000; // far in the past

    let token = jwt_authenticate(
        "example.com",
        "bob",
        &jwt_data(mfa.clone()),
        &key,
        15,
        JwtOidcParams {
            client_id: "example.com".to_string(),
            nonce: None,
            amr: amr_values(&mfa),
            acr: acr_value(&mfa),
            access_token: None,
            auth_time: Some(original_auth_time),
        },
    )
    .expect("signing must succeed");

    let claims = decode_claims(&token, &key);
    assert_eq!(claims.auth_time, Some(original_auth_time));
    assert_eq!(claims.amr, Some(vec!["hwk".to_string()]));
    assert_eq!(claims.acr, Some("1".to_string()));
}

#[test]
fn test_social_only_auth_omits_amr_but_keeps_acr() {
    let key = test_key();
    let mfa = set(&["oauth2"]);

    let token = jwt_authenticate(
        "example.com",
        "carol",
        &jwt_data(mfa.clone()),
        &key,
        15,
        JwtOidcParams {
            client_id: "example.com".to_string(),
            nonce: None,
            amr: amr_values(&mfa),
            acr: acr_value(&mfa),
            access_token: None,
            auth_time: None,
        },
    )
    .expect("signing must succeed");

    let claims = decode_claims(&token, &key);
    assert_eq!(
        claims.amr, None,
        "no registered RFC 8176 value for federated login"
    );
    assert_eq!(claims.acr, Some("1".to_string()));
}
