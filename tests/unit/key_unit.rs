//! Unit tests for the pure key-material contract: `at_hash` computation
//! (OIDC Core §3.1.3.6/§3.3.2), the function all three token-mint sites
//! in `oidc.rs` call via `janux::jwt::compute_at_hash`.
//!
//! G-137: this file used to never import janux — it re-implemented the
//! hash locally and asserted tautologies (`EXPECTED_ALG.len() == 5`,
//! `now + 900 >= now`) while `tests/README.md` advertised it as real
//! coverage. The RSA key LIFECYCLE (generation, encryption at rest, kid
//! routing, retirement, JWKS) needs a database and is covered by the lib
//! tests in `src/key.rs` / `src/db.rs`.

use base64::Engine;
use janux::jwt::compute_at_hash;
use sha2::Digest;

/// Independent reference construction: left half of SHA-256 over the
/// token's octets, base64url without padding.
fn reference_at_hash(access_token: &str) -> String {
    let digest = sha2::Sha256::digest(access_token.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..16])
}

#[test]
fn at_hash_matches_a_pinned_spec_vector() {
    // SHA-256("at_12345")[..16], base64url-no-pad — computed independently
    // of the product code and pinned so any change to the construction
    // (wrong half, wrong alphabet, padding) fails here.
    assert_eq!(compute_at_hash("at_12345"), "OdClz_bNRQ96i3tyxufAsA");
}

#[test]
fn at_hash_matches_the_reference_construction() {
    for token in [
        "at_12345",
        "dGhpcyBpcyBhbiBhY2Nlc3MgdG9rZW4",
        "",
        "token-with-unicode-密钥",
    ] {
        assert_eq!(
            compute_at_hash(token),
            reference_at_hash(token),
            "at_hash({token:?})"
        );
    }
}

#[test]
fn at_hash_is_deterministic_and_token_sensitive() {
    assert_eq!(compute_at_hash("token-a"), compute_at_hash("token-a"));
    assert_ne!(compute_at_hash("token-a"), compute_at_hash("token-b"));
}

#[test]
fn at_hash_shape_is_base64url_no_pad_half_sha256() {
    let at_hash = compute_at_hash("test_access_token");
    assert_eq!(at_hash.len(), 22, "128 bits base64url-no-pad → 22 chars");
    assert!(!at_hash.ends_with('='), "no padding");
    for c in at_hash.chars() {
        assert!(
            c.is_ascii_alphanumeric() || c == '-' || c == '_',
            "base64url charset only, got '{c}'"
        );
    }
}
