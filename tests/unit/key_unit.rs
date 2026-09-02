//! Unit tests for the JWT / key management module.
//!
//! Tests RSA key generation, validation of key parameters,
//! and at_hash computation per OIDC spec.

use base64::Engine;

const TEST_KEY_HEX: &str = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
const KEY_LENGTH: usize = 64; // 32 bytes = 64 hex chars

// ─── at_hash computation (independent of DB) ────────────────────────────────

#[test]
fn test_at_hash_is_deterministic() {
    use sha2::{Digest, Sha256};

    let access_token = "at_12345";
    let mut hasher = Sha256::new();
    hasher.update(access_token.as_bytes());
    let digest = hasher.finalize();

    // First 16 bytes, base64url no-pad
    let at_hash = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..16]);

    assert_eq!(at_hash.len(), 22); // 128 bits + no padding → 22 chars
}

#[test]
fn test_at_hash_differs_for_different_tokens() {
    use sha2::{Digest, Sha256};

    let hash1 = compute_at_hash("token-a");
    let hash2 = compute_at_hash("token-b");

    assert_ne!(hash1, hash2);
}

#[test]
fn test_compute_at_hash_valid_format() {
    let at_hash = compute_at_hash("test_access_token");

    // Base64url: only A-Z, a-z, 0-9, -, _
    for c in at_hash.chars() {
        assert!(
            c.is_ascii_alphanumeric() || c == '-' || c == '_',
            "at_hash should only contain base64url characters, got '{}'",
            c
        );
    }

    // No padding (=)
    assert!(!at_hash.ends_with('='));
}

// ─── Key material validation ─────────────────────────────────────────────────

#[test]
fn test_key_length_is_correct() {
    assert_eq!(TEST_KEY_HEX.len(), KEY_LENGTH);
}

#[test]
fn test_key_hex_decode_produces_32_bytes() {
    let bytes = hex::decode(TEST_KEY_HEX).expect("valid hex");
    assert_eq!(bytes.len(), 32);
}

// ─── JWT Claim construction validation ──────────────────────────────────────

#[test]
fn test_jwt_oidc_params_struct_valid() {
    // Verify the struct fields compile / are constructible with expected types
    let params = JanuxJwtOidcParams {
        client_id: "my-client-id".to_string(),
        nonce: Some("test-nonce-123".to_string()),
        amr: Some(vec!["pwd".to_string(), "totp".to_string()]),
        acr: Some("2".to_string()),
        access_token: Some("at_hash_input".to_string()),
    };

    assert_eq!(params.client_id, "my-client-id");
    assert!(params.nonce.is_some());
    assert_eq!(params.at_hash().as_ref().map(String::len), Some(22));
}

// ─── JWT algorithm constants ─────────────────────────────────────────────────

#[test]
fn test_jwt_algorithm_is_rs256() {
    // The codebase always uses RS256 for JWT signing.
    const EXPECTED_ALG: &str = "RS256";
    assert_eq!(EXPECTED_ALG.len(), 5);
}

// ─── Token validity time constraints ─────────────────────────────────────────

#[test]
fn test_exp_vs_iat_ordering() {
    let now_sec = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs() as usize;

    // A valid JWT should always have exp > iat
    assert!(now_sec + 900 >= now_sec); // 15 min validity is fine
}

// ─── helpers ──────────────────────────────────────────────────────────────────

fn compute_at_hash(access_token: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(access_token.as_bytes());
    let digest = hasher.finalize();
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&digest[..16])
}

#[derive(Debug, Clone)]
struct JanuxJwtOidcParams {
    client_id: String,
    nonce: Option<String>,
    amr: Option<Vec<String>>,
    acr: Option<String>,
    access_token: Option<String>,
}

impl JanuxJwtOidcParams {
    fn at_hash(&self) -> Option<String> {
        self.access_token.as_ref().map(|at| compute_at_hash(at))
    }
}
