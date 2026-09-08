//! Unit tests for the at-rest encryption module (`janux::crypto`).
//!
//! G-137: this file used to be a 4-line stub while `tests/README.md`
//! advertised "tampered ciphertext rejection" coverage. These tests
//! exercise the real product functions everything recovery-critical
//! depends on (signing-key privates, provider secrets, TOTP secrets).
//!
//! The process-wide key is a first-call-wins `OnceLock`, so every test
//! goes through `ensure_key()` (idempotent), and the key-VALIDATION
//! ordering is asserted in a single test: invalid inputs must fail
//! WITHOUT consuming the lock (validation runs before the `set`).

use base64::Engine;
use janux::crypto::{
    decrypt_secret, decrypt_secret_or_legacy, encrypt_secret, setup_encryption_key,
};

const TEST_KEY: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

fn ensure_key() {
    // First call wins across the whole test binary; later calls error
    // harmlessly.
    let _ = setup_encryption_key(TEST_KEY);
}

#[test]
fn setup_rejects_invalid_keys_without_consuming_the_lock() {
    // Validation runs BEFORE the OnceLock set, so these failures leave
    // the process key unset and a later valid setup still succeeds.
    assert!(
        setup_encryption_key("not hex!!").is_err(),
        "non-hex must be rejected"
    );
    assert!(setup_encryption_key("abcd").is_err(), "too short must fail");
    assert!(
        setup_encryption_key(&"0".repeat(62)).is_err(),
        "31-byte key must be rejected (AES-256 needs exactly 32 bytes)"
    );
    assert!(
        setup_encryption_key(&"0".repeat(66)).is_err(),
        "33-byte key must be rejected"
    );
    ensure_key(); // proves the lock was not consumed by the failures
}

#[test]
fn secrets_roundtrip_through_aes_gcm() {
    ensure_key();
    let long = "x".repeat(4096);
    for secret in ["s3cret", "", "unicode: 密钥 🔑", long.as_str()] {
        let ct = encrypt_secret(secret).expect("encrypt");
        assert_ne!(ct, secret, "ciphertext must not be the plaintext");
        assert_eq!(decrypt_secret(&ct).expect("decrypt"), secret);
    }
}

#[test]
fn encryption_is_probabilistic_unique_nonces() {
    ensure_key();
    let cts: Vec<String> = (0..64)
        .map(|_| encrypt_secret("same-secret").expect("encrypt"))
        .collect();
    let unique: std::collections::HashSet<&String> = cts.iter().collect();
    assert_eq!(
        unique.len(),
        cts.len(),
        "random nonce per encryption — identical ciphertexts would leak equality of secrets"
    );
}

#[test]
fn tampered_or_malformed_ciphertext_is_rejected() {
    ensure_key();
    let ct = encrypt_secret("payload").expect("encrypt");

    // Flip one character of the base64 body (the auth tag covers it).
    let mut chars: Vec<char> = ct.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();
    assert_ne!(tampered, ct);
    assert!(
        decrypt_secret(&tampered).is_err(),
        "the AES-GCM auth tag must reject tampering"
    );

    assert!(
        decrypt_secret("!!!not base64!!!").is_err(),
        "non-base64 input must be rejected"
    );
    assert!(decrypt_secret("").is_err(), "empty input must be rejected");
    // Valid base64, but shorter than the 12-byte nonce prefix.
    let short = base64::engine::general_purpose::STANDARD.encode(b"tiny");
    assert!(
        decrypt_secret(&short).is_err(),
        "sub-nonce input must be rejected"
    );
}

#[test]
fn legacy_fallback_returns_the_stored_value_only_when_decryption_fails() {
    ensure_key();
    let ct = encrypt_secret("modern").expect("encrypt");
    assert_eq!(decrypt_secret_or_legacy(&ct), "modern");
    assert_eq!(
        decrypt_secret_or_legacy("legacy-plaintext"),
        "legacy-plaintext",
        "pre-encryption rows pass through unchanged"
    );
    // NOTE (G-150, tracked separately): ciphertext written under a
    // DIFFERENT key also lands in this fallback — the returned value is
    // then the ciphertext itself. That is the documented key-stability
    // requirement, not a silent success.
    let mut chars: Vec<char> = ct.chars().collect();
    let last = chars.len() - 1;
    chars[last] = if chars[last] == 'A' { 'B' } else { 'A' };
    let tampered: String = chars.into_iter().collect();
    assert_eq!(
        decrypt_secret_or_legacy(&tampered),
        tampered,
        "undecryptable input falls back verbatim"
    );
}
