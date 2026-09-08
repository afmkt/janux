use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, KeyInit},
};
use anyhow::{Result, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use std::sync::OnceLock;

const KEY_BYTES: usize = 32;

static ENCRYPTION_KEY: OnceLock<Key<Aes256Gcm>> = OnceLock::new();

pub fn setup_encryption_key(hex_key: &str) -> Result<()> {
    let bytes = hex::decode(hex_key)
        .map_err(|e| anyhow!("JANUX_ENCRYPTION_KEY must be hex-encoded: {e}"))?;
    if bytes.len() != KEY_BYTES {
        anyhow::bail!(
            "JANUX_ENCRYPTION_KEY must be exactly {} bytes ({} hex chars), got {}",
            KEY_BYTES,
            KEY_BYTES * 2,
            bytes.len()
        );
    }
    ENCRYPTION_KEY
        .set(*Key::<Aes256Gcm>::from_slice(&bytes))
        .map_err(|_| anyhow!("encryption key already initialized"))?;
    Ok(())
}

fn get_encryption_key() -> Result<&'static Key<Aes256Gcm>> {
    ENCRYPTION_KEY.get().ok_or_else(|| {
        anyhow!("JANUX_ENCRYPTION_KEY is not set; secrets at rest cannot be protected")
    })
}

pub fn encrypt_secret(plaintext: &str) -> Result<String> {
    encrypt_secret_with(get_encryption_key()?, plaintext)
}

pub fn decrypt_secret(encrypted: &str) -> Result<String> {
    decrypt_secret_with(get_encryption_key()?, encrypted)
}

/// An explicit AES-256-GCM cipher — the explicit-key variant used by the
/// rekey tool (G-150). The process-wide key is a first-call-wins
/// `OnceLock` and cannot be swapped in place, so rekey decrypts with the
/// global OLD key and encrypts with an explicit NEW cipher.
pub type SecretCipher = Key<Aes256Gcm>;

/// Parse and validate a 64-hex-char (32-byte) key — the same rules
/// `setup_encryption_key` enforces.
pub fn parse_key_hex(hex_key: &str) -> Result<SecretCipher> {
    let bytes =
        hex::decode(hex_key).map_err(|e| anyhow!("encryption key must be hex-encoded: {e}"))?;
    if bytes.len() != KEY_BYTES {
        anyhow::bail!(
            "encryption key must be exactly {} bytes ({} hex chars), got {}",
            KEY_BYTES,
            KEY_BYTES * 2,
            bytes.len()
        );
    }
    Ok(*SecretCipher::from_slice(&bytes))
}

pub fn encrypt_secret_with(cipher: &SecretCipher, plaintext: &str) -> Result<String> {
    let cipher = Aes256Gcm::new(cipher);
    let nonce: [u8; 12] = rand::random();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
        .map_err(|e| anyhow!("AES-GCM encryption failed: {e}"))?;

    let mut out = nonce.to_vec();
    out.extend(ciphertext);
    Ok(BASE64.encode(out))
}

pub fn decrypt_secret_with(cipher: &SecretCipher, encrypted: &str) -> Result<String> {
    let cipher = Aes256Gcm::new(cipher);
    let data = BASE64
        .decode(encrypted)
        .map_err(|e| anyhow!("invalid ciphertext: {e}"))?;

    if data.len() < 12 {
        return Err(anyhow!("ciphertext too short"));
    }

    let (nonce_bytes, ciphertext) = data.split_at(12);
    let nonce_array: [u8; 12] = nonce_bytes.try_into().expect("slice with incorrect length");
    let plaintext = cipher
        .decrypt(Nonce::from_slice(&nonce_array), ciphertext.as_ref())
        .map_err(|e| anyhow!("decryption failed: {e}"))?;

    String::from_utf8(plaintext).map_err(|e| anyhow!("UTF-8 decode failed: {e}"))
}

/// Decrypt a stored secret, falling back to the stored value itself for
/// rows written before encryption at rest. The fallback is unambiguous:
/// the AES-GCM auth tag makes it cryptographically impossible for a
/// legacy plaintext to "decrypt successfully", so a decryption failure
/// means the value is not ciphertext. (A ciphertext written under a
/// different key also lands in the fallback — key stability is already
/// required, since social provider secrets fail hard without it.)
pub fn decrypt_secret_or_legacy(stored: &str) -> String {
    decrypt_secret(stored).unwrap_or_else(|_| stored.to_string())
}
