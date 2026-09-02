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
        .set(Key::<Aes256Gcm>::from_slice(&bytes).clone())
        .map_err(|_| anyhow!("encryption key already initialized"))?;
    Ok(())
}

fn get_encryption_key() -> &'static Key<Aes256Gcm> {
    ENCRYPTION_KEY.get_or_init(|| {
        panic!("JANUX_ENCRYPTION_KEY must be set before encrypting/decrypting client secrets");
    })
}

pub fn encrypt_client_secret(plaintext: &str) -> Result<String> {
    let cipher = Aes256Gcm::new(get_encryption_key());
    let nonce: [u8; 12] = rand::random();
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext.as_bytes())
        .map_err(|e| anyhow!("AES-GCM encryption failed: {e}"))?;

    let mut out = nonce.to_vec();
    out.extend(ciphertext);
    Ok(BASE64.encode(out))
}

pub fn decrypt_client_secret(encrypted: &str) -> Result<String> {
    let cipher = Aes256Gcm::new(get_encryption_key());
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
