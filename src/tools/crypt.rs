// SPDX-License-Identifier: GPL-3.0
//! Symmetric crypto primitives used by the pipeline.
//!
//! ## AES-256-GCM
//! [`aes_encrypt`] and [`aes_decrypt`] are the workhorse functions. Nonces are randomly
//! generated per call and prepended to the ciphertext so callers only handle a single opaque blob.
//!
//! ## Password hashing
//! [`hash_password`] applies HMAC-SHA256 with an OS-keyring pepper before running Argon2id.
//! The pepper version is stored alongside the hash so [`verify_password`] can fetch the exact
//! pepper version that was active at hash time — enabling `rotate_pepper` without a forced
//! re-hash of all existing passwords.
//!
//! ## Key-encrypted blobs
//! [`key_encrypt`] / [`key_decrypt`] derive an AES-256 key from a password via Argon2id and
//! return a self-contained base64 blob (salt ‖ nonce ‖ ciphertext). Intended for encrypting
//! small secrets (API keys, private key material) at rest.
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, OsRng as AesOsRng},
};
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use argon2::password_hash::SaltString;
use argon2::password_hash::rand_core::OsRng;
use base64::{Engine as _, engine::general_purpose::STANDARD as B64};
use rand_core::RngCore;
use zeroize::{Zeroize, Zeroizing};
use anyhow::Context as _;
use crate::tools::helper::{hmac, pstore, sha2};

#[derive(Debug, thiserror::Error)]
pub enum CryptError {
    #[error("pstore error: {0}")]
    PstoreError(String),
    #[error("hash error: {0}")]
    HashError(String),
    #[error("encryption error: {0}")]
    EncryptionError(String),
    #[error("decryption error: {0}")]
    DecryptionError(String),
}

fn argon2_instance() -> Argon2<'static> {
    let params = Params::new(65536, 3, 4, None).expect("valid argon2 params");
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
}

/// Hashes a password using HMAC-SHA256 (pepper) + Argon2id and returns `(phc_string, pepper_version)`.
///
/// ## Process
/// 1. Fetch the current pepper from the OS keyring via [`crate::tools::helper::pstore`].
/// 2. Compute `peppered = HMAC-SHA256(password, pepper)` to bind the hash to a secret that lives
///    outside the database.
/// 3. Run Argon2id (65 536 KiB, 3 passes, 4 lanes) over the peppered value with a random salt.
/// 4. Return the PHC-format hash string and the **pepper version** so the caller can store both
///    alongside the hash. Pass the version back to [`verify_password`] at login time.
///
/// Both `pepper` and the intermediate `peppered` value are [`Zeroizing`]-wrapped and wiped from
/// memory after use.
pub fn hash_password(password: &str) -> Result<(String, i16), CryptError> {
    let (pepper_bytes, version) = pstore::get_current_pepper()
        .map_err(|e| CryptError::PstoreError(e.to_string()))?;
    let mut pepper   = Zeroizing::new(pepper_bytes);
    let mut peppered = Zeroizing::new(hmac::sign(password.as_bytes(), &pepper));
    pepper.zeroize();

    let salt = SaltString::generate(&mut OsRng);
    let hash = argon2_instance()
        .hash_password(&peppered, &salt)
        .map_err(|e| CryptError::HashError(e.to_string()))?
        .to_string();
    peppered.zeroize();

    Ok((hash, version))
}

/// Verifies `password` against a stored Argon2id PHC hash using the given pepper version.
///
/// Fetches the pepper at `pepper_version` from the OS keyring (not necessarily the *current*
/// pepper — this is intentional so old hashes remain verifiable after a [`crate::tools::helper::pstore::rotate_pepper`]).
/// Recomputes `HMAC-SHA256(password, pepper)` then delegates to Argon2's constant-time verifier.
///
/// Returns `Ok(true)` on match, `Ok(false)` on mismatch, and `Err` only for keyring or hash
/// parse failures.
pub fn verify_password(password: &str, hash: &str, pepper_version: i16) -> Result<bool, CryptError> {
    let pepper_bytes = pstore::get_pepper(pepper_version)
        .map_err(|e| CryptError::PstoreError(e.to_string()))?;
    let mut pepper   = Zeroizing::new(pepper_bytes);
    let mut peppered = Zeroizing::new(hmac::sign(password.as_bytes(), &pepper));
    pepper.zeroize();

    let parsed = PasswordHash::new(hash).map_err(|e| CryptError::HashError(e.to_string()))?;
    let ok     = argon2_instance().verify_password(&peppered, &parsed).is_ok();
    peppered.zeroize();

    Ok(ok)
}

/// Returns the current pepper version number from the keyring.
pub fn current_pepper_version() -> i16 {
    pstore::get_current_pepper().map(|(_, v)| v).unwrap_or(1)
}

/// Encrypts `plaintext` with AES-256-GCM using a random 12-byte nonce prepended to the output.
pub fn aes_encrypt(plaintext: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptError> {
    let cipher_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher     = Aes256Gcm::new(cipher_key);
    let nonce      = Aes256Gcm::generate_nonce(&mut AesOsRng);
    let ciphertext = cipher.encrypt(&nonce, plaintext)
        .map_err(|e| CryptError::EncryptionError(e.to_string()))?;
    let mut out = Vec::with_capacity(12 + ciphertext.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Decrypts AES-256-GCM data where the first 12 bytes are the nonce.
pub fn aes_decrypt(data: &[u8], key: &[u8; 32]) -> Result<Vec<u8>, CryptError> {
    if data.len() < 12 {
        return Err(CryptError::DecryptionError("data too short".into()));
    }
    let cipher_key = Key::<Aes256Gcm>::from_slice(key);
    let cipher     = Aes256Gcm::new(cipher_key);
    let nonce      = Nonce::from_slice(&data[..12]);
    cipher.decrypt(nonce, &data[12..])
        .map_err(|e| CryptError::DecryptionError(e.to_string()))
}

/// Generates `bytes` random bytes and returns them as a lowercase hex string.
pub fn generate_random_hex(bytes: usize) -> String {
    let buf: Vec<u8> = (0..bytes).map(|_| rand::random()).collect();
    buf.iter().fold(String::with_capacity(bytes * 2), |mut acc, b| {
        use std::fmt::Write;
        let _ = write!(acc, "{:02x}", b);
        acc
    })
}

/// Returns the SHA-256 hash of `token` as a lowercase hex string.
pub fn sha256_token_hash(token: &str) -> String {
    sha2::hash_hex(token.as_bytes())
}

fn derive_key_from_password(password: &str, salt: &[u8]) -> [u8; 32] {
    let params = Params::new(65536, 3, 1, Some(32)).expect("valid argon2 params");
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut key = [0u8; 32];
    argon2.hash_password_into(password.as_bytes(), salt, &mut key)
        .expect("argon2 key derivation failed");
    key
}

/// Encrypts `plaintext` with a password-derived AES-256-GCM key.
///
/// Returns a base64-encoded blob with layout: `[16-byte Argon2id salt][12-byte AES-GCM nonce][ciphertext]`.
/// The salt and nonce are randomly generated per call so the same plaintext + password always
/// produces a different blob. Pass the blob to [`key_decrypt`] with the same password to recover
/// the original string.
///
/// Intended for encrypting small secrets at rest (e.g. private key material, API tokens).
pub fn key_encrypt(plaintext: &str, password: &str) -> anyhow::Result<String> {
    let mut salt = [0u8; 16];
    AesOsRng.fill_bytes(&mut salt);
    let key_bytes = derive_key_from_password(password, &salt);
    let key       = Key::<Aes256Gcm>::from(key_bytes);
    let cipher    = Aes256Gcm::new(&key);

    let mut nonce_bytes = [0u8; 12];
    AesOsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher.encrypt(nonce, plaintext.as_bytes())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;

    let mut blob = salt.to_vec();
    blob.extend_from_slice(&nonce_bytes);
    blob.extend_from_slice(&ciphertext);
    Ok(B64.encode(blob))
}

/// Decrypts a base64 blob produced by `key_encrypt` using the given password.
pub fn key_decrypt(blob_str: &str, password: &str) -> anyhow::Result<String> {
    let data = B64.decode(blob_str).context("Failed to decode blob")?;
    if data.len() < 29 { anyhow::bail!("Blob too short"); }
    let (salt, rest)      = data.split_at(16);
    let (nonce_bytes, ct) = rest.split_at(12);
    let key_bytes         = derive_key_from_password(password, salt);
    let key               = Key::<Aes256Gcm>::from(key_bytes);
    let cipher            = Aes256Gcm::new(&key);
    let nonce             = Nonce::from_slice(nonce_bytes);
    let plaintext         = cipher.decrypt(nonce, ct)
        .map_err(|_| anyhow::anyhow!("Decryption failed — wrong password?"))?;
    String::from_utf8(plaintext).context("Invalid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_encrypt_decrypt_roundtrip() {
        let key       = [0x42u8; 32];
        let plaintext = b"alterion-enc-pipeline secret payload";
        let ct        = aes_encrypt(plaintext, &key).unwrap();
        assert_ne!(&ct[12..], plaintext.as_ref());
        assert_eq!(aes_decrypt(&ct, &key).unwrap(), plaintext);
    }

    #[test]
    fn aes_encrypt_prepends_12_byte_nonce() {
        let ct = aes_encrypt(b"data", &[0x11u8; 32]).unwrap();
        assert!(ct.len() >= 12 + 4 + 16);
    }

    #[test]
    fn aes_decrypt_rejects_wrong_key() {
        let ct = aes_encrypt(b"secret", &[0x01u8; 32]).unwrap();
        assert!(aes_decrypt(&ct, &[0x02u8; 32]).is_err());
    }

    #[test]
    fn aes_decrypt_rejects_truncated_input() {
        assert!(aes_decrypt(&[0u8; 8], &[0xFFu8; 32]).is_err());
    }

    #[test]
    fn aes_decrypt_rejects_tampered_ciphertext() {
        let mut ct = aes_encrypt(b"authentic", &[0xABu8; 32]).unwrap();
        ct[15] ^= 0xFF;
        assert!(aes_decrypt(&ct, &[0xABu8; 32]).is_err());
    }

    #[test]
    fn generate_random_hex_correct_length() {
        assert_eq!(generate_random_hex(16).len(), 32);
        assert_eq!(generate_random_hex(32).len(), 64);
    }

    #[test]
    fn generate_random_hex_is_hex() {
        let h = generate_random_hex(32);
        assert!(h.chars().all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c)));
    }

    #[test]
    fn generate_random_hex_is_random() {
        assert_ne!(generate_random_hex(32), generate_random_hex(32));
    }

    #[test]
    fn sha256_token_hash_is_64_hex_chars() {
        assert_eq!(sha256_token_hash("some-session-token").len(), 64);
    }

    #[test]
    fn sha256_token_hash_is_deterministic() {
        let t = "test-token-abc123";
        assert_eq!(sha256_token_hash(t), sha256_token_hash(t));
    }

    #[test]
    fn sha256_token_hash_differs_per_token() {
        assert_ne!(sha256_token_hash("token-a"), sha256_token_hash("token-b"));
    }

}
