// SPDX-License-Identifier: GPL-3.0
//! HMAC-SHA256 signing and verification.
//!
//! [`sign`] produces a 32-byte tag and [`verify`] checks one using the constant-time
//! [`Mac::verify_slice`] to prevent timing-based forgery. Used by the pipeline to authenticate
//! response ciphertext so the client can detect tampering before attempting decryption.
use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

/// Computes HMAC-SHA256 of `data` under `key` and returns the 32-byte signature.
pub fn sign(data: impl AsRef<[u8]>, key: impl AsRef<[u8]>) -> Vec<u8> {
    let mut mac = HmacSha256::new_from_slice(key.as_ref())
        .expect("HMAC accepts any key length");
    mac.update(data.as_ref());
    mac.finalize().into_bytes().to_vec()
}

/// Verifies that `expected` matches HMAC-SHA256(`data`, `key`) using a constant-time comparison.
pub fn verify(data: impl AsRef<[u8]>, key: impl AsRef<[u8]>, expected: &[u8]) -> bool {
    let mut mac = HmacSha256::new_from_slice(key.as_ref())
        .expect("HMAC accepts any key length");
    mac.update(data.as_ref());
    mac.verify_slice(expected).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_produces_32_bytes() {
        assert_eq!(sign(b"test payload", &[0xABu8; 32]).len(), 32);
    }

    #[test]
    fn sign_is_deterministic() {
        let key  = [0x55u8; 32];
        let data = b"alterion-enc-pipeline";
        assert_eq!(sign(data, &key), sign(data, &key));
    }

    #[test]
    fn sign_differs_per_key() {
        assert_ne!(sign(b"same data", &[0x01u8; 32]), sign(b"same data", &[0x02u8; 32]));
    }

    #[test]
    fn verify_passes_for_correct_hmac() {
        let key = [0xDEu8; 32];
        let sig = sign(b"verify me", &key);
        assert!(verify(b"verify me", &key, &sig));
    }

    #[test]
    fn verify_fails_for_tampered_data() {
        let key = [0xDEu8; 32];
        let sig = sign(b"original", &key);
        assert!(!verify(b"tampered", &key, &sig));
    }

    #[test]
    fn verify_fails_for_wrong_key() {
        let sig = sign(b"data", &[0x01u8; 32]);
        assert!(!verify(b"data", &[0x02u8; 32], &sig));
    }
}
