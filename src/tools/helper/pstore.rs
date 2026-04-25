// SPDX-License-Identifier: GPL-3.0
//! OS-keyring pepper store for the Argon2id password hasher.
//!
//! ## What is a pepper?
//! A pepper is a 32-byte random secret stored **outside** the database (in the OS keyring) and
//! mixed into the password hash via HMAC-SHA256 before Argon2id runs. If the database is
//! exfiltrated without the keyring, offline brute-force attacks are infeasible even for weak
//! passwords.
//!
//! ## Backends
//! - **Default (Linux)** — backed by the kernel keyring via [`keyutils`]. No D-Bus or Secret
//!   Service daemon required; works on any kernel ≥ 2.6.10.
//! - **Windows** (`features = ["win64"]`) — backed by Windows Credential Manager via [`keyring`].
//!
//! ## Storage layout
//! | Key name | Value |
//! |----------|-------|
//! | `alterion_pepper_v1` | Lowercase hex of 32 random bytes |
//! | `alterion_pepper_v2` | … next version after rotation … |
//! | `alterion_pepper_current_v` | Version number of the active pepper (e.g. `"1"`) |
//!
//! ## Pepper rotation
//! Call [`rotate_pepper`] to generate a new pepper at `current_version + 1` and advance the
//! version pointer. Old pepper versions are **not deleted** — [`verify_password`](crate::tools::crypt::verify_password)
//! accepts a `pepper_version` argument so existing hashes remain verifiable indefinitely.
//! Re-hash on next successful login to migrate users to the new pepper.

use zeroize::Zeroizing;

const SERVICE:             &str = "alterion-enc-pipeline";
const PEPPER_KEY_PREFIX:   &str = "alterion_pepper_v";
const VERSION_POINTER_KEY: &str = "alterion_pepper_current_v";

#[derive(Debug, thiserror::Error)]
pub enum PstoreError {
    #[error("keystore error: {0}")]
    KeystoreError(String),
    #[error("invalid pepper encoding")]
    InvalidEncoding,
    #[error("invalid pepper length — expected 32 bytes")]
    InvalidLength,
}

// ── Linux kernel keyring backend (default) ──────────────────────────────────

#[cfg(not(feature = "win64"))]
fn store_get(key: &str) -> Result<Option<String>, PstoreError> {
    use keyutils::{Keyring, SpecialKeyring, keytypes::User};

    let ring = Keyring::attach_or_create(SpecialKeyring::User)
        .map_err(|e| PstoreError::KeystoreError(e.to_string()))?;
    let desc = format!("{}:{}", SERVICE, key);

    match ring.search_for_key::<User, _, _>(desc.as_str(), None) {
        Ok(k) => {
            let bytes = k.read()
                .map_err(|e| PstoreError::KeystoreError(e.to_string()))?;
            Ok(Some(String::from_utf8(bytes)
                .map_err(|_| PstoreError::InvalidEncoding)?))
        }
        Err(e) if e.0 == libc::ENOKEY => Ok(None),
        Err(e) => Err(PstoreError::KeystoreError(e.to_string())),
    }
}

#[cfg(not(feature = "win64"))]
fn store_set(key: &str, value: &str) -> Result<(), PstoreError> {
    use keyutils::{Keyring, SpecialKeyring, keytypes::User};

    let mut ring = Keyring::attach_or_create(SpecialKeyring::User)
        .map_err(|e| PstoreError::KeystoreError(e.to_string()))?;
    let desc = format!("{}:{}", SERVICE, key);

    ring.add_key::<User, _, _>(desc.as_str(), value.as_bytes())
        .map_err(|e| PstoreError::KeystoreError(e.to_string()))?;
    Ok(())
}

// ── Windows Credential Manager backend (feature = "win64") ──────────────────

#[cfg(feature = "win64")]
fn store_get(key: &str) -> Result<Option<String>, PstoreError> {
    use keyring::Entry;

    let entry = Entry::new(SERVICE, key)
        .map_err(|e| PstoreError::KeystoreError(e.to_string()))?;
    match entry.get_password() {
        Ok(s)                        => Ok(Some(s)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e)                       => Err(PstoreError::KeystoreError(e.to_string())),
    }
}

#[cfg(feature = "win64")]
fn store_set(key: &str, value: &str) -> Result<(), PstoreError> {
    use keyring::Entry;

    Entry::new(SERVICE, key)
        .map_err(|e| PstoreError::KeystoreError(e.to_string()))?
        .set_password(value)
        .map_err(|e| PstoreError::KeystoreError(e.to_string()))
}

// ── Shared logic ─────────────────────────────────────────────────────────────

fn key_name(version: i16) -> String {
    format!("{}{}", PEPPER_KEY_PREFIX, version)
}

fn read_current_version() -> Result<i16, PstoreError> {
    match store_get(VERSION_POINTER_KEY)? {
        Some(s) => s.trim().parse::<i16>().map_err(|_| PstoreError::InvalidEncoding),
        None    => { set_current_version(1)?; Ok(1) }
    }
}

fn set_current_version(version: i16) -> Result<(), PstoreError> {
    store_set(VERSION_POINTER_KEY, &version.to_string())
}

/// Returns `(pepper_bytes, version)` for the currently active pepper, lazily creating v1 if none exists.
///
/// This is the function [`crate::tools::crypt::hash_password`] calls. The returned `version` must
/// be persisted alongside the password hash so the correct pepper can be fetched at verify time.
pub fn get_current_pepper() -> Result<([u8; 32], i16), PstoreError> {
    let version = read_current_version()?;
    get_pepper(version).map(|p| (p, version))
}

/// Retrieves the pepper at `version` from the keystore, generating and persisting it if absent.
///
/// Called by [`crate::tools::crypt::verify_password`] with the version stored at hash time.
/// Old versions are kept indefinitely — rotation does not delete them.
pub fn get_pepper(version: i16) -> Result<[u8; 32], PstoreError> {
    match store_get(&key_name(version))? {
        Some(hex_str) => {
            let raw = Zeroizing::new(
                hex::decode(&hex_str).map_err(|_| PstoreError::InvalidEncoding)?
            );
            if raw.len() != 32 { return Err(PstoreError::InvalidLength); }
            let mut out = [0u8; 32];
            out.copy_from_slice(&raw);
            Ok(out)
        }
        None => {
            let pepper = generate_pepper();
            store_set(&key_name(version), &hex::encode(&pepper))?;
            Ok(pepper)
        }
    }
}

fn generate_pepper() -> [u8; 32] {
    rand::random()
}

/// Rotates to a new pepper: generates 32 random bytes, stores them at `current_version + 1`,
/// advances the version pointer, and returns the new version number.
///
/// Existing hashes are **not invalidated** — they still reference their original version, which
/// remains in the keyring. To fully migrate, re-hash users' passwords on their next successful
/// login using [`crate::tools::crypt::hash_password`] (which will pick up the new active version).
pub fn rotate_pepper() -> Result<i16, PstoreError> {
    let current     = read_current_version()?;
    let new_version = current + 1;
    store_set(&key_name(new_version), &hex::encode(&generate_pepper()))?;
    set_current_version(new_version)?;
    Ok(new_version)
}
