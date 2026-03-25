// SPDX-License-Identifier: GPL-3.0
//! Cross-platform pepper store.
//!
//! **Default** — backed by the Linux kernel keyring via [`keyutils`].  No D-Bus or Secret
//! Service daemon is required; works on any kernel ≥ 2.6.10.
//!
//! **Windows** (`features = ["win64"]`) — backed by Windows Credential Manager via the
//! [`keyring`] crate.  Enable this when building for Windows targets.
//!
//! Peppers are 32 random bytes stored as lowercase hex strings.  A version pointer key tracks
//! the current active version so that [`rotate_pepper`] advances correctly beyond v2.

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

/// Returns the current pepper bytes and version number, generating and storing one if absent.
pub fn get_current_pepper() -> Result<([u8; 32], i16), PstoreError> {
    let version = read_current_version()?;
    get_pepper(version).map(|p| (p, version))
}

/// Retrieves a specific pepper version from the keystore, generating and storing one if absent.
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
    let mut buf = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::thread_rng(), &mut buf);
    buf
}

/// Generates a new pepper at `current_version + 1`, stores it, advances the version pointer,
/// and returns the new version number.
pub fn rotate_pepper() -> Result<i16, PstoreError> {
    let current     = read_current_version()?;
    let new_version = current + 1;
    store_set(&key_name(new_version), &hex::encode(&generate_pepper()))?;
    set_current_version(new_version)?;
    Ok(new_version)
}
