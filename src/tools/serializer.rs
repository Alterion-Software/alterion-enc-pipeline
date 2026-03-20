// SPDX-License-Identifier: GPL-3.0
use serde::{Deserialize, Serialize};
use serde::de::DeserializeOwned;
use serde_bytes::ByteBuf;
use flate2::write::DeflateEncoder;
use flate2::read::DeflateDecoder;
use flate2::Compression;
use std::io::{Write, Read};
use hkdf::Hkdf;
use sha2::Sha256;
use crate::tools::helper::hmac;
use crate::tools::crypt::aes_encrypt;

/// Acceptable clock skew in seconds for replay protection.
const REPLAY_WINDOW_SECS: i64 = 30;

/// Derives a 32-byte AES encryption key and a 32-byte HMAC key from the ECDH shared secret,
/// binding both parties' public keys into the derivation via the HKDF salt.
///
/// `client_pk` and `server_pk` are the raw 32-byte X25519 public keys used in the exchange.
pub fn derive_session_keys(
    shared_secret: &[u8; 32],
    client_pk:     &[u8; 32],
    server_pk:     &[u8; 32],
) -> ([u8; 32], [u8; 32]) {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(client_pk);
    salt[32..].copy_from_slice(server_pk);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut enc_key = [0u8; 32];
    let mut mac_key = [0u8; 32];
    hk.expand(b"alterion-enc", &mut enc_key).expect("HKDF expand failed");
    hk.expand(b"alterion-mac", &mut mac_key).expect("HKDF expand failed");
    (enc_key, mac_key)
}

/// Incoming request packet: AES-encrypted body + client ephemeral X25519 public key + metadata.
///
/// The `mac` field is HMAC-SHA256 over `key_id || ts_le_bytes || client_pk || data`
/// using the HKDF-derived mac key. Verified by the server after performing ECDH.
#[derive(Debug, Serialize, Deserialize)]
pub struct WrappedPacket {
    pub data:      ByteBuf,
    /// Client's ephemeral X25519 public key (32 bytes). Used server-side to perform ECDH and
    /// derive the session encryption and MAC keys.
    pub client_pk: ByteBuf,
    pub key_id:    String,
    /// Unix timestamp (seconds) set by the client. Validated server-side within ±30 seconds.
    pub ts:        i64,
    /// HMAC-SHA256(mac_key, key_id || ts_le || client_pk || data) — binds all metadata to the ciphertext.
    pub mac:       ByteBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignedResponse {
    pub payload: ByteBuf,
    pub hmac:    ByteBuf,
}

#[derive(Debug, thiserror::Error)]
pub enum SerializerError {
    #[error("serialize error: {0}")]
    Serialize(String),
    #[error("deserialize error: {0}")]
    Deserialize(String),
    #[error("compress error: {0}")]
    Compress(String),
    #[error("decompress error: {0}")]
    Decompress(String),
}

impl From<SerializerError> for actix_web::Error {
    fn from(e: SerializerError) -> Self {
        actix_web::error::ErrorInternalServerError(e.to_string())
    }
}

/// Encodes a value to MessagePack bytes using named fields.
pub fn serialize<T: Serialize>(value: &T) -> Result<Vec<u8>, SerializerError> {
    rmp_serde::to_vec_named(value)
        .map_err(|e| SerializerError::Serialize(e.to_string()))
}

/// Decodes MessagePack bytes into the target type.
pub fn deserialize<T: DeserializeOwned>(data: &[u8]) -> Result<T, SerializerError> {
    rmp_serde::from_slice(data)
        .map_err(|e| SerializerError::Deserialize(e.to_string()))
}

/// Deflate-compresses `data` and returns the compressed bytes.
pub fn compress(data: &[u8]) -> Result<Vec<u8>, SerializerError> {
    let mut encoder = DeflateEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(data)
        .map_err(|e: std::io::Error| SerializerError::Compress(e.to_string()))?;
    encoder.finish()
        .map_err(|e: std::io::Error| SerializerError::Compress(e.to_string()))
}

/// Deflate-decompresses `data` and returns the original bytes.
pub fn decompress(data: &[u8]) -> Result<Vec<u8>, SerializerError> {
    let mut decoder = DeflateDecoder::new(data);
    let mut out     = Vec::new();
    decoder.read_to_end(&mut out)
        .map_err(|e: std::io::Error| SerializerError::Decompress(e.to_string()))?;
    Ok(out)
}

/// Deserialises and timestamp-validates a `WrappedPacket`.
///
/// Returns an error if the packet's `ts` deviates more than ±30 seconds from the server clock.
/// Call [`verify_packet_mac`] separately once session keys have been derived via ECDH.
pub fn deserialize_packet(data: &[u8]) -> Result<WrappedPacket, SerializerError> {
    let packet = deserialize::<WrappedPacket>(data)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| SerializerError::Deserialize(format!("system clock error: {e}")))?
        .as_secs() as i64;
    if (packet.ts - now).abs() > REPLAY_WINDOW_SECS {
        return Err(SerializerError::Deserialize(
            format!("timestamp out of window: skew={}s", packet.ts - now)
        ));
    }
    Ok(packet)
}

/// Verifies the packet `mac` field using the HKDF-derived mac key.
///
/// Returns `false` if the MAC is invalid — the request must be rejected.
pub fn verify_packet_mac(mac_key: &[u8; 32], packet: &WrappedPacket) -> bool {
    let msg = packet_mac_msg(packet);
    hmac::verify(&msg, mac_key, packet.mac.as_ref())
}

fn packet_mac_msg(packet: &WrappedPacket) -> Vec<u8> {
    let mut msg = Vec::new();
    msg.extend_from_slice(packet.key_id.as_bytes());
    msg.extend_from_slice(&packet.ts.to_le_bytes());
    msg.extend_from_slice(packet.client_pk.as_ref());
    msg.extend_from_slice(packet.data.as_ref());
    msg
}

/// Decodes a request payload from AES-decrypted bytes:
/// msgpack decode → deflate decompress → JSON deserialise.
pub fn decode_request_payload<T: DeserializeOwned>(
    decrypted_data: &[u8],
) -> Result<T, SerializerError> {
    let compressed: ByteBuf = deserialize(decrypted_data)?;
    let json_bytes          = decompress(&compressed)?;
    serde_json::from_slice(&json_bytes)
        .map_err(|e| SerializerError::Deserialize(e.to_string()))
}

/// Serialises `value` to JSON then passes it through `build_signed_response_raw`.
pub fn build_signed_response<T: Serialize>(
    value:   &T,
    enc_key: &[u8; 32],
    mac_key: &[u8; 32],
) -> Result<Vec<u8>, SerializerError> {
    let json_bytes = serde_json::to_vec(value)
        .map_err(|e| SerializerError::Serialize(e.to_string()))?;
    build_signed_response_raw(&json_bytes, enc_key, mac_key)
}

/// Builds a signed response from raw JSON bytes:
/// deflate compress → msgpack → AES-256-GCM (enc_key) → HMAC-SHA256 (mac_key) → `SignedResponse` → msgpack.
pub fn build_signed_response_raw(
    json_bytes: &[u8],
    enc_key:    &[u8; 32],
    mac_key:    &[u8; 32],
) -> Result<Vec<u8>, SerializerError> {
    let compressed = compress(json_bytes)?;
    let msgpacked  = serialize(&ByteBuf::from(compressed))?;
    let encrypted  = aes_encrypt(&msgpacked, enc_key)
        .map_err(|e| SerializerError::Serialize(e.to_string()))?;
    let sig        = hmac::sign(&encrypted, mac_key);
    let response   = SignedResponse {
        payload: ByteBuf::from(encrypted),
        hmac:    ByteBuf::from(sig),
    };
    serialize(&response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use crate::tools::crypt::aes_decrypt;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestPayload { id: u32, name: String, flag: bool }

    fn sample() -> TestPayload { TestPayload { id: 42, name: "alterion".into(), flag: true } }

    fn test_keys() -> ([u8; 32], [u8; 32]) {
        let shared    = [0x42u8; 32];
        let client_pk = [0x01u8; 32];
        let server_pk = [0x02u8; 32];
        derive_session_keys(&shared, &client_pk, &server_pk)
    }

    #[test]
    fn compress_decompress_roundtrip() {
        let data = b"hello alterion enc pipeline payload";
        assert_eq!(decompress(&compress(data).unwrap()).unwrap(), data);
    }

    #[test]
    fn decode_request_payload_roundtrip() {
        let original   = sample();
        let json_bytes = serde_json::to_vec(&original).unwrap();
        let compressed = compress(&json_bytes).unwrap();
        let msgpacked  = serialize(&ByteBuf::from(compressed)).unwrap();
        let decoded: TestPayload = decode_request_payload(&msgpacked).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn build_signed_response_roundtrip() {
        let (enc_key, mac_key) = test_keys();
        let payload = sample();
        let bytes   = build_signed_response(&payload, &enc_key, &mac_key).unwrap();
        let signed: SignedResponse = deserialize(&bytes).unwrap();

        assert_eq!(signed.hmac.as_ref(), hmac::sign(&signed.payload, &mac_key).as_slice());

        let decrypted: Vec<u8>   = aes_decrypt(&signed.payload, &enc_key).unwrap();
        let compressed: ByteBuf  = deserialize(&decrypted).unwrap();
        let json_bytes           = decompress(&compressed).unwrap();
        let decoded: TestPayload = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn derive_session_keys_enc_and_mac_are_distinct() {
        let (enc, mac) = test_keys();
        assert_ne!(enc, mac);
    }

    #[test]
    fn derive_session_keys_bound_to_public_keys() {
        let shared    = [0x42u8; 32];
        let client_pk = [0x01u8; 32];
        let server_pk = [0x02u8; 32];
        let (enc1, _) = derive_session_keys(&shared, &client_pk, &server_pk);
        // Swapping client/server pk produces different keys
        let (enc2, _) = derive_session_keys(&shared, &server_pk, &client_pk);
        assert_ne!(enc1, enc2);
    }

    #[test]
    fn verify_packet_mac_accepts_valid_mac() {
        let (_, mac_key) = test_keys();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let data      = ByteBuf::from(vec![1u8; 32]);
        let client_pk = ByteBuf::from(vec![0x01u8; 32]);
        let key_id    = "test-key-id".to_string();
        let mut msg   = Vec::new();
        msg.extend_from_slice(key_id.as_bytes());
        msg.extend_from_slice(&ts.to_le_bytes());
        msg.extend_from_slice(client_pk.as_ref());
        msg.extend_from_slice(data.as_ref());
        let mac    = ByteBuf::from(hmac::sign(&msg, &mac_key));
        let packet = WrappedPacket { data, client_pk, key_id, ts, mac };
        assert!(verify_packet_mac(&mac_key, &packet));
    }

    #[test]
    fn verify_packet_mac_rejects_tampered_key_id() {
        let (_, mac_key) = test_keys();
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() as i64;
        let data      = ByteBuf::from(vec![1u8; 32]);
        let client_pk = ByteBuf::from(vec![0x01u8; 32]);
        let key_id    = "original-key-id".to_string();
        let mut msg   = Vec::new();
        msg.extend_from_slice(key_id.as_bytes());
        msg.extend_from_slice(&ts.to_le_bytes());
        msg.extend_from_slice(client_pk.as_ref());
        msg.extend_from_slice(data.as_ref());
        let mac    = ByteBuf::from(hmac::sign(&msg, &mac_key));
        let packet = WrappedPacket { data, client_pk, key_id: "tampered-key-id".to_string(), ts, mac };
        assert!(!verify_packet_mac(&mac_key, &packet));
    }

    #[test]
    fn decompress_garbage_returns_error() {
        assert!(decompress(b"not compressed").is_err());
    }
}
