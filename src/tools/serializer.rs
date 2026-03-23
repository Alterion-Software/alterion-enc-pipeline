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
use crate::tools::crypt::{aes_encrypt, aes_decrypt};
use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};
use rand::RngCore;

/// Acceptable clock skew in seconds for replay protection.
const REPLAY_WINDOW_SECS: i64 = 30;

/// Derives a 32-byte AES wrapping key from the ECDH shared secret via HKDF-SHA256,
/// binding both parties' public keys into the derivation via the salt.
///
/// Used server-side to unwrap the client's randomly-generated AES key from the `Request`.
pub fn derive_wrap_key(
    shared_secret: &[u8; 32],
    client_pk:     &[u8; 32],
    server_pk:     &[u8; 32],
) -> [u8; 32] {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(client_pk);
    salt[32..].copy_from_slice(server_pk);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared_secret);
    let mut key = [0u8; 32];
    hk.expand(b"alterion-wrap", &mut key).expect("HKDF expand failed");
    key
}

/// Outgoing encrypted request packet produced by [`build_request_packet`].
///
/// `data` is the AES-256-GCM-encrypted payload. `wrapped_key` is the client's randomly-generated
/// AES key encrypted with the ECDH-derived wrap key — the server unwraps it via ECDH then uses it
/// to decrypt `data`. Integrity is provided by the AES-GCM authentication tags on both fields.
#[derive(Debug, Serialize, Deserialize)]
pub struct Request {
    pub data:        ByteBuf,
    /// Client's randomly-generated AES-256 key, wrapped with the ECDH-derived wrap key.
    pub wrapped_key: ByteBuf,
    /// Client's ephemeral X25519 public key (32 bytes). Used server-side to perform ECDH.
    pub client_pk:   ByteBuf,
    pub key_id:      String,
    /// Unix timestamp (seconds) set by the client. Validated server-side within ±30 seconds.
    pub ts:          i64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Response {
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

/// Deserialises and timestamp-validates a [`Request`].
///
/// Returns an error if `ts` deviates more than ±30 seconds from the server clock.
/// After this succeeds, call [`derive_wrap_key`] via ECDH to unwrap the AES key and decrypt.
pub fn deserialize_packet(data: &[u8]) -> Result<Request, SerializerError> {
    let packet = deserialize::<Request>(data)?;
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
) -> Result<Vec<u8>, SerializerError> {
    let json_bytes = serde_json::to_vec(value)
        .map_err(|e| SerializerError::Serialize(e.to_string()))?;
    build_signed_response_raw(&json_bytes, enc_key)
}

/// Builds a signed response from raw JSON bytes:
/// deflate compress → msgpack → AES-256-GCM (enc_key) → HMAC-SHA256 (enc_key) → `Response` → msgpack.
pub fn build_signed_response_raw(
    json_bytes: &[u8],
    enc_key:    &[u8; 32],
) -> Result<Vec<u8>, SerializerError> {
    let compressed = compress(json_bytes)?;
    let msgpacked  = serialize(&ByteBuf::from(compressed))?;
    let encrypted  = aes_encrypt(&msgpacked, enc_key)
        .map_err(|e| SerializerError::Serialize(e.to_string()))?;
    let sig        = hmac::sign(&encrypted, enc_key);
    let response   = Response {
        payload: ByteBuf::from(encrypted),
        hmac:    ByteBuf::from(sig),
    };
    serialize(&response)
}

/// Builds an encrypted request packet ready to send to the server.
///
/// ## Pipeline
/// `T` → JSON → deflate compress → msgpack (`ByteBuf`) → AES-256-GCM (random `enc_key`) →
/// ECDH-wrap `enc_key` → [`Request`] → msgpack
///
/// A fresh random AES-256 key is generated per call and used to encrypt the payload. An ephemeral
/// X25519 keypair is generated, ECDH is performed against `server_pk`, and the AES key is wrapped
/// with the HKDF-derived wrap key so only the server can recover it. Integrity of both the payload
/// and the wrapped key is guaranteed by the AES-GCM authentication tags.
///
/// # Arguments
/// * `value`     – Any `serde::Serialize` payload.
/// * `server_pk` – Server's 32-byte X25519 public key (from the server's key endpoint).
/// * `key_id`    – Key identifier returned alongside the server's public key.
///
/// # Returns
/// `(wire_bytes, enc_key)` — store `enc_key` client-side indexed by request ID and pass it to
/// [`decode_response_packet`] when the server's reply arrives.
pub fn build_request_packet<T: Serialize>(
    value:     &T,
    server_pk: &[u8; 32],
    key_id:    String,
) -> Result<(Vec<u8>, [u8; 32]), SerializerError> {
    let json_bytes = serde_json::to_vec(value)
        .map_err(|e| SerializerError::Serialize(e.to_string()))?;
    let compressed = compress(&json_bytes)?;
    let msgpacked  = serialize(&ByteBuf::from(compressed))?;

    let mut enc_key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut enc_key);

    let encrypted = aes_encrypt(&msgpacked, &enc_key)
        .map_err(|e| SerializerError::Serialize(e.to_string()))?;

    let client_sk       = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
    let client_pk       = X25519PublicKey::from(&client_sk);
    let server_pub      = X25519PublicKey::from(*server_pk);
    let shared          = client_sk.diffie_hellman(&server_pub);
    let client_pk_bytes = client_pk.to_bytes();

    let wrap_key    = derive_wrap_key(shared.as_bytes(), &client_pk_bytes, server_pk);
    let wrapped_key = aes_encrypt(&enc_key, &wrap_key)
        .map_err(|e| SerializerError::Serialize(e.to_string()))?;

    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|e| SerializerError::Serialize(format!("system clock error: {e}")))?
        .as_secs() as i64;

    let packet = Request {
        data:        ByteBuf::from(encrypted),
        wrapped_key: ByteBuf::from(wrapped_key),
        client_pk:   ByteBuf::from(client_pk_bytes.to_vec()),
        key_id,
        ts,
    };
    let wire_bytes = serialize(&packet)?;

    Ok((wire_bytes, enc_key))
}

/// Decodes and verifies a server [`Response`] using the AES key returned by [`build_request_packet`].
///
/// ## Pipeline
/// msgpack → [`Response`] → HMAC-SHA256 verify (enc_key) → AES-256-GCM decrypt → msgpack →
/// deflate decompress → JSON → `T`
///
/// Returns `Err` if the HMAC is invalid, decryption fails, or deserialization fails.
pub fn decode_response_packet<T: DeserializeOwned>(
    data:    &[u8],
    enc_key: &[u8; 32],
) -> Result<T, SerializerError> {
    let signed: Response = deserialize(data)?;

    if !hmac::verify(signed.payload.as_ref(), enc_key, signed.hmac.as_ref()) {
        return Err(SerializerError::Deserialize("response HMAC invalid".into()));
    }

    let decrypted        = aes_decrypt(signed.payload.as_ref(), enc_key)
        .map_err(|e| SerializerError::Deserialize(e.to_string()))?;
    let compressed: ByteBuf = deserialize(&decrypted)?;
    let json_bytes       = decompress(&compressed)?;

    serde_json::from_slice(&json_bytes)
        .map_err(|e| SerializerError::Deserialize(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    use crate::tools::crypt::aes_decrypt;

    #[derive(Debug, PartialEq, Serialize, Deserialize)]
    struct TestPayload { id: u32, name: String, flag: bool }

    fn sample() -> TestPayload { TestPayload { id: 42, name: "alterion".into(), flag: true } }

    fn test_enc_key() -> [u8; 32] { [0x42u8; 32] }

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
    fn derive_wrap_key_bound_to_public_keys() {
        let shared    = [0x42u8; 32];
        let client_pk = [0x01u8; 32];
        let server_pk = [0x02u8; 32];
        let k1 = derive_wrap_key(&shared, &client_pk, &server_pk);
        let k2 = derive_wrap_key(&shared, &server_pk, &client_pk);
        assert_ne!(k1, k2);
    }

    #[test]
    fn build_signed_response_roundtrip() {
        let enc_key = test_enc_key();
        let payload = sample();
        let bytes   = build_signed_response(&payload, &enc_key).unwrap();
        let signed: Response = deserialize(&bytes).unwrap();

        assert_eq!(signed.hmac.as_ref(), hmac::sign(&signed.payload, &enc_key).as_slice());

        let decrypted: Vec<u8>   = aes_decrypt(&signed.payload, &enc_key).unwrap();
        let compressed: ByteBuf  = deserialize(&decrypted).unwrap();
        let json_bytes           = decompress(&compressed).unwrap();
        let decoded: TestPayload = serde_json::from_slice(&json_bytes).unwrap();
        assert_eq!(payload, decoded);
    }

    #[test]
    fn decompress_garbage_returns_error() {
        assert!(decompress(b"not compressed").is_err());
    }

    /// Full client→server→client round trip with actual ephemeral ECDH and AES key wrapping.
    /// Mirrors the steps the interceptor performs on the server side.
    #[test]
    fn request_response_full_roundtrip() {
        use x25519_dalek::{EphemeralSecret, PublicKey as X25519PublicKey};

        let server_sk       = EphemeralSecret::random_from_rng(rand::rngs::OsRng);
        let server_pk       = X25519PublicKey::from(&server_sk);
        let server_pk_bytes: [u8; 32] = server_pk.to_bytes();

        let (wire, client_enc_key) =
            build_request_packet(&sample(), &server_pk_bytes, "test-key".to_string()).unwrap();

        let packet: Request           = deserialize(&wire).unwrap();
        let client_pk_bytes: [u8; 32] = packet.client_pk.as_ref().try_into().unwrap();
        let client_pub                = X25519PublicKey::from(client_pk_bytes);
        let shared                    = server_sk.diffie_hellman(&client_pub);
        let wrap_key                  = derive_wrap_key(shared.as_bytes(), &client_pk_bytes, &server_pk_bytes);

        let enc_key_bytes             = aes_decrypt(packet.wrapped_key.as_ref(), &wrap_key).unwrap();
        let srv_enc_key: [u8; 32]     = enc_key_bytes.as_slice().try_into().unwrap();
        assert_eq!(client_enc_key, srv_enc_key);

        let decrypted: TestPayload = decode_request_payload(
            &aes_decrypt(packet.data.as_ref(), &srv_enc_key).unwrap()
        ).unwrap();
        assert_eq!(decrypted, sample());

        let response_bytes = build_signed_response(&sample(), &srv_enc_key).unwrap();
        let decoded: TestPayload =
            decode_response_packet(&response_bytes, &client_enc_key).unwrap();
        assert_eq!(decoded, sample());
    }

    #[test]
    fn decode_response_packet_rejects_tampered_hmac() {
        let enc_key   = test_enc_key();
        let mut bytes = build_signed_response(&sample(), &enc_key).unwrap();
        let last      = bytes.len() - 1;
        bytes[last] ^= 0xFF;
        assert!(decode_response_packet::<TestPayload>(&bytes, &enc_key).is_err());
    }

    #[test]
    fn decode_response_packet_rejects_wrong_key() {
        let enc_key   = test_enc_key();
        let bytes     = build_signed_response(&sample(), &enc_key).unwrap();
        let wrong_key = [0x00u8; 32];
        assert!(decode_response_packet::<TestPayload>(&bytes, &wrong_key).is_err());
    }
}
