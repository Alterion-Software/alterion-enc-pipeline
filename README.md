<div align="center">
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.png">
        <source media="(prefers-color-scheme: light)" srcset="assets/logo-light.png">
        <img alt="Alterion Logo" src="assets/logo-dark.png" width="400">
    </picture>
</div>

<div align="center">

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/alterion-encrypt.svg)](https://crates.io/crates/alterion-encrypt)
[![Rust](https://img.shields.io/badge/Rust-2024-orange?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Actix-web](https://img.shields.io/badge/Actix--web-4-green?style=flat)](https://actix.rs/)
[![AES-256-GCM](https://img.shields.io/badge/AES--256--GCM-Encrypted-blue?style=flat)](https://docs.rs/aes-gcm)
[![GitHub](https://img.shields.io/badge/GitHub-Alterion--Software-181717?style=flat&logo=github&logoColor=white)](https://github.com/Alterion-Software)

_A full end-to-end encryption pipeline for Actix-web — X25519 ECDH key exchange, AES-256-GCM session encryption, Argon2id password hashing, and a MessagePack + Deflate request/response pipeline, all behind a single middleware._

> **JavaScript/TypeScript client?** See [alterion-encrypt-js](https://github.com/Alterion-Software/alterion-encrypt-js) — the framework-agnostic JS counterpart implementing the same wire protocol.

---

</div>

## What it does

Each request from the client is packaged as a `Request`:

```
Client → Request { data: AES-256-GCM ciphertext, wrapped_key, client_pk: ephemeral X25519, key_id, ts }
```

The `Interceptor` middleware:

1. **Decrypts the request** — performs X25519 ECDH with the client's ephemeral key, derives a `wrap_key` via HKDF-SHA256, uses it to unwrap the client's randomly-generated `enc_key` from `wrapped_key`, then AES-GCM-decrypts the payload. The raw bytes are injected into request extensions as `DecryptedBody` for your handlers to read.
2. **Encrypts the response** — re-encrypts the JSON response body with the **same** `enc_key` the client generated. A separate HMAC key is derived from `enc_key` via HKDF and used to sign the ciphertext. The response is `Response { payload, hmac }` — no second ECDH round-trip is needed.

`build_request_packet` and `decode_response_packet` in `tools::serializer` implement the matching client-side pipeline so Rust clients can participate in the same exchange without re-implementing the protocol.

The X25519 key pair rotates automatically on a configurable interval with a 300-second grace window so in-flight requests using the previous key still succeed.

---

## Crate layout

```
alterion_encrypt
├── interceptor    Actix-web middleware — the main public API
└── tools
    ├── crypt      AES-256-GCM encrypt/decrypt, Argon2id password hashing, Argon2id KDF
    ├── serializer MessagePack serialisation, Deflate compression, signed-response builder
    └── helper
        ├── hmac   HMAC-SHA256 sign / constant-time verify
        ├── sha2   SHA-256 — raw bytes, hex string, file hash
        └── pstore Versioned pepper store via OS native keyring (cross-platform)
```

---

## Quick start

### 1. Add the dependency

```toml
[dependencies]
alterion-encrypt = "1.3"
alterion-ecdh    = "0.3"
```

### 2. Initialise the key store and mount the interceptor

```rust
use alterion_encrypt::interceptor::Interceptor;
use alterion_encrypt::{init_key_store, init_handshake_store, start_rotation};
use actix_web::{web, App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Rotate X25519 keys every hour; keep the previous key live for 5 minutes.
    let store = init_key_store(3600);
    let hs    = init_handshake_store();
    start_rotation(store.clone(), 3600, hs.clone());

    HttpServer::new(move || {
        App::new()
            .wrap(Interceptor { key_store: store.clone(), handshake_store: hs.clone(), replay_store: None })
            // your routes here
    })
    .bind("0.0.0.0:8080")?
    .run()
    .await
}
```

### 3. Read the decrypted body in a handler

```rust
use actix_web::{post, HttpRequest, HttpMessage, HttpResponse};
use alterion_encrypt::interceptor::DecryptedBody;

#[post("/api/example")]
async fn example_handler(req: HttpRequest) -> HttpResponse {
    let body = match req.extensions().get::<DecryptedBody>().cloned() {
        Some(b) => b,
        None    => return HttpResponse::BadRequest().body("missing encrypted body"),
    };
    // body.0 is the raw decrypted bytes — deserialise however you like
    HttpResponse::Ok().json(serde_json::json!({ "ok": true }))
}
```

### 4. Expose the current public key to clients

```rust
use actix_web::{get, web, HttpResponse};
use alterion_encrypt::{KeyStore, get_current_public_key};
use std::sync::Arc;
use tokio::sync::RwLock;

#[get("/api/pubkey")]
async fn public_key_handler(
    store: web::Data<Arc<RwLock<KeyStore>>>,
) -> HttpResponse {
    let (key_id, public_key_b64) = get_current_public_key(&store).await;
    HttpResponse::Ok().json(serde_json::json!({ "key_id": key_id, "public_key": public_key_b64 }))
}
```

The `public_key` is a base64-encoded 32-byte X25519 public key for the client to use in ECDH.

---

## Key store

| Function | Description |
|---|---|
| `init_key_store(interval_secs)` | Generates the initial X25519 key pair and wraps it in an `Arc<RwLock<KeyStore>>` |
| `start_rotation(store, interval_secs)` | Spawns a background task that rotates the key every `interval_secs` seconds |
| `get_current_public_key(store)` | Returns `(key_id, base64_public_key)` for the active key |
| `ecdh(store, key_id, client_pk)` | Performs X25519 ECDH, returns `(shared_secret, server_pk_bytes)` |

The grace window is fixed at **300 seconds**. The previous key remains valid for 5 minutes after rotation so any request encrypted just before a rotation still decrypts successfully.

> **Frontend note:** Pre-fetch a new public key at `rotation_interval − 300` seconds so the cached key is never stale when a rotation occurs.

---

## Tools

### `tools::crypt`

```rust
use alterion_encrypt::tools::crypt;

// AES-256-GCM (nonce prepended to output)
let ct = crypt::aes_encrypt(b"hello", &key)?;
let pt = crypt::aes_decrypt(&ct, &key)?;

// Argon2id password hashing with HMAC-pepper
let (hash, pepper_version) = crypt::hash_password("my-password")?;
let valid = crypt::verify_password("my-password", &hash, pepper_version)?;

// Argon2id KDF — encrypt/decrypt a secret string with a password
let blob   = crypt::key_encrypt("secret value", "master-password")?;
let secret = crypt::key_decrypt(&blob, "master-password")?;
```

### `tools::serializer`

```rust
use alterion_encrypt::tools::serializer;

// ── Server side ──────────────────────────────────────────────────────────────

// Decode an incoming request payload (msgpack → deflate decompress → JSON)
let payload: Request = serializer::decode_request_payload(&decrypted_bytes)?;

// Build an AES-encrypted, HMAC-signed response from any Serialize type
let bytes = serializer::build_signed_response(&response, &enc_key)?;

// ── Client side ──────────────────────────────────────────────────────────────

// Build an encrypted request packet (JSON → compress → msgpack → AES-256-GCM → Request).
// Returns wire bytes and the AES key — hold enc_key to decrypt the server's response.
let (wire_bytes, enc_key) =
    serializer::build_request_packet(&request, &server_pk, key_id)?;

// Decode and verify a server Response using the AES key from build_request_packet.
let decoded: MyResponse =
    serializer::decode_response_packet(&wire_bytes, &enc_key)?;
```

### `tools::helper`

```rust
use alterion_encrypt::tools::helper::{sha2, hmac, pstore};

// SHA-256
let hex  = sha2::hash_hex(b"some data");
let file = sha2::hash_file(Path::new("a.bin"))?;

// HMAC-SHA256 (constant-time verify)
let sig   = hmac::sign(b"data", &key);
let valid = hmac::verify(b"data", &key, &sig);

// OS keyring pepper store (Secret Service / Keychain / Credential Manager)
let (pepper, version) = pstore::get_current_pepper()?;
let new_version       = pstore::rotate_pepper()?;
```

---

## Pipelines

### Client request (`build_request_packet`)

```
Any Serialize value
        │
        ▼
  serde_json::to_vec
        │
        ▼
  Deflate compress
        │
        ▼
  MessagePack encode  ──→  ByteBuf
        │
        ▼
  AES-256-GCM encrypt  (random enc_key — stored client-side by request ID)
        │
        ▼
  Ephemeral X25519 keygen  ──→  ECDH(client_sk, server_pk)  ──→  HKDF-SHA256  ──→  wrap_key
        │
        ▼
  AES-256-GCM wrap enc_key  (wrap_key)  ──→  wrapped_key
        │
        ▼
  Request { data, wrapped_key, client_pk, key_id, ts }
        │
        ▼
  MessagePack encode  ──→  wire bytes
```

`enc_key` is returned to the caller and must be stored client-side (e.g. keyed by request ID).
The `wrapped_key` lets the server recover `enc_key` via ECDH without it ever appearing in plain
text on the wire. AES-GCM authentication tags on both `data` and `wrapped_key` ensure integrity.

### Server response (`build_signed_response`)

```
Handler returns JSON bytes
        │
        ▼
  Deflate compress
        │
        ▼
  MessagePack encode  ──→  ByteBuf
        │
        ▼
  AES-256-GCM encrypt  (enc_key — same key the client generated for the request)
        │
        ▼
  HMAC-SHA256 sign  (mac_key derived from enc_key via HKDF, over the ciphertext)
        │
        ▼
  Response { payload: ByteBuf, hmac: ByteBuf }
        │
        ▼
  MessagePack encode  ──→  sent to client
```

The client uses `enc_key` (retrieved by request ID) to verify the HMAC and decrypt via
`decode_response_packet`. No second ECDH round-trip is needed. If HMAC verification fails
the response must be discarded.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Open an issue before writing any code.

---

## License

GNU General Public License v3.0 — see [LICENSE](LICENSE).

---

<div align="center">

**Made with ❤️ by the Alterion Software team**

[![Discord](https://img.shields.io/badge/Discord-Join-5865F2?style=flat&logo=discord&logoColor=white)](https://discord.com/invite/3gy9gJyJY8)
[![Website](https://img.shields.io/badge/Website-Coming%20Soon-blue?style=flat&logo=globe&logoColor=white)](.)
[![GitHub](https://img.shields.io/badge/GitHub-Alterion--Software-181717?style=flat&logo=github&logoColor=white)](https://github.com/Alterion-Software)

</div>
