<div align="center">
    <picture>
        <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.png">
        <source media="(prefers-color-scheme: light)" srcset="assets/logo-light.png">
        <img alt="Alterion Logo" src="assets/logo-dark.png" width="400">
    </picture>
</div>

<div align="center">

[![License: GPL-3.0](https://img.shields.io/badge/License-GPL--3.0-blue.svg)](LICENSE)
[![Crates.io](https://img.shields.io/crates/v/alterion-enc-pipeline.svg)](https://crates.io/crates/alterion-enc-pipeline)
[![Rust](https://img.shields.io/badge/Rust-2024-orange?style=flat&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![Actix-web](https://img.shields.io/badge/Actix--web-4-green?style=flat)](https://actix.rs/)
[![AES-256-GCM](https://img.shields.io/badge/AES--256--GCM-Encrypted-blue?style=flat)](https://docs.rs/aes-gcm)
[![GitHub](https://img.shields.io/badge/GitHub-Alterion--Software-181717?style=flat&logo=github&logoColor=white)](https://github.com/Alterion-Software)

_A full end-to-end encryption pipeline for Actix-web — RSA key rotation, AES-256-GCM session encryption, Argon2id password hashing, and a MessagePack + Deflate request/response pipeline, all behind a single middleware._

---

</div>

## What it does

Each request from the client is packaged as a `WrappedPacket`:

```
Client → [AES-256-GCM encrypted body] + [RSA-OAEP-SHA256 encrypted AES key] + [key_id]
```

The `Interceptor` middleware:

1. **Decrypts the request** — RSA-unwraps the AES key using the active key-store entry, then AES-decrypts the payload. The raw bytes are injected into request extensions as `DecryptedBody` for your handlers to read.
2. **Encrypts the response** — Takes the JSON response body and pipes it through: `Deflate → MessagePack → AES-256-GCM → HMAC-SHA256`, returning a signed `SignedResponse` packet.

The RSA key pair rotates automatically on a configurable interval with a grace window so in-flight requests using the previous key still succeed.

---

## Crate layout

```
alterion_enc_pipeline
├── keystore       RSA-2048 key store with timed rotation and grace-window overlap
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
alterion-enc-pipeline = "0.1"
```

### 2. Initialise the key store and mount the interceptor

```rust
use alterion_enc_pipeline::{
    interceptor::Interceptor,
    keystore::{init_key_store, start_rotation},
};
use actix_web::{web, App, HttpServer};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Rotate RSA keys every hour; keep the previous key live for 5 minutes (grace window).
    let store = init_key_store(3600);
    start_rotation(store.clone(), 3600);

    HttpServer::new(move || {
        App::new()
            .wrap(Interceptor { key_store: store.clone() })
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
use alterion_enc_pipeline::interceptor::DecryptedBody;

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
use alterion_enc_pipeline::keystore::{KeyStore, get_current_public_key};
use std::sync::Arc;
use tokio::sync::RwLock;

#[get("/api/pubkey")]
async fn public_key_handler(
    store: web::Data<Arc<RwLock<KeyStore>>>,
) -> HttpResponse {
    let (key_id, pem) = get_current_public_key(&store).await;
    HttpResponse::Ok().json(serde_json::json!({ "key_id": key_id, "public_key": pem }))
}
```

---

## Key store

| Function | Description |
|---|---|
| `init_key_store(interval_secs)` | Generates the initial RSA-2048 key pair and wraps it in an `Arc<RwLock<KeyStore>>` |
| `start_rotation(store, interval_secs)` | Spawns a background task that rotates the key every `interval_secs` seconds |
| `get_current_public_key(store)` | Returns `(key_id, pem)` for the active key |
| `decrypt(store, key_id, cdata)` | RSA-OAEP-SHA256 decrypts `cdata`, falling back to the previous key within its grace window |

The grace window is fixed at **300 seconds**. The previous key remains valid for 5 minutes after rotation so any request encrypted just before a rotation still decrypts successfully.

> **Frontend note:** Pre-fetch a new public key at `rotation_interval − 300` seconds so the cached key is never stale when a rotation occurs.

---

## Tools

### `tools::crypt`

```rust
use alterion_enc_pipeline::tools::crypt;

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
use alterion_enc_pipeline::tools::serializer;

// Build an AES+HMAC signed response from any Serialize type
let bytes = serializer::build_signed_response(&my_struct, &aes_key)?;

// Decode an incoming request payload (msgpack → deflate → JSON)
let payload: MyStruct = serializer::decode_request_payload(&decrypted_bytes)?;
```

### `tools::helper`

```rust
use alterion_enc_pipeline::tools::helper::{sha2, hmac, pstore};

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

## Response pipeline

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
  AES-256-GCM encrypt  (nonce prepended)
        │
        ▼
  HMAC-SHA256 sign  (over the ciphertext)
        │
        ▼
  SignedResponse { payload: ByteBuf, hmac: ByteBuf }
        │
        ▼
  MessagePack encode  ──→  sent to client
```

The client verifies the HMAC before decrypting. If verification fails the response must be discarded.

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
