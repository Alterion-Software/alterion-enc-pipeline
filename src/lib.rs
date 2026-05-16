// SPDX-License-Identifier: GPL-3.0
//! # alterion-encrypt
//!
//! End-to-end encrypted request/response pipeline for Actix-web services.
//!
//! ## Architecture
//!
//! The library is built in three layers:
//!
//! | Layer | Crate path | Responsibility |
//! |-------|-----------|----------------|
//! | Key management | `alterion-ecdh` (re-exported) | Rotating X25519 key store, ephemeral handshakes |
//! | Crypto primitives | `tools::crypt` | AES-256-GCM encrypt/decrypt, Argon2id password hashing, pepper store |
//! | Wire format | `tools::serializer` | JSON → deflate → msgpack → AES-GCM → ECDH wrap → [`Request`](tools::serializer::Request) |
//! | Middleware | `interceptor` | Actix-web [`Transform`](actix_web::dev::Transform) that applies the pipeline transparently |
//!
//! ## Security properties
//!
//! - **Forward secrecy** — each request uses a fresh ephemeral X25519 keypair; compromise of the
//!   server's long-term key does not expose past traffic.
//! - **Payload confidentiality** — AES-256-GCM with a randomly-generated per-request key; the key
//!   itself is wrapped with the ECDH-derived wrap key so only the server can recover it.
//! - **Response integrity** — HMAC-SHA256 over the ciphertext, keyed with a key domain-separated
//!   from the encryption key via HKDF-SHA256 (`"alterion-response-mac"` label).
//! - **Replay protection** — each packet carries a Unix timestamp validated within ±30 seconds; an
//!   optional Redis store (`replay_store`) rejects duplicate `wrapped_key` values.
//! - **Password security** — Argon2id (65 536 KiB, 3 passes, 4 lanes) with a randomly-generated
//!   pepper stored in the OS keyring and rotatable without invalidating existing hashes.
//!
//! ## Typical server setup
//!
//! The primary entry point is [`interceptor::Interceptor`]: mount it as an Actix-web middleware
//! and every encrypted request is transparently decrypted, and every response re-encrypted,
//! using the X25519 ECDH + AES-256-GCM + HMAC-SHA256 pipeline.
//!
//! ## Example
//!
//! ```rust,no_run
//! use alterion_encrypt::{init_key_store, init_handshake_store, start_rotation};
//! use alterion_encrypt::interceptor::{Interceptor, DecryptedBody};
//! use actix_web::{web, App, HttpServer, HttpRequest, HttpMessage, HttpResponse, post, get};
//!
//! #[post("/api/example")]
//! async fn example_handler(req: HttpRequest) -> HttpResponse {
//!     let body = match req.extensions().get::<DecryptedBody>().cloned() {
//!         Some(b) => b,
//!         None    => return HttpResponse::BadRequest().body("missing encrypted body"),
//!     };
//!     // body.0 is the raw decrypted bytes — deserialise however you like
//!     HttpResponse::Ok().json(serde_json::json!({ "ok": true }))
//! }
//!
//! #[actix_web::main]
//! async fn main() -> std::io::Result<()> {
//!     // Rotate ECDH keys every hour; keep the previous key live for 5 minutes.
//!     let store = init_key_store(3600);
//!     let hs    = init_handshake_store();
//!     start_rotation(store.clone(), 3600, hs.clone());
//!
//!     HttpServer::new(move || {
//!         App::new()
//!             .wrap(Interceptor::new_with_memory_replay(store.clone(), hs.clone()))
//!             .service(example_handler)
//!     })
//!     .bind("0.0.0.0:8080")?
//!     .run()
//!     .await
//! }
//! ```

pub mod interceptor;
pub mod tools;

pub use alterion_ecdh::{
    KeyStore, KeyEntry, EcdhError, HandshakeStore,
    init_key_store, init_handshake_store,
    start_rotation, get_current_public_key,
    ecdh, init_handshake, ecdh_ephemeral, prune_handshakes,
};
