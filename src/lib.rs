// SPDX-License-Identifier: GPL-3.0
//! # alterion-encrypt
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
//!             .wrap(Interceptor { key_store: store.clone(), handshake_store: hs.clone(), replay_store: None })
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
