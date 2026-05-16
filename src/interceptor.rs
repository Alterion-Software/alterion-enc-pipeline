// SPDX-License-Identifier: GPL-3.0
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    web, Error, HttpMessage,
    body::{BoxBody, EitherBody, MessageBody},
};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use futures_util::TryStreamExt;
use std::{
    collections::HashMap,
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::sync::{Mutex, RwLock};
use alterion_ecdh::{KeyStore, HandshakeStore, ecdh, ecdh_ephemeral};
use redis::aio::ConnectionManager;
use serde_bytes::ByteBuf;
use crate::tools::crypt::aes_decrypt;
use crate::tools::serializer::{
    deserialize_packet, deserialize, decompress,
    build_signed_response_raw, derive_wrap_key,
    MAX_DECOMPRESSED_SIZE,
};
use zeroize::ZeroizeOnDrop;

/// Default maximum raw request body size (1 MiB). Override via [`Interceptor::max_body_bytes`].
pub const DEFAULT_MAX_BODY_BYTES: usize = 1024 * 1024;

/// In-memory replay protection store for environments without Redis.
///
/// Tracks seen `kx` hashes for a configurable TTL and prunes expired entries on each check.
/// Wrap in `Arc` (via [`MemoryReplayStore::new`]) and share across all Actix workers via [`Interceptor`].
pub struct MemoryReplayStore {
    seen: Mutex<HashMap<String, Instant>>,
    ttl:  Duration,
}

impl MemoryReplayStore {
    /// Creates an `Arc`-wrapped store whose entries expire after `ttl`.
    pub fn new(ttl: Duration) -> Arc<Self> {
        Arc::new(Self { seen: Mutex::default(), ttl })
    }

    /// Returns `true` if `key` is new (not seen within `ttl`), inserting it.
    /// Returns `false` on replay. Prunes expired entries on every call.
    pub async fn is_new(&self, key: &str) -> bool {
        let mut map = self.seen.lock().await;
        let now = Instant::now();
        map.retain(|_, inserted_at| now.duration_since(*inserted_at) < self.ttl);
        if map.contains_key(key) {
            return false;
        }
        map.insert(key.to_string(), now);
        true
    }
}

/// Raw decrypted request body, injected into Actix request extensions by [`Interceptor`] after a
/// packet is successfully validated and decrypted.
///
/// Retrieve it inside a handler with:
/// ```rust,ignore
/// let body = req.extensions().get::<DecryptedBody>().cloned();
/// ```
/// `body.0` contains the original plaintext bytes as sent by the client (post-AES-GCM decrypt,
/// before any application-level deserialisation). The bytes are in the same format the client
/// packed them: msgpack-encoded `ByteBuf` wrapping deflate-compressed JSON.
/// Use [`crate::tools::serializer::decode_request_payload`] to complete the decode.
#[derive(Clone)]
pub struct DecryptedBody(pub Vec<u8>);

/// Per-request AES-256 session key, injected alongside [`DecryptedBody`].
///
/// The interceptor stores this so the **response** can be encrypted with the exact same key that
/// the client generated for this request. The client holds the key in memory indexed by request
/// ID and passes it to [`crate::tools::serializer::decode_response_packet`] to decrypt the reply.
///
/// Zeroized on drop — the key material is cleared from memory as soon as the response has been
/// sent and this struct is dropped.
#[derive(Clone, ZeroizeOnDrop)]
pub struct RequestSessionKeys {
    pub enc_key: [u8; 32],
}

/// Actix-web middleware that transparently decrypts incoming request bodies and encrypts outgoing
/// response bodies using the X25519 ECDH + AES-256-GCM + HMAC-SHA256 pipeline.
///
/// # Usage
///
/// Prefer [`Interceptor::new_with_memory_replay`] for new deployments — it enables in-memory
/// replay protection and sensible body/decompression size limits without requiring Redis:
///
/// ```rust,no_run
/// use alterion_encrypt::interceptor::Interceptor;
/// use alterion_encrypt::{init_key_store, init_handshake_store, start_rotation};
///
/// let store = init_key_store(3600);
/// let hs    = init_handshake_store();
/// start_rotation(store.clone(), 3600, hs.clone());
/// // App::new().wrap(Interceptor::new_with_memory_replay(store, hs))
/// ```
///
/// To tune size limits or add Redis replay protection after construction:
/// ```rust,no_run
/// # use alterion_encrypt::interceptor::Interceptor;
/// # use alterion_encrypt::{init_key_store, init_handshake_store};
/// # let store = init_key_store(3600);
/// # let hs    = init_handshake_store();
/// let mut interceptor = Interceptor::new_with_memory_replay(store, hs);
/// interceptor.max_body_bytes        = 5 * 1024 * 1024;  // 5 MiB raw body
/// interceptor.max_decompressed_bytes = 50 * 1024 * 1024; // 50 MiB decompressed
/// // interceptor.replay_store = Some(redis_connection_manager);
/// ```
///
/// **Request path** (POST / PUT / PATCH, and GET when `allow_encrypted_get` is `true`):
/// 1. Collect raw body bytes up to `max_body_bytes` — reject 413 if exceeded.
/// 2. MessagePack-decode a [`Request`](crate::tools::serializer::Request) and validate timestamp.
/// 3. Check the replay store (Redis → in-memory fallback). Fails closed on store error.
/// 4. ECDH → wrap key → AES-GCM unwrap `enc_key` → AES-256-GCM decrypt payload.
/// 5. Preflight decompress against `max_decompressed_bytes` — reject 413 if exceeded.
/// 6. Inject `DecryptedBody` and `RequestSessionKeys` into request extensions.
///
/// Requests whose body is not a valid encrypted `Request` are passed through unchanged.
///
/// **Response path** (only when `RequestSessionKeys` is present):
/// JSON → deflate → msgpack → AES-256-GCM → HMAC-SHA256 → [`Response`](crate::tools::serializer::Response) → msgpack.
pub struct Interceptor {
    pub key_store:             Arc<RwLock<KeyStore>>,
    pub handshake_store:       HandshakeStore,
    /// Redis-backed replay store. Takes precedence over `memory_replay_store` when `Some`.
    pub replay_store:          Option<ConnectionManager>,
    /// In-memory replay store used when `replay_store` is `None`.
    /// Initialized automatically by [`Interceptor::new_with_memory_replay`].
    pub memory_replay_store:   Option<Arc<MemoryReplayStore>>,
    /// Maximum raw (compressed + encrypted) request body in bytes. Requests exceeding this are
    /// rejected with 413 before any decryption occurs. Default: [`DEFAULT_MAX_BODY_BYTES`] (1 MiB).
    pub max_body_bytes:        usize,
    /// Maximum decompressed payload size in bytes. Requests whose payload would expand beyond this
    /// are rejected with 413 after decryption but before the handler sees the body. Set this to
    /// whatever your largest valid request body is — there is no upper bound imposed by the library.
    /// Default: [`MAX_DECOMPRESSED_SIZE`] (10 MiB).
    pub max_decompressed_bytes: usize,
    /// When `true`, GET requests that carry a body are processed through the full encrypt/decrypt
    /// pipeline identically to POST/PUT/PATCH. The client sends the msgpack-encoded [`Request`]
    /// as the GET body using the same `buildRequestPacket` function. Default: `false`.
    pub allow_encrypted_get:   bool,
}

impl Interceptor {
    /// Creates an `Interceptor` with in-memory replay protection and default size limits
    /// (1 MiB raw body, 10 MiB decompressed).
    ///
    /// This is the recommended constructor for new deployments. Tune `max_body_bytes` and
    /// `max_decompressed_bytes` on the returned value for your workload, or assign `replay_store`
    /// to upgrade to Redis-backed replay detection for multi-instance deployments.
    pub fn new_with_memory_replay(
        key_store:       Arc<RwLock<KeyStore>>,
        handshake_store: HandshakeStore,
    ) -> Self {
        Self {
            key_store,
            handshake_store,
            replay_store:           None,
            memory_replay_store:    Some(MemoryReplayStore::new(Duration::from_secs(90))),
            max_body_bytes:         DEFAULT_MAX_BODY_BYTES,
            max_decompressed_bytes: MAX_DECOMPRESSED_SIZE,
            allow_encrypted_get:    false,
        }
    }
}

impl<S, B> Transform<S, ServiceRequest> for Interceptor
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response  = ServiceResponse<EitherBody<B>>;
    type Error     = Error;
    type Transform = InterceptorService<S>;
    type InitError = ();
    type Future    = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        if self.replay_store.is_none() && self.memory_replay_store.is_none() {
            tracing::warn!(
                "alterion-encrypt: no replay_store configured — replay attacks are possible \
                 within the 30-second timestamp window. Use Interceptor::new_with_memory_replay() \
                 or configure a Redis ConnectionManager for production deployments."
            );
        }
        ready(Ok(InterceptorService {
            service:               Rc::new(service),
            key_store:             self.key_store.clone(),
            handshake_store:       self.handshake_store.clone(),
            replay_store:          self.replay_store.clone(),
            memory_replay_store:   self.memory_replay_store.clone(),
            max_body_bytes:        self.max_body_bytes,
            max_decompressed_bytes: self.max_decompressed_bytes,
            allow_encrypted_get:   self.allow_encrypted_get,
        }))
    }
}

/// The concrete [`Service`](actix_web::dev::Service) produced by [`Interceptor::new_transform`].
///
/// One instance is created per worker thread. Holds `Rc`-wrapped references to the inner service
/// and `Arc`-shared references to the key/handshake/replay stores. Not constructed directly —
/// Actix creates it automatically when the middleware is mounted.
pub struct InterceptorService<S> {
    service:               Rc<S>,
    key_store:             Arc<RwLock<KeyStore>>,
    handshake_store:       HandshakeStore,
    replay_store:          Option<ConnectionManager>,
    memory_replay_store:   Option<Arc<MemoryReplayStore>>,
    max_body_bytes:        usize,
    max_decompressed_bytes: usize,
    allow_encrypted_get:   bool,
}

impl<S, B> Service<ServiceRequest> for InterceptorService<S>
where
    S: Service<ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    B: MessageBody + 'static,
{
    type Response = ServiceResponse<EitherBody<B>>;
    type Error    = Error;
    type Future   = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    forward_ready!(service);

    fn call(&self, mut req: ServiceRequest) -> Self::Future {
        let service               = self.service.clone();
        let key_store             = self.key_store.clone();
        let handshake_store       = self.handshake_store.clone();
        let replay_store          = self.replay_store.clone();
        let memory_replay_store   = self.memory_replay_store.clone();
        let max_body_bytes        = self.max_body_bytes;
        let max_decompressed_bytes = self.max_decompressed_bytes;
        let allow_encrypted_get   = self.allow_encrypted_get;

        Box::pin(async move {
            let method = req.method().as_str();
            let has_body = match method {
                "HEAD" | "OPTIONS" => false,
                "GET"              => allow_encrypted_get,
                _                  => true,
            };

            if has_body {
                let mut payload = req.take_payload();
                let mut raw = web::BytesMut::new();
                while let Some(chunk) = payload
                    .try_next().await
                    .map_err(actix_web::error::ErrorBadRequest)?
                {
                    raw.extend_from_slice(&chunk);
                    if raw.len() > max_body_bytes {
                        return Err(actix_web::error::ErrorPayloadTooLarge(
                            "request body exceeds maximum allowed size",
                        ));
                    }
                }

                if !raw.is_empty() {
                    match deserialize_packet(&raw) {
                        Ok(packet) => {
                            let client_pk_bytes: [u8; 32] = packet.client_pk.as_ref()
                                .try_into()
                                .map_err(|_| actix_web::error::ErrorBadRequest("client_pk must be 32 bytes"))?;

                            let (shared_secret, server_pk) =
                                if packet.key_id.starts_with("hs_") {
                                    ecdh_ephemeral(&handshake_store, &packet.key_id, &client_pk_bytes)
                                        .await
                                        .map_err(|e| actix_web::error::ErrorUnauthorized(e.to_string()))?
                                } else {
                                    ecdh(&key_store, &packet.key_id, &client_pk_bytes)
                                        .await
                                        .map_err(|e| actix_web::error::ErrorUnauthorized(e.to_string()))?
                                };

                            let shared_bytes: &[u8; 32] = shared_secret.as_ref()
                                .try_into()
                                .map_err(|_| actix_web::error::ErrorInternalServerError("shared secret length invalid"))?;
                            let wrap_key = derive_wrap_key(shared_bytes, &client_pk_bytes, &server_pk);

                            let enc_key_bytes = aes_decrypt(packet.kx.as_ref(), &wrap_key)
                                .map_err(|e| actix_web::error::ErrorUnauthorized(e.to_string()))?;
                            let enc_key: [u8; 32] = enc_key_bytes.as_slice()
                                .try_into()
                                .map_err(|_| actix_web::error::ErrorBadRequest("enc_key must be 32 bytes"))?;

                            let seen_key = format!("replay:seen:{}", hex::encode(packet.kx.as_ref()));
                            if let Some(mut redis) = replay_store {
                                let is_new: bool = redis::cmd("SET")
                                    .arg(&seen_key).arg(1u8)
                                    .arg("NX").arg("EX").arg(60u64)
                                    .query_async::<Option<String>>(&mut redis)
                                    .await
                                    .map_err(|e| {
                                        tracing::error!("replay store unavailable: {e}");
                                        actix_web::error::ErrorInternalServerError("replay store unavailable")
                                    })?
                                    .is_some();
                                if !is_new {
                                    return Err(actix_web::error::ErrorUnauthorized("replay detected"));
                                }
                            } else if let Some(mem) = &memory_replay_store {
                                if !mem.is_new(&seen_key).await {
                                    return Err(actix_web::error::ErrorUnauthorized("replay detected"));
                                }
                            }

                            let decrypted = aes_decrypt(packet.data.as_ref(), &enc_key)
                                .map_err(|e| actix_web::error::ErrorBadRequest(e.to_string()))?;

                            let compressed: ByteBuf = deserialize(&decrypted)
                                .map_err(|_| actix_web::error::ErrorBadRequest("payload msgpack decode failed"))?;
                            decompress(&compressed, max_decompressed_bytes)
                                .map_err(|_| actix_web::error::ErrorPayloadTooLarge("decompressed payload exceeds limit"))?;

                            req.extensions_mut().insert(DecryptedBody(decrypted));
                            req.extensions_mut().insert(RequestSessionKeys { enc_key });
                        }
                        Err(_) => {
                            let frozen: actix_web::web::Bytes = raw.freeze();
                            let (_, mut pl) = actix_http::h1::Payload::create(true);
                            pl.unread_data(frozen);
                            req.set_payload(actix_web::dev::Payload::from(pl));
                        }
                    }
                }
            }

            let session_keys = req.extensions().get::<RequestSessionKeys>().cloned();
            let res          = service.call(req).await?;

            let session_keys = match session_keys {
                Some(k) => k,
                None    => return Ok(res.map_into_left_body()),
            };

            let (req, res)   = res.into_parts();
            let (head, body) = res.into_parts();

            let body_bytes = actix_web::body::to_bytes(body)
                .await
                .map_err(|_| actix_web::error::ErrorInternalServerError("body collect failed"))?;

            let encrypted = match build_signed_response_raw(&body_bytes, &session_keys.enc_key) {
                Ok(b)  => b,
                Err(_) => return Ok(ServiceResponse::new(
                    req,
                    head.set_body(BoxBody::new(body_bytes)).map_into_right_body(),
                )),
            };

            Ok(ServiceResponse::new(
                req,
                head.set_body(BoxBody::new(encrypted)).map_into_right_body(),
            ))
        })
    }
}
