// SPDX-License-Identifier: GPL-3.0
use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    web, Error, HttpMessage,
    body::{BoxBody, EitherBody, MessageBody},
};
use futures_util::future::{ready, LocalBoxFuture, Ready};
use futures_util::TryStreamExt;
use std::{rc::Rc, sync::Arc};
use tokio::sync::RwLock;
use alterion_ecdh::{KeyStore, ecdh};
use crate::tools::crypt::aes_decrypt;
use crate::tools::serializer::{deserialize_packet, build_signed_response_raw, derive_session_keys, verify_packet_mac};

/// Injected into request extensions after successful decryption of an encrypted request body.
#[derive(Clone)]
pub struct DecryptedBody(pub Vec<u8>);

/// Injected alongside `DecryptedBody`; carries the derived per-request session keys so the
/// response can be encrypted with the same keys the client derived.
#[derive(Clone)]
pub struct RequestSessionKeys {
    pub enc_key: [u8; 32],
    pub mac_key: [u8; 32],
}

/// Actix-web middleware that transparently decrypts incoming request bodies and encrypts outgoing
/// response bodies using the X25519 ECDH + AES-256-GCM + HMAC-SHA256 pipeline.
///
/// # Usage
/// ```rust,no_run
/// use alterion_enc_pipeline::interceptor::Interceptor;
/// use alterion_key_exchange::init_key_store;
///
/// let store = init_key_store(3600);
/// // App::new().wrap(Interceptor { key_store: store })
/// ```
///
/// **Request path** (POST / PUT / PATCH):
/// 1. Collect raw body bytes.
/// 2. MessagePack-decode a `WrappedPacket` and validate timestamp.
/// 3. Perform X25519 ECDH using the server key identified by `key_id` and the client's ephemeral
///    public key from the packet.
/// 4. Derive `enc_key` and `mac_key` via HKDF-SHA256 bound to both public keys.
/// 5. Verify the packet MAC over `key_id || ts || client_pk || data`.
/// 6. AES-256-GCM-decrypt the payload using `enc_key`.
/// 7. Inject `DecryptedBody` and `RequestSessionKeys` into request extensions.
///
/// Requests whose body is not a valid `WrappedPacket` are passed through unchanged.
///
/// **Response path** (only when `RequestSessionKeys` was set):
/// Deflate-compress → msgpack → AES-256-GCM (enc_key) → HMAC-SHA256 (mac_key) → msgpack.
pub struct Interceptor {
    pub key_store: Arc<RwLock<KeyStore>>,
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
        ready(Ok(InterceptorService {
            service:   Rc::new(service),
            key_store: self.key_store.clone(),
        }))
    }
}

pub struct InterceptorService<S> {
    service:   Rc<S>,
    key_store: Arc<RwLock<KeyStore>>,
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
        let service   = self.service.clone();
        let key_store = self.key_store.clone();

        Box::pin(async move {
            let has_body = !matches!(req.method().as_str(), "GET" | "HEAD" | "OPTIONS");

            if has_body {
                let mut payload = req.take_payload();
                let mut raw = web::BytesMut::new();
                while let Some(chunk) = payload
                    .try_next().await
                    .map_err(actix_web::error::ErrorBadRequest)?
                {
                    raw.extend_from_slice(&chunk);
                }

                if !raw.is_empty() {
                    match deserialize_packet(&raw) {
                        Ok(packet) => {
                            let client_pk_bytes: [u8; 32] = packet.client_pk.as_ref()
                                .try_into()
                                .map_err(|_| actix_web::error::ErrorBadRequest("client_pk must be 32 bytes"))?;

                            let (shared_secret, server_pk) = ecdh(
                                &key_store, &packet.key_id, &client_pk_bytes,
                            )
                            .await
                            .map_err(|e| actix_web::error::ErrorUnauthorized(e.to_string()))?;

                            let (enc_key, mac_key) = derive_session_keys(
                                shared_secret.as_ref().try_into().unwrap(),
                                &client_pk_bytes,
                                &server_pk,
                            );

                            if !verify_packet_mac(&mac_key, &packet) {
                                return Err(actix_web::error::ErrorUnauthorized("packet mac invalid"));
                            }

                            let decrypted = aes_decrypt(packet.data.as_ref(), &enc_key)
                                .map_err(|e| actix_web::error::ErrorBadRequest(e.to_string()))?;

                            req.extensions_mut().insert(DecryptedBody(decrypted));
                            req.extensions_mut().insert(RequestSessionKeys { enc_key, mac_key });
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

            let encrypted = match build_signed_response_raw(
                &body_bytes, &session_keys.enc_key, &session_keys.mac_key,
            ) {
                Ok(b)  => b,
                Err(e) => {
                    tracing::error!("response encrypt: {e}");
                    return Ok(ServiceResponse::new(
                        req,
                        head.set_body(BoxBody::new(body_bytes)).map_into_right_body(),
                    ));
                }
            };

            Ok(ServiceResponse::new(
                req,
                head.set_body(BoxBody::new(encrypted)).map_into_right_body(),
            ))
        })
    }
}
