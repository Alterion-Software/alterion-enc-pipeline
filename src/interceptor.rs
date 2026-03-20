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
use alterion_rsa_key_manager::{KeyStore, decrypt as rsa_decrypt};
use crate::tools::crypt::aes_decrypt;
use crate::tools::serializer::{deserialize_packet, build_signed_response_raw};

/// Injected into request extensions after successful decryption of an encrypted request body.
#[derive(Clone)]
pub struct DecryptedBody(pub Vec<u8>);

/// Injected alongside `DecryptedBody`; carries the per-request AES key so the response
/// can be encrypted with the same key the client used.
#[derive(Clone)]
pub struct RequestAesKey(pub [u8; 32]);

/// Actix-web middleware that transparently decrypts incoming request bodies and encrypts outgoing
/// response bodies using the RSA + AES-256-GCM + HMAC-SHA256 pipeline.
///
/// # Usage
/// ```rust,no_run
/// use alterion_enc_pipeline::interceptor::Interceptor;
/// use alterion_enc_pipeline::keystore::init_key_store;
///
/// let store = init_key_store(3600);
/// // App::new().wrap(Interceptor { key_store: store })
/// ```
///
/// **Request path** (POST / PUT / PATCH):
/// 1. Collect raw body bytes.
/// 2. MessagePack-decode a `WrappedPacket`.
/// 3. RSA-OAEP-SHA256-decrypt the wrapped AES key via the active `KeyStore` entry.
/// 4. AES-256-GCM-decrypt the payload.
/// 5. Inject `DecryptedBody` and `RequestAesKey` into request extensions.
///
/// Requests whose body is not a valid `WrappedPacket` are passed through unchanged.
///
/// **Response path** (only when `RequestAesKey` was set):
/// Deflate-compress → msgpack → AES-256-GCM → HMAC-SHA256 → msgpack the response body.
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
                    .try_next()
                    .await
                    .map_err(actix_web::error::ErrorBadRequest)?
                {
                    raw.extend_from_slice(&chunk);
                }

                if !raw.is_empty() {
                    match deserialize_packet(&raw) {
                        Ok(packet) => {
                            let aes_key_bytes = rsa_decrypt(
                                &key_store, &packet.key_id, packet.cdata.as_ref(),
                            )
                            .await
                            .map_err(|e| actix_web::error::ErrorUnauthorized(e.to_string()))?;

                            let aes_key: [u8; 32] = aes_key_bytes.as_slice()
                                .try_into()
                                .map_err(|_| actix_web::error::ErrorBadRequest("aes key length"))?;

                            let decrypted = aes_decrypt(packet.data.as_ref(), &aes_key)
                                .map_err(|e| actix_web::error::ErrorBadRequest(e.to_string()))?;

                            req.extensions_mut().insert(DecryptedBody(decrypted));
                            req.extensions_mut().insert(RequestAesKey(aes_key));
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

            let aes_key = req.extensions().get::<RequestAesKey>().cloned();
            let res     = service.call(req).await?;

            let aes_key = match aes_key {
                Some(k) => k.0,
                None    => return Ok(res.map_into_left_body()),
            };

            let (req, res)   = res.into_parts();
            let (head, body) = res.into_parts();

            let body_bytes = actix_web::body::to_bytes(body)
                .await
                .map_err(|_| actix_web::error::ErrorInternalServerError("body collect failed"))?;

            let encrypted = match build_signed_response_raw(&body_bytes, &aes_key) {
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
