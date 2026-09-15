//! The RFC 9421 request-signing profile airdress operators use.
//!
//! One implementation, so a signer and the verifier it is checked against
//! cannot drift apart. The functions host signs a function's outbound
//! requests with it under the `airdress-webhook` tag (SPEC-095 FR-42–FR-44);
//! an enrolled machine signs its API requests with it under the
//! `airdress-machine` tag (FR-61).
//!
//! The profile (design §7.1):
//!
//! - covered components `@method`, `@target-uri`, `content-digest`
//!   (RFC 9530, `sha-256`), plus `content-type` and `authorization` when the
//!   request carries them;
//! - parameters `created`, `expires` (`created` + the lifetime), a 128-bit
//!   random `nonce`, `keyid`, `alg="ed25519"` and the tag;
//! - label [`LABEL`] — a receiver selects by tag, never by label.
//!
//! A caller-set `Signature`, `Signature-Input` or `Content-Digest` is removed
//! and replaced, never trusted.

#![forbid(unsafe_code)]

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Uri};
use httpsig_hyper::MessageSignatureReq as _;
use httpsig_hyper::prelude::message_component::HttpMessageComponentId;
use httpsig_hyper::prelude::{AlgorithmName, HttpSignatureParams, SecretKey};
use sha2::{Digest as _, Sha256};

/// The tag an operator-to-operator webhook signature carries.
pub const WEBHOOK_TAG: &str = "airdress-webhook";

/// The tag an enrolled machine's API request signature carries.
pub const MACHINE_TAG: &str = "airdress-machine";

/// The signature label. Receivers never rely on it.
pub const LABEL: &str = "sig1";

/// Headers the signer owns on a signed request.
const SIGNER_OWNED: [&str; 3] = ["signature", "signature-input", "content-digest"];

/// Who signs, and under which tag.
#[derive(Debug, Clone, Copy)]
pub struct Profile<'a> {
    /// The `tag` parameter: what kind of request this is.
    pub tag: &'a str,
    /// The `keyid` parameter the receiver looks the key up by.
    pub keyid: &'a str,
    /// `expires` is `created` plus this.
    pub lifetime: Duration,
}

/// Why a request could not be signed.
#[derive(Debug, thiserror::Error)]
pub enum SignRequestError {
    #[error("target `{0}` is not absolute")]
    RelativeTarget(String),
    #[error("{0}")]
    Signer(String),
}

/// An Ed25519 signing key from its 32-byte seed.
///
/// # Errors
/// [`SignRequestError::Signer`] if the seed is refused.
pub fn secret_key(seed: &[u8; 32]) -> Result<SecretKey, SignRequestError> {
    SecretKey::from_bytes(&AlgorithmName::Ed25519, seed)
        .map_err(|e| SignRequestError::Signer(e.to_string()))
}

/// The `Content-Digest` value for `body`: `sha-256=:<base64>:`.
#[must_use]
pub fn content_digest(body: &[u8]) -> String {
    format!("sha-256=:{}:", STANDARD.encode(Sha256::digest(body)))
}

/// Sign a request that is otherwise finished: replace any signer-owned
/// header, set `Content-Digest` over `body`, and add `Signature-Input` and
/// `Signature` over the profile.
///
/// `target` must be the absolute URI the request is sent to. The body cap is
/// the caller's: this signs whatever it is given.
///
/// # Errors
/// [`SignRequestError::RelativeTarget`], or [`SignRequestError::Signer`] for
/// a header the signer cannot serialize.
pub async fn sign_request(
    key: &SecretKey,
    profile: &Profile<'_>,
    method: &Method,
    target: &Uri,
    headers: &mut HeaderMap,
    body: &[u8],
    now: SystemTime,
) -> Result<(), SignRequestError> {
    let signer = |e: &dyn std::fmt::Display| SignRequestError::Signer(e.to_string());
    if target.scheme().is_none() || target.authority().is_none() {
        return Err(SignRequestError::RelativeTarget(target.to_string()));
    }
    for name in SIGNER_OWNED {
        headers.remove(name);
    }
    headers.insert(
        HeaderName::from_static("content-digest"),
        HeaderValue::from_str(&content_digest(body)).map_err(|e| signer(&e))?,
    );

    let mut components = vec!["@method", "@target-uri", "content-digest"];
    if headers.contains_key(http::header::CONTENT_TYPE) {
        components.push("content-type");
    }
    if headers.contains_key(http::header::AUTHORIZATION) {
        components.push("authorization");
    }
    let ids = components
        .iter()
        .map(|c| HttpMessageComponentId::try_from(*c))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| signer(&e))?;
    let mut params = HttpSignatureParams::try_new(&ids).map_err(|e| signer(&e))?;
    let created = now.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let nonce: [u8; 16] = rand::random();
    params
        .set_created(created)
        .set_expires(created + profile.lifetime.as_secs())
        .set_nonce(&URL_SAFE_NO_PAD.encode(nonce))
        .set_keyid(profile.keyid)
        .set_alg(&AlgorithmName::Ed25519)
        .set_tag(profile.tag);

    let mut req = http::Request::builder()
        .method(method.clone())
        .uri(target.clone())
        .body(http_body_util::Empty::<bytes::Bytes>::new())
        .map_err(|e| signer(&e))?;
    req.headers_mut().clone_from(headers);
    req.set_message_signature(&params, key, Some(LABEL))
        .await
        .map_err(|e| signer(&e))?;
    for name in ["signature-input", "signature"] {
        let value = req
            .headers()
            .get(name)
            .cloned()
            .ok_or_else(|| SignRequestError::Signer(format!("the signer set no `{name}`")))?;
        headers.insert(HeaderName::from_static(name), value);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use httpsig_hyper::prelude::PublicKey;

    use super::*;

    const SEED: [u8; 32] = [7u8; 32];

    fn public() -> PublicKey {
        let secret = secret_key(&SEED).unwrap();
        secret.public_key()
    }

    #[tokio::test]
    async fn the_tag_and_keyid_are_the_callers_and_the_request_verifies() {
        let key = secret_key(&SEED).unwrap();
        let target: Uri = "https://op.example/v1/kinds/Pool/a".parse().unwrap();
        let mut headers = HeaderMap::new();
        let now = UNIX_EPOCH + Duration::from_hours(500_000);
        let profile = Profile {
            tag: MACHINE_TAG,
            keyid: "machine:00000000-0000-0000-0000-000000000001#k-0011223344556677",
            lifetime: Duration::from_mins(1),
        };
        sign_request(
            &key,
            &profile,
            &Method::GET,
            &target,
            &mut headers,
            b"",
            now,
        )
        .await
        .unwrap();
        let input = headers["signature-input"].to_str().unwrap().to_owned();
        assert!(
            input.starts_with("sig1=(\"@method\" \"@target-uri\" \"content-digest\");"),
            "{input}"
        );
        assert!(input.contains(";tag=\"airdress-machine\""), "{input}");
        assert!(input.contains(";expires=1800000060"), "{input}");
        assert!(input.contains(";keyid=\"machine:"), "{input}");
        assert_eq!(headers["content-digest"], content_digest(b""));

        let mut req = http::Request::builder()
            .method(Method::GET)
            .uri(target)
            .body(http_body_util::Empty::<bytes::Bytes>::new())
            .unwrap();
        req.headers_mut().clone_from(&headers);
        assert!(
            req.verify_message_signature(&public(), Some(profile.keyid))
                .await
                .is_ok()
        );
    }

    #[tokio::test]
    async fn a_relative_target_is_refused() {
        let key = secret_key(&SEED).unwrap();
        let profile = Profile {
            tag: WEBHOOK_TAG,
            keyid: "k",
            lifetime: Duration::from_mins(1),
        };
        let err = sign_request(
            &key,
            &profile,
            &Method::POST,
            &"/x".parse().unwrap(),
            &mut HeaderMap::new(),
            b"",
            SystemTime::now(),
        )
        .await
        .unwrap_err();
        assert!(matches!(err, SignRequestError::RelativeTarget(_)));
    }
}
