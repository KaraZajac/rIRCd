//! draft/webpush: Web Push delivery.
//!
//! Payloads are encrypted with `aes128gcm` ([RFC 8188]) keyed as described in
//! [RFC 8291], and requests are signed with VAPID ([RFC 8292]) so the push
//! service can attribute them to this server.
//!
//! [RFC 8188]: https://www.rfc-editor.org/rfc/rfc8188
//! [RFC 8291]: https://www.rfc-editor.org/rfc/rfc8291
//! [RFC 8292]: https://www.rfc-editor.org/rfc/rfc8292

use aes_gcm::{aead::Aead, Aes128Gcm, KeyInit, Nonce};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD as B64URL, Engine};
use hkdf::Hkdf;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use sha2::Sha256;
use std::net::IpAddr;
use std::path::Path;

/// Record size advertised in the payload header. One notification is always a
/// single record, so this only has to exceed the plaintext.
const RECORD_SIZE: u32 = 4096;

/// Largest plaintext we will encrypt; push services commonly cap the body at 4 KB.
pub const MAX_PAYLOAD: usize = RECORD_SIZE as usize - 17 - 86;

/// VAPID JWTs are valid for this long. RFC 8292 caps it at 24 hours.
const JWT_LIFETIME_SECS: i64 = 12 * 60 * 60;

// ─── VAPID identity key ───────────────────────────────────────────────────────

/// The server's long-lived VAPID key pair. The public key is handed to clients in
/// the `VAPID` ISUPPORT token and repeated in every `Authorization` header.
pub struct VapidKey {
    secret: SecretKey,
    public_b64: String,
}

impl VapidKey {
    /// Load the key from `path`, generating and storing one if it isn't there yet.
    /// The file holds the base64url-encoded 32-byte private scalar.
    pub fn load_or_create(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            let raw = std::fs::read_to_string(path)?;
            let bytes = B64URL
                .decode(raw.trim())
                .map_err(|e| anyhow::anyhow!("VAPID key file is not base64url: {}", e))?;
            let secret = SecretKey::from_slice(&bytes)
                .map_err(|e| anyhow::anyhow!("VAPID key file is not a P-256 key: {}", e))?;
            return Ok(Self::from_secret(secret));
        }

        let secret = SecretKey::random(&mut rand_core_compat::OsRng);
        let encoded = B64URL.encode(secret.to_bytes());
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(path, &encoded)?;
        restrict_permissions(path);
        tracing::info!("Generated VAPID key at {}", path.display());
        Ok(Self::from_secret(secret))
    }

    fn from_secret(secret: SecretKey) -> Self {
        let public_b64 = B64URL.encode(secret.public_key().to_encoded_point(false).as_bytes());
        Self { secret, public_b64 }
    }

    /// URL-safe base64 of the uncompressed public key, for `VAPID=` and the `k=` parameter.
    pub fn public_b64(&self) -> &str {
        &self.public_b64
    }

    /// Build the `Authorization: vapid t=<jwt>,k=<key>` header for one endpoint.
    pub fn auth_header(&self, endpoint: &str, contact: &str) -> anyhow::Result<String> {
        let audience = endpoint_origin(endpoint)
            .ok_or_else(|| anyhow::anyhow!("push endpoint has no origin: {}", endpoint))?;
        let exp = chrono::Utc::now().timestamp() + JWT_LIFETIME_SECS;

        let header = B64URL.encode(br#"{"typ":"JWT","alg":"ES256"}"#);
        let claims = B64URL
            .encode(serde_json::json!({ "aud": audience, "exp": exp, "sub": contact }).to_string());
        let signing_input = format!("{}.{}", header, claims);

        let signing_key = SigningKey::from(&self.secret);
        let signature: Signature = signing_key.sign(signing_input.as_bytes());

        Ok(format!(
            "vapid t={}.{},k={}",
            signing_input,
            B64URL.encode(signature.to_bytes()),
            self.public_b64
        ))
    }
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) {}

/// `rand` 0.8 (used elsewhere in the crate) and the `rand_core` that p256 expects
/// are different versions, so use the RNG p256 ships with.
mod rand_core_compat {
    pub use p256::elliptic_curve::rand_core::OsRng;
}

impl std::fmt::Debug for VapidKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never print the private scalar.
        f.debug_struct("VapidKey")
            .field("public", &self.public_b64)
            .finish()
    }
}

// ─── Runtime ──────────────────────────────────────────────────────────────────

/// Everything push delivery needs at runtime, built once at startup and shared
/// through `Config::webpush_runtime`.
#[derive(Debug)]
pub struct WebpushRuntime {
    pub key: VapidKey,
    pub http: reqwest::Client,
    pub contact: String,
    pub ttl_secs: u32,
    pub max_subscriptions: usize,
    pub max_failures: u32,
    pub allow_private_endpoints: bool,
}

impl WebpushRuntime {
    /// Load or create the VAPID key and build the HTTP client.
    pub fn new(cfg: &crate::config::WebpushConfig) -> anyhow::Result<Self> {
        let key = VapidKey::load_or_create(Path::new(&cfg.key_file))?;
        let http = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(15))
            .user_agent(concat!("rIRCd/", env!("CARGO_PKG_VERSION")))
            .build()?;
        Ok(Self {
            key,
            http,
            contact: cfg.contact.clone(),
            ttl_secs: cfg.ttl_secs,
            max_subscriptions: cfg.max_subscriptions_per_account,
            max_failures: cfg.max_failures,
            allow_private_endpoints: cfg.allow_private_endpoints,
        })
    }
}

/// Send `msg` to every push endpoint registered by `account`.
///
/// Returns immediately: delivery runs in its own task, because the whole server
/// handles commands in a single loop and a push service can be slow. Endpoints the
/// service reports as gone, or that keep failing, are dropped.
pub fn notify(cfg: &crate::config::Config, account: &str, msg: &crate::protocol::Message) {
    let (Some(runtime), Some(pool)) = (cfg.webpush_runtime.clone(), cfg.db.clone()) else {
        return;
    };

    // One IRC message per notification, without the trailing CRLF.
    let payload = crate::protocol::format_message(msg)
        .trim_end_matches("\r\n")
        .to_string();
    if payload.len() > MAX_PAYLOAD {
        tracing::debug!(account, "Web Push payload too large, skipping");
        return;
    }
    let account = account.to_lowercase();

    tokio::spawn(async move {
        let subs = crate::persist::load_webpush_subscriptions(&pool, &account).await;
        for sub in subs {
            let body = match encrypt(&sub.p256dh, &sub.auth, payload.as_bytes()) {
                Ok(b) => b,
                Err(e) => {
                    tracing::warn!(account, endpoint = %sub.endpoint, "Web Push encrypt failed: {}", e);
                    crate::persist::delete_webpush_subscription(&pool, &sub.endpoint).await;
                    continue;
                }
            };

            match deliver(
                &runtime.http,
                &runtime.key,
                &runtime.contact,
                &sub.endpoint,
                body,
                runtime.ttl_secs,
            )
            .await
            {
                Ok(()) => {
                    crate::persist::reset_webpush_failures(&pool, &sub.endpoint).await;
                    tracing::debug!(account, endpoint = %sub.endpoint, "Web Push delivered");
                }
                Err(PushError::Gone) => {
                    tracing::info!(account, endpoint = %sub.endpoint, "Push endpoint gone, removing subscription");
                    crate::persist::delete_webpush_subscription(&pool, &sub.endpoint).await;
                }
                Err(PushError::Failed(e)) => {
                    let failures =
                        crate::persist::record_webpush_failure(&pool, &sub.endpoint).await;
                    tracing::warn!(
                        account,
                        endpoint = %sub.endpoint,
                        failures,
                        "Web Push delivery failed: {}", e
                    );
                    if failures >= runtime.max_failures {
                        tracing::info!(
                            account,
                            endpoint = %sub.endpoint,
                            "Dropping push subscription after {} failures", failures
                        );
                        crate::persist::delete_webpush_subscription(&pool, &sub.endpoint).await;
                    }
                }
            }
        }
    });
}

// ─── Payload encryption (RFC 8291) ────────────────────────────────────────────

/// Encrypt `plaintext` for one subscription. `ua_public_b64` is the client's
/// `p256dh` key and `auth_b64` its 16-byte `auth` secret, both URL-safe base64.
pub fn encrypt(ua_public_b64: &str, auth_b64: &str, plaintext: &[u8]) -> anyhow::Result<Vec<u8>> {
    let ua_public = decode_b64(ua_public_b64).map_err(|e| anyhow::anyhow!("p256dh: {}", e))?;
    let auth = decode_b64(auth_b64).map_err(|e| anyhow::anyhow!("auth: {}", e))?;
    if auth.len() != 16 {
        anyhow::bail!("auth secret must be 16 bytes, got {}", auth.len());
    }
    if plaintext.len() > MAX_PAYLOAD {
        anyhow::bail!("payload too large: {} > {}", plaintext.len(), MAX_PAYLOAD);
    }

    let as_secret = SecretKey::random(&mut rand_core_compat::OsRng);
    let mut salt = [0u8; 16];
    use rand::RngCore;
    rand::thread_rng().fill_bytes(&mut salt);

    encrypt_with(&as_secret, salt, &ua_public, &auth, plaintext)
}

/// The deterministic half of [`encrypt`], with the ephemeral key and salt supplied
/// so it can be checked against the RFC 8291 test vector.
fn encrypt_with(
    as_secret: &SecretKey,
    salt: [u8; 16],
    ua_public: &[u8],
    auth: &[u8],
    plaintext: &[u8],
) -> anyhow::Result<Vec<u8>> {
    let ua_key = PublicKey::from_sec1_bytes(ua_public)
        .map_err(|e| anyhow::anyhow!("client key is not a P-256 point: {}", e))?;
    let as_public = as_secret.public_key().to_encoded_point(false);
    let as_public = as_public.as_bytes();

    // ECDH, then derive the input keying material the content encryption uses.
    let shared = p256::ecdh::diffie_hellman(as_secret.to_nonzero_scalar(), ua_key.as_affine());

    let mut key_info = Vec::with_capacity(14 + ua_public.len() + as_public.len());
    key_info.extend_from_slice(b"WebPush: info\0");
    key_info.extend_from_slice(ua_public);
    key_info.extend_from_slice(as_public);

    let mut ikm = [0u8; 32];
    Hkdf::<Sha256>::new(Some(auth), shared.raw_secret_bytes())
        .expand(&key_info, &mut ikm)
        .map_err(|e| anyhow::anyhow!("HKDF expand (IKM): {}", e))?;

    // RFC 8188 content encryption keys.
    let prk = Hkdf::<Sha256>::new(Some(&salt), &ikm);
    let mut cek = [0u8; 16];
    prk.expand(b"Content-Encoding: aes128gcm\0", &mut cek)
        .map_err(|e| anyhow::anyhow!("HKDF expand (CEK): {}", e))?;
    let mut nonce = [0u8; 12];
    prk.expand(b"Content-Encoding: nonce\0", &mut nonce)
        .map_err(|e| anyhow::anyhow!("HKDF expand (nonce): {}", e))?;

    // Single record: plaintext followed by the last-record delimiter.
    let mut record = Vec::with_capacity(plaintext.len() + 1);
    record.extend_from_slice(plaintext);
    record.push(0x02);

    let ciphertext = Aes128Gcm::new_from_slice(&cek)
        .map_err(|e| anyhow::anyhow!("AES key: {}", e))?
        .encrypt(Nonce::from_slice(&nonce), record.as_slice())
        .map_err(|e| anyhow::anyhow!("AES-GCM encrypt: {}", e))?;

    // Header: salt | record size | key id length | key id (our public key).
    let mut body = Vec::with_capacity(21 + as_public.len() + ciphertext.len());
    body.extend_from_slice(&salt);
    body.extend_from_slice(&RECORD_SIZE.to_be_bytes());
    body.push(as_public.len() as u8);
    body.extend_from_slice(as_public);
    body.extend_from_slice(&ciphertext);
    Ok(body)
}

/// Check subscription keys before storing them, so a broken client is told at
/// REGISTER time instead of silently never receiving notifications.
pub fn validate_keys(p256dh: &str, auth: &str) -> Result<(), String> {
    let key = decode_b64(p256dh).map_err(|_| "p256dh is not valid base64".to_string())?;
    PublicKey::from_sec1_bytes(&key).map_err(|_| "p256dh is not a P-256 public key".to_string())?;

    let auth = decode_b64(auth).map_err(|_| "auth is not valid base64".to_string())?;
    if auth.len() != 16 {
        return Err(format!("auth must be 16 bytes, got {}", auth.len()));
    }
    Ok(())
}

/// Accept both URL-safe base64 spellings, with or without padding — clients send
/// keys straight from the browser's PushSubscription, which varies.
fn decode_b64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    let trimmed = s.trim_end_matches('=');
    B64URL.decode(trimmed).or_else(|_| {
        base64::engine::general_purpose::STANDARD_NO_PAD.decode(trimmed.replace(['-', '_'], ""))
    })
}

// ─── Endpoint checks ──────────────────────────────────────────────────────────

/// Scheme and origin of a push endpoint, e.g. `https://push.example.com:8443`.
fn endpoint_origin(endpoint: &str) -> Option<String> {
    let url = reqwest::Url::parse(endpoint).ok()?;
    let host = url.host_str()?;
    match url.port() {
        Some(port) => Some(format!("{}://{}:{}", url.scheme(), host, port)),
        None => Some(format!("{}://{}", url.scheme(), host)),
    }
}

/// Why an endpoint was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum EndpointError {
    NotHttps,
    Unparseable,
    /// Resolves to an address the server must not be tricked into probing.
    PrivateAddress,
    /// DNS lookup failed.
    Unresolvable,
}

/// Check an endpoint before it is stored or used. RFC 8030 requires HTTPS, and
/// the draft requires servers to keep clients from aiming pushes at internal
/// hosts. Resolution here and at connect time can differ, so this is a filter
/// against accidents and casual probing, not a guarantee.
pub async fn check_endpoint(endpoint: &str, allow_private: bool) -> Result<(), EndpointError> {
    let url = reqwest::Url::parse(endpoint).map_err(|_| EndpointError::Unparseable)?;
    if url.scheme() != "https" {
        return Err(EndpointError::NotHttps);
    }
    let host = url.host_str().ok_or(EndpointError::Unparseable)?;
    if allow_private {
        return Ok(());
    }

    // An address literal needs no lookup. IPv6 literals arrive bracketed.
    let literal = host.trim_start_matches('[').trim_end_matches(']');
    if let Ok(ip) = literal.parse::<IpAddr>() {
        return if is_internal(ip) {
            Err(EndpointError::PrivateAddress)
        } else {
            Ok(())
        };
    }

    let port = url.port_or_known_default().unwrap_or(443);
    // The client chose the name, so it chose whose name server answers. One
    // that never does would otherwise keep this waiting for as long as the
    // resolver is willing to retry.
    let addrs = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::net::lookup_host((host, port)),
    )
    .await
    .map_err(|_| EndpointError::Unresolvable)?
    .map_err(|_| EndpointError::Unresolvable)?;

    let mut saw_any = false;
    for addr in addrs {
        saw_any = true;
        if is_internal(addr.ip()) {
            return Err(EndpointError::PrivateAddress);
        }
    }
    if saw_any {
        Ok(())
    } else {
        Err(EndpointError::Unresolvable)
    }
}

/// Addresses that must never be reached through a client-supplied endpoint.
fn is_internal(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
                // 100.64.0.0/10 carrier-grade NAT
                || (v4.octets()[0] == 100 && (64..128).contains(&v4.octets()[1]))
                // 192.0.0.0/24 IETF protocol assignments
                || (v4.octets()[0] == 192 && v4.octets()[1] == 0 && v4.octets()[2] == 0)
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fc00::/7 unique local
                || (v6.segments()[0] & 0xfe00) == 0xfc00
                // fe80::/10 link local
                || (v6.segments()[0] & 0xffc0) == 0xfe80
                // IPv4-mapped: judge the embedded address
                || v6.to_ipv4_mapped().is_some_and(|v4| is_internal(IpAddr::V4(v4)))
        }
    }
}

// ─── Delivery ─────────────────────────────────────────────────────────────────

/// What happened when a notification was posted to a push service.
#[derive(Debug)]
pub enum PushError {
    /// The subscription is dead (404/410) and should be dropped.
    Gone,
    /// Anything else: network trouble, 5xx, rate limits.
    Failed(String),
}

/// POST one encrypted notification to a push service.
pub async fn deliver(
    http: &reqwest::Client,
    key: &VapidKey,
    contact: &str,
    endpoint: &str,
    body: Vec<u8>,
    ttl_secs: u32,
) -> Result<(), PushError> {
    let auth = key
        .auth_header(endpoint, contact)
        .map_err(|e| PushError::Failed(e.to_string()))?;

    let response = http
        .post(endpoint)
        .header("Authorization", auth)
        .header("Content-Encoding", "aes128gcm")
        .header("Content-Type", "application/octet-stream")
        .header("TTL", ttl_secs.to_string())
        .header("Urgency", "high")
        .body(body)
        .send()
        .await
        .map_err(|e| PushError::Failed(e.to_string()))?;

    let status = response.status();
    if status.is_success() {
        Ok(())
    } else if status == reqwest::StatusCode::NOT_FOUND || status == reqwest::StatusCode::GONE {
        Err(PushError::Gone)
    } else {
        let detail = response.text().await.unwrap_or_default();
        let detail: String = detail.chars().take(200).collect();
        Err(PushError::Failed(format!("{}: {}", status, detail)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The worked example in RFC 8291 section 5: with its ephemeral key and salt,
    /// the encryption must reproduce the published body byte for byte.
    #[test]
    fn rfc8291_test_vector() {
        let plaintext = b"When I grow up, I want to be a watermelon";
        let ua_public = B64URL.decode(
            "BCVxsr7N_eNgVRqvHtD0zTZsEc6-VV-JvLexhqUzORcxaOzi6-AYWXvTBHm4bjyPjs7Vd8pZGH6SRpkNtoIAiw4"
        ).unwrap();
        let auth = B64URL.decode("BTBZMqHH6r4Tts7J_aSIgg").unwrap();
        let as_private = B64URL
            .decode("yfWPiYE-n46HLnH0KqZOF1fJJU3MYrct3AELtAQ-oRw")
            .unwrap();
        let salt: [u8; 16] = B64URL
            .decode("DGv6ra1nlYgDCS1FRnbzlw")
            .unwrap()
            .try_into()
            .unwrap();

        let as_secret = SecretKey::from_slice(&as_private).unwrap();
        let body = encrypt_with(&as_secret, salt, &ua_public, &auth, plaintext).unwrap();

        assert_eq!(
            B64URL.encode(&body),
            "DGv6ra1nlYgDCS1FRnbzlwAAEABBBP4z9KsN6nGRTbVYI_c7VJSPQTBtkgcy27mlmlMoZIIgDll6e3v\
             CYLocInmYWAmS6TlzAC8wEqKK6PBru3jl7A_yl95bQpu6cVPTpK4Mqgkf1CXztLVBSt2Ks3oZwbuwXPX\
             LWyouBWLVWGNWQexSgSxsj_Qulcy4a-fN"
                .replace(['\n', ' '], "")
        );
    }

    #[test]
    fn encrypt_rejects_bad_keys() {
        let auth = B64URL.encode([7u8; 16]);
        assert!(encrypt("not-base64!!", &auth, b"hi").is_err());

        let valid_key = B64URL.encode(
            SecretKey::random(&mut rand_core_compat::OsRng)
                .public_key()
                .to_encoded_point(false)
                .as_bytes(),
        );
        assert!(encrypt(&valid_key, &B64URL.encode([7u8; 8]), b"hi").is_err());
        assert!(encrypt(&valid_key, &auth, b"hi").is_ok());
    }

    #[test]
    fn vapid_header_carries_a_jwt_for_the_endpoint_origin() {
        let key = VapidKey::from_secret(SecretKey::random(&mut rand_core_compat::OsRng));
        let header = key
            .auth_header(
                "https://push.example.com/push/abc123",
                "mailto:admin@example.org",
            )
            .unwrap();

        let (scheme, rest) = header.split_once(' ').unwrap();
        assert_eq!(scheme, "vapid");
        let (t, k) = rest.split_once(',').unwrap();
        assert_eq!(k, format!("k={}", key.public_b64()));

        let jwt = t.strip_prefix("t=").unwrap();
        let parts: Vec<&str> = jwt.split('.').collect();
        assert_eq!(parts.len(), 3, "header.claims.signature");

        let claims: serde_json::Value =
            serde_json::from_slice(&B64URL.decode(parts[1]).unwrap()).unwrap();
        assert_eq!(claims["aud"], "https://push.example.com");
        assert_eq!(claims["sub"], "mailto:admin@example.org");
        assert!(claims["exp"].as_i64().unwrap() > chrono::Utc::now().timestamp());

        // Signature must verify under the advertised public key.
        use p256::ecdsa::signature::Verifier;
        let verifying = p256::ecdsa::VerifyingKey::from(SigningKey::from(&key.secret));
        let sig = Signature::from_slice(&B64URL.decode(parts[2]).unwrap()).unwrap();
        verifying
            .verify(format!("{}.{}", parts[0], parts[1]).as_bytes(), &sig)
            .expect("signature verifies");
    }

    #[tokio::test]
    async fn endpoints_must_be_https_and_external() {
        assert_eq!(
            check_endpoint("http://push.example.com/x", false).await,
            Err(EndpointError::NotHttps)
        );
        assert_eq!(
            check_endpoint("not a url", false).await,
            Err(EndpointError::Unparseable)
        );
        assert_eq!(
            check_endpoint("https://127.0.0.1/x", false).await,
            Err(EndpointError::PrivateAddress)
        );
        assert_eq!(
            check_endpoint("https://192.168.1.10/x", false).await,
            Err(EndpointError::PrivateAddress)
        );
        assert_eq!(
            check_endpoint("https://[::1]/x", false).await,
            Err(EndpointError::PrivateAddress)
        );
        // The escape hatch exists for testing against a local push service.
        assert_eq!(check_endpoint("https://127.0.0.1/x", true).await, Ok(()));
    }

    #[test]
    fn internal_ranges_are_recognised() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "172.16.0.1",
            "192.168.0.1",
            "169.254.1.1",
            "100.64.0.1",
            "0.0.0.0",
            "::1",
            "fc00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(is_internal(ip.parse().unwrap()), "{ip} should be internal");
        }
        for ip in ["1.1.1.1", "93.184.216.34", "2606:4700::1111"] {
            assert!(!is_internal(ip.parse().unwrap()), "{ip} should be external");
        }
    }
}
