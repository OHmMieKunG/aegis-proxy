use std::{
    collections::HashMap,
    fmt,
    future::Future,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use aegisproxy_config::{AdminWebOidcConfig, AdminWebOidcGroups};
use aegisproxy_secrets::SecretRef;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper_rustls::{HttpsConnector, HttpsConnectorBuilder};
use hyper_util::{
    client::legacy::{Client as HyperClient, connect::HttpConnector},
    rt::TokioExecutor,
};
use openidconnect::{
    AccessTokenHash, AsyncHttpClient, AuthorizationCode, ClaimsVerificationError, ClientId,
    ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet, EndpointSet, HttpRequest,
    HttpResponse, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, SignatureVerificationError, TokenResponse,
    core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata},
    url::Url,
};
use serde::de::{DeserializeSeed, IgnoredAny, MapAccess, Visitor};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use crate::{ObjectId, Role};

const MAX_ENDPOINT_BYTES: usize = 2_048;
const MAX_HEADERS: usize = 64;
const MAX_DISCOVERY_BYTES: usize = 256 * 1024;
const MAX_TOKEN_BYTES: usize = 64 * 1024;
const MAX_TRANSACTIONS: usize = 1_024;
const TRANSACTION_TTL_SECS: u64 = 10 * 60;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

type OidcClient = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointSet,
    EndpointMaybeSet,
>;
type Client = HyperClient<HttpsConnector<HttpConnector>, Full<Bytes>>;

#[derive(Clone)]
pub(super) struct OidcProvider {
    config: Arc<AdminWebOidcConfig>,
    redirect_uri: String,
    cached: Arc<RwLock<Option<DiscoveredProvider>>>,
    transactions: Arc<LoginTransactions>,
    available: Arc<AtomicBool>,
}

impl fmt::Debug for OidcProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OidcProvider")
            .field("issuer", &self.config.issuer)
            .field("redirect_uri", &self.redirect_uri)
            .field("available", &self.available.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
struct DiscoveredProvider {
    client: OidcClient,
    transport: BoundedOidcTransport,
}

struct LoginTransaction {
    nonce: Nonce,
    pkce_verifier: PkceCodeVerifier,
    return_path: String,
    expires_unix_secs: u64,
}

struct LoginTransactions(Mutex<HashMap<String, LoginTransaction>>);

impl fmt::Debug for LoginTransactions {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoginTransactions")
            .field(
                "entries",
                &self
                    .0
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .len(),
            )
            .finish()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct OidcIdentity {
    pub(super) identity_id: ObjectId,
    pub(super) fingerprint: String,
    pub(super) role: Role,
}

#[derive(Debug)]
pub(super) struct OidcLogin {
    pub(super) authorization_url: String,
}

#[derive(Debug, Error)]
pub(super) enum OidcError {
    #[error("OIDC provider is unavailable")]
    Unavailable,
    #[error("OIDC response is invalid")]
    Invalid,
    #[error("OIDC login capacity is exhausted")]
    Capacity,
}

impl OidcProvider {
    pub(super) fn new(
        config: AdminWebOidcConfig,
        origin: &str,
        available: Arc<AtomicBool>,
    ) -> Self {
        Self {
            config: Arc::new(config),
            redirect_uri: format!("{origin}/v1/auth/callback"),
            cached: Arc::new(RwLock::new(None)),
            transactions: Arc::new(LoginTransactions(Mutex::new(HashMap::new()))),
            available,
        }
    }

    pub(super) fn available(&self) -> bool {
        self.available.load(Ordering::Acquire)
    }

    pub(super) fn mark_unavailable(&self) {
        self.available.store(false, Ordering::Release);
    }

    pub(super) async fn warm(&self) {
        let _ = self.discovered(false).await;
    }

    pub(super) async fn login(
        &self,
        return_path: String,
        now_unix_secs: u64,
    ) -> Result<OidcLogin, OidcError> {
        let provider = self.discovered(false).await?;
        let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
        let (authorization_url, state, nonce) = provider
            .client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(pkce_challenge)
            .url();
        self.transactions.insert(
            state.secret().to_owned(),
            LoginTransaction {
                nonce,
                pkce_verifier,
                return_path,
                expires_unix_secs: now_unix_secs
                    .checked_add(TRANSACTION_TTL_SECS)
                    .ok_or(OidcError::Invalid)?,
            },
            now_unix_secs,
        )?;
        Ok(OidcLogin {
            authorization_url: authorization_url.to_string(),
        })
    }

    pub(super) async fn callback(
        &self,
        code: String,
        state: &str,
        now_unix_secs: u64,
    ) -> Result<(OidcIdentity, String), OidcError> {
        let transaction = self
            .transactions
            .consume(state, now_unix_secs)
            .ok_or(OidcError::Invalid)?;
        let provider = self.discovered(false).await?;
        let request = provider
            .client
            .exchange_code(AuthorizationCode::new(code))
            .set_pkce_verifier(transaction.pkce_verifier);
        let token_response = match request.request_async(&provider.transport).await {
            Ok(response) => response,
            Err(openidconnect::RequestTokenError::Request(_)) => {
                self.invalidate().await;
                return Err(OidcError::Unavailable);
            }
            Err(_) => return Err(OidcError::Invalid),
        };
        let id_token = token_response.id_token().ok_or(OidcError::Invalid)?;
        let mut verification_client = provider.client.clone();
        let mut verifier = verification_client.id_token_verifier();
        let claims = match id_token.claims(&verifier, &transaction.nonce) {
            Ok(claims) => claims,
            Err(error) if unknown_signing_key(&error) => {
                drop(verifier);
                verification_client = self.discovered(true).await?.client;
                verifier = verification_client.id_token_verifier();
                id_token
                    .claims(&verifier, &transaction.nonce)
                    .map_err(|_| OidcError::Invalid)?
            }
            Err(_) => return Err(OidcError::Invalid),
        };
        if claims.audiences().len() != 1
            || claims.audiences()[0].as_str() != self.config.client_id
            || claims.issuer().as_str() != self.config.issuer
        {
            return Err(OidcError::Invalid);
        }
        if let Some(expected) = claims.access_token_hash() {
            let actual = AccessTokenHash::from_token(
                token_response.access_token(),
                id_token.signing_alg().map_err(|_| OidcError::Invalid)?,
                id_token
                    .signing_key(&verifier)
                    .map_err(|_| OidcError::Invalid)?,
            )
            .map_err(|_| OidcError::Invalid)?;
            if &actual != expected {
                return Err(OidcError::Invalid);
            }
        }
        let serialized = Zeroizing::new(id_token.to_string());
        let groups = groups_from_id_token(&serialized, &self.config.groups_claim)?;
        let role = resolve_role(&groups, &self.config.groups)?;
        let subject = claims.subject().as_str();
        if subject.is_empty() || subject.len() > MAX_ENDPOINT_BYTES {
            return Err(OidcError::Invalid);
        }
        let fingerprint = issuer_subject_fingerprint(&self.config.issuer, subject);
        let identity_id = derived_identity_id(&fingerprint)?;
        Ok((
            OidcIdentity {
                identity_id,
                fingerprint,
                role,
            },
            transaction.return_path,
        ))
    }

    async fn discovered(&self, force: bool) -> Result<DiscoveredProvider, OidcError> {
        if !force && let Some(provider) = self.cached.read().await.clone() {
            return Ok(provider);
        }
        let mut cached = self.cached.write().await;
        if !force && let Some(provider) = cached.clone() {
            return Ok(provider);
        }
        let config = Arc::clone(&self.config);
        let redirect_uri = self.redirect_uri.clone();
        let prepared =
            tokio::task::spawn_blocking(move || prepare_discovery(&config, &redirect_uri))
                .await
                .map_err(|_| OidcError::Unavailable)?
                .map_err(|_| OidcError::Unavailable)?;
        let metadata = match CoreProviderMetadata::discover_async(
            prepared.issuer.clone(),
            &prepared.transport,
        )
        .await
        {
            Ok(metadata) => metadata,
            Err(_) => {
                self.available.store(false, Ordering::Release);
                return Err(OidcError::Unavailable);
            }
        };
        let provider = build_discovered(metadata, prepared, &self.config)?;
        *cached = Some(provider.clone());
        self.available.store(true, Ordering::Release);
        Ok(provider)
    }

    async fn invalidate(&self) {
        *self.cached.write().await = None;
        self.available.store(false, Ordering::Release);
    }
}

impl LoginTransactions {
    fn insert(
        &self,
        state: String,
        transaction: LoginTransaction,
        now_unix_secs: u64,
    ) -> Result<(), OidcError> {
        let mut transactions = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        transactions.retain(|_, item| now_unix_secs < item.expires_unix_secs);
        if transactions.len() >= MAX_TRANSACTIONS || transactions.contains_key(&state) {
            return Err(OidcError::Capacity);
        }
        transactions.insert(state, transaction);
        Ok(())
    }

    fn consume(&self, state: &str, now_unix_secs: u64) -> Option<LoginTransaction> {
        let mut transactions = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        transactions.retain(|_, item| now_unix_secs < item.expires_unix_secs);
        transactions.remove(state)
    }
}

struct PreparedDiscovery {
    issuer: IssuerUrl,
    client_secret: ClientSecret,
    redirect_uri: RedirectUrl,
    transport: BoundedOidcTransport,
}

fn prepare_discovery(
    config: &AdminWebOidcConfig,
    redirect_uri: &str,
) -> Result<PreparedDiscovery, OidcError> {
    let secret = SecretRef::parse(&config.client_secret)
        .and_then(|reference| reference.resolve(4_096))
        .map_err(|_| OidcError::Unavailable)?;
    let secret = std::str::from_utf8(secret.as_ref()).map_err(|_| OidcError::Unavailable)?;
    if secret.is_empty() {
        return Err(OidcError::Unavailable);
    }
    let issuer = IssuerUrl::new(config.issuer.clone()).map_err(|_| OidcError::Invalid)?;
    let origin = Url::parse(&config.issuer).map_err(|_| OidcError::Invalid)?;
    Ok(PreparedDiscovery {
        issuer,
        client_secret: ClientSecret::new(secret.to_owned()),
        redirect_uri: RedirectUrl::new(redirect_uri.to_owned()).map_err(|_| OidcError::Invalid)?,
        transport: BoundedOidcTransport::new(origin, config.ca_bundle.as_deref())
            .map_err(|_| OidcError::Unavailable)?,
    })
}

fn build_discovered(
    metadata: CoreProviderMetadata,
    prepared: PreparedDiscovery,
    config: &AdminWebOidcConfig,
) -> Result<DiscoveredProvider, OidcError> {
    if metadata.issuer().as_str() != config.issuer {
        return Err(OidcError::Invalid);
    }
    let token_endpoint = metadata
        .token_endpoint()
        .cloned()
        .ok_or(OidcError::Invalid)?;
    for endpoint in [
        metadata.authorization_endpoint().url(),
        token_endpoint.url(),
        metadata.jwks_uri().url(),
    ]
    .into_iter()
    .chain(metadata.userinfo_endpoint().map(|endpoint| endpoint.url()))
    {
        validate_endpoint(&prepared.transport.origin, endpoint)?;
    }
    if metadata.id_token_signing_alg_values_supported().is_empty() {
        return Err(OidcError::Invalid);
    }
    let client = CoreClient::from_provider_metadata(
        metadata,
        ClientId::new(config.client_id.clone()),
        Some(prepared.client_secret),
    )
    .set_token_uri(token_endpoint)
    .set_redirect_uri(prepared.redirect_uri);
    Ok(DiscoveredProvider {
        client,
        transport: prepared.transport,
    })
}

fn validate_endpoint(origin: &Url, endpoint: &Url) -> Result<(), OidcError> {
    (endpoint.as_str().len() <= MAX_ENDPOINT_BYTES
        && same_origin(origin, endpoint)
        && endpoint.fragment().is_none())
    .then_some(())
    .ok_or(OidcError::Invalid)
}

fn same_origin(origin: &Url, endpoint: &Url) -> bool {
    endpoint.scheme() == "https"
        && endpoint.scheme() == origin.scheme()
        && endpoint.host_str().is_some_and(|host| {
            origin
                .host_str()
                .is_some_and(|expected| host.eq_ignore_ascii_case(expected))
        })
        && endpoint.port_or_known_default() == origin.port_or_known_default()
        && endpoint.username().is_empty()
        && endpoint.password().is_none()
}

fn unknown_signing_key(error: &ClaimsVerificationError) -> bool {
    matches!(
        error,
        ClaimsVerificationError::SignatureVerification(SignatureVerificationError::NoMatchingKey)
    )
}

fn groups_from_id_token(token: &str, claim: &str) -> Result<Vec<String>, OidcError> {
    let mut parts = token.split('.');
    let _header = parts.next().ok_or(OidcError::Invalid)?;
    let payload = parts.next().ok_or(OidcError::Invalid)?;
    let _signature = parts.next().ok_or(OidcError::Invalid)?;
    if parts.next().is_some() {
        return Err(OidcError::Invalid);
    }
    let payload = Zeroizing::new(
        URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| OidcError::Invalid)?,
    );
    let mut deserializer = serde_json::Deserializer::from_slice(&payload);
    let groups = GroupClaimSeed(claim)
        .deserialize(&mut deserializer)
        .map_err(|_| OidcError::Invalid)?;
    deserializer.end().map_err(|_| OidcError::Invalid)?;
    let groups = groups.ok_or(OidcError::Invalid)?;
    if groups.len() > 256
        || groups.iter().any(|group| {
            group.is_empty() || group.len() > 256 || group.chars().any(char::is_control)
        })
    {
        return Err(OidcError::Invalid);
    }
    Ok(groups)
}

struct GroupClaimSeed<'a>(&'a str);

impl<'de> DeserializeSeed<'de> for GroupClaimSeed<'_> {
    type Value = Option<Vec<String>>;

    fn deserialize<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        deserializer.deserialize_map(GroupClaimVisitor(self.0))
    }
}

struct GroupClaimVisitor<'a>(&'a str);

impl<'de> Visitor<'de> for GroupClaimVisitor<'_> {
    type Value = Option<Vec<String>>;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("an ID token claims object")
    }

    fn visit_map<M>(self, mut map: M) -> Result<Self::Value, M::Error>
    where
        M: MapAccess<'de>,
    {
        let mut groups = None;
        while let Some(key) = map.next_key::<String>()? {
            if key == self.0 {
                if groups.is_some() {
                    return Err(serde::de::Error::duplicate_field("configured groups claim"));
                }
                groups = Some(map.next_value::<Vec<String>>()?);
            } else {
                map.next_value::<IgnoredAny>()?;
            }
        }
        Ok(groups)
    }
}

fn resolve_role(groups: &[String], mapping: &AdminWebOidcGroups) -> Result<Role, OidcError> {
    let mut matched = None;
    for (role, allowed) in [
        (Role::Viewer, &mapping.viewer),
        (Role::Auditor, &mapping.auditor),
        (Role::Operator, &mapping.operator),
        (Role::Admin, &mapping.admin),
    ] {
        if groups.iter().any(|group| allowed.contains(group)) && matched.replace(role).is_some() {
            return Err(OidcError::Invalid);
        }
    }
    matched.ok_or(OidcError::Invalid)
}

pub(super) fn issuer_subject_fingerprint(issuer: &str, subject: &str) -> String {
    let digest = Sha256::new()
        .chain_update(issuer.as_bytes())
        .chain_update([0])
        .chain_update(subject.as_bytes())
        .finalize();
    hex(&digest)
}

pub(super) fn derived_identity_id(fingerprint: &str) -> Result<ObjectId, OidcError> {
    format!("oidc-{}", &fingerprint[..58])
        .parse()
        .map_err(|_| OidcError::Invalid)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

#[derive(Clone)]
struct BoundedOidcTransport {
    client: Client,
    origin: Url,
}

impl fmt::Debug for BoundedOidcTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundedOidcTransport")
            .field("origin", &self.origin)
            .finish_non_exhaustive()
    }
}

#[derive(Debug, Error)]
enum OidcTransportError {
    #[error("OIDC endpoint violates the configured origin")]
    Origin,
    #[error("OIDC transport initialization failed")]
    Initialization,
    #[error("OIDC request failed")]
    Request,
    #[error("OIDC response exceeded its resource bound")]
    ResponseBound,
    #[error("OIDC redirect response is forbidden")]
    Redirect,
    #[error("OIDC request timed out")]
    Timeout,
}

impl BoundedOidcTransport {
    fn new(origin: Url, ca_bundle: Option<&str>) -> Result<Self, OidcTransportError> {
        let mut http = HttpConnector::new();
        http.enforce_http(false);
        http.set_connect_timeout(Some(CONNECT_TIMEOUT));
        let connector = HttpsConnectorBuilder::new()
            .with_tls_config(
                aegisproxy_tls::client_config(ca_bundle)
                    .map_err(|_| OidcTransportError::Initialization)?,
            )
            .https_only()
            .enable_http1()
            .wrap_connector(http);
        let mut builder = HyperClient::builder(TokioExecutor::new());
        builder
            .pool_idle_timeout(Duration::from_secs(30))
            .pool_max_idle_per_host(2)
            .http1_max_buf_size(64 * 1024)
            .http1_max_headers(MAX_HEADERS);
        Ok(Self {
            client: builder.build(connector),
            origin,
        })
    }
}

impl<'client> AsyncHttpClient<'client> for BoundedOidcTransport {
    type Error = OidcTransportError;
    type Future = Pin<Box<dyn Future<Output = Result<HttpResponse, Self::Error>> + Send + 'client>>;

    fn call(&'client self, request: HttpRequest) -> Self::Future {
        let endpoint = request.uri().to_string();
        let permitted = endpoint.len() <= MAX_ENDPOINT_BYTES
            && request.headers().len() <= MAX_HEADERS
            && Url::parse(&endpoint)
                .is_ok_and(|url| same_origin(&self.origin, &url) && url.fragment().is_none());
        if !permitted {
            return Box::pin(async { Err(OidcTransportError::Origin) });
        }
        let limit = if request.method() == hyper::Method::POST {
            MAX_TOKEN_BYTES
        } else {
            MAX_DISCOVERY_BYTES
        };
        let client = self.client.clone();
        Box::pin(async move {
            tokio::time::timeout(REQUEST_TIMEOUT, async move {
                let request = request.map(|body| Full::new(Bytes::from(body)));
                let response = client
                    .request(request)
                    .await
                    .map_err(|_| OidcTransportError::Request)?;
                if response.status().is_redirection() {
                    return Err(OidcTransportError::Redirect);
                }
                if response.headers().len() > MAX_HEADERS {
                    return Err(OidcTransportError::ResponseBound);
                }
                let (parts, body) = response.into_parts();
                let body = Limited::new(body, limit)
                    .collect()
                    .await
                    .map_err(|_| OidcTransportError::ResponseBound)?
                    .to_bytes()
                    .to_vec();
                Ok(HttpResponse::from_parts(parts, body))
            })
            .await
            .map_err(|_| OidcTransportError::Timeout)?
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        convert::Infallible,
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicU8, Ordering},
    };

    use chrono::Utc;
    use hyper::{Request, Response, StatusCode, body::Incoming, service::service_fn};
    use hyper_util::rt::TokioIo;
    use openidconnect::{
        AccessToken, AdditionalClaims, Audience, IdToken, IdTokenClaims, StandardClaims,
        SubjectIdentifier,
        core::{
            CoreGenderClaim, CoreHmacKey, CoreJweContentEncryptionAlgorithm,
            CoreJwsSigningAlgorithm,
        },
    };
    use serde::{Deserialize, Serialize};
    use tokio::{net::TcpListener, task::JoinHandle};
    use tokio_rustls::{
        TlsAcceptor,
        rustls::{ServerConfig, crypto::aws_lc_rs, pki_types::PrivateKeyDer, version},
    };
    use tokio_util::sync::CancellationToken;

    #[test]
    fn role_mapping_rejects_missing_and_conflicting_groups() {
        let mapping = AdminWebOidcGroups {
            viewer: vec!["readers".into()],
            auditor: Vec::new(),
            operator: vec!["operators".into()],
            admin: vec!["admins".into()],
        };
        assert_eq!(
            resolve_role(&["operators".into()], &mapping).expect("operator"),
            Role::Operator
        );
        assert!(resolve_role(&["unknown".into()], &mapping).is_err());
        assert!(resolve_role(&["operators".into(), "admins".into()], &mapping).is_err());
    }

    #[test]
    fn fingerprints_are_stable_unambiguous_and_bounded_ids() {
        let first = issuer_subject_fingerprint("https://issuer.test/a", "bc");
        let second = issuer_subject_fingerprint("https://issuer.test/ab", "c");
        assert_ne!(first, second);
        assert_eq!(first.len(), 64);
        let id = derived_identity_id(&first).expect("identity ID");
        assert_eq!(id.as_str().len(), 63);
        assert!(id.as_str().starts_with("oidc-"));
    }

    #[test]
    fn dynamic_group_claim_requires_one_string_array() {
        fn token(payload: &str) -> String {
            format!("e30.{}.signature", URL_SAFE_NO_PAD.encode(payload))
        }
        assert_eq!(
            groups_from_id_token(
                &token(r#"{"roles":["admins"],"email":"canary@test"}"#),
                "roles"
            )
            .expect("groups"),
            vec!["admins"]
        );
        assert!(groups_from_id_token(&token(r#"{"roles":"admins"}"#), "roles").is_err());
        assert!(
            groups_from_id_token(
                &token(r#"{"roles":["admins"],"roles":["operators"]}"#),
                "roles"
            )
            .is_err()
        );
    }

    #[test]
    fn transaction_store_is_bounded_expiring_and_one_use() {
        let store = LoginTransactions(Mutex::new(HashMap::new()));
        let transaction = || LoginTransaction {
            nonce: Nonce::new("nonce".into()),
            pkce_verifier: PkceCodeVerifier::new("verifier".into()),
            return_path: "/".into(),
            expires_unix_secs: 20,
        };
        store
            .insert("state".into(), transaction(), 10)
            .expect("insert");
        assert!(store.consume("state", 10).is_some());
        assert!(store.consume("state", 10).is_none());
        store
            .insert("expired".into(), transaction(), 10)
            .expect("insert");
        assert!(store.consume("expired", 20).is_none());
    }

    #[test]
    fn transport_origin_rejects_scheme_host_port_and_credentials() {
        let issuer = Url::parse("https://issuer.test:8443/tenant").expect("issuer");
        assert!(same_origin(
            &issuer,
            &Url::parse("https://ISSUER.test:8443/jwks").expect("same")
        ));
        for endpoint in [
            "http://issuer.test:8443/jwks",
            "https://other.test:8443/jwks",
            "https://issuer.test/jwks",
            "https://user:secret@issuer.test:8443/jwks",
        ] {
            assert!(!same_origin(
                &issuer,
                &Url::parse(endpoint).expect("endpoint")
            ));
        }
    }

    #[tokio::test]
    async fn in_process_https_provider_enforces_oidc_claims_and_one_use_state() {
        let test_provider = TestProvider::start().await;
        let available = Arc::new(AtomicBool::new(false));
        let provider = OidcProvider::new(
            test_provider.config(),
            "http://localhost:9090",
            Arc::clone(&available),
        );

        let login = provider.login("/".into(), 100).await.expect("login");
        test_provider.capture_authorization(&login.authorization_url);
        let state = query_value(&login.authorization_url, "state");
        let (identity, return_path) = provider
            .callback("valid-code".into(), &state, 100)
            .await
            .expect("callback");
        assert_eq!(identity.role, Role::Admin);
        assert_eq!(return_path, "/");
        assert!(provider.available());
        assert!(
            provider
                .callback("valid-code".into(), &state, 100)
                .await
                .is_err()
        );

        test_provider.mode.store(1, Ordering::Release);
        let login = provider.login("/".into(), 200).await.expect("second login");
        test_provider.capture_authorization(&login.authorization_url);
        let state = query_value(&login.authorization_url, "state");
        assert!(matches!(
            provider.callback("valid-code".into(), &state, 200).await,
            Err(OidcError::Invalid)
        ));

        test_provider.stop().await;
    }

    #[derive(Debug, Deserialize, Serialize)]
    struct TestAdditionalClaims {
        groups: serde_json::Value,
    }

    impl AdditionalClaims for TestAdditionalClaims {}

    type TestIdToken = IdToken<
        TestAdditionalClaims,
        CoreGenderClaim,
        CoreJweContentEncryptionAlgorithm,
        CoreJwsSigningAlgorithm,
    >;

    struct TestProvider {
        issuer: String,
        ca_path: std::path::PathBuf,
        secret_path: std::path::PathBuf,
        expected_nonce: Arc<Mutex<Option<String>>>,
        expected_challenge: Arc<Mutex<Option<String>>>,
        mode: Arc<AtomicU8>,
        shutdown: CancellationToken,
        task: JoinHandle<()>,
    }

    impl TestProvider {
        async fn start() -> Self {
            let generated =
                rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("certificate");
            let certificate_pem = generated.cert.pem();
            let private_key = PrivateKeyDer::Pkcs8(generated.signing_key.serialize_der().into());
            let server_config =
                ServerConfig::builder_with_provider(Arc::new(aws_lc_rs::default_provider()))
                    .with_protocol_versions(&[&version::TLS13, &version::TLS12])
                    .expect("TLS versions")
                    .with_no_client_auth()
                    .with_single_cert(vec![generated.cert.der().clone()], private_key)
                    .expect("server identity");
            let acceptor = TlsAcceptor::from(Arc::new(server_config));
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let issuer = format!(
                "https://localhost:{}",
                listener.local_addr().expect("address").port()
            );
            let root = std::env::temp_dir().join(format!(
                "aegisproxy-oidc-{}-{}",
                std::process::id(),
                super::super::request_id().expect("request ID")
            ));
            fs::create_dir(&root).expect("test directory");
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).expect("private");
            let ca_path = root.join("ca.pem");
            let secret_path = root.join("secret");
            fs::write(&ca_path, certificate_pem).expect("CA");
            fs::write(&secret_path, b"test-client-secret").expect("secret");
            fs::set_permissions(&ca_path, fs::Permissions::from_mode(0o600)).expect("CA mode");
            fs::set_permissions(&secret_path, fs::Permissions::from_mode(0o600))
                .expect("secret mode");
            let expected_nonce = Arc::new(Mutex::new(None));
            let expected_challenge = Arc::new(Mutex::new(None));
            let mode = Arc::new(AtomicU8::new(0));
            let shutdown = CancellationToken::new();
            let task_shutdown = shutdown.clone();
            let service_state = TestProviderState {
                issuer: issuer.clone(),
                expected_nonce: Arc::clone(&expected_nonce),
                expected_challenge: Arc::clone(&expected_challenge),
                mode: Arc::clone(&mode),
            };
            let task = tokio::spawn(async move {
                loop {
                    let accepted = tokio::select! {
                        () = task_shutdown.cancelled() => return,
                        accepted = listener.accept() => accepted,
                    };
                    let Ok((stream, _)) = accepted else {
                        return;
                    };
                    let acceptor = acceptor.clone();
                    let state = service_state.clone();
                    tokio::spawn(async move {
                        let Ok(stream) = acceptor.accept(stream).await else {
                            return;
                        };
                        let service = service_fn(move |request| {
                            test_provider_response(request, state.clone())
                        });
                        let _ = hyper::server::conn::http1::Builder::new()
                            .serve_connection(TokioIo::new(stream), service)
                            .await;
                    });
                }
            });
            Self {
                issuer,
                ca_path,
                secret_path,
                expected_nonce,
                expected_challenge,
                mode,
                shutdown,
                task,
            }
        }

        fn config(&self) -> AdminWebOidcConfig {
            AdminWebOidcConfig {
                issuer: self.issuer.clone(),
                client_id: "test-client".into(),
                client_secret: format!("file://{}", self.secret_path.display()),
                ca_bundle: Some(format!("file://{}", self.ca_path.display())),
                groups_claim: "groups".into(),
                groups: AdminWebOidcGroups {
                    viewer: vec!["readers".into()],
                    auditor: Vec::new(),
                    operator: Vec::new(),
                    admin: vec!["admins".into()],
                },
            }
        }

        fn capture_authorization(&self, authorization_url: &str) {
            *self
                .expected_nonce
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(query_value(authorization_url, "nonce"));
            *self
                .expected_challenge
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                Some(query_value(authorization_url, "code_challenge"));
            assert_eq!(
                query_value(authorization_url, "code_challenge_method"),
                "S256"
            );
            assert_eq!(query_value(authorization_url, "response_type"), "code");
        }

        async fn stop(self) {
            self.shutdown.cancel();
            self.task.await.expect("provider task");
            fs::remove_dir_all(self.ca_path.parent().expect("test root")).expect("cleanup");
        }
    }

    #[derive(Clone)]
    struct TestProviderState {
        issuer: String,
        expected_nonce: Arc<Mutex<Option<String>>>,
        expected_challenge: Arc<Mutex<Option<String>>>,
        mode: Arc<AtomicU8>,
    }

    async fn test_provider_response(
        request: Request<Incoming>,
        state: TestProviderState,
    ) -> Result<Response<Full<Bytes>>, Infallible> {
        let response = match request.uri().path() {
            "/.well-known/openid-configuration" => json_response(serde_json::json!({
                "issuer": state.issuer,
                "authorization_endpoint": format!("{}/authorize", state.issuer),
                "token_endpoint": format!("{}/token", state.issuer),
                "userinfo_endpoint": format!("{}/userinfo", state.issuer),
                "jwks_uri": format!("{}/jwks", state.issuer),
                "response_types_supported": ["code"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["HS256"]
            })),
            "/jwks" => json_response(serde_json::json!({"keys": []})),
            "/token" => token_response(request, &state).await,
            _ => Response::builder()
                .status(StatusCode::NOT_FOUND)
                .body(Full::new(Bytes::new()))
                .expect("not found"),
        };
        Ok(response)
    }

    async fn token_response(
        request: Request<Incoming>,
        state: &TestProviderState,
    ) -> Response<Full<Bytes>> {
        let body = request
            .into_body()
            .collect()
            .await
            .expect("token body")
            .to_bytes();
        let fields = openidconnect::url::form_urlencoded::parse(&body)
            .into_owned()
            .collect::<HashMap<_, _>>();
        let verifier = fields.get("code_verifier").expect("PKCE verifier");
        let challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()));
        let expected = state
            .expected_challenge
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
            .expect("challenge");
        if fields.get("code").map(String::as_str) != Some("valid-code")
            || challenge != expected
            || fields.get("redirect_uri").map(String::as_str)
                != Some("http://localhost:9090/v1/auth/callback")
        {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from_static(
                    b"{\"error\":\"invalid_grant\"}",
                )))
                .expect("bad request");
        }
        let mode = state.mode.load(Ordering::Acquire);
        let nonce = if mode == 1 {
            "wrong-nonce".into()
        } else {
            state
                .expected_nonce
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone()
                .expect("nonce")
        };
        let now = Utc::now();
        let claims = IdTokenClaims::new(
            IssuerUrl::new(state.issuer.clone()).expect("issuer"),
            vec![Audience::new("test-client".into())],
            now + chrono::Duration::minutes(5),
            now,
            StandardClaims::<CoreGenderClaim>::new(SubjectIdentifier::new("subject-1".into())),
            TestAdditionalClaims {
                groups: serde_json::json!(["admins"]),
            },
        )
        .set_nonce(Some(Nonce::new(nonce)));
        let access_token = AccessToken::new("access-token".into());
        let id_token = TestIdToken::new(
            claims,
            &CoreHmacKey::new(b"test-client-secret".to_vec()),
            CoreJwsSigningAlgorithm::HmacSha256,
            None,
            None,
        )
        .expect("ID token");
        json_response(serde_json::json!({
            "access_token": access_token.secret(),
            "token_type": "Bearer",
            "expires_in": 300,
            "id_token": id_token.to_string()
        }))
    }

    fn json_response(value: serde_json::Value) -> Response<Full<Bytes>> {
        Response::builder()
            .status(StatusCode::OK)
            .header(hyper::header::CONTENT_TYPE, "application/json")
            .body(Full::new(Bytes::from(
                serde_json::to_vec(&value).expect("JSON"),
            )))
            .expect("response")
    }

    fn query_value(url: &str, name: &str) -> String {
        Url::parse(url)
            .expect("URL")
            .query_pairs()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value.into_owned())
            .unwrap_or_else(|| panic!("missing query {name}"))
    }
}
