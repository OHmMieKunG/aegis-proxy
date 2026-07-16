use std::{collections::BTreeSet, fmt, time::Duration};

use instant_acme::{
    AuthorizationStatus, ChallengeStatus, ChallengeType, Identifier, NewOrder, Order, OrderStatus,
    RetryPolicy,
};
use rcgen::{CertificateParams, DistinguishedName, KeyPair};
use thiserror::Error;
use zeroize::Zeroizing;

use super::AcmeClient;
use crate::store::identity_from_pem;

const MAX_ORDER_IDENTIFIERS: usize = 64;
const MAX_IDENTIFIER_BYTES: usize = 253;
const MAX_PROFILE_BYTES: usize = 64;
const MAX_CHALLENGE_TOKEN_BYTES: usize = 512;
const MAX_KEY_AUTHORIZATION_BYTES: usize = 2 * 1024;
const MAX_CSR_BYTES: usize = 64 * 1024;
const MAX_ISSUED_CHAIN_BYTES: usize = 1024 * 1024;
const MAX_ISSUED_PRIVATE_KEY_BYTES: usize = 256 * 1024;
const MIN_POLL_TIMEOUT: Duration = Duration::from_secs(1);
const MAX_POLL_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Supported ACME authorization mechanism for one order.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AcmeChallengeKind {
    /// RFC 8555 HTTP-01.
    Http01,
    /// RFC 8555 DNS-01.
    Dns01,
    /// RFC 8737 TLS-ALPN-01.
    TlsAlpn01,
}

impl AcmeChallengeKind {
    fn instant(self) -> ChallengeType {
        match self {
            Self::Http01 => ChallengeType::Http01,
            Self::Dns01 => ChallengeType::Dns01,
            Self::TlsAlpn01 => ChallengeType::TlsAlpn01,
        }
    }
}

/// Inputs for creating one bounded DNS-identifier order.
#[derive(Debug)]
pub struct AcmeOrderRequest<'a> {
    /// Canonical lower-case DNS names, including an optional `*.` prefix.
    pub identifiers: &'a [String],
    /// Challenge mechanism selected by validated configuration.
    pub challenge: AcmeChallengeKind,
    /// Optional CA certificate profile.
    pub profile: Option<&'a str>,
}

/// Opaque challenge response material. Debug formatting never reveals its response.
pub struct AcmeChallengeMaterial {
    identifier: String,
    token: String,
    response: AcmeChallengeResponse,
}

/// Validated issued chain and matching private key ready for encrypted generation storage.
pub struct AcmeIssuedCertificate {
    certificate_chain_pem: Vec<u8>,
    private_key_pem: Zeroizing<Vec<u8>>,
}

impl fmt::Debug for AcmeIssuedCertificate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcmeIssuedCertificate")
            .field(
                "certificate_chain_pem_bytes",
                &self.certificate_chain_pem.len(),
            )
            .field("private_key_pem", &"[REDACTED]")
            .finish()
    }
}

impl AcmeIssuedCertificate {
    /// PEM certificate chain, leaf first.
    #[must_use]
    pub fn certificate_chain_pem(&self) -> &[u8] {
        &self.certificate_chain_pem
    }

    /// Matching PEM private key. Callers must encrypt it before persistence.
    #[must_use]
    pub fn private_key_pem(&self) -> &[u8] {
        self.private_key_pem.as_slice()
    }

    /// Revalidate this candidate as a runtime identity before durable activation.
    pub fn runtime_identity(
        &self,
        id: String,
        hosts: Vec<String>,
    ) -> Result<crate::Identity, AcmeOrderError> {
        identity_from_pem(
            id,
            hosts,
            &self.certificate_chain_pem,
            self.private_key_pem.as_slice(),
        )
        .map_err(|_| AcmeOrderError::Protocol)
    }
}

enum AcmeChallengeResponse {
    Http01(String),
    Dns01(String),
    TlsAlpn01([u8; 32]),
}

impl fmt::Debug for AcmeChallengeMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcmeChallengeMaterial")
            .field("identifier", &self.identifier)
            .field("token", &"[REDACTED]")
            .field("response", &"[REDACTED]")
            .finish()
    }
}

impl AcmeChallengeMaterial {
    /// Authorization identifier exactly as requested.
    #[must_use]
    pub fn identifier(&self) -> &str {
        &self.identifier
    }

    /// ACME token used as the HTTP path component when applicable.
    #[must_use]
    pub fn token(&self) -> &str {
        &self.token
    }

    /// HTTP-01 key authorization, when this is HTTP-01 material.
    #[must_use]
    pub fn http_key_authorization(&self) -> Option<&str> {
        match &self.response {
            AcmeChallengeResponse::Http01(value) => Some(value),
            _ => None,
        }
    }

    /// DNS-01 TXT value, when this is DNS-01 material.
    #[must_use]
    pub fn dns_value(&self) -> Option<&str> {
        match &self.response {
            AcmeChallengeResponse::Dns01(value) => Some(value),
            _ => None,
        }
    }

    /// TLS-ALPN-01 `acmeIdentifier` digest, when this is TLS-ALPN-01 material.
    #[must_use]
    pub fn tls_alpn_digest(&self) -> Option<&[u8; 32]> {
        match &self.response {
            AcmeChallengeResponse::TlsAlpn01(value) => Some(value),
            _ => None,
        }
    }
}

/// Sanitized ACME order failure.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AcmeOrderError {
    /// Configured identifiers/profile were malformed, duplicate, or outside a bound.
    #[error("invalid ACME order input")]
    Input,
    /// The CA response did not match the requested order or challenge.
    #[error("invalid ACME order response")]
    Protocol,
    /// Network, CA API, or polling failed without exposing response details.
    #[error("ACME order transport failed")]
    Transport,
    /// An operation was attempted in the wrong order stage.
    #[error("invalid ACME order state transition")]
    State,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AcmeOrderStage {
    Created,
    ChallengesPrepared,
    ChallengesNotified,
    Ready,
    CsrPrepared,
    Finalized,
    Issued,
}

/// Stateful order adapter enforcing prepare, provision, notify, and poll sequencing.
pub struct AcmeOrder {
    inner: Order,
    identifiers: BTreeSet<String>,
    challenge: AcmeChallengeKind,
    stage: AcmeOrderStage,
    pending_csr: Option<Vec<u8>>,
    pending_private_key: Option<Zeroizing<Vec<u8>>>,
}

impl fmt::Debug for AcmeOrder {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcmeOrder")
            .field("identifier_count", &self.identifiers.len())
            .field("challenge", &self.challenge)
            .field("stage", &self.stage)
            .field("inner", &"[REDACTED]")
            .finish()
    }
}

impl AcmeClient {
    /// Create one order after locally validating all identifiers and limits.
    pub async fn new_order(
        &self,
        request: AcmeOrderRequest<'_>,
    ) -> Result<AcmeOrder, AcmeOrderError> {
        let identifiers = validate_order_request(&request)?;
        let instant_identifiers = identifiers
            .iter()
            .cloned()
            .map(Identifier::Dns)
            .collect::<Vec<_>>();
        let mut new_order = NewOrder::new(&instant_identifiers);
        if let Some(profile) = request.profile {
            new_order = new_order.profile(profile);
        }
        let inner = self
            .account()
            .new_order(&new_order)
            .await
            .map_err(|_| AcmeOrderError::Transport)?;
        Ok(AcmeOrder {
            inner,
            identifiers,
            challenge: request.challenge,
            stage: AcmeOrderStage::Created,
            pending_csr: None,
            pending_private_key: None,
        })
    }
}

impl AcmeOrder {
    /// Derive owned response material for every pending authorization.
    ///
    /// The caller must provision every returned item before calling
    /// [`AcmeOrder::notify_challenges_ready`].
    pub async fn prepare_challenges(
        &mut self,
    ) -> Result<Vec<AcmeChallengeMaterial>, AcmeOrderError> {
        if self.stage != AcmeOrderStage::Created {
            return Err(AcmeOrderError::State);
        }
        let mut seen = BTreeSet::new();
        let mut material = Vec::new();
        let mut authorizations = self.inner.authorizations();
        while let Some(result) = authorizations.next().await {
            if seen.len() >= self.identifiers.len() {
                return Err(AcmeOrderError::Protocol);
            }
            let mut authorization = result.map_err(|_| AcmeOrderError::Transport)?;
            let identifier = authorization.identifier().to_string();
            if !self.identifiers.contains(&identifier) || !seen.insert(identifier.clone()) {
                return Err(AcmeOrderError::Protocol);
            }
            match authorization.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                _ => return Err(AcmeOrderError::Protocol),
            }
            let challenge = authorization
                .challenge(self.challenge.instant())
                .ok_or(AcmeOrderError::Protocol)?;
            if challenge.token.is_empty()
                || challenge.token.len() > MAX_CHALLENGE_TOKEN_BYTES
                || challenge.status != ChallengeStatus::Pending
                || !challenge
                    .token
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
            {
                return Err(AcmeOrderError::Protocol);
            }
            let key_authorization = challenge.key_authorization();
            let response = match self.challenge {
                AcmeChallengeKind::Http01 => {
                    if key_authorization.as_str().len() > MAX_KEY_AUTHORIZATION_BYTES {
                        return Err(AcmeOrderError::Protocol);
                    }
                    AcmeChallengeResponse::Http01(key_authorization.as_str().to_owned())
                }
                AcmeChallengeKind::Dns01 => {
                    AcmeChallengeResponse::Dns01(key_authorization.dns_value())
                }
                AcmeChallengeKind::TlsAlpn01 => {
                    let digest = key_authorization.digest();
                    let digest = digest.as_ref();
                    let digest: [u8; 32] =
                        digest.try_into().map_err(|_| AcmeOrderError::Protocol)?;
                    AcmeChallengeResponse::TlsAlpn01(digest)
                }
            };
            material.push(AcmeChallengeMaterial {
                identifier,
                token: challenge.token.clone(),
                response,
            });
        }
        if seen != self.identifiers {
            return Err(AcmeOrderError::Protocol);
        }
        self.stage = AcmeOrderStage::ChallengesPrepared;
        Ok(material)
    }

    /// Notify the CA only after the caller successfully provisions all prepared material.
    pub async fn notify_challenges_ready(&mut self) -> Result<(), AcmeOrderError> {
        if self.stage != AcmeOrderStage::ChallengesPrepared {
            return Err(AcmeOrderError::State);
        }
        let mut seen = BTreeSet::new();
        let mut authorizations = self.inner.authorizations();
        while let Some(result) = authorizations.next().await {
            if seen.len() >= self.identifiers.len() {
                return Err(AcmeOrderError::Protocol);
            }
            let mut authorization = result.map_err(|_| AcmeOrderError::Transport)?;
            let identifier = authorization.identifier().to_string();
            if !self.identifiers.contains(&identifier) || !seen.insert(identifier) {
                return Err(AcmeOrderError::Protocol);
            }
            match authorization.status {
                AuthorizationStatus::Valid => continue,
                AuthorizationStatus::Pending => {}
                _ => return Err(AcmeOrderError::Protocol),
            }
            authorization
                .challenge(self.challenge.instant())
                .ok_or(AcmeOrderError::Protocol)?
                .set_ready()
                .await
                .map_err(|_| AcmeOrderError::Transport)?;
        }
        if seen != self.identifiers {
            return Err(AcmeOrderError::Protocol);
        }
        self.stage = AcmeOrderStage::ChallengesNotified;
        Ok(())
    }

    /// Poll with an explicit bounded total timeout until the order becomes ready.
    pub async fn poll_ready(&mut self, timeout: Duration) -> Result<(), AcmeOrderError> {
        if self.stage != AcmeOrderStage::ChallengesNotified
            || !(MIN_POLL_TIMEOUT..=MAX_POLL_TIMEOUT).contains(&timeout)
        {
            return Err(AcmeOrderError::State);
        }
        let retries = RetryPolicy::new()
            .initial_delay(Duration::from_millis(250))
            .backoff(2.0)
            .timeout(timeout);
        match self.inner.poll_ready(&retries).await {
            Ok(OrderStatus::Ready) => {
                self.stage = AcmeOrderStage::Ready;
                Ok(())
            }
            Ok(_) => Err(AcmeOrderError::Protocol),
            Err(_) => Err(AcmeOrderError::Transport),
        }
    }

    /// Generate one CSR off the Tokio worker pool and finalize using the same key on retries.
    pub async fn finalize(&mut self) -> Result<(), AcmeOrderError> {
        if self.stage == AcmeOrderStage::Ready {
            let identifiers = self.identifiers.iter().cloned().collect::<Vec<_>>();
            let (csr, private_key) =
                tokio::task::spawn_blocking(move || generate_csr_material(identifiers))
                    .await
                    .map_err(|_| AcmeOrderError::Protocol)??;
            self.pending_csr = Some(csr);
            self.pending_private_key = Some(private_key);
            self.stage = AcmeOrderStage::CsrPrepared;
        }
        if self.stage != AcmeOrderStage::CsrPrepared {
            return Err(AcmeOrderError::State);
        }
        let csr = self.pending_csr.as_deref().ok_or(AcmeOrderError::State)?;
        match self.inner.finalize_csr(csr).await {
            Ok(()) => {
                self.pending_csr = None;
                self.stage = AcmeOrderStage::Finalized;
                Ok(())
            }
            Err(_) => match self.inner.refresh().await {
                Ok(state)
                    if matches!(state.status, OrderStatus::Processing | OrderStatus::Valid) =>
                {
                    self.pending_csr = None;
                    self.stage = AcmeOrderStage::Finalized;
                    Ok(())
                }
                Ok(state) if state.status == OrderStatus::Ready => Err(AcmeOrderError::Transport),
                Ok(_) => Err(AcmeOrderError::Protocol),
                Err(_) => Err(AcmeOrderError::Transport),
            },
        }
    }

    /// Poll for, bound, and verify the issued chain before releasing its private key.
    pub async fn poll_certificate(
        &mut self,
        timeout: Duration,
    ) -> Result<AcmeIssuedCertificate, AcmeOrderError> {
        if self.stage != AcmeOrderStage::Finalized
            || !(MIN_POLL_TIMEOUT..=MAX_POLL_TIMEOUT).contains(&timeout)
        {
            return Err(AcmeOrderError::State);
        }
        let retries = RetryPolicy::new()
            .initial_delay(Duration::from_millis(250))
            .backoff(2.0)
            .timeout(timeout);
        let certificate_chain = self
            .inner
            .poll_certificate(&retries)
            .await
            .map_err(|_| AcmeOrderError::Transport)?
            .into_bytes();
        if certificate_chain.is_empty() || certificate_chain.len() > MAX_ISSUED_CHAIN_BYTES {
            return Err(AcmeOrderError::Protocol);
        }
        let private_key = self
            .pending_private_key
            .as_ref()
            .ok_or(AcmeOrderError::State)?;
        identity_from_pem(
            "acme-candidate".into(),
            self.identifiers.iter().cloned().collect(),
            &certificate_chain,
            private_key.as_slice(),
        )
        .map_err(|_| AcmeOrderError::Protocol)?;
        let private_key = self
            .pending_private_key
            .take()
            .ok_or(AcmeOrderError::State)?;
        self.stage = AcmeOrderStage::Issued;
        Ok(AcmeIssuedCertificate {
            certificate_chain_pem: certificate_chain,
            private_key_pem: private_key,
        })
    }
}

fn generate_csr_material(
    identifiers: Vec<String>,
) -> Result<(Vec<u8>, Zeroizing<Vec<u8>>), AcmeOrderError> {
    if identifiers.is_empty() || identifiers.len() > MAX_ORDER_IDENTIFIERS {
        return Err(AcmeOrderError::Input);
    }
    let mut parameters =
        CertificateParams::new(identifiers).map_err(|_| AcmeOrderError::Protocol)?;
    parameters.distinguished_name = DistinguishedName::new();
    let private_key = KeyPair::generate().map_err(|_| AcmeOrderError::Protocol)?;
    let csr = parameters
        .serialize_request(&private_key)
        .map_err(|_| AcmeOrderError::Protocol)?;
    let csr = csr.der().to_vec();
    let private_key = Zeroizing::new(private_key.serialize_pem().into_bytes());
    if csr.is_empty()
        || csr.len() > MAX_CSR_BYTES
        || private_key.is_empty()
        || private_key.len() > MAX_ISSUED_PRIVATE_KEY_BYTES
    {
        return Err(AcmeOrderError::Protocol);
    }
    Ok((csr, private_key))
}

fn validate_order_request(
    request: &AcmeOrderRequest<'_>,
) -> Result<BTreeSet<String>, AcmeOrderError> {
    if request.identifiers.is_empty() || request.identifiers.len() > MAX_ORDER_IDENTIFIERS {
        return Err(AcmeOrderError::Input);
    }
    if let Some(profile) = request.profile
        && (profile.is_empty()
            || profile.len() > MAX_PROFILE_BYTES
            || !profile
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.')))
    {
        return Err(AcmeOrderError::Input);
    }
    let mut identifiers = BTreeSet::new();
    for identifier in request.identifiers {
        if !valid_dns_identifier(identifier)
            || identifier.starts_with("*.") && request.challenge != AcmeChallengeKind::Dns01
            || !identifiers.insert(identifier.clone())
        {
            return Err(AcmeOrderError::Input);
        }
    }
    Ok(identifiers)
}

pub(super) fn valid_dns_identifier(identifier: &str) -> bool {
    if identifier.is_empty()
        || identifier.len() > MAX_IDENTIFIER_BYTES
        || !identifier.is_ascii()
        || identifier.bytes().any(|byte| byte.is_ascii_uppercase())
        || identifier.ends_with('.')
    {
        return false;
    }
    let name = identifier.strip_prefix("*.").unwrap_or(identifier);
    !name.is_empty()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_canonical_bounded_order_inputs() {
        let names = vec!["example.test".into(), "www.example.test".into()];
        let request = AcmeOrderRequest {
            identifiers: &names,
            challenge: AcmeChallengeKind::Http01,
            profile: Some("short-lived"),
        };
        assert_eq!(validate_order_request(&request).map(|set| set.len()), Ok(2));

        let wildcard = vec!["*.example.test".into()];
        let request = AcmeOrderRequest {
            identifiers: &wildcard,
            challenge: AcmeChallengeKind::Dns01,
            profile: None,
        };
        assert!(validate_order_request(&request).is_ok());
    }

    #[test]
    fn rejects_duplicates_noncanonical_names_and_unsafe_wildcards() {
        for names in [
            vec!["example.test".into(), "example.test".into()],
            vec!["Example.test".into()],
            vec!["-bad.example".into()],
            vec!["bad_.example".into()],
            vec!["example.test.".into()],
        ] {
            let request = AcmeOrderRequest {
                identifiers: &names,
                challenge: AcmeChallengeKind::Http01,
                profile: None,
            };
            assert_eq!(validate_order_request(&request), Err(AcmeOrderError::Input));
        }

        let wildcard = vec!["*.example.test".into()];
        let request = AcmeOrderRequest {
            identifiers: &wildcard,
            challenge: AcmeChallengeKind::TlsAlpn01,
            profile: None,
        };
        assert_eq!(validate_order_request(&request), Err(AcmeOrderError::Input));
    }

    #[test]
    fn challenge_material_debug_is_redacted() {
        let material = AcmeChallengeMaterial {
            identifier: "example.test".into(),
            token: "token-canary".into(),
            response: AcmeChallengeResponse::Http01("key-auth-canary".into()),
        };
        let debug = format!("{material:?}");
        assert!(!debug.contains("token-canary"));
        assert!(!debug.contains("key-auth-canary"));
        assert_eq!(material.http_key_authorization(), Some("key-auth-canary"));
        assert_eq!(material.dns_value(), None);
    }

    #[test]
    fn generates_bounded_csr_and_redacts_issued_key() {
        let (csr, key) = generate_csr_material(vec!["example.test".into()]).expect("CSR material");
        assert!(!csr.is_empty());
        assert!(key.starts_with(b"-----BEGIN PRIVATE KEY-----"));

        let issued = AcmeIssuedCertificate {
            certificate_chain_pem: b"public-certificate".to_vec(),
            private_key_pem: Zeroizing::new(b"private-key-canary".to_vec()),
        };
        let debug = format!("{issued:?}");
        assert!(!debug.contains("private-key-canary"));
        assert_eq!(issued.private_key_pem(), b"private-key-canary");
    }
}
