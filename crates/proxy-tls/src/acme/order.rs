use std::{collections::BTreeSet, fmt, time::Duration};

use instant_acme::{
    AuthorizationStatus, ChallengeStatus, ChallengeType, Identifier, NewOrder, Order, OrderStatus,
    RetryPolicy,
};
use thiserror::Error;

use super::AcmeClient;

const MAX_ORDER_IDENTIFIERS: usize = 64;
const MAX_IDENTIFIER_BYTES: usize = 253;
const MAX_PROFILE_BYTES: usize = 64;
const MAX_CHALLENGE_TOKEN_BYTES: usize = 512;
const MAX_KEY_AUTHORIZATION_BYTES: usize = 2 * 1024;
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
}

/// Stateful order adapter enforcing prepare, provision, notify, and poll sequencing.
pub struct AcmeOrder {
    inner: Order,
    identifiers: BTreeSet<String>,
    challenge: AcmeChallengeKind,
    stage: AcmeOrderStage,
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

fn valid_dns_identifier(identifier: &str) -> bool {
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
}
