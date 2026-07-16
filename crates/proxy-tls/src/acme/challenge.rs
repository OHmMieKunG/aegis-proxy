use std::{
    collections::HashMap,
    fmt,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use thiserror::Error;

const HTTP_CHALLENGE_PREFIX: &str = "/.well-known/acme-challenge/";
const MAX_CHALLENGES: usize = 256;
const MAX_TOKEN_BYTES: usize = 256;
const MAX_KEY_AUTHORIZATION_BYTES: usize = 1024;
const MAX_LIFETIME: Duration = Duration::from_secs(60 * 60);

/// Failure to install an isolated HTTP-01 challenge response.
#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum HttpChallengeError {
    /// Token or key-authorization bytes are malformed or oversized.
    #[error("invalid HTTP-01 challenge material")]
    Invalid,
    /// The bounded registry is full.
    #[error("HTTP-01 challenge registry is full")]
    Full,
    /// The token is already owned by another active authorization.
    #[error("HTTP-01 challenge token collision")]
    Collision,
    /// The registry lock was poisoned; challenge handling fails closed.
    #[error("HTTP-01 challenge registry is unavailable")]
    Unavailable,
}

#[derive(Debug)]
struct Challenge {
    generation: u64,
    listener_id: String,
    identifier: String,
    key_authorization: Arc<[u8]>,
    expires_at: Instant,
}

#[derive(Debug, Default)]
struct RegistryState {
    next_generation: u64,
    challenges: HashMap<String, Challenge>,
}

/// Bounded in-memory HTTP-01 responses shared by the ACME worker and HTTP edge.
#[derive(Clone, Default)]
pub struct HttpChallengeRegistry {
    state: Arc<Mutex<RegistryState>>,
}

impl fmt::Debug for HttpChallengeRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("HttpChallengeRegistry")
            .finish_non_exhaustive()
    }
}

impl HttpChallengeRegistry {
    /// Install one exact, time-limited token response.
    pub fn install(
        &self,
        listener_id: &str,
        identifier: &str,
        token: &str,
        key_authorization: &[u8],
        lifetime: Duration,
    ) -> Result<HttpChallengeLease, HttpChallengeError> {
        validate_material(listener_id, identifier, token, key_authorization, lifetime)?;
        let mut state = self
            .state
            .lock()
            .map_err(|_| HttpChallengeError::Unavailable)?;
        prune_expired(&mut state, Instant::now());
        if state.challenges.contains_key(token) {
            return Err(HttpChallengeError::Collision);
        }
        if state.challenges.len() >= MAX_CHALLENGES {
            return Err(HttpChallengeError::Full);
        }
        state.next_generation = state.next_generation.wrapping_add(1);
        let generation = state.next_generation;
        state.challenges.insert(
            token.to_owned(),
            Challenge {
                generation,
                listener_id: listener_id.to_owned(),
                identifier: identifier.to_owned(),
                key_authorization: Arc::from(key_authorization),
                expires_at: Instant::now() + lifetime,
            },
        );
        Ok(HttpChallengeLease {
            registry: self.clone(),
            token: token.to_owned(),
            generation,
        })
    }

    /// Resolve only the exact ACME system path. Query strings are not accepted.
    pub fn response_for_request(
        &self,
        listener_id: &str,
        identifier: &str,
        path: &str,
    ) -> Result<Option<Arc<[u8]>>, HttpChallengeError> {
        if !valid_identifier(identifier) {
            return Ok(None);
        }
        let Some(token) = path.strip_prefix(HTTP_CHALLENGE_PREFIX) else {
            return Ok(None);
        };
        if path.contains('?') || !valid_token(token) {
            return Ok(None);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| HttpChallengeError::Unavailable)?;
        prune_expired(&mut state, Instant::now());
        Ok(state
            .challenges
            .get(token)
            .filter(|challenge| {
                challenge.listener_id == listener_id && challenge.identifier == identifier
            })
            .map(|challenge| Arc::clone(&challenge.key_authorization)))
    }

    fn remove(&self, token: &str, generation: u64) {
        let Ok(mut state) = self.state.lock() else {
            return;
        };
        if state
            .challenges
            .get(token)
            .is_some_and(|challenge| challenge.generation == generation)
        {
            state.challenges.remove(token);
        }
    }
}

/// Removes its installed challenge when the authorization attempt ends.
#[derive(Debug)]
pub struct HttpChallengeLease {
    registry: HttpChallengeRegistry,
    token: String,
    generation: u64,
}

impl Drop for HttpChallengeLease {
    fn drop(&mut self) {
        self.registry.remove(&self.token, self.generation);
    }
}

fn validate_material(
    listener_id: &str,
    identifier: &str,
    token: &str,
    key_authorization: &[u8],
    lifetime: Duration,
) -> Result<(), HttpChallengeError> {
    if !valid_listener_id(listener_id)
        || !valid_identifier(identifier)
        || !valid_token(token)
        || key_authorization.is_empty()
        || key_authorization.len() > MAX_KEY_AUTHORIZATION_BYTES
        || !key_authorization.is_ascii()
        || key_authorization.iter().any(u8::is_ascii_control)
        || lifetime.is_zero()
        || lifetime > MAX_LIFETIME
    {
        return Err(HttpChallengeError::Invalid);
    }
    Ok(())
}

fn valid_listener_id(listener_id: &str) -> bool {
    listener_id
        .as_bytes()
        .first()
        .is_some_and(u8::is_ascii_lowercase)
        && listener_id.len() <= 63
        && listener_id.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn valid_identifier(identifier: &str) -> bool {
    !identifier.is_empty()
        && identifier.len() <= 253
        && identifier == identifier.to_ascii_lowercase()
        && !identifier.ends_with('.')
        && !identifier.contains([':', '*'])
        && identifier.split('.').count() >= 2
        && identifier.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        })
}

fn valid_token(token: &str) -> bool {
    !token.is_empty()
        && token.len() <= MAX_TOKEN_BYTES
        && token
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
}

fn prune_expired(state: &mut RegistryState, now: Instant) {
    state
        .challenges
        .retain(|_, challenge| challenge.expires_at > now);
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOKEN: &str = "abc_DEF-123";
    const KEY_AUTHORIZATION: &[u8] = b"abc_DEF-123.thumbprint";
    const IDENTIFIER: &str = "example.test";
    const LISTENER: &str = "web";

    #[test]
    fn exact_path_resolves_until_lease_drop() {
        let registry = HttpChallengeRegistry::default();
        let lease = registry
            .install(
                LISTENER,
                IDENTIFIER,
                TOKEN,
                KEY_AUTHORIZATION,
                Duration::from_secs(60),
            )
            .expect("install challenge");
        let path = format!("{HTTP_CHALLENGE_PREFIX}{TOKEN}");
        assert_eq!(
            registry
                .response_for_request(LISTENER, IDENTIFIER, &path)
                .expect("lookup")
                .as_deref(),
            Some(KEY_AUTHORIZATION)
        );
        assert!(
            registry
                .response_for_request(LISTENER, IDENTIFIER, &format!("{path}/extra"))
                .expect("lookup")
                .is_none()
        );
        assert!(
            registry
                .response_for_request(LISTENER, IDENTIFIER, &format!("{path}?query=1"))
                .expect("lookup")
                .is_none()
        );
        assert!(
            registry
                .response_for_request(LISTENER, "other.test", &path)
                .expect("lookup")
                .is_none()
        );
        assert!(
            registry
                .response_for_request("other", IDENTIFIER, &path)
                .expect("lookup")
                .is_none()
        );
        drop(lease);
        assert!(
            registry
                .response_for_request(LISTENER, IDENTIFIER, &path)
                .expect("lookup")
                .is_none()
        );
    }

    #[test]
    fn collisions_and_invalid_material_fail_closed() {
        let registry = HttpChallengeRegistry::default();
        let _lease = registry
            .install(
                LISTENER,
                IDENTIFIER,
                TOKEN,
                KEY_AUTHORIZATION,
                Duration::from_secs(60),
            )
            .expect("install challenge");
        assert!(matches!(
            registry.install(
                LISTENER,
                IDENTIFIER,
                TOKEN,
                KEY_AUTHORIZATION,
                Duration::from_secs(60)
            ),
            Err(HttpChallengeError::Collision)
        ));
        assert!(matches!(
            registry.install(
                LISTENER,
                IDENTIFIER,
                "../token",
                KEY_AUTHORIZATION,
                Duration::from_secs(60)
            ),
            Err(HttpChallengeError::Invalid)
        ));
        assert!(matches!(
            registry.install(
                LISTENER,
                IDENTIFIER,
                "token",
                b"bad\r\n",
                Duration::from_secs(60)
            ),
            Err(HttpChallengeError::Invalid)
        ));
        assert!(matches!(
            registry.install(
                LISTENER,
                "*.example.test",
                "token",
                KEY_AUTHORIZATION,
                Duration::from_secs(60)
            ),
            Err(HttpChallengeError::Invalid)
        ));
    }

    #[test]
    fn expired_entries_are_removed_before_capacity_check() {
        let registry = HttpChallengeRegistry::default();
        for index in 0..MAX_CHALLENGES {
            let lease = registry
                .install(
                    LISTENER,
                    IDENTIFIER,
                    &format!("token{index}"),
                    KEY_AUTHORIZATION,
                    Duration::from_secs(60),
                )
                .expect("install expiring challenge");
            std::mem::forget(lease);
        }
        registry
            .state
            .lock()
            .expect("registry lock")
            .challenges
            .values_mut()
            .for_each(|challenge| challenge.expires_at = Instant::now());
        let lease = registry
            .install(
                LISTENER,
                IDENTIFIER,
                "fresh",
                KEY_AUTHORIZATION,
                Duration::from_secs(60),
            )
            .expect("expired challenges must not consume capacity");
        drop(lease);
    }
}
