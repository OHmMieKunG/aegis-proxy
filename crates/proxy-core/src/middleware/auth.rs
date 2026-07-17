use std::{collections::HashMap, sync::Arc, time::Duration};

use aegisproxy_config::{Config, MiddlewareConfig, RouteConfig};
use aegisproxy_secrets::{SecretBytes, SecretRef};
use argon2::{ARGON2ID_IDENT, Argon2, Params, PasswordHash, PasswordVerifier};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hyper::{HeaderMap, header::AUTHORIZATION};
use thiserror::Error;
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

const MAX_HASH_BYTES: usize = 1_024;
const MAX_AUTHORIZATION_BYTES: usize = 2_048;
const MAX_PASSWORD_BYTES: usize = 1_024;

pub(crate) type BasicAuthPolicies = Arc<HashMap<String, Arc<BasicAuthPolicy>>>;

#[derive(Debug)]
pub(crate) struct BasicAuthPolicy {
    realm: String,
    users: HashMap<String, Arc<SecretBytes>>,
    fallback: Arc<SecretBytes>,
    semaphore: Arc<Semaphore>,
    timeout: Duration,
}

#[derive(Debug, Error)]
pub(crate) enum BuildError {
    #[error("Basic authentication secret could not be loaded")]
    Secret,
    #[error("Basic authentication hash is invalid or outside the approved Argon2id policy")]
    Hash,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum Outcome {
    NotConfigured,
    Authenticated(String),
    Unauthorized(String),
    Unavailable,
}

pub(crate) fn build(config: &Config) -> Result<BasicAuthPolicies, BuildError> {
    let mut policies = HashMap::new();
    let mut total_memory_kib = 0_usize;
    let mut total_iteration_slots = 0_usize;
    for (id, definition) in &config.middlewares {
        let MiddlewareConfig::BasicAuth {
            realm,
            users,
            max_concurrent_verifications,
            timeout_secs,
        } = definition
        else {
            continue;
        };
        let mut resolved = HashMap::with_capacity(users.len());
        let mut approved_cost = None;
        for (username, reference) in users {
            let secret = SecretRef::parse(reference)
                .map_err(|_| BuildError::Secret)?
                .resolve(MAX_HASH_BYTES)
                .map_err(|_| BuildError::Secret)?;
            let cost = validate_hash(secret.as_ref())?;
            if approved_cost.is_some_and(|approved| approved != cost) {
                return Err(BuildError::Hash);
            }
            approved_cost = Some(cost);
            resolved.insert(username.clone(), Arc::new(secret));
        }
        let Some((memory_kib, iterations, _)) = approved_cost else {
            return Err(BuildError::Hash);
        };
        let memory_kib = usize::try_from(memory_kib)
            .ok()
            .and_then(|memory| memory.checked_mul(*max_concurrent_verifications))
            .ok_or(BuildError::Hash)?;
        let iteration_slots = usize::try_from(iterations)
            .ok()
            .and_then(|iterations| iterations.checked_mul(*max_concurrent_verifications))
            .ok_or(BuildError::Hash)?;
        total_memory_kib = total_memory_kib
            .checked_add(memory_kib)
            .ok_or(BuildError::Hash)?;
        total_iteration_slots = total_iteration_slots
            .checked_add(iteration_slots)
            .ok_or(BuildError::Hash)?;
        if total_memory_kib > 512 * 1024 || total_iteration_slots > 64 {
            return Err(BuildError::Hash);
        }
        let fallback = resolved.values().next().cloned().ok_or(BuildError::Hash)?;
        policies.insert(
            id.clone(),
            Arc::new(BasicAuthPolicy {
                realm: realm.clone(),
                users: resolved,
                fallback,
                semaphore: Arc::new(Semaphore::new(*max_concurrent_verifications)),
                timeout: Duration::from_secs(*timeout_secs),
            }),
        );
    }
    Ok(Arc::new(policies))
}

pub(crate) async fn authenticate(
    policies: &BasicAuthPolicies,
    config: &Config,
    route: &RouteConfig,
    headers: &HeaderMap,
) -> Outcome {
    let Some(id) = route.middlewares.iter().find(|id| {
        matches!(
            config.middlewares.get(id.as_str()),
            Some(MiddlewareConfig::BasicAuth { .. })
        )
    }) else {
        return Outcome::NotConfigured;
    };
    let Some(policy) = policies.get(id) else {
        return Outcome::Unavailable;
    };
    let Some((username, password)) = credentials(headers) else {
        return Outcome::Unauthorized(policy.realm.clone());
    };
    let known = policy.users.get(&username).cloned();
    let hash = known
        .clone()
        .unwrap_or_else(|| Arc::clone(&policy.fallback));
    let Ok(permit) = Arc::clone(&policy.semaphore).try_acquire_owned() else {
        return Outcome::Unavailable;
    };
    let verification = tokio::task::spawn_blocking(move || {
        let _permit = permit;
        verify(&password, hash.as_ref())
    });
    match tokio::time::timeout(policy.timeout, verification).await {
        Ok(Ok(true)) if known.is_some() => Outcome::Authenticated(username),
        Ok(Ok(_)) => Outcome::Unauthorized(policy.realm.clone()),
        Ok(Err(_)) | Err(_) => Outcome::Unavailable,
    }
}

fn credentials(headers: &HeaderMap) -> Option<(String, Zeroizing<Vec<u8>>)> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() || value.len() > MAX_AUTHORIZATION_BYTES {
        return None;
    }
    let (scheme, encoded) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") || encoded.is_empty() || encoded.contains(' ') {
        return None;
    }
    let decoded = Zeroizing::new(STANDARD.decode(encoded).ok()?);
    if decoded.len() > MAX_PASSWORD_BYTES + 65 {
        return None;
    }
    let separator = decoded.iter().position(|byte| *byte == b':')?;
    let username = std::str::from_utf8(&decoded[..separator]).ok()?.to_owned();
    if username.is_empty() || username.len() > 64 {
        return None;
    }
    let password = Zeroizing::new(decoded[separator + 1..].to_vec());
    if password.len() > MAX_PASSWORD_BYTES {
        return None;
    }
    Some((username, password))
}

fn validate_hash(bytes: &[u8]) -> Result<(u32, u32, u32), BuildError> {
    let value = std::str::from_utf8(bytes).map_err(|_| BuildError::Hash)?;
    let hash = PasswordHash::new(value).map_err(|_| BuildError::Hash)?;
    if hash.algorithm != ARGON2ID_IDENT || hash.version != Some(0x13) {
        return Err(BuildError::Hash);
    }
    let params = Params::try_from(&hash).map_err(|_| BuildError::Hash)?;
    if !(8_192..=65_536).contains(&params.m_cost())
        || !(1..=10).contains(&params.t_cost())
        || !(1..=4).contains(&params.p_cost())
        || hash.salt.is_none()
        || hash.hash.is_none()
    {
        return Err(BuildError::Hash);
    }
    Ok((params.m_cost(), params.t_cost(), params.p_cost()))
}

fn verify(password: &[u8], hash: &SecretBytes) -> bool {
    let Ok(value) = std::str::from_utf8(hash.as_ref()) else {
        return false;
    };
    let Ok(hash) = PasswordHash::new(value) else {
        return false;
    };
    Argon2::default().verify_password(password, &hash).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use argon2::PasswordHasher;
    use argon2::password_hash::SaltString;
    use hyper::header::HeaderValue;
    use std::{
        collections::BTreeMap,
        fs,
        sync::atomic::{AtomicU64, Ordering},
    };

    #[tokio::test]
    async fn verifies_known_user_and_returns_one_generic_denial() {
        static SEQUENCE: AtomicU64 = AtomicU64::new(0);
        let salt = SaltString::encode_b64(b"0123456789abcdef").expect("salt");
        let hash = Argon2::default()
            .hash_password(b"correct horse", &salt)
            .expect("hash")
            .to_string();
        let path = std::env::temp_dir().join(format!(
            "aegisproxy-basic-auth-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, hash).expect("write hash");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("permissions");
        }

        let mut config: Config = toml::from_str(
            r#"
            schema_version = 1
            [[listeners]]
            id = "public"
            bind = "127.0.0.1:8443"
            protocol = "https"
        "#,
        )
        .expect("test config");
        config.middlewares = BTreeMap::from([(
            "basic".into(),
            MiddlewareConfig::BasicAuth {
                realm: "Private".into(),
                users: BTreeMap::from([("alice".into(), format!("file://{}", path.display()))]),
                max_concurrent_verifications: 2,
                timeout_secs: 5,
            },
        )]);
        let policies = build(&config).expect("build policies");
        let route = test_route();

        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!(
                "Basic {}",
                STANDARD.encode(b"alice:correct horse")
            ))
            .expect("header"),
        );
        assert_eq!(
            authenticate(&policies, &config, &route, &headers).await,
            Outcome::Authenticated("alice".into())
        );

        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", STANDARD.encode(b"unknown:wrong")))
                .expect("header"),
        );
        assert_eq!(
            authenticate(&policies, &config, &route, &headers).await,
            Outcome::Unauthorized("Private".into())
        );
        let Some(MiddlewareConfig::BasicAuth {
            max_concurrent_verifications,
            ..
        }) = config.middlewares.get_mut("basic")
        else {
            panic!("Basic auth policy");
        };
        *max_concurrent_verifications = 100;
        assert!(build(&config).is_err());
        fs::remove_file(path).expect("remove hash");
    }

    #[test]
    fn rejects_unbounded_argon2_parameters() {
        let salt = SaltString::encode_b64(b"0123456789abcdef").expect("salt");
        let hash = Argon2::default()
            .hash_password(b"password", &salt)
            .expect("hash")
            .to_string()
            .replace("m=19456", "m=999999");
        assert!(validate_hash(hash.as_bytes()).is_err());
    }

    fn test_route() -> RouteConfig {
        RouteConfig {
            id: "route".into(),
            listeners: vec!["public".into()],
            hosts: vec![],
            paths: vec![],
            path_prefixes: vec![],
            methods: vec![],
            headers: vec![],
            default: true,
            priority: 0,
            middlewares: vec!["basic".into()],
            upstream_group: Some("app".into()),
        }
    }
}
