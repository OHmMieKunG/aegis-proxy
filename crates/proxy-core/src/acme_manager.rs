use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use aegisproxy_config::{
    AcmeCertificateConfig, AcmeChallenge, AcmeDnsProviderConfig, AcmeEnvironment, AcmeIssuerConfig,
    Config,
};
use aegisproxy_secrets::{SecretBytes, SecretRef};
use aegisproxy_tls::{
    ManagedCertificateEnvironment, ManagedCertificateProvenance,
    acme::{
        AcmeAccountCreateRequest, AcmeChallengeKind, AcmeClient, AcmeExternalAccountBinding,
        AcmeOrderRequest, CertificateOrderLock, CloudflareDnsProvider, CloudflareDnsRecord,
        HttpChallengeLease, StoredAcmeEnvironment, TlsAlpnChallengeLease, expiry_alert_days,
        fallback_renewal_schedule, load_account_generation, persist_account_generation,
        retry_delay,
    },
    inspect_certificate, persist_managed_certificate,
};
use hickory_resolver::{Resolver, TokioResolver, proto::rr::RData};
use thiserror::Error;
use tokio::sync::Semaphore;
use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::RuntimeHandle;

const RECONCILE_INTERVAL: Duration = Duration::from_secs(60);
const CHALLENGE_LIFETIME: Duration = Duration::from_secs(5 * 60);
const AUTHORIZATION_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const CERTIFICATE_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const DNS_PROPAGATION_TIMEOUT: Duration = Duration::from_secs(2 * 60);
const DNS_LOOKUP_TIMEOUT: Duration = Duration::from_secs(5);
const DNS_RETRY_INTERVAL: Duration = Duration::from_secs(2);
const MAX_DNS_CHALLENGE_ANSWERS: usize = 32;
const MAX_DNS_CHALLENGE_VALUE_BYTES: usize = 2 * 1024;
const MAX_STATE_IDENTITY_BYTES: usize = 16 * 1024;
const MAX_EAB_KEY_BYTES: usize = 4 * 1024;

#[derive(Debug, Error)]
enum ManagerError {
    #[error("ACME state operation failed")]
    State,
    #[error("ACME account operation failed")]
    Account,
    #[error("ACME order operation failed")]
    Order,
    #[error("ACME challenge operation failed")]
    Challenge,
    #[error("ACME DNS operation failed")]
    Dns,
    #[error("ACME runtime publication failed")]
    Runtime,
}

struct ProvisionedChallenges {
    _http: Vec<HttpChallengeLease>,
    _tls: Vec<TlsAlpnChallengeLease>,
    dns_provider: Option<CloudflareDnsProvider>,
    dns: Vec<CloudflareDnsRecord>,
    dns_values: Vec<String>,
}

struct CertificateSchedule {
    due: bool,
    expiry_alert_days: Option<u16>,
}

impl ProvisionedChallenges {
    async fn cleanup(self) -> Result<(), ManagerError> {
        let mut failed = false;
        if let Some(provider) = self.dns_provider {
            for record in &self.dns {
                if provider.cleanup(record).await.is_err() {
                    failed = true;
                }
            }
        }
        drop(self._http);
        drop(self._tls);
        if failed {
            Err(ManagerError::Dns)
        } else {
            Ok(())
        }
    }
}

pub(crate) fn start(runtime: RuntimeHandle, shutdown: CancellationToken) -> TaskTracker {
    let tasks = TaskTracker::new();
    tasks.spawn(run(runtime, shutdown));
    tasks.close();
    tasks
}

async fn run(runtime: RuntimeHandle, shutdown: CancellationToken) {
    let mut attempts = HashMap::<String, u32>::new();
    let mut retry_at = HashMap::<String, tokio::time::Instant>::new();
    let mut expiry_alerts = HashMap::<String, u16>::new();
    loop {
        if let Err(error) = reconcile(
            &runtime,
            &mut attempts,
            &mut retry_at,
            &mut expiry_alerts,
            &shutdown,
        )
        .await
        {
            tracing::error!(%error, "ACME reconciliation failed");
        }
        tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            _ = tokio::time::sleep(RECONCILE_INTERVAL) => {}
        }
    }
}

async fn reconcile(
    runtime: &RuntimeHandle,
    attempts: &mut HashMap<String, u32>,
    retry_at: &mut HashMap<String, tokio::time::Instant>,
    expiry_alerts: &mut HashMap<String, u16>,
    shutdown: &CancellationToken,
) -> Result<(), ManagerError> {
    let snapshot = runtime.load();
    let config = Arc::clone(&snapshot.config);
    drop(snapshot);
    attempts.retain(|id, _| {
        config
            .acme
            .certificates
            .iter()
            .any(|certificate| certificate.id == *id)
    });
    retry_at.retain(|id, _| {
        config
            .acme
            .certificates
            .iter()
            .any(|certificate| certificate.id == *id)
    });
    expiry_alerts.retain(|id, _| {
        config
            .acme
            .certificates
            .iter()
            .any(|certificate| certificate.id == *id)
    });
    if config.acme.certificates.is_empty() {
        return Ok(());
    }
    let now = unix_now()?;
    let mut due = Vec::new();
    for certificate in &config.acme.certificates {
        if retry_at
            .get(&certificate.id)
            .is_some_and(|deadline| *deadline > tokio::time::Instant::now())
        {
            continue;
        }
        match certificate_schedule(&config, certificate, now).await {
            Ok(schedule) => {
                match schedule.expiry_alert_days {
                    Some(days) if expiry_alerts.get(&certificate.id) != Some(&days) => {
                        tracing::warn!(
                            certificate = %certificate.id,
                            days_remaining = days,
                            "ACME certificate expiry threshold reached"
                        );
                        expiry_alerts.insert(certificate.id.clone(), days);
                    }
                    None => {
                        expiry_alerts.remove(&certificate.id);
                    }
                    _ => {}
                }
                if schedule.due {
                    due.push(certificate.clone());
                    continue;
                }
                attempts.remove(&certificate.id);
                retry_at.remove(&certificate.id);
            }
            Err(error) => {
                tracing::error!(certificate = %certificate.id, %error, "ACME schedule inspection failed")
            }
        }
    }
    if due.is_empty() {
        return Ok(());
    }

    let mut clients = HashMap::new();
    for issuer in &config.acme.issuers {
        if !due
            .iter()
            .any(|certificate| certificate.issuer == issuer.id)
        {
            continue;
        }
        match initialize_client(&config, issuer).await {
            Ok(client) => {
                clients.insert(issuer.id.clone(), client);
            }
            Err(error) => tracing::error!(issuer = %issuer.id, %error, "ACME account unavailable"),
        }
    }

    let global = Arc::new(Semaphore::new(config.acme.max_concurrent_orders));
    let issuer_limits = config
        .acme
        .issuers
        .iter()
        .map(|issuer| {
            (
                issuer.id.clone(),
                Arc::new(Semaphore::new(issuer.max_concurrent_orders)),
            )
        })
        .collect::<HashMap<_, _>>();
    let mut orders = tokio::task::JoinSet::new();
    for certificate in due {
        let Some(client) = clients.get(&certificate.issuer).cloned() else {
            record_failure(&certificate.id, attempts, retry_at);
            continue;
        };
        let Some(issuer) = config
            .acme
            .issuers
            .iter()
            .find(|issuer| issuer.id == certificate.issuer)
            .cloned()
        else {
            record_failure(&certificate.id, attempts, retry_at);
            continue;
        };
        let Some(issuer_limit) = issuer_limits.get(&issuer.id).cloned() else {
            record_failure(&certificate.id, attempts, retry_at);
            continue;
        };
        let global = Arc::clone(&global);
        let runtime = runtime.clone();
        let config = Arc::clone(&config);
        let shutdown = shutdown.clone();
        orders.spawn(async move {
            let id = certificate.id.clone();
            let result = async {
                if shutdown.is_cancelled() {
                    return Err(ManagerError::State);
                }
                let _global = global
                    .acquire_owned()
                    .await
                    .map_err(|_| ManagerError::State)?;
                let _issuer = issuer_limit
                    .acquire_owned()
                    .await
                    .map_err(|_| ManagerError::State)?;
                issue(&runtime, &config, &issuer, &certificate, &client).await
            }
            .await;
            (id, result)
        });
    }
    while let Some(result) = orders.join_next().await {
        match result {
            Ok((id, Ok(()))) => {
                attempts.remove(&id);
                retry_at.remove(&id);
                tracing::info!(certificate = %id, "ACME certificate activated");
            }
            Ok((id, Err(error))) => {
                tracing::error!(certificate = %id, %error, "ACME certificate order failed");
                record_failure(&id, attempts, retry_at);
            }
            Err(error) => tracing::error!(%error, "ACME order task failed"),
        }
    }
    Ok(())
}

async fn certificate_schedule(
    config: &Config,
    certificate: &AcmeCertificateConfig,
    now: u64,
) -> Result<CertificateSchedule, ManagerError> {
    let state_dir = PathBuf::from(&config.runtime.state_dir);
    let id = certificate.id.clone();
    let renew_before_days = certificate.renew_before_days;
    tokio::task::spawn_blocking(move || {
        if !state_dir.join("certificates").join(&id).exists() {
            return Ok(CertificateSchedule {
                due: true,
                expiry_alert_days: None,
            });
        }
        let metadata = inspect_certificate(&state_dir, &id).map_err(|_| ManagerError::State)?;
        let schedule = fallback_renewal_schedule(
            &id,
            metadata.not_before_unix_secs,
            metadata.not_after_unix_secs,
            now,
            renew_before_days,
        )
        .map_err(|_| ManagerError::State)?;
        Ok(CertificateSchedule {
            due: schedule.renew_at_unix_secs <= now,
            expiry_alert_days: expiry_alert_days(metadata.not_after_unix_secs, now),
        })
    })
    .await
    .map_err(|_| ManagerError::State)?
}

async fn initialize_client(
    config: &Config,
    issuer: &AcmeIssuerConfig,
) -> Result<AcmeClient, ManagerError> {
    let state_dir = PathBuf::from(&config.runtime.state_dir);
    let account_pointer = state_dir
        .join("acme")
        .join("accounts")
        .join(&issuer.id)
        .join("current.json");
    let account_exists = tokio::task::spawn_blocking(move || account_pointer.exists())
        .await
        .map_err(|_| ManagerError::State)?;
    if account_exists {
        let identity = resolve_secret(
            config.tls.identity.as_deref().ok_or(ManagerError::State)?,
            MAX_STATE_IDENTITY_BYTES,
        )
        .await?;
        let issuer_id = issuer.id.clone();
        let directory = issuer.directory_url.to_string();
        let environment = stored_environment(issuer.environment);
        let (_, credentials) = tokio::task::spawn_blocking(move || {
            load_account_generation(
                &state_dir,
                &issuer_id,
                &directory,
                environment,
                identity.as_ref(),
            )
        })
        .await
        .map_err(|_| ManagerError::State)?
        .map_err(|_| ManagerError::State)?;
        return AcmeClient::restore(credentials.as_ref(), issuer.ca_bundle.as_deref())
            .await
            .map_err(|_| ManagerError::Account);
    }

    let hmac_key = match issuer.external_account.as_ref() {
        Some(binding) => Some(resolve_secret(&binding.hmac_key, MAX_EAB_KEY_BYTES).await?),
        None => None,
    };
    let external_account =
        issuer
            .external_account
            .as_ref()
            .zip(hmac_key.as_ref())
            .map(|(binding, key)| AcmeExternalAccountBinding {
                key_id: &binding.key_id,
                hmac_key: key.as_ref(),
            });
    let (client, credentials) = AcmeClient::create(
        AcmeAccountCreateRequest {
            directory_url: &issuer.directory_url,
            account_email: issuer.account_email.as_deref(),
            terms_of_service_agreed: issuer.terms_of_service_agreed,
            external_account,
        },
        issuer.ca_bundle.as_deref(),
    )
    .await
    .map_err(|_| ManagerError::Account)?;
    let issuer_id = issuer.id.clone();
    let directory = issuer.directory_url.to_string();
    let environment = stored_environment(issuer.environment);
    let recipients = config.tls.state_encryption_recipients.clone();
    tokio::task::spawn_blocking(move || {
        persist_account_generation(
            &state_dir,
            &issuer_id,
            &directory,
            environment,
            credentials.as_slice(),
            &recipients,
        )
    })
    .await
    .map_err(|_| ManagerError::State)?
    .map_err(|_| ManagerError::State)?;
    Ok(client)
}

async fn issue(
    runtime: &RuntimeHandle,
    config: &Config,
    issuer: &AcmeIssuerConfig,
    certificate: &AcmeCertificateConfig,
    client: &AcmeClient,
) -> Result<(), ManagerError> {
    let _order_lock =
        CertificateOrderLock::acquire(Path::new(&config.runtime.state_dir), &certificate.id)
            .await
            .map_err(|_| ManagerError::State)?;
    let mut order = client
        .new_order(AcmeOrderRequest {
            identifiers: &certificate.hosts,
            challenge: challenge_kind(certificate.challenge),
            profile: certificate.profile.as_deref(),
        })
        .await
        .map_err(|_| ManagerError::Order)?;
    let material = order
        .prepare_challenges()
        .await
        .map_err(|_| ManagerError::Order)?;
    let challenges = provision(runtime, config, certificate, &material).await?;
    let authorization = async {
        order
            .notify_challenges_ready()
            .await
            .map_err(|_| ManagerError::Order)?;
        order
            .poll_ready(AUTHORIZATION_TIMEOUT)
            .await
            .map_err(|_| ManagerError::Order)
    }
    .await;
    let cleanup = challenges.cleanup().await;
    authorization?;
    cleanup?;
    order.finalize().await.map_err(|_| ManagerError::Order)?;
    let issued = order
        .poll_certificate(CERTIFICATE_TIMEOUT)
        .await
        .map_err(|_| ManagerError::Order)?;
    let identity = issued
        .runtime_identity(certificate.id.clone(), certificate.hosts.clone())
        .map_err(|_| ManagerError::Order)?;

    let _runtime_guard = runtime.lock_mutation().await;
    let active = runtime.load();
    let active_certificate = active
        .config
        .acme
        .certificates
        .iter()
        .find(|active| active.id == certificate.id)
        .ok_or(ManagerError::Runtime)?;
    let active_issuer = active
        .config
        .acme
        .issuers
        .iter()
        .find(|active| active.id == issuer.id)
        .ok_or(ManagerError::Runtime)?;
    if !same_certificate_policy(active_certificate, certificate)
        || !same_issuer_policy(active_issuer, issuer)
    {
        return Err(ManagerError::Runtime);
    }
    drop(active);
    let prepared = runtime
        .prepare_certificate_publication(&certificate.id, identity)
        .map_err(|_| ManagerError::Runtime)?;
    let state_dir = PathBuf::from(&config.runtime.state_dir);
    let id = certificate.id.clone();
    let hosts = certificate.hosts.clone();
    let chain = issued.certificate_chain_pem().to_vec();
    let key = issued.private_key_pem().to_vec();
    let provenance = ManagedCertificateProvenance {
        issuer_id: issuer.id.clone(),
        environment: managed_environment(issuer.environment),
        profile: certificate.profile.clone(),
    };
    let recipients = config.tls.state_encryption_recipients.clone();
    tokio::task::spawn_blocking(move || {
        persist_managed_certificate(
            &state_dir,
            &id,
            hosts,
            &chain,
            &key,
            provenance,
            &recipients,
        )
    })
    .await
    .map_err(|_| ManagerError::State)?
    .map_err(|_| ManagerError::State)?;
    runtime
        .publish_certificate(prepared)
        .map_err(|_| ManagerError::Runtime)
}

async fn provision(
    runtime: &RuntimeHandle,
    config: &Config,
    certificate: &AcmeCertificateConfig,
    material: &[aegisproxy_tls::acme::AcmeChallengeMaterial],
) -> Result<ProvisionedChallenges, ManagerError> {
    let mut provisioned = ProvisionedChallenges {
        _http: Vec::new(),
        _tls: Vec::new(),
        dns_provider: None,
        dns: Vec::new(),
        dns_values: Vec::new(),
    };
    let result = async {
        match certificate.challenge {
            AcmeChallenge::Http01 => {
                let listener = certificate
                    .challenge_listener
                    .as_deref()
                    .ok_or(ManagerError::Challenge)?;
                for challenge in material {
                    let response = challenge
                        .http_key_authorization()
                        .ok_or(ManagerError::Challenge)?;
                    provisioned._http.push(
                        runtime
                            .http_challenges()
                            .install(
                                listener,
                                challenge.identifier(),
                                challenge.token(),
                                response.as_bytes(),
                                CHALLENGE_LIFETIME,
                            )
                            .map_err(|_| ManagerError::Challenge)?,
                    );
                }
            }
            AcmeChallenge::TlsAlpn01 => {
                for challenge in material {
                    let digest = *challenge.tls_alpn_digest().ok_or(ManagerError::Challenge)?;
                    provisioned._tls.push(
                        runtime
                            .tls_challenges()
                            .install(challenge.identifier(), digest, CHALLENGE_LIFETIME)
                            .await
                            .map_err(|_| ManagerError::Challenge)?,
                    );
                }
            }
            AcmeChallenge::Dns01 => {
                let provider_id = certificate
                    .dns_provider
                    .as_deref()
                    .ok_or(ManagerError::Dns)?;
                let provider = cloudflare_provider(config, provider_id).await?;
                for challenge in material {
                    let value = challenge.dns_value().ok_or(ManagerError::Challenge)?;
                    provisioned.dns.push(
                        provider
                            .present(challenge.identifier(), value)
                            .await
                            .map_err(|_| ManagerError::Dns)?,
                    );
                    provisioned.dns_values.push(value.to_owned());
                }
                provisioned.dns_provider = Some(provider);
                wait_for_dns_propagation(&provisioned.dns, &provisioned.dns_values).await?;
            }
        }
        Ok(())
    }
    .await;
    if let Err(error) = result {
        if let Err(cleanup) = provisioned.cleanup().await {
            tracing::error!(%cleanup, "ACME partial challenge cleanup failed");
        }
        return Err(error);
    }
    Ok(provisioned)
}

async fn wait_for_dns_propagation(
    records: &[CloudflareDnsRecord],
    values: &[String],
) -> Result<(), ManagerError> {
    if records.is_empty() || records.len() != values.len() || records.len() > 64 {
        return Err(ManagerError::Dns);
    }
    let resolver = tokio::task::spawn_blocking(|| {
        let mut builder = Resolver::builder_tokio().map_err(|_| ManagerError::Dns)?;
        let options = builder.options_mut();
        options.attempts = 1;
        options.num_concurrent_reqs = 1;
        options.max_active_requests = 16;
        options.cache_size = 0;
        builder.build().map(Arc::new).map_err(|_| ManagerError::Dns)
    })
    .await
    .map_err(|_| ManagerError::Dns)??;
    let mut expected = HashMap::<String, Vec<Vec<u8>>>::new();
    for (record, value) in records.iter().zip(values) {
        expected
            .entry(record.name().to_owned())
            .or_default()
            .push(value.as_bytes().to_vec());
    }
    let deadline = tokio::time::Instant::now() + DNS_PROPAGATION_TIMEOUT;
    loop {
        if dns_values_visible(&resolver, &expected).await {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(ManagerError::Dns);
        }
        tokio::time::sleep(DNS_RETRY_INTERVAL).await;
    }
}

async fn dns_values_visible(
    resolver: &Arc<TokioResolver>,
    expected: &HashMap<String, Vec<Vec<u8>>>,
) -> bool {
    let mut lookups = tokio::task::JoinSet::new();
    for (name, values) in expected {
        let resolver = Arc::clone(resolver);
        let query = format!("{name}.");
        let values = values.clone();
        lookups.spawn(async move {
            let lookup = tokio::time::timeout(DNS_LOOKUP_TIMEOUT, resolver.txt_lookup(query))
                .await
                .ok()?
                .ok()?;
            let mut answers = 0_usize;
            let mut found = vec![false; values.len()];
            for answer in lookup.answers() {
                let RData::TXT(txt) = &answer.data else {
                    continue;
                };
                answers += 1;
                if answers > MAX_DNS_CHALLENGE_ANSWERS {
                    return None;
                }
                for (index, expected) in values.iter().enumerate() {
                    if txt_value_matches(&txt.txt_data, expected) {
                        found[index] = true;
                    }
                }
            }
            found.into_iter().all(|value| value).then_some(())
        });
    }
    while let Some(result) = lookups.join_next().await {
        if !matches!(result, Ok(Some(()))) {
            return false;
        }
    }
    true
}

fn txt_value_matches(segments: &[Box<[u8]>], expected: &[u8]) -> bool {
    let total = segments.iter().map(|segment| segment.len()).sum::<usize>();
    if total > MAX_DNS_CHALLENGE_VALUE_BYTES || total != expected.len() {
        return false;
    }
    segments
        .iter()
        .flat_map(|segment| segment.iter().copied())
        .eq(expected.iter().copied())
}

async fn cloudflare_provider(
    config: &Config,
    provider_id: &str,
) -> Result<CloudflareDnsProvider, ManagerError> {
    let provider = config
        .acme
        .dns_providers
        .iter()
        .find(|provider| match provider {
            AcmeDnsProviderConfig::Cloudflare { id, .. } => id == provider_id,
        })
        .ok_or(ManagerError::Dns)?;
    match provider {
        AcmeDnsProviderConfig::Cloudflare {
            zone_id, api_token, ..
        } => CloudflareDnsProvider::new(zone_id.clone(), api_token)
            .await
            .map_err(|_| ManagerError::Dns),
    }
}

async fn resolve_secret(reference: &str, max_bytes: usize) -> Result<SecretBytes, ManagerError> {
    let reference = SecretRef::parse(reference).map_err(|_| ManagerError::State)?;
    tokio::task::spawn_blocking(move || reference.resolve(max_bytes))
        .await
        .map_err(|_| ManagerError::State)?
        .map_err(|_| ManagerError::State)
}

fn record_failure(
    id: &str,
    attempts: &mut HashMap<String, u32>,
    retry_at: &mut HashMap<String, tokio::time::Instant>,
) {
    let attempt = attempts.entry(id.to_owned()).or_insert(0);
    let delay = retry_delay(id, *attempt);
    *attempt = attempt.saturating_add(1);
    retry_at.insert(id.to_owned(), tokio::time::Instant::now() + delay);
}

fn challenge_kind(challenge: AcmeChallenge) -> AcmeChallengeKind {
    match challenge {
        AcmeChallenge::Http01 => AcmeChallengeKind::Http01,
        AcmeChallenge::Dns01 => AcmeChallengeKind::Dns01,
        AcmeChallenge::TlsAlpn01 => AcmeChallengeKind::TlsAlpn01,
    }
}

fn stored_environment(environment: AcmeEnvironment) -> StoredAcmeEnvironment {
    match environment {
        AcmeEnvironment::Production => StoredAcmeEnvironment::Production,
        AcmeEnvironment::Staging => StoredAcmeEnvironment::Staging,
    }
}

fn managed_environment(environment: AcmeEnvironment) -> ManagedCertificateEnvironment {
    match environment {
        AcmeEnvironment::Production => ManagedCertificateEnvironment::Production,
        AcmeEnvironment::Staging => ManagedCertificateEnvironment::Staging,
    }
}

fn same_certificate_policy(left: &AcmeCertificateConfig, right: &AcmeCertificateConfig) -> bool {
    left.id == right.id
        && left.hosts == right.hosts
        && left.issuer == right.issuer
        && left.challenge == right.challenge
        && left.challenge_listener == right.challenge_listener
        && left.dns_provider == right.dns_provider
        && left.profile == right.profile
        && left.renew_before_days == right.renew_before_days
}

fn same_issuer_policy(left: &AcmeIssuerConfig, right: &AcmeIssuerConfig) -> bool {
    left.id == right.id
        && left.directory_url == right.directory_url
        && left.environment == right.environment
        && left.account_email == right.account_email
        && left.terms_of_service_agreed == right.terms_of_service_agreed
        && left.ca_bundle == right.ca_bundle
        && left.max_concurrent_orders == right.max_concurrent_orders
        && match (&left.external_account, &right.external_account) {
            (None, None) => true,
            (Some(left), Some(right)) => {
                left.key_id == right.key_id && left.hmac_key == right.hmac_key
            }
            _ => false,
        }
}

fn unix_now() -> Result<u64, ManagerError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|_| ManagerError::State)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_state_is_bounded_and_advances() {
        let mut attempts = HashMap::new();
        let mut retry_at = HashMap::new();
        record_failure("site", &mut attempts, &mut retry_at);
        assert_eq!(attempts.get("site"), Some(&1));
        assert!(retry_at["site"] > tokio::time::Instant::now());
        for _ in 0..100 {
            record_failure("site", &mut attempts, &mut retry_at);
        }
        assert_eq!(attempts.get("site"), Some(&101));
        assert!(retry_at.len() == 1);
    }

    #[test]
    fn environment_classification_is_explicit() {
        assert_eq!(
            stored_environment(AcmeEnvironment::Staging),
            StoredAcmeEnvironment::Staging
        );
        assert_eq!(
            managed_environment(AcmeEnvironment::Production),
            ManagedCertificateEnvironment::Production
        );
    }

    #[test]
    fn txt_matching_is_exact_bounded_and_joins_segments() {
        let segments = vec![
            b"first".to_vec().into_boxed_slice(),
            b"second".to_vec().into_boxed_slice(),
        ];
        assert!(txt_value_matches(&segments, b"firstsecond"));
        assert!(!txt_value_matches(&segments, b"first"));
        assert!(!txt_value_matches(
            &[vec![b'x'; MAX_DNS_CHALLENGE_VALUE_BYTES + 1].into_boxed_slice()],
            &vec![b'x'; MAX_DNS_CHALLENGE_VALUE_BYTES + 1]
        ));
    }
}
