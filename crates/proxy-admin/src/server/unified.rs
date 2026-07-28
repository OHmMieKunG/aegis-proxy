use super::*;

pub(super) enum DesiredOverride {
    ProxyHosts(Vec<ApiObject<ProxyHostSpec>>),
    StreamHosts(Vec<ApiObject<StreamHostSpec>>),
    DiscoverySources(Vec<ApiObject<DiscoverySourceSpec>>),
}

struct DesiredState {
    proxy_hosts: Vec<ApiObject<ProxyHostSpec>>,
    stream_hosts: Vec<ApiObject<StreamHostSpec>>,
    discovery_sources: Vec<ApiObject<DiscoverySourceSpec>>,
}

pub(super) async fn create_unified_candidate(
    state: &AppState,
    principal: &Principal,
    audit: &MutationAudit,
    expected_revision: &str,
    desired_override: DesiredOverride,
    source_domain: &str,
) -> Result<RevisionMetadata, ApiError> {
    let active = state.control.runtime().config();
    let current = active_typed_state(state, expected_revision, audit).await?;
    let mut desired = desired_state(state, audit).await?;
    match desired_override {
        DesiredOverride::ProxyHosts(objects) => desired.proxy_hosts = objects,
        DesiredOverride::StreamHosts(objects) => desired.stream_hosts = objects,
        DesiredOverride::DiscoverySources(objects) => desired.discovery_sources = objects,
    }
    let (access_policy_records, access_policies) =
        access_policy_dependencies(state, Arc::clone(&active), &desired.proxy_hosts).await?;
    let (certificate_records, certificates) =
        certificate_dependencies(state, Arc::clone(&active), &desired.proxy_hosts, audit).await?;

    let current_proxy_hosts = current
        .as_ref()
        .map_or_else(Vec::new, |candidate| candidate.objects().to_vec());
    let current_stream_hosts = current
        .as_ref()
        .map_or_else(Vec::new, |candidate| candidate.stream_hosts().to_vec());
    let current_discovery_sources = current
        .as_ref()
        .map_or_else(Vec::new, |candidate| candidate.discovery_sources().to_vec());
    let desired_for_compile = DesiredState {
        proxy_hosts: desired.proxy_hosts.clone(),
        stream_hosts: desired.stream_hosts.clone(),
        discovery_sources: desired.discovery_sources.clone(),
    };
    let config = match tokio::task::spawn_blocking(move || {
        let config = crate::proxy_host::prepare_proxy_host_set(
            &current_proxy_hosts,
            &desired_for_compile.proxy_hosts,
            &active,
            &access_policies,
            &certificates,
        )
        .map_err(|_| ApiError::InvalidRequest)?
        .config()
        .clone();
        let config = crate::compile_stream_hosts(
            &config,
            &current_stream_hosts,
            &desired_for_compile.stream_hosts,
        )
        .map_err(|_| ApiError::InvalidRequest)?;
        crate::compile_discovery_sources(
            &config,
            &current_discovery_sources,
            &desired_for_compile.discovery_sources,
        )
        .map_err(|_| ApiError::InvalidRequest)
    })
    .await
    {
        Ok(Ok(config)) => config,
        Ok(Err(_)) => {
            return Err(audited_failure(
                audit,
                "invalid_typed_candidate",
                ApiError::InvalidRequest,
            )
            .await);
        }
        Err(_) => return Err(audited_failure(audit, "compile_failed", ApiError::Internal).await),
    };
    if state.control.runtime().revision().as_ref() != expected_revision {
        return Err(audited_failure(audit, "revision_conflict", ApiError::Conflict).await);
    }
    let binding_hash = ProxyHostStore::unified_binding_hash(
        &desired.proxy_hosts,
        &desired.stream_hosts,
        &desired.discovery_sources,
        &access_policy_records,
        &certificate_records,
    )
    .map_err(|_| ApiError::InvalidRequest)?;
    let revisions = state.control.revisions();
    let source = format!(
        "admin:{}:{}:{source_domain}",
        principal.actor_type, principal.actor_id
    );
    let revision_binding = binding_hash.clone();
    let (metadata, retained) = match tokio::task::spawn_blocking(move || {
        let metadata = revisions.create_bound_candidate(&config, &source, &revision_binding)?;
        Ok::<_, RevisionError>((metadata, revisions.list()?))
    })
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(RevisionError::InvalidConfig(_))) => {
            return Err(
                audited_failure(audit, "invalid_candidate", ApiError::InvalidRequest).await,
            );
        }
        Ok(Err(_)) | Err(_) => {
            return Err(
                audited_failure(audit, "revision_store_failed", ApiError::Unavailable).await,
            );
        }
    };
    let store = Arc::clone(&state.proxy_hosts);
    let revision_id = metadata.id.clone();
    let bound_hash = binding_hash;
    match tokio::task::spawn_blocking(move || {
        store.reconcile_candidates(&retained)?;
        store.bind_unified_candidate(
            &revision_id,
            &bound_hash,
            crate::UnifiedCandidateState {
                proxy_hosts: &desired.proxy_hosts,
                stream_hosts: &desired.stream_hosts,
                discovery_sources: &desired.discovery_sources,
                access_policies: &access_policy_records,
                certificates: &certificate_records,
            },
        )
    })
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(_)) | Err(_) => {
            return Err(
                audited_failure(audit, "candidate_binding_failed", ApiError::Unavailable).await,
            );
        }
    }
    if state.control.runtime().revision().as_ref() != expected_revision {
        return Err(audited_failure(audit, "revision_conflict", ApiError::Conflict).await);
    }
    Ok(metadata)
}

pub(super) async fn verify_unified_binding(
    state: &AppState,
    bound: &crate::BoundProxyHostCandidate,
    audit: &MutationAudit,
) -> Result<(), ApiError> {
    let desired = desired_state(state, audit).await?;
    let active = state.control.runtime().config();
    let (access_policies, _) =
        access_policy_dependencies(state, Arc::clone(&active), &desired.proxy_hosts).await?;
    let (certificates, _) =
        certificate_dependencies(state, active, &desired.proxy_hosts, audit).await?;
    if bound.objects() != desired.proxy_hosts
        || bound.stream_hosts() != desired.stream_hosts
        || bound.discovery_sources() != desired.discovery_sources
        || bound.access_policies() != access_policies
        || bound.certificates() != certificates
    {
        return Err(
            audited_failure(audit, "candidate_conflict", ApiError::CandidateConflict).await,
        );
    }
    Ok(())
}

pub(super) async fn rollback_unified_snapshot(
    state: &AppState,
    audit: &MutationAudit,
    expected_revision: &str,
    target_id: &str,
    target: crate::BoundProxyHostCandidate,
) -> Result<Response, ApiError> {
    let active = state.control.runtime().config();
    let (access_policies, _) =
        access_policy_dependencies(state, Arc::clone(&active), target.objects()).await?;
    let (certificates, _) =
        certificate_dependencies(state, active, target.objects(), audit).await?;
    if target.access_policies() != access_policies || target.certificates() != certificates {
        return Err(audited_failure(audit, "rollback_conflict", ApiError::CandidateConflict).await);
    }
    let revisions = state.control.revisions();
    let load_id = target_id.to_owned();
    let config = match tokio::task::spawn_blocking(move || revisions.load(&load_id)).await {
        Ok(Ok(config)) => config,
        Ok(Err(RevisionError::Io(error))) if error.kind() == std::io::ErrorKind::NotFound => {
            return Err(audited_failure(audit, "revision_not_found", ApiError::NotFound).await);
        }
        Ok(Err(_)) | Err(_) => {
            return Err(
                audited_failure(audit, "revision_store_failed", ApiError::Unavailable).await,
            );
        }
    };
    let binding_hash = ProxyHostStore::unified_binding_hash(
        target.objects(),
        target.stream_hosts(),
        target.discovery_sources(),
        target.access_policies(),
        target.certificates(),
    )
    .map_err(|_| ApiError::CandidateConflict)?;
    let revisions = state.control.revisions();
    let source = format!("rollback:typed:{target_id}");
    let revision_binding = binding_hash.clone();
    let (forward, retained) = match tokio::task::spawn_blocking(move || {
        let metadata =
            revisions.create_bound_forward_revision(&config, &source, &revision_binding)?;
        Ok::<_, RevisionError>((metadata, revisions.list()?))
    })
    .await
    {
        Ok(Ok(result)) => result,
        Ok(Err(_)) | Err(_) => {
            return Err(
                audited_failure(audit, "revision_store_failed", ApiError::Unavailable).await,
            );
        }
    };
    let store = Arc::clone(&state.proxy_hosts);
    let forward_id = forward.id.clone();
    let target_for_binding = target.clone();
    match tokio::task::spawn_blocking(move || {
        store.reconcile_candidates(&retained)?;
        store.bind_unified_candidate(
            &forward_id,
            &binding_hash,
            crate::UnifiedCandidateState {
                proxy_hosts: target_for_binding.objects(),
                stream_hosts: target_for_binding.stream_hosts(),
                discovery_sources: target_for_binding.discovery_sources(),
                access_policies: target_for_binding.access_policies(),
                certificates: target_for_binding.certificates(),
            },
        )
    })
    .await
    {
        Ok(Ok(_)) => {}
        Ok(Err(_)) | Err(_) => {
            return Err(
                audited_failure(audit, "candidate_binding_failed", ApiError::Unavailable).await,
            );
        }
    }
    if state.control.runtime().revision().as_ref() != expected_revision {
        return Err(audited_failure(audit, "revision_conflict", ApiError::Conflict).await);
    }
    let proxy_store = Arc::clone(&state.proxy_hosts);
    let stream_store = Arc::clone(&state.stream_hosts);
    let discovery_store = Arc::clone(&state.discovery_sources);
    let rollback_revision = forward.id.clone();
    let target_proxy = target.objects().to_vec();
    let target_stream = target.stream_hosts().to_vec();
    let target_discovery = target.discovery_sources().to_vec();
    let expected_epoch = proxy_store.snapshot().epoch();
    let replacements = tokio::task::spawn_blocking(move || {
        proxy_store
            .begin_rollback(&rollback_revision, &target_proxy, expected_epoch)
            .map_err(|_| ())?;
        let previous_stream = match stream_store.replace_all(target_stream) {
            Ok(previous) => previous,
            Err(_) => {
                let _ = proxy_store.abort_rollback(&rollback_revision);
                return Err(());
            }
        };
        let previous_discovery = match discovery_store.replace_all(target_discovery) {
            Ok(previous) => previous,
            Err(_) => {
                let _ = stream_store.restore_all(previous_stream);
                let _ = proxy_store.abort_rollback(&rollback_revision);
                return Err(());
            }
        };
        Ok::<_, ()>((previous_stream, previous_discovery))
    })
    .await;
    let (previous_stream, previous_discovery) = match replacements {
        Ok(Ok(previous)) => previous,
        Ok(Err(())) | Err(_) => {
            return Err(audited_failure(audit, "object_store_failed", ApiError::Unavailable).await);
        }
    };
    let result = match state
        .control
        .coordinator()
        .activate(&forward.id, Some(expected_revision))
        .await
    {
        Ok(result) => result,
        Err(error) => {
            let proxy_store = Arc::clone(&state.proxy_hosts);
            let stream_store = Arc::clone(&state.stream_hosts);
            let discovery_store = Arc::clone(&state.discovery_sources);
            let forward_id = forward.id.clone();
            let recovered = tokio::task::spawn_blocking(move || {
                discovery_store.restore_all(previous_discovery)?;
                stream_store.restore_all(previous_stream)?;
                proxy_store
                    .abort_rollback(&forward_id)
                    .map_err(|_| crate::typed_store::TypedStoreError::Invalid)
            })
            .await;
            if !matches!(recovered, Ok(Ok(()))) {
                return Err(audited_failure(
                    audit,
                    "rollback_recovery_failed",
                    ApiError::Unavailable,
                )
                .await);
            }
            let (code, error) = activation_error(error);
            return Err(audited_failure(audit, code, error).await);
        }
    };
    let proxy_store = Arc::clone(&state.proxy_hosts);
    let forward_id = forward.id.clone();
    if !matches!(
        tokio::task::spawn_blocking(move || proxy_store.commit_rollback(&forward_id)).await,
        Ok(Ok(()))
    ) {
        return Err(audited_failure(audit, "rollback_commit_failed", ApiError::Unavailable).await);
    }
    audit
        .record(AuditOutcome::Success, Some(result.active.clone()), None)
        .await?;
    let mut response = axum::Json(ActivationResponse {
        active: result.active.clone(),
        previous: result.previous,
    })
    .into_response();
    response
        .headers_mut()
        .insert(ETAG, etag(&result.active).ok_or(ApiError::Internal)?);
    Ok(response)
}

async fn desired_state(state: &AppState, audit: &MutationAudit) -> Result<DesiredState, ApiError> {
    let proxy_store = Arc::clone(&state.proxy_hosts);
    let stream_store = Arc::clone(&state.stream_hosts);
    let discovery_store = Arc::clone(&state.discovery_sources);
    match tokio::task::spawn_blocking(move || {
        Ok::<_, ApiError>(DesiredState {
            proxy_hosts: proxy_store
                .snapshot()
                .objects()
                .iter()
                .map(|stored| stored.object.clone())
                .collect(),
            stream_hosts: stream_store
                .all()
                .map_err(|_| ApiError::Unavailable)?
                .into_iter()
                .map(|stored| stored.object)
                .collect(),
            discovery_sources: discovery_store
                .all()
                .map_err(|_| ApiError::Unavailable)?
                .into_iter()
                .map(|stored| stored.object)
                .collect(),
        })
    })
    .await
    {
        Ok(Ok(desired)) => Ok(desired),
        Ok(Err(error)) => Err(audited_failure(audit, "store_failed", error).await),
        Err(_) => Err(audited_failure(audit, "store_failed", ApiError::Internal).await),
    }
}

async fn active_typed_state(
    state: &AppState,
    revision_id: &str,
    audit: &MutationAudit,
) -> Result<Option<crate::BoundProxyHostCandidate>, ApiError> {
    let revisions = state.control.revisions();
    let store = Arc::clone(&state.proxy_hosts);
    let revision_id = revision_id.to_owned();
    match tokio::task::spawn_blocking(move || {
        let metadata = revisions.metadata(&revision_id)?;
        metadata
            .binding_hash
            .map(|hash| store.load_candidate(&revision_id, &hash))
            .transpose()
            .map_err(|_| RevisionError::InvalidStored("typed binding is invalid".into()))
    })
    .await
    {
        Ok(Ok(candidate)) => Ok(candidate),
        Ok(Err(_)) | Err(_) => {
            Err(audited_failure(audit, "active_binding_unavailable", ApiError::Unavailable).await)
        }
    }
}

async fn certificate_dependencies(
    state: &AppState,
    config: Arc<Config>,
    proxy_hosts: &[ApiObject<ProxyHostSpec>],
    audit: &MutationAudit,
) -> Result<
    (
        Vec<StoredCertificate>,
        BTreeMap<ObjectId, crate::CertificateMetadata>,
    ),
    ApiError,
> {
    if !proxy_hosts
        .iter()
        .any(|object| object.spec.automatic_https == crate::AutomaticHttps::Managed)
    {
        return Ok((Vec::new(), BTreeMap::new()));
    }
    let store = Arc::clone(&state.certificates);
    let proxy_hosts = proxy_hosts.to_vec();
    match tokio::task::spawn_blocking(move || {
        let records = store.all().map_err(|_| ApiError::Unavailable)?;
        let metadata = records
            .iter()
            .map(|stored| {
                crate::compile_certificate_metadata(&stored.object, &config)
                    .map(|metadata| (stored.object.metadata.id.clone(), metadata))
                    .map_err(|_| ApiError::InvalidRequest)
            })
            .collect::<Result<BTreeMap<_, _>, _>>()?;
        let mut selected = BTreeSet::new();
        for object in proxy_hosts
            .iter()
            .filter(|object| object.spec.automatic_https == crate::AutomaticHttps::Managed)
        {
            let policy = crate::select_managed_https_policy(
                &metadata,
                &object.metadata.owner_id,
                &object.spec.domain,
            )
            .map_err(|_| ApiError::InvalidRequest)?;
            let id = metadata
                .iter()
                .find_map(|(id, metadata)| (metadata.policy() == &policy).then(|| id.clone()))
                .ok_or(ApiError::InvalidRequest)?;
            selected.insert(id);
        }
        let dependencies = records
            .into_iter()
            .filter(|stored| selected.contains(&stored.object.metadata.id))
            .collect();
        Ok::<_, ApiError>((dependencies, metadata))
    })
    .await
    {
        Ok(Ok(result)) => Ok(result),
        Ok(Err(error)) => Err(audited_failure(audit, "certificate_unavailable", error).await),
        Err(_) => Err(audited_failure(audit, "certificate_unavailable", ApiError::Internal).await),
    }
}
