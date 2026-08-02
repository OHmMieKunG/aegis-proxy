use super::*;

#[derive(Debug, Serialize)]
pub(super) struct TypedCandidateChange {
    kind: &'static str,
    owner_id: ObjectId,
    id: ObjectId,
    operation: &'static str,
    fields: Vec<&'static str>,
}

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

pub(super) fn typed_candidate_changes(
    current: Option<&crate::BoundProxyHostCandidate>,
    desired: &crate::BoundProxyHostCandidate,
) -> Vec<TypedCandidateChange> {
    let mut changes = Vec::new();
    object_changes(
        "proxy_host",
        current.map_or(&[], crate::BoundProxyHostCandidate::objects),
        desired.objects(),
        &[
            "domain",
            "forward_host",
            "forward_port",
            "forward_protocol",
            "automatic_https",
            "access_policy_ref",
            "enabled",
        ],
        &mut changes,
    );
    object_changes(
        "stream_host",
        current.map_or(&[], crate::BoundProxyHostCandidate::stream_hosts),
        desired.stream_hosts(),
        &[
            "listen_port",
            "protocol",
            "forward_host",
            "forward_port",
            "sni_hosts",
            "enabled",
        ],
        &mut changes,
    );
    object_changes(
        "discovery_source",
        current.map_or(&[], crate::BoundProxyHostCandidate::discovery_sources),
        desired.discovery_sources(),
        &[
            "kind",
            "enabled",
            "upstream_group",
            "source",
            "transport",
            "refresh",
            "stale_policy",
            "bounds",
        ],
        &mut changes,
    );
    dependency_changes(
        "access_policy",
        current.map_or(&[], crate::BoundProxyHostCandidate::access_policies),
        desired.access_policies(),
        &[
            "generation",
            "owner_id",
            "enabled",
            "shared_with",
            "middlewares",
        ],
        |stored| (&stored.object.metadata.owner_id, &stored.object.metadata.id),
        &mut changes,
    );
    dependency_changes(
        "certificate",
        current.map_or(&[], crate::BoundProxyHostCandidate::certificates),
        desired.certificates(),
        &[
            "generation",
            "owner_id",
            "enabled",
            "shared_with",
            "certificate_ref",
        ],
        |stored| (&stored.object.metadata.owner_id, &stored.object.metadata.id),
        &mut changes,
    );
    changes.sort_by(|left, right| {
        (left.kind, &left.owner_id, &left.id).cmp(&(right.kind, &right.owner_id, &right.id))
    });
    changes
}

fn object_changes<T: Eq>(
    kind: &'static str,
    current: &[ApiObject<T>],
    desired: &[ApiObject<T>],
    fields: &[&'static str],
    changes: &mut Vec<TypedCandidateChange>,
) {
    let current = current
        .iter()
        .map(|object| ((&object.metadata.owner_id, &object.metadata.id), object))
        .collect::<BTreeMap<_, _>>();
    let desired = desired
        .iter()
        .map(|object| ((&object.metadata.owner_id, &object.metadata.id), object))
        .collect::<BTreeMap<_, _>>();
    for (identity, object) in &desired {
        let operation = match current.get(identity) {
            None => "add",
            Some(previous) if *previous != *object => "update",
            Some(_) => continue,
        };
        changes.push(TypedCandidateChange {
            kind,
            owner_id: identity.0.clone(),
            id: identity.1.clone(),
            operation,
            fields: if operation == "update" {
                fields.to_vec()
            } else {
                Vec::new()
            },
        });
    }
    for identity in current
        .keys()
        .filter(|identity| !desired.contains_key(*identity))
    {
        changes.push(TypedCandidateChange {
            kind,
            owner_id: identity.0.clone(),
            id: identity.1.clone(),
            operation: "remove",
            fields: Vec::new(),
        });
    }
}

fn dependency_changes<T: Eq>(
    kind: &'static str,
    current: &[T],
    desired: &[T],
    fields: &[&'static str],
    identity: fn(&T) -> (&ObjectId, &ObjectId),
    changes: &mut Vec<TypedCandidateChange>,
) {
    let current = current
        .iter()
        .map(|stored| (identity(stored), stored))
        .collect::<BTreeMap<_, _>>();
    let desired = desired
        .iter()
        .map(|stored| (identity(stored), stored))
        .collect::<BTreeMap<_, _>>();
    for (object_identity, stored) in &desired {
        let operation = match current.get(object_identity) {
            None => "add",
            Some(previous) if *previous != *stored => "update",
            Some(_) => continue,
        };
        changes.push(TypedCandidateChange {
            kind,
            owner_id: object_identity.0.clone(),
            id: object_identity.1.clone(),
            operation,
            fields: if operation == "update" {
                fields.to_vec()
            } else {
                Vec::new()
            },
        });
    }
    for (object_identity, _) in current
        .iter()
        .filter(|(identity, _)| !desired.contains_key(*identity))
    {
        changes.push(TypedCandidateChange {
            kind,
            owner_id: object_identity.0.clone(),
            id: object_identity.1.clone(),
            operation: "remove",
            fields: Vec::new(),
        });
    }
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
        Err(_) => {
            return Err(
                audited_failure(audit, "compilation_failed", ApiError::CompilationFailed).await,
            );
        }
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
            return Err(audited_failure(
                audit,
                "candidate_persistence_failed",
                ApiError::CandidatePersistenceFailed,
            )
            .await);
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
            return Err(audited_failure(
                audit,
                "candidate_persistence_failed",
                ApiError::CandidatePersistenceFailed,
            )
            .await);
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
    let expected_epoch = match proxy_store.mutation_snapshot() {
        Ok(snapshot) => snapshot.epoch(),
        Err(ProxyHostStoreError::Indeterminate(_) | ProxyHostStoreError::RecoveryRequired) => {
            return Err(
                audited_failure(audit, "recovery_required", ApiError::RecoveryRequired).await,
            );
        }
        Err(_) => {
            return Err(audited_failure(audit, "object_store_failed", ApiError::Unavailable).await);
        }
    };
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
                    ApiError::RollbackFailed,
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
        return Err(
            audited_failure(audit, "rollback_commit_failed", ApiError::RollbackFailed).await,
        );
    }
    record_activation_success(audit, result.active.clone()).await?;
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
                .mutation_snapshot()
                .map_err(|error| match error {
                    ProxyHostStoreError::Indeterminate(_)
                    | ProxyHostStoreError::RecoveryRequired => ApiError::RecoveryRequired,
                    _ => ApiError::Unavailable,
                })?
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
        Ok(Err(ApiError::RecoveryRequired)) => {
            Err(audited_failure(audit, "recovery_required", ApiError::RecoveryRequired).await)
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy(enabled: bool) -> ApiObject<ProxyHostSpec> {
        serde_json::from_value(serde_json::json!({
            "api_version": "v1",
            "metadata": {"id": "proxy-a", "owner_id": "alice"},
            "spec": {
                "domain": "a.example.test",
                "forward_host": "127.0.0.1",
                "forward_port": 8080,
                "forward_protocol": "http",
                "automatic_https": "disabled",
                "access_policy_ref": null,
                "enabled": enabled
            }
        }))
        .expect("proxy")
    }

    #[test]
    fn typed_change_uses_only_the_closed_field_allowlist() {
        let mut changes = Vec::new();
        object_changes(
            "proxy_host",
            &[proxy(true)],
            &[proxy(false)],
            &["enabled"],
            &mut changes,
        );
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].fields, ["enabled"]);
        let json = serde_json::to_string(&changes).expect("changes");
        assert!(!json.contains("127.0.0.1"));
        assert!(!json.contains("a.example.test"));
    }
}
