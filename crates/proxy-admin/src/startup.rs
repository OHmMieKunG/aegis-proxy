//! Restart reconciliation for durable typed desired state.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    path::PathBuf,
};

use aegisproxy_config::{Config, revision::RevisionStore};
use thiserror::Error;

use crate::{
    AccessPolicyStore, ApiObject, AutomaticHttps, CertificateMetadata, CertificateStore, ObjectId,
    ProxyHostSpec, ProxyHostStore, StoredCertificate, StreamHostStore, UnifiedCandidateState,
    compile_discovery_sources, compile_stream_hosts, select_managed_https_policy,
};

/// Validated typed startup configuration and its immutable bound revision.
#[derive(Clone)]
pub struct ReconciledStartup {
    config: Config,
    revision_id: String,
}

impl fmt::Debug for ReconciledStartup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReconciledStartup")
            .field("revision_id", &self.revision_id)
            .field("route_count", &self.config.routes.len())
            .finish_non_exhaustive()
    }
}

impl ReconciledStartup {
    /// Return the compiled runtime configuration.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }

    /// Return the immutable bound revision to activate.
    #[must_use]
    pub fn revision_id(&self) -> &str {
        &self.revision_id
    }
}

/// Fail-closed typed startup reconciliation error.
#[derive(Debug, Error)]
#[error("typed startup reconciliation failed: {0}")]
pub struct StartupReconcileError(String);

fn failed(stage: &str, error: impl fmt::Display) -> StartupReconcileError {
    StartupReconcileError(format!("{stage}: {error}"))
}

/// Compile durable typed objects over the mounted restart-time base configuration.
///
/// `None` preserves the existing file-managed runtime when neither current desired state nor the
/// active revision is typed. Invalid or unavailable typed state is never treated as empty.
pub fn reconcile_startup(
    base: &Config,
) -> Result<Option<ReconciledStartup>, StartupReconcileError> {
    let state_dir = PathBuf::from(&base.runtime.state_dir);
    let revisions =
        RevisionStore::open(&state_dir).map_err(|error| failed("revision store", error))?;
    let active = revisions
        .recover_incomplete()
        .map_err(|error| failed("revision recovery", error))?;
    let active_revision = active.as_ref().map(|pointer| pointer.active.id.as_str());
    let active_is_typed = active_revision
        .map(|id| revisions.metadata(id))
        .transpose()
        .map_err(|error| failed("active revision", error))?
        .is_some_and(|metadata| metadata.binding_hash.is_some());

    let proxy_hosts = ProxyHostStore::open(state_dir.join("admin/proxy-hosts.json"))
        .map_err(|error| failed("Proxy Host store", error))?;
    match active_revision {
        Some(id) => proxy_hosts
            .recover_rollback(id)
            .map_err(|error| failed("typed rollback recovery", error))?,
        None if proxy_hosts.rollback_pending() => {
            return Err(StartupReconcileError(
                "typed rollback recovery: no active revision".into(),
            ));
        }
        None => {}
    }
    let retained = revisions
        .list()
        .map_err(|error| failed("revision listing", error))?;
    proxy_hosts
        .reconcile_candidates(&retained)
        .map_err(|error| failed("typed candidate reconciliation", error))?;
    if let Some(active_revision) = active_revision.filter(|_| active_is_typed) {
        let metadata = revisions
            .metadata(active_revision)
            .map_err(|error| failed("active typed revision", error))?;
        let binding_hash = metadata.binding_hash.ok_or_else(|| {
            StartupReconcileError("active typed revision: binding is missing".into())
        })?;
        proxy_hosts
            .load_candidate(active_revision, &binding_hash)
            .map_err(|error| failed("active typed binding", error))?;
        let config = revisions
            .load(active_revision)
            .map_err(|error| failed("active typed configuration", error))?;
        return Ok(Some(ReconciledStartup {
            config,
            revision_id: active_revision.to_owned(),
        }));
    }

    let access_policies = AccessPolicyStore::open(state_dir.join("admin/access-policies.json"))
        .map_err(|error| failed("Access Policy store", error))?;
    let certificates = CertificateStore::open(state_dir.join("admin/certificate-objects.json"))
        .map_err(|error| failed("Certificate store", error))?;
    let stream_hosts = StreamHostStore::open(state_dir.join("admin/stream-hosts.json"))
        .map_err(|error| failed("Stream Host store", error))?;
    let discovery_sources =
        crate::DiscoverySourceStore::open(state_dir.join("admin/discovery-sources.json"))
            .map_err(|error| failed("Discovery Source store", error))?;

    let proxy_objects = proxy_hosts
        .snapshot()
        .objects()
        .iter()
        .map(|stored| stored.object.clone())
        .collect::<Vec<_>>();
    let stream_objects = stream_hosts
        .all()
        .map_err(|error| failed("Stream Host state", error))?
        .into_iter()
        .map(|stored| stored.object)
        .collect::<Vec<_>>();
    let discovery_objects = discovery_sources
        .all()
        .map_err(|error| failed("Discovery Source state", error))?
        .into_iter()
        .map(|stored| stored.object)
        .collect::<Vec<_>>();
    if proxy_objects.is_empty()
        && stream_objects.is_empty()
        && discovery_objects.is_empty()
        && !active_is_typed
    {
        return Ok(None);
    }

    let policy_ids = proxy_objects
        .iter()
        .filter_map(|object| {
            object
                .spec
                .access_policy_ref
                .as_ref()
                .map(|reference| reference.id().clone())
        })
        .collect::<BTreeSet<_>>();
    let (policy_records, policy_metadata) = access_policies
        .candidate_dependencies(base, &policy_ids)
        .map_err(|error| failed("Access Policy dependencies", error))?;
    let (certificate_records, certificate_metadata) =
        certificate_dependencies(base, &proxy_objects, &certificates)?;

    let config = crate::proxy_host::prepare_proxy_host_set(
        &[],
        &proxy_objects,
        base,
        &policy_metadata,
        &certificate_metadata,
    )
    .map_err(|error| failed("Proxy Host compilation", error))?
    .config()
    .clone();
    let config = compile_stream_hosts(&config, &[], &stream_objects)
        .map_err(|error| failed("Stream Host compilation", error))?;
    let config = compile_discovery_sources(&config, &[], &discovery_objects)
        .map_err(|error| failed("Discovery Source compilation", error))?;

    let binding_hash = ProxyHostStore::unified_binding_hash(
        &proxy_objects,
        &stream_objects,
        &discovery_objects,
        &policy_records,
        &certificate_records,
    )
    .map_err(|error| failed("typed binding", error))?;
    let revision = revisions
        .create_bound_candidate(&config, "startup:typed", &binding_hash)
        .map_err(|error| failed("typed revision", error))?;
    let retained = revisions
        .list()
        .map_err(|error| failed("revision listing", error))?;
    proxy_hosts
        .reconcile_candidates(&retained)
        .and_then(|_| {
            proxy_hosts.bind_unified_candidate(
                &revision.id,
                &binding_hash,
                UnifiedCandidateState {
                    proxy_hosts: &proxy_objects,
                    stream_hosts: &stream_objects,
                    discovery_sources: &discovery_objects,
                    access_policies: &policy_records,
                    certificates: &certificate_records,
                },
            )
        })
        .map_err(|error| failed("typed candidate binding", error))?;

    Ok(Some(ReconciledStartup {
        config,
        revision_id: revision.id,
    }))
}

fn certificate_dependencies(
    config: &Config,
    proxy_hosts: &[ApiObject<ProxyHostSpec>],
    store: &CertificateStore,
) -> Result<
    (
        Vec<StoredCertificate>,
        BTreeMap<ObjectId, CertificateMetadata>,
    ),
    StartupReconcileError,
> {
    if !proxy_hosts
        .iter()
        .any(|object| object.spec.automatic_https == AutomaticHttps::Managed)
    {
        return Ok((Vec::new(), BTreeMap::new()));
    }
    let records = store
        .all()
        .map_err(|error| failed("Certificate state", error))?;
    let metadata = records
        .iter()
        .map(|stored| {
            crate::compile_certificate_metadata(&stored.object, config)
                .map(|metadata| (stored.object.metadata.id.clone(), metadata))
                .map_err(|error| failed("Certificate metadata", error))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let mut selected = BTreeSet::new();
    for object in proxy_hosts
        .iter()
        .filter(|object| object.spec.automatic_https == AutomaticHttps::Managed)
    {
        let policy =
            select_managed_https_policy(&metadata, &object.metadata.owner_id, &object.spec.domains)
                .map_err(|error| failed("managed HTTPS selection", error))?;
        let id = metadata
            .iter()
            .find_map(|(id, metadata)| (metadata.policy() == &policy).then(|| id.clone()))
            .ok_or_else(|| StartupReconcileError("managed HTTPS selection failed".into()))?;
        selected.insert(id);
    }
    let dependencies = records
        .into_iter()
        .filter(|stored| selected.contains(&stored.object.metadata.id))
        .collect();
    Ok((dependencies, metadata))
}

#[cfg(test)]
mod tests {
    use std::{fs, time::SystemTime};

    use super::*;

    fn temporary_directory(name: &str) -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("current time")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "aegisproxy-startup-{name}-{}-{nonce}",
            std::process::id()
        ))
    }

    fn base(root: &std::path::Path) -> Config {
        let mut config =
            aegisproxy_config::load_bytes(include_bytes!("../../../config/examples/minimal.toml"))
                .expect("base configuration");
        config.runtime.state_dir = root.to_string_lossy().into_owned();
        config
    }

    fn proxy(id: &str, domain: &str) -> ApiObject<ProxyHostSpec> {
        serde_json::from_value(serde_json::json!({
            "api_version": "v1",
            "metadata": {"id": id, "owner_id": "alice"},
            "spec": {
                "domain": domain,
                "forward_host": "127.0.0.1",
                "forward_port": 9001,
                "forward_protocol": "http",
                "automatic_https": "disabled",
                "access_policy_ref": null,
                "enabled": true
            }
        }))
        .expect("Proxy Host")
    }

    #[test]
    fn recompiles_durable_objects_and_resumes_bound_revision() {
        let root = temporary_directory("resume");
        let config = base(&root);
        ProxyHostStore::open(root.join("admin/proxy-hosts.json"))
            .expect("store")
            .create(proxy("restart-host", "restart.example.test"))
            .expect("create");

        let first = reconcile_startup(&config)
            .expect("reconcile")
            .expect("typed startup");
        assert!(first.config().routes.iter().any(|route| {
            route.hosts == ["restart.example.test"]
                && route
                    .upstream_group
                    .as_deref()
                    .is_some_and(|group| group.starts_with("ph-"))
        }));
        let second = reconcile_startup(&config)
            .expect("second reconcile")
            .expect("typed startup");
        assert_eq!(second.revision_id(), first.revision_id());

        let revisions = RevisionStore::open(&root).expect("revisions");
        assert!(
            revisions
                .metadata(first.revision_id())
                .expect("metadata")
                .binding_hash
                .is_some()
        );
        drop(revisions);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn invalid_typed_overlay_never_falls_back_to_base() {
        let root = temporary_directory("invalid");
        let config = base(&root);
        ProxyHostStore::open(root.join("admin/proxy-hosts.json"))
            .expect("store")
            .create(proxy("conflict-host", "example.test"))
            .expect("create");

        let error = reconcile_startup(&config).expect_err("domain conflict");
        assert!(error.to_string().contains("Proxy Host compilation"));
        let revisions = RevisionStore::open(&root).expect("revisions");
        assert!(revisions.active().expect("active pointer").is_none());
        drop(revisions);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn resumes_exact_active_typed_revision_without_applying_newer_desired_or_draft() {
        let root = temporary_directory("active-not-draft");
        let config = base(&root);
        let store = ProxyHostStore::open(root.join("admin/proxy-hosts.json")).expect("store");
        store
            .create(proxy("active-host", "active.example.test"))
            .expect("create active object");
        store
            .create(proxy("deleted-host", "deleted.example.test"))
            .expect("create object later deleted");
        drop(store);
        let first = reconcile_startup(&config)
            .expect("first reconcile")
            .expect("typed startup");
        let revisions = RevisionStore::open(&root).expect("revisions");
        revisions
            .begin_activation(first.revision_id(), None)
            .expect("begin activation");
        revisions
            .mark_probation(first.revision_id())
            .expect("mark probation");
        revisions
            .commit_activation(first.revision_id())
            .expect("commit activation");
        drop(revisions);

        let store = ProxyHostStore::open(root.join("admin/proxy-hosts.json")).expect("store");
        let owner: crate::ObjectId = "alice".parse().expect("owner");
        let active_id: crate::ObjectId = "active-host".parse().expect("active id");
        let deleted_id: crate::ObjectId = "deleted-host".parse().expect("deleted id");
        let mut disabled = store.get(&owner, &active_id).expect("active object").object;
        disabled.spec.enabled = false;
        disabled
            .spec
            .domains
            .push("newer.example.test".parse().expect("domain"));
        disabled.spec.locations.push(
            serde_json::from_value(serde_json::json!({
                "id": "loc-newer",
                "match_kind": "prefix",
                "path": "/newer",
                "forward_host": "127.0.0.1",
                "forward_port": 9002,
                "forward_protocol": "http",
                "access_policy_ref": null,
                "enabled": true
            }))
            .expect("desired location"),
        );
        store
            .update(disabled, 1)
            .expect("persist disabled desired state");
        store
            .delete(&owner, &deleted_id, 1)
            .expect("persist deleted desired state");
        let mut draft = proxy("draft-host", "draft.example.test");
        draft
            .spec
            .domains
            .push("draft-alias.example.test".parse().expect("domain"));
        draft.spec.locations.push(
            serde_json::from_value(serde_json::json!({
                "id": "loc-draft",
                "match_kind": "prefix",
                "path": "/draft",
                "forward_host": "127.0.0.1",
                "forward_port": 9003,
                "forward_protocol": "http",
                "access_policy_ref": null,
                "enabled": true
            }))
            .expect("draft location"),
        );
        store
            .create_draft(draft, None)
            .expect("create inactive draft");
        drop(store);
        let resumed = reconcile_startup(&config)
            .expect("restart reconcile")
            .expect("typed startup");

        assert_eq!(resumed.revision_id(), first.revision_id());
        assert!(
            resumed
                .config()
                .routes
                .iter()
                .any(|route| route.hosts == ["active.example.test"])
        );
        assert!(
            resumed
                .config()
                .routes
                .iter()
                .any(|route| route.hosts == ["deleted.example.test"])
        );
        assert!(
            !resumed
                .config()
                .routes
                .iter()
                .any(|route| route.hosts == ["draft.example.test"])
        );
        assert!(resumed.config().routes.iter().all(|route| {
            route.hosts != ["newer.example.test"] && route.hosts != ["draft-alias.example.test"]
        }));
        assert!(resumed.config().routes.iter().all(|route| {
            route.path_prefixes != ["/newer"] && route.path_prefixes != ["/draft"]
        }));
        let store =
            ProxyHostStore::open(root.join("admin/proxy-hosts.json")).expect("reopen store");
        assert_eq!(store.list_drafts(&owner).len(), 1);
        assert_eq!(store.snapshot().objects().len(), 1);
        fs::remove_dir_all(root).expect("cleanup");
    }
}
