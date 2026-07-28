//! Strict typed Discovery Source compilation and persistence.

use std::{collections::BTreeSet, path::Path};

use aegisproxy_config::{
    Config,
    provider::{DnsProviderConfig, FileProviderConfig, ProviderConfig},
    validate,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    ApiObject, DiscoverySourceSpec, ObjectId,
    typed_store::{StoredObject, TypedStore, TypedStoreError},
};

const MAX_DISCOVERY_SOURCES: usize = 64;
const MAX_STORE_BYTES: u64 = 1024 * 1024;

/// One persisted Discovery Source generation.
pub type StoredDiscoverySource = StoredObject<DiscoverySourceSpec>;

/// Durable Discovery Source storage failure.
pub type DiscoverySourceStoreError = TypedStoreError;

/// Exclusively owned durable Discovery Source store.
#[derive(Debug)]
pub struct DiscoverySourceStore(TypedStore<DiscoverySourceSpec>);

impl DiscoverySourceStore {
    /// Open and strictly validate a private Discovery Source file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, DiscoverySourceStoreError> {
        TypedStore::open(
            path,
            ".discovery-sources-owner.lock",
            MAX_DISCOVERY_SOURCES,
            MAX_STORE_BYTES,
            validate_source,
        )
        .map(Self)
    }

    /// Create one globally unique owned Discovery Source.
    pub fn create(
        &self,
        object: ApiObject<DiscoverySourceSpec>,
    ) -> Result<StoredDiscoverySource, DiscoverySourceStoreError> {
        self.0.create(object)
    }

    /// Replace one owned Discovery Source at its exact generation.
    pub fn update(
        &self,
        object: ApiObject<DiscoverySourceSpec>,
        expected_generation: u64,
    ) -> Result<StoredDiscoverySource, DiscoverySourceStoreError> {
        self.0.update(object, expected_generation)
    }

    /// Delete one owned Discovery Source at its exact generation.
    pub fn delete(
        &self,
        owner_id: &ObjectId,
        object_id: &ObjectId,
        expected_generation: u64,
    ) -> Result<StoredDiscoverySource, DiscoverySourceStoreError> {
        self.0.delete(owner_id, object_id, expected_generation)
    }

    /// Return one Discovery Source only within the requested owner namespace.
    #[must_use]
    pub fn get(&self, owner_id: &ObjectId, object_id: &ObjectId) -> Option<StoredDiscoverySource> {
        self.0.get(owner_id, object_id)
    }

    /// Return stable Discovery Source ordering within one owner namespace.
    #[must_use]
    pub fn list(&self, owner_id: &ObjectId) -> Vec<StoredDiscoverySource> {
        self.0.list(owner_id)
    }

    /// Return complete canonical desired state.
    pub fn all(&self) -> Result<Vec<StoredDiscoverySource>, DiscoverySourceStoreError> {
        self.0.all()
    }

    pub(crate) fn replace_all(
        &self,
        objects: Vec<ApiObject<DiscoverySourceSpec>>,
    ) -> Result<Vec<StoredDiscoverySource>, DiscoverySourceStoreError> {
        self.0.replace_all(objects)
    }

    pub(crate) fn restore_all(
        &self,
        objects: Vec<StoredDiscoverySource>,
    ) -> Result<(), DiscoverySourceStoreError> {
        self.0.restore_all(objects)
    }
}

/// Stable fail-closed Discovery Source compilation error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum DiscoverySourceCompileError {
    /// Typed contract shape is invalid.
    #[error("discovery source contract is invalid")]
    InvalidContract,
    /// Base configuration is invalid.
    #[error("discovery source base configuration is invalid")]
    InvalidConfiguration,
    /// Generated namespace collides with manual or tampered state.
    #[error("discovery source namespace conflicts")]
    NamespaceConflict,
    /// Complete compiled configuration is invalid.
    #[error("discovery source configuration is invalid")]
    SemanticValidation,
    /// Typed object count exceeds the fixed bound.
    #[error("discovery source count exceeds its limit")]
    Limit,
}

/// Compile complete Discovery Source desired state without file reads, DNS, or network I/O.
pub fn compile_discovery_sources(
    base: &Config,
    current: &[ApiObject<DiscoverySourceSpec>],
    desired: &[ApiObject<DiscoverySourceSpec>],
) -> Result<Config, DiscoverySourceCompileError> {
    validate(base).map_err(|_| DiscoverySourceCompileError::InvalidConfiguration)?;
    if current.len() > MAX_DISCOVERY_SOURCES || desired.len() > MAX_DISCOVERY_SOURCES {
        return Err(DiscoverySourceCompileError::Limit);
    }
    let mut config = base.clone();
    for object in current.iter().filter(|object| enabled(&object.spec)) {
        let expected = provider(object);
        let matching = config
            .providers
            .iter()
            .filter(|provider| provider.id() == expected.id())
            .collect::<Vec<_>>();
        if matching.as_slice() != [&expected] {
            return Err(DiscoverySourceCompileError::NamespaceConflict);
        }
        config
            .providers
            .retain(|provider| provider.id() != expected.id());
    }

    let mut desired = desired.to_vec();
    desired.sort_by(|left, right| {
        (&left.metadata.owner_id, &left.metadata.id)
            .cmp(&(&right.metadata.owner_id, &right.metadata.id))
    });
    let mut identities = BTreeSet::new();
    for object in &mut desired {
        if !validate_source(object)
            || !identities.insert((&object.metadata.owner_id, &object.metadata.id))
        {
            return Err(DiscoverySourceCompileError::InvalidContract);
        }
        if enabled(&object.spec) {
            config.providers.push(provider(object));
        }
    }
    validate(&config).map_err(|_| DiscoverySourceCompileError::SemanticValidation)?;
    Ok(config)
}

fn validate_source(object: &mut ApiObject<DiscoverySourceSpec>) -> bool {
    object.spec.validate_shape().is_ok()
}

fn enabled(spec: &DiscoverySourceSpec) -> bool {
    match spec {
        DiscoverySourceSpec::File { enabled, .. } | DiscoverySourceSpec::Dns { enabled, .. } => {
            *enabled
        }
    }
}

fn provider(object: &ApiObject<DiscoverySourceSpec>) -> ProviderConfig {
    let id = namespace(&object.metadata.owner_id, &object.metadata.id);
    match &object.spec {
        DiscoverySourceSpec::File {
            enabled,
            upstream_group,
            path,
            scheme,
            server_name,
            refresh_secs,
            debounce_millis,
            stale_after_secs,
            max_endpoints,
        } => ProviderConfig::File(FileProviderConfig {
            id,
            enabled: *enabled,
            upstream_group: upstream_group.to_string(),
            path: path.clone(),
            scheme: *scheme,
            server_name: server_name.clone(),
            ca_bundle: None,
            refresh_secs: *refresh_secs,
            debounce_millis: *debounce_millis,
            stale_after_secs: *stale_after_secs,
            max_endpoints: *max_endpoints,
        }),
        DiscoverySourceSpec::Dns {
            enabled,
            upstream_group,
            hostname,
            port,
            scheme,
            server_name,
            weight,
            refresh_secs,
            stale_after_secs,
            max_answers,
        } => ProviderConfig::Dns(DnsProviderConfig {
            id,
            enabled: *enabled,
            upstream_group: upstream_group.to_string(),
            hostname: hostname.clone(),
            port: *port,
            scheme: *scheme,
            server_name: server_name.clone(),
            ca_bundle: None,
            weight: *weight,
            refresh_secs: *refresh_secs,
            stale_after_secs: *stale_after_secs,
            max_answers: *max_answers,
        }),
    }
}

fn namespace(owner: &ObjectId, object: &ObjectId) -> String {
    let mut digest = Sha256::new();
    digest.update(owner.as_str().as_bytes());
    digest.update([0]);
    digest.update(object.as_str().as_bytes());
    let digest = digest.finalize();
    format!(
        "ds-{}",
        digest[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn source(kind: &str, group: &str, enabled: bool) -> ApiObject<DiscoverySourceSpec> {
        let spec = if kind == "file" {
            serde_json::json!({
                "kind": "file",
                "enabled": enabled,
                "upstream_group": group,
                "path": "/run/aegisproxy/endpoints.toml",
                "scheme": "http",
                "server_name": null,
                "refresh_secs": 30,
                "debounce_millis": 100,
                "stale_after_secs": 300,
                "max_endpoints": 16
            })
        } else {
            serde_json::json!({
                "kind": "dns",
                "enabled": enabled,
                "upstream_group": group,
                "hostname": "nodes.example.test",
                "port": 9000,
                "scheme": "http",
                "server_name": null,
                "weight": 1,
                "refresh_secs": 30,
                "stale_after_secs": 300,
                "max_answers": 16
            })
        };
        serde_json::from_value(serde_json::json!({
            "api_version": "v1",
            "metadata": {"id": format!("{kind}-nodes"), "owner_id": "alice"},
            "spec": spec
        }))
        .expect("source")
    }

    #[test]
    fn compiles_file_and_dns_without_source_io() {
        let base =
            aegisproxy_config::load_bytes(include_bytes!("../../../config/examples/minimal.toml"))
                .expect("base");
        let file = source("file", "app", true);
        let compiled = compile_discovery_sources(&base, &[], std::slice::from_ref(&file))
            .expect("file compile without reading absent path");
        assert_eq!(compiled.providers.len(), 1);
        assert_eq!(compiled.providers[0].kind(), "file");
        let restored = compile_discovery_sources(&compiled, &[file], &[]).expect("remove source");
        assert!(restored.providers.is_empty());
    }

    #[test]
    fn rejects_provider_namespace_and_manual_collisions() {
        let base =
            aegisproxy_config::load_bytes(include_bytes!("../../../config/examples/minimal.toml"))
                .expect("base");
        assert!(matches!(
            compile_discovery_sources(
                &base,
                &[],
                &[source("file", "app", true), source("dns", "app", true)]
            ),
            Err(DiscoverySourceCompileError::SemanticValidation)
        ));
        let current = source("file", "app", true);
        let mut compiled =
            compile_discovery_sources(&base, &[], std::slice::from_ref(&current)).expect("compile");
        if let ProviderConfig::File(provider) = &mut compiled.providers[0] {
            provider.path = "/run/tampered.toml".into();
        }
        assert!(matches!(
            compile_discovery_sources(&compiled, &[current], &[]),
            Err(DiscoverySourceCompileError::NamespaceConflict)
        ));
    }
}
