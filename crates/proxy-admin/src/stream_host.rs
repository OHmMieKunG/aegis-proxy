//! Strict typed Stream Host compilation and persistence.

use std::{collections::BTreeSet, fmt, net::SocketAddr, path::Path};

use aegisproxy_config::{
    Config, EndpointConfig, HealthCheckKind, ListenerConfig, RetryConfig, RouteConfig,
    UpstreamGroupConfig, validate,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    ApiObject, ObjectId, StreamHostSpec, StreamProtocol,
    typed_store::{StoredObject, TypedStore, TypedStoreError},
};

const MAX_STREAM_HOSTS: usize = 128;
const MAX_STORE_BYTES: u64 = 1024 * 1024;

/// One persisted Stream Host generation.
pub type StoredStreamHost = StoredObject<StreamHostSpec>;

/// Durable Stream Host storage failure.
pub type StreamHostStoreError = TypedStoreError;

/// Exclusively owned durable Stream Host store.
#[derive(Debug)]
pub struct StreamHostStore(TypedStore<StreamHostSpec>);

impl StreamHostStore {
    /// Open and strictly validate a private Stream Host file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StreamHostStoreError> {
        TypedStore::open(
            path,
            ".stream-hosts-owner.lock",
            MAX_STREAM_HOSTS,
            MAX_STORE_BYTES,
            canonicalize_stream_host,
        )
        .map(Self)
    }

    /// Create one globally unique owned Stream Host.
    pub fn create(
        &self,
        object: ApiObject<StreamHostSpec>,
    ) -> Result<StoredStreamHost, StreamHostStoreError> {
        self.0.create(object)
    }

    /// Replace one owned Stream Host at its exact generation.
    pub fn update(
        &self,
        object: ApiObject<StreamHostSpec>,
        expected_generation: u64,
    ) -> Result<StoredStreamHost, StreamHostStoreError> {
        self.0.update(object, expected_generation)
    }

    /// Delete one owned Stream Host at its exact generation.
    pub fn delete(
        &self,
        owner_id: &ObjectId,
        object_id: &ObjectId,
        expected_generation: u64,
    ) -> Result<StoredStreamHost, StreamHostStoreError> {
        self.0.delete(owner_id, object_id, expected_generation)
    }

    /// Return one Stream Host only within the requested owner namespace.
    #[must_use]
    pub fn get(&self, owner_id: &ObjectId, object_id: &ObjectId) -> Option<StoredStreamHost> {
        self.0.get(owner_id, object_id)
    }

    /// Return stable Stream Host ordering within one owner namespace.
    #[must_use]
    pub fn list(&self, owner_id: &ObjectId) -> Vec<StoredStreamHost> {
        self.0.list(owner_id)
    }

    /// Return complete canonical desired state.
    pub fn all(&self) -> Result<Vec<StoredStreamHost>, StreamHostStoreError> {
        self.0.all()
    }

    pub(crate) fn replace_all(
        &self,
        objects: Vec<ApiObject<StreamHostSpec>>,
    ) -> Result<Vec<StoredStreamHost>, StreamHostStoreError> {
        self.0.replace_all(objects)
    }

    pub(crate) fn restore_all(
        &self,
        objects: Vec<StoredStreamHost>,
    ) -> Result<(), StreamHostStoreError> {
        self.0.restore_all(objects)
    }
}

/// Stable fail-closed Stream Host compilation error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum StreamHostCompileError {
    /// Typed contract shape is invalid.
    #[error("stream host contract is invalid")]
    InvalidContract,
    /// Base configuration is invalid.
    #[error("stream host base configuration is invalid")]
    InvalidConfiguration,
    /// No unique compatible public listener exists.
    #[error("stream host bind policy is unavailable")]
    ListenerUnavailable,
    /// No unique transport-neutral upstream template exists.
    #[error("stream host upstream template is unavailable")]
    TemplateUnavailable,
    /// Generated namespace collides with manual or tampered state.
    #[error("stream host generated namespace conflicts")]
    NamespaceConflict,
    /// Complete compiled configuration is invalid.
    #[error("stream host configuration is invalid")]
    SemanticValidation,
    /// Typed object count exceeds the fixed bound.
    #[error("stream host count exceeds its limit")]
    Limit,
}

/// Compile complete Stream Host desired state without I/O or activation.
pub fn compile_stream_hosts(
    base: &Config,
    current: &[ApiObject<StreamHostSpec>],
    desired: &[ApiObject<StreamHostSpec>],
) -> Result<Config, StreamHostCompileError> {
    validate(base).map_err(|_| StreamHostCompileError::InvalidConfiguration)?;
    if current.len() > MAX_STREAM_HOSTS || desired.len() > MAX_STREAM_HOSTS {
        return Err(StreamHostCompileError::Limit);
    }
    let mut desired = desired.to_vec();
    desired.sort_by(|left, right| {
        (&left.metadata.owner_id, &left.metadata.id)
            .cmp(&(&right.metadata.owner_id, &right.metadata.id))
    });
    let mut identities = BTreeSet::new();
    for object in &mut desired {
        if !canonicalize_stream_host(object)
            || !identities.insert((&object.metadata.owner_id, &object.metadata.id))
        {
            return Err(StreamHostCompileError::InvalidContract);
        }
    }

    let mut config = strip_current(base, current)?;
    let bind_ip = {
        let mut listeners = config
            .listeners
            .iter()
            .filter(|listener| listener.protocol == "http");
        let ip = listeners
            .next()
            .map(|listener| listener.bind.ip())
            .ok_or(StreamHostCompileError::ListenerUnavailable)?;
        if listeners.next().is_some() {
            return Err(StreamHostCompileError::ListenerUnavailable);
        }
        ip
    };
    let template = {
        let mut templates = config.upstream_groups.iter().filter(|group| {
            !group.id.starts_with("ph-")
                && !group.endpoints.is_empty()
                && group
                    .endpoints
                    .iter()
                    .all(|endpoint| matches!(endpoint.url.scheme(), "http" | "https"))
        });
        let template = templates
            .next()
            .cloned()
            .ok_or(StreamHostCompileError::TemplateUnavailable)?;
        if templates.next().is_some()
            || template.retry != RetryConfig::default()
            || template
                .health
                .as_ref()
                .is_some_and(|health| health.kind != HealthCheckKind::Tcp)
        {
            return Err(StreamHostCompileError::TemplateUnavailable);
        }
        template
    };

    for object in desired.iter().filter(|object| object.spec.enabled) {
        let ids = ManagedIds::new(object);
        let listener = ListenerConfig {
            id: ids.listener.clone(),
            bind: SocketAddr::new(bind_ip, object.spec.listen_port),
            protocol: match object.spec.protocol {
                StreamProtocol::Tcp => "tcp",
                StreamProtocol::TlsPassthrough => "tls_passthrough",
            }
            .into(),
            certificates: Vec::new(),
        };
        let endpoint = compile_endpoint(object, &template.endpoints[0], &ids.endpoint)?;
        let group = UpstreamGroupConfig {
            id: ids.group.clone(),
            endpoints: vec![endpoint],
            retry: RetryConfig::default(),
            ..template.clone()
        };
        let route = RouteConfig {
            id: ids.route,
            listeners: vec![ids.listener],
            hosts: object.spec.sni_hosts.clone(),
            paths: Vec::new(),
            path_prefixes: Vec::new(),
            methods: Vec::new(),
            headers: Vec::new(),
            default: object.spec.protocol == StreamProtocol::Tcp,
            priority: 0,
            middlewares: Vec::new(),
            upstream_group: Some(ids.group),
        };
        config.listeners.push(listener);
        config.upstream_groups.push(group);
        config.routes.push(route);
    }
    validate(&config).map_err(|_| StreamHostCompileError::SemanticValidation)?;
    Ok(config)
}

fn canonicalize_stream_host(object: &mut ApiObject<StreamHostSpec>) -> bool {
    if object.spec.validate_shape().is_err() {
        return false;
    }
    object.spec.sni_hosts.sort_unstable();
    true
}

fn compile_endpoint(
    object: &ApiObject<StreamHostSpec>,
    template: &EndpointConfig,
    id: &str,
) -> Result<EndpointConfig, StreamHostCompileError> {
    let host = object
        .spec
        .forward_host
        .parse::<std::net::Ipv6Addr>()
        .map_or_else(
            |_| object.spec.forward_host.clone(),
            |address| format!("[{address}]"),
        );
    let mut value =
        serde_json::to_value(template).map_err(|_| StreamHostCompileError::InvalidContract)?;
    value["id"] = serde_json::json!(id);
    value["url"] = serde_json::json!(format!("tcp://{host}:{}", object.spec.forward_port));
    value["server_name"] = serde_json::Value::Null;
    value["ca_bundle"] = serde_json::Value::Null;
    serde_json::from_value(value).map_err(|_| StreamHostCompileError::InvalidContract)
}

fn strip_current(
    base: &Config,
    current: &[ApiObject<StreamHostSpec>],
) -> Result<Config, StreamHostCompileError> {
    let mut config = base.clone();
    for object in current.iter().filter(|object| object.spec.enabled) {
        let ids = ManagedIds::new(object);
        let listener = config
            .listeners
            .iter()
            .filter(|listener| listener.id == ids.listener)
            .count();
        let route = config
            .routes
            .iter()
            .filter(|route| route.id == ids.route)
            .count();
        let groups = config
            .upstream_groups
            .iter()
            .filter(|group| group.id == ids.group)
            .collect::<Vec<_>>();
        if listener != 1
            || route != 1
            || groups.len() != 1
            || groups[0].endpoints.len() != 1
            || groups[0].endpoints[0].id != ids.endpoint
        {
            return Err(StreamHostCompileError::NamespaceConflict);
        }
        config
            .listeners
            .retain(|listener| listener.id != ids.listener);
        config.routes.retain(|route| route.id != ids.route);
        config.upstream_groups.retain(|group| group.id != ids.group);
    }
    Ok(config)
}

struct ManagedIds {
    listener: String,
    route: String,
    group: String,
    endpoint: String,
}

impl ManagedIds {
    fn new(object: &ApiObject<StreamHostSpec>) -> Self {
        let namespace = namespace(&object.metadata.owner_id, &object.metadata.id);
        Self {
            listener: format!("{namespace}-listener"),
            route: format!("{namespace}-route"),
            group: format!("{namespace}-upstream"),
            endpoint: format!("{namespace}-endpoint"),
        }
    }
}

impl fmt::Debug for ManagedIds {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("ManagedIds").finish_non_exhaustive()
    }
}

fn namespace(owner: &ObjectId, object: &ObjectId) -> String {
    let mut digest = Sha256::new();
    digest.update(owner.as_str().as_bytes());
    digest.update([0]);
    digest.update(object.as_str().as_bytes());
    let digest = digest.finalize();
    format!(
        "sh-{}",
        digest[..16]
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn object(protocol: &str, enabled: bool) -> ApiObject<StreamHostSpec> {
        serde_json::from_value(serde_json::json!({
            "api_version": "v1",
            "metadata": {"id": format!("{protocol}-host"), "owner_id": "alice"},
            "spec": {
                "listen_port": if protocol == "tcp" { 9000 } else { 9443 },
                "protocol": protocol,
                "forward_host": "127.0.0.1",
                "forward_port": 7000,
                "sni_hosts": if protocol == "tcp" { serde_json::json!([]) } else { serde_json::json!(["db.example.test"]) },
                "enabled": enabled
            }
        }))
        .expect("stream host")
    }

    #[test]
    fn compiles_tcp_tls_and_disabled_without_io() {
        let base =
            aegisproxy_config::load_bytes(include_bytes!("../../../config/examples/minimal.toml"))
                .expect("base");
        let desired = [object("tcp", true), object("tls_passthrough", true)];
        let compiled = compile_stream_hosts(&base, &[], &desired).expect("compiled");
        assert_eq!(compiled.listeners.len(), base.listeners.len() + 2);
        assert!(compiled.routes.iter().any(|route| route.default));
        assert!(compiled.routes.iter().any(|route| {
            route.hosts == ["db.example.test"] && !route.default && route.paths.is_empty()
        }));
        assert!(
            compiled
                .upstream_groups
                .iter()
                .flat_map(|group| &group.endpoints)
                .filter(|endpoint| endpoint.url.scheme() == "tcp")
                .all(|endpoint| endpoint.url.host_str() == Some("127.0.0.1"))
        );
        let disabled =
            compile_stream_hosts(&base, &[], &[object("tcp", false)]).expect("disabled compile");
        assert_eq!(
            serde_json::to_vec(&disabled).expect("disabled"),
            serde_json::to_vec(&base).expect("base")
        );
    }

    #[test]
    fn rejects_sni_wildcards_listener_conflicts_and_ssrf() {
        let base =
            aegisproxy_config::load_bytes(include_bytes!("../../../config/examples/minimal.toml"))
                .expect("base");
        let mut invalid = object("tls_passthrough", true);
        invalid.spec.sni_hosts = vec!["*.example.test".into()];
        assert!(matches!(
            compile_stream_hosts(&base, &[], &[invalid]),
            Err(StreamHostCompileError::InvalidContract)
        ));
        let mut conflict = object("tcp", true);
        conflict.spec.listen_port = 8080;
        assert!(matches!(
            compile_stream_hosts(&base, &[], &[conflict]),
            Err(StreamHostCompileError::SemanticValidation)
        ));
        let mut denied = object("tcp", true);
        denied.spec.forward_host = "169.254.169.254".into();
        assert!(matches!(
            compile_stream_hosts(&base, &[], &[denied]),
            Err(StreamHostCompileError::SemanticValidation)
        ));
    }
}
