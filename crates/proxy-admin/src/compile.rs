//! Side-effect-free compilation from high-level objects to canonical configuration candidates.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    net::IpAddr,
};

use aegisproxy_config::{
    Config, EndpointConfig, RouteConfig, validate, validate_exact_host, validate_upstream_hostname,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::object_store::MAX_PROXY_HOSTS;
use crate::{ApiObject, AutomaticHttps, ForwardProtocol, ObjectId, ProxyHostSpec};

/// Read-only access-policy metadata available during compilation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccessPolicyMetadata {
    /// Policy owner.
    pub owner_id: ObjectId,
    /// Other owners explicitly allowed to reference this policy.
    pub shared_with: BTreeSet<ObjectId>,
    /// Disabled policies fail closed.
    pub enabled: bool,
    /// Existing canonical middleware IDs implementing this policy.
    pub middleware_ids: Vec<String>,
}

/// Existing certificate policy used for managed HTTPS intent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ManagedHttpsPolicy {
    /// Existing HTTPS listener ID.
    pub listener_id: String,
    /// Existing configured certificate ID covering the Proxy Host domain.
    pub certificate_id: String,
}

/// Immutable inputs allowed to influence Proxy Host compilation.
pub struct CompileContext<'a> {
    /// Existing semantically valid configuration to extend.
    pub base_config: &'a Config,
    /// Authenticated owner scope; RBAC remains outside this compiler.
    pub owner_id: &'a ObjectId,
    /// Existing HTTP listener used when automatic HTTPS is disabled.
    pub http_listener_id: &'a str,
    /// Existing upstream group whose egress and resilience policy is cloned.
    pub upstream_template_id: &'a str,
    /// Available access-policy metadata keyed by opaque policy ID.
    pub access_policies: &'a BTreeMap<ObjectId, AccessPolicyMetadata>,
    /// Existing owner/object identities retained by the control plane.
    pub claimed_objects: &'a BTreeSet<(ObjectId, ObjectId)>,
    /// Existing exact domain ownership, including disabled objects.
    pub claimed_domains: &'a BTreeMap<String, (ObjectId, ObjectId)>,
    /// Prepared certificate/listener policy required for managed HTTPS.
    pub managed_https: Option<&'a ManagedHttpsPolicy>,
}

impl fmt::Debug for CompileContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CompileContext")
            .field("schema_version", &self.base_config.schema_version)
            .field("owner_id", self.owner_id)
            .field("http_listener_id", &self.http_listener_id)
            .field("upstream_template_id", &self.upstream_template_id)
            .field("access_policy_count", &self.access_policies.len())
            .field("claimed_object_count", &self.claimed_objects.len())
            .field("claimed_domain_count", &self.claimed_domains.len())
            .field("managed_https", &self.managed_https.is_some())
            .finish()
    }
}

/// Immutable inputs for compiling complete typed Proxy Host desired state.
pub struct ProxyHostSetCompileContext<'a> {
    /// Existing semantically valid active configuration.
    pub base_config: &'a Config,
    /// Existing HTTP listener used when automatic HTTPS is disabled.
    pub http_listener_id: &'a str,
    /// Existing upstream group whose policy is cloned.
    pub upstream_template_id: &'a str,
    /// Available access-policy metadata keyed by opaque policy ID.
    pub access_policies: &'a BTreeMap<ObjectId, AccessPolicyMetadata>,
    /// Prepared HTTPS policy keyed by owner and object identity.
    pub managed_https: &'a BTreeMap<(ObjectId, ObjectId), ManagedHttpsPolicy>,
}

impl fmt::Debug for ProxyHostSetCompileContext<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyHostSetCompileContext")
            .field("schema_version", &self.base_config.schema_version)
            .field("http_listener_id", &self.http_listener_id)
            .field("upstream_template_id", &self.upstream_template_id)
            .field("access_policy_count", &self.access_policies.len())
            .field("managed_https_count", &self.managed_https.len())
            .finish()
    }
}

/// High-level object plus semantically validated configuration candidate.
#[derive(Clone)]
pub struct ProxyHostCandidate {
    object: ApiObject<ProxyHostSpec>,
    config: Config,
}

impl fmt::Debug for ProxyHostCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyHostCandidate")
            .field("object_id", &self.object.metadata.id)
            .field("owner_id", &self.object.metadata.owner_id)
            .field("enabled", &self.object.spec.enabled)
            .field("route_count", &self.config.routes.len())
            .field("upstream_group_count", &self.config.upstream_groups.len())
            .finish()
    }
}

impl ProxyHostCandidate {
    /// Return retained control-plane state, including disabled state and ownership.
    #[must_use]
    pub const fn object(&self) -> &ApiObject<ProxyHostSpec> {
        &self.object
    }

    /// Return canonical candidate configuration; this does not persist or activate it.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }
}

/// Complete typed desired state plus one semantically validated configuration candidate.
#[derive(Clone)]
pub struct ProxyHostSetCandidate {
    objects: Vec<ApiObject<ProxyHostSpec>>,
    config: Config,
}

impl fmt::Debug for ProxyHostSetCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyHostSetCandidate")
            .field("object_count", &self.objects.len())
            .field("route_count", &self.config.routes.len())
            .field("upstream_group_count", &self.config.upstream_groups.len())
            .finish()
    }
}

impl ProxyHostSetCandidate {
    /// Return canonical owner/object-ordered desired state.
    #[must_use]
    pub fn objects(&self) -> &[ApiObject<ProxyHostSpec>] {
        &self.objects
    }

    /// Return complete canonical candidate configuration without persistence or activation.
    #[must_use]
    pub const fn config(&self) -> &Config {
        &self.config
    }
}

/// Stable fail-closed Proxy Host compilation error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum ProxyHostCompileError {
    /// Public domain is malformed or non-canonical.
    #[error("invalid proxy host domain")]
    InvalidDomain,
    /// Wildcard, Unicode, or trailing-dot domain form is unsupported.
    #[error("unsupported proxy host domain form")]
    UnsupportedDomainForm,
    /// Forward host is malformed or non-canonical.
    #[error("invalid forward host")]
    InvalidUpstreamHost,
    /// Forward port is zero.
    #[error("invalid forward port")]
    InvalidPort,
    /// Requested transport is unsupported.
    #[error("unsupported forward protocol")]
    UnsupportedProtocol,
    /// Referenced access policy does not exist or is disabled.
    #[error("access policy is unavailable")]
    MissingAccessPolicy,
    /// Caller owner cannot use referenced access policy.
    #[error("access policy reference is unauthorized")]
    UnauthorizedAccessPolicy,
    /// Authenticated owner scope does not own this object.
    #[error("proxy host owner is unauthorized")]
    UnauthorizedOwner,
    /// Owner/object identity or generated identifier already exists.
    #[error("proxy host object already exists")]
    ConflictingObjectId,
    /// Domain is already claimed or routed.
    #[error("proxy host domain conflicts with existing configuration")]
    ConflictingDomain,
    /// Canonical configuration schema is unsupported.
    #[error("unsupported configuration version")]
    UnsupportedConfigurationVersion,
    /// Required listener or certificate policy is unavailable or incompatible.
    #[error("required certificate or listener policy is unavailable")]
    InvalidCertificatePolicy,
    /// Existing base or template configuration violates compiler invariants.
    #[error("control-plane compilation invariant failed")]
    InternalInvariant,
    /// Typed desired state exceeds its fixed object bound.
    #[error("proxy host desired state exceeds its hard limit")]
    LimitExceeded,
    /// Active generated resources do not form a verified managed resource set.
    #[error("managed proxy host resources conflict with active configuration")]
    ManagedResourceConflict,
    /// Generated candidate failed canonical semantic validation.
    #[error("compiled candidate failed semantic validation")]
    SemanticValidation,
}

/// Compile one Proxy Host after caller RBAC, without persistence, DNS, or runtime activation.
pub fn compile_proxy_host(
    object: &ApiObject<ProxyHostSpec>,
    context: &CompileContext<'_>,
) -> Result<ProxyHostCandidate, ProxyHostCompileError> {
    if context.base_config.schema_version != 1 {
        return Err(ProxyHostCompileError::UnsupportedConfigurationVersion);
    }
    validate(context.base_config).map_err(|_| ProxyHostCompileError::InternalInvariant)?;
    if &object.metadata.owner_id != context.owner_id {
        return Err(ProxyHostCompileError::UnauthorizedOwner);
    }
    let identity = (object.metadata.owner_id.clone(), object.metadata.id.clone());
    if context.claimed_objects.contains(&identity) {
        return Err(ProxyHostCompileError::ConflictingObjectId);
    }

    validate_domain(&object.spec.domain)?;
    validate_forward_host(&object.spec.forward_host)?;
    if object.spec.forward_port == 0 {
        return Err(ProxyHostCompileError::InvalidPort);
    }
    if context.claimed_domains.contains_key(&object.spec.domain)
        || context.base_config.routes.iter().any(|route| {
            route
                .hosts
                .iter()
                .any(|host| host_matches(host, &object.spec.domain))
        })
    {
        return Err(ProxyHostCompileError::ConflictingDomain);
    }

    let middlewares = resolve_access_policy(object, context)?;
    let listener_id = resolve_listener(object, context)?;
    let mut config = context.base_config.clone();
    if object.spec.enabled {
        let namespace = namespace(&object.metadata.owner_id, &object.metadata.id);
        let group_id = format!("{namespace}-upstream");
        let endpoint_id = format!("{namespace}-endpoint");
        let route_id = format!("{namespace}-route");
        if config
            .upstream_groups
            .iter()
            .any(|group| group.id == group_id)
            || config.routes.iter().any(|route| route.id == route_id)
            || config
                .upstream_groups
                .iter()
                .flat_map(|group| &group.endpoints)
                .any(|endpoint| endpoint.id == endpoint_id)
        {
            return Err(ProxyHostCompileError::ConflictingObjectId);
        }
        let mut group = context
            .base_config
            .upstream_groups
            .iter()
            .find(|group| group.id == context.upstream_template_id)
            .cloned()
            .ok_or(ProxyHostCompileError::InternalInvariant)?;
        let prototype = group
            .endpoints
            .first()
            .cloned()
            .ok_or(ProxyHostCompileError::InternalInvariant)?;
        group.id = group_id.clone();
        group.endpoints = vec![compile_endpoint(object, prototype, endpoint_id)?];
        config.upstream_groups.push(group);
        config.routes.push(RouteConfig {
            id: route_id,
            listeners: vec![listener_id],
            hosts: vec![object.spec.domain.clone()],
            paths: Vec::new(),
            path_prefixes: Vec::new(),
            methods: Vec::new(),
            headers: Vec::new(),
            default: false,
            priority: 0,
            middlewares,
            upstream_group: Some(group_id),
        });
    }
    validate(&config).map_err(|_| ProxyHostCompileError::SemanticValidation)?;
    Ok(ProxyHostCandidate {
        object: object.clone(),
        config,
    })
}

/// Compile all typed Proxy Hosts into one canonical candidate without persistence or activation.
///
/// `current_objects` reserves namespaces that may already exist in `base_config`; only a complete
/// compiler-shaped route/group/endpoint set for those identities is removed before desired state is
/// rebuilt. `desired_objects` is the complete post-change state, not a partial patch.
pub fn compile_proxy_hosts(
    current_objects: &[ApiObject<ProxyHostSpec>],
    desired_objects: &[ApiObject<ProxyHostSpec>],
    context: &ProxyHostSetCompileContext<'_>,
) -> Result<ProxyHostSetCandidate, ProxyHostCompileError> {
    if context.base_config.schema_version != 1 {
        return Err(ProxyHostCompileError::UnsupportedConfigurationVersion);
    }
    validate(context.base_config).map_err(|_| ProxyHostCompileError::InternalInvariant)?;
    let current = canonical_objects(current_objects)?;
    let desired = canonical_objects(desired_objects)?;
    let manual = strip_managed_resources(context.base_config, &current)?;
    let template = manual
        .upstream_groups
        .iter()
        .find(|group| group.id == context.upstream_template_id)
        .cloned()
        .ok_or(ProxyHostCompileError::InternalInvariant)?;
    let prototype = template
        .endpoints
        .first()
        .cloned()
        .ok_or(ProxyHostCompileError::InternalInvariant)?;

    let empty_objects = BTreeSet::new();
    let empty_domains = BTreeMap::new();
    let mut route_ids = manual
        .routes
        .iter()
        .map(|route| route.id.clone())
        .collect::<BTreeSet<_>>();
    let mut group_ids = manual
        .upstream_groups
        .iter()
        .map(|group| group.id.clone())
        .collect::<BTreeSet<_>>();
    let mut endpoint_ids = manual
        .upstream_groups
        .iter()
        .flat_map(|group| group.endpoints.iter().map(|endpoint| endpoint.id.clone()))
        .collect::<BTreeSet<_>>();
    let manual_hosts = DomainClaims::from_config(&manual);
    let mut config = manual.clone();

    for object in &desired {
        if manual_hosts.conflicts(&object.spec.domain) {
            return Err(ProxyHostCompileError::ConflictingDomain);
        }
        let identity = (object.metadata.owner_id.clone(), object.metadata.id.clone());
        let single = CompileContext {
            base_config: &manual,
            owner_id: &object.metadata.owner_id,
            http_listener_id: context.http_listener_id,
            upstream_template_id: context.upstream_template_id,
            access_policies: context.access_policies,
            claimed_objects: &empty_objects,
            claimed_domains: &empty_domains,
            managed_https: context.managed_https.get(&identity),
        };
        let middlewares = resolve_access_policy(object, &single)?;
        let listener_id = resolve_listener(object, &single)?;
        if !object.spec.enabled {
            continue;
        }
        let ids = ManagedIds::new(object);
        if !route_ids.insert(ids.route.clone())
            || !group_ids.insert(ids.group.clone())
            || !endpoint_ids.insert(ids.endpoint.clone())
        {
            return Err(ProxyHostCompileError::ConflictingObjectId);
        }
        let mut group = template.clone();
        group.id = ids.group.clone();
        group.endpoints = vec![compile_endpoint(object, prototype.clone(), ids.endpoint)?];
        config.upstream_groups.push(group);
        config.routes.push(RouteConfig {
            id: ids.route,
            listeners: vec![listener_id],
            hosts: vec![object.spec.domain.clone()],
            paths: Vec::new(),
            path_prefixes: Vec::new(),
            methods: Vec::new(),
            headers: Vec::new(),
            default: false,
            priority: 0,
            middlewares,
            upstream_group: Some(ids.group),
        });
    }
    validate(&config).map_err(|_| ProxyHostCompileError::SemanticValidation)?;
    Ok(ProxyHostSetCandidate {
        objects: desired,
        config,
    })
}

#[derive(Clone)]
struct ManagedIds {
    route: String,
    group: String,
    endpoint: String,
}

impl ManagedIds {
    fn new(object: &ApiObject<ProxyHostSpec>) -> Self {
        let namespace = namespace(&object.metadata.owner_id, &object.metadata.id);
        Self {
            route: format!("{namespace}-route"),
            group: format!("{namespace}-upstream"),
            endpoint: format!("{namespace}-endpoint"),
        }
    }
}

fn canonical_objects(
    objects: &[ApiObject<ProxyHostSpec>],
) -> Result<Vec<ApiObject<ProxyHostSpec>>, ProxyHostCompileError> {
    if objects.len() > MAX_PROXY_HOSTS {
        return Err(ProxyHostCompileError::LimitExceeded);
    }
    let mut objects = objects.to_vec();
    objects.sort_by(|left, right| {
        (&left.metadata.owner_id, &left.metadata.id)
            .cmp(&(&right.metadata.owner_id, &right.metadata.id))
    });
    let mut identities = BTreeSet::new();
    let mut domains = BTreeSet::new();
    for object in &objects {
        validate_domain(&object.spec.domain)?;
        validate_forward_host(&object.spec.forward_host)?;
        if object.spec.forward_port == 0 {
            return Err(ProxyHostCompileError::InvalidPort);
        }
        if !identities.insert((&object.metadata.owner_id, &object.metadata.id)) {
            return Err(ProxyHostCompileError::ConflictingObjectId);
        }
        if !domains.insert(&object.spec.domain) {
            return Err(ProxyHostCompileError::ConflictingDomain);
        }
    }
    Ok(objects)
}

fn strip_managed_resources(
    base: &Config,
    current: &[ApiObject<ProxyHostSpec>],
) -> Result<Config, ProxyHostCompileError> {
    let mut routes = BTreeMap::new();
    let mut groups = BTreeMap::new();
    let mut endpoints = BTreeSet::new();
    for object in current {
        let ids = ManagedIds::new(object);
        if routes.insert(ids.route, ids.group.clone()).is_some()
            || groups.insert(ids.group, ids.endpoint.clone()).is_some()
            || !endpoints.insert(ids.endpoint)
        {
            return Err(ProxyHostCompileError::ConflictingObjectId);
        }
    }

    let mut config = base.clone();
    let mut seen_routes = BTreeSet::new();
    let mut retained_routes = Vec::with_capacity(config.routes.len());
    for route in std::mem::take(&mut config.routes) {
        let Some(group) = routes.get(&route.id) else {
            retained_routes.push(route);
            continue;
        };
        if route.listeners.len() != 1
            || route.hosts.len() != 1
            || !route.paths.is_empty()
            || !route.path_prefixes.is_empty()
            || !route.methods.is_empty()
            || !route.headers.is_empty()
            || route.default
            || route.priority != 0
            || route.upstream_group.as_ref() != Some(group)
        {
            return Err(ProxyHostCompileError::ManagedResourceConflict);
        }
        seen_routes.insert(route.id);
    }
    config.routes = retained_routes;

    let mut seen_groups = BTreeSet::new();
    let mut retained_groups = Vec::with_capacity(config.upstream_groups.len());
    for group in std::mem::take(&mut config.upstream_groups) {
        if let Some(endpoint) = groups.get(&group.id) {
            if group.endpoints.len() != 1 || group.endpoints[0].id != *endpoint {
                return Err(ProxyHostCompileError::ManagedResourceConflict);
            }
            seen_groups.insert(group.id);
        } else {
            if group
                .endpoints
                .iter()
                .any(|endpoint| endpoints.contains(&endpoint.id))
            {
                return Err(ProxyHostCompileError::ManagedResourceConflict);
            }
            retained_groups.push(group);
        }
    }
    config.upstream_groups = retained_groups;

    for (route, group) in routes {
        if seen_routes.contains(&route) != seen_groups.contains(&group) {
            return Err(ProxyHostCompileError::ManagedResourceConflict);
        }
    }
    validate(&config).map_err(|_| ProxyHostCompileError::ManagedResourceConflict)?;
    Ok(config)
}

#[derive(Default)]
struct DomainClaims {
    exact: BTreeSet<String>,
    wildcard: BTreeSet<String>,
}

impl DomainClaims {
    fn from_config(config: &Config) -> Self {
        let mut claims = Self::default();
        for host in config.routes.iter().flat_map(|route| &route.hosts) {
            if host.starts_with("*.") {
                claims.wildcard.insert(host.clone());
            } else {
                claims.exact.insert(host.clone());
            }
        }
        claims
    }

    fn conflicts(&self, domain: &str) -> bool {
        self.exact.contains(domain)
            || domain
                .split_once('.')
                .is_some_and(|(_, suffix)| self.wildcard.contains(&format!("*.{suffix}")))
    }
}

fn validate_domain(domain: &str) -> Result<(), ProxyHostCompileError> {
    if !domain.is_ascii() || domain.ends_with('.') || domain.contains('*') {
        return Err(ProxyHostCompileError::UnsupportedDomainForm);
    }
    if domain.parse::<IpAddr>().is_ok() || validate_exact_host(domain).is_err() {
        return Err(ProxyHostCompileError::InvalidDomain);
    }
    Ok(())
}

fn validate_forward_host(host: &str) -> Result<(), ProxyHostCompileError> {
    if host.parse::<IpAddr>().is_ok() {
        return Ok(());
    }
    validate_upstream_hostname(host).map_err(|_| ProxyHostCompileError::InvalidUpstreamHost)
}

fn resolve_access_policy(
    object: &ApiObject<ProxyHostSpec>,
    context: &CompileContext<'_>,
) -> Result<Vec<String>, ProxyHostCompileError> {
    let Some(reference) = object.spec.access_policy_ref.as_ref() else {
        return Ok(Vec::new());
    };
    let policy = context
        .access_policies
        .get(reference.id())
        .filter(|policy| policy.enabled)
        .ok_or(ProxyHostCompileError::MissingAccessPolicy)?;
    if policy.owner_id != object.metadata.owner_id
        && !policy.shared_with.contains(&object.metadata.owner_id)
    {
        return Err(ProxyHostCompileError::UnauthorizedAccessPolicy);
    }
    Ok(policy.middleware_ids.clone())
}

fn resolve_listener(
    object: &ApiObject<ProxyHostSpec>,
    context: &CompileContext<'_>,
) -> Result<String, ProxyHostCompileError> {
    match object.spec.automatic_https {
        AutomaticHttps::Disabled => context
            .base_config
            .listeners
            .iter()
            .find(|listener| listener.id == context.http_listener_id && listener.protocol == "http")
            .map(|listener| listener.id.clone())
            .ok_or(ProxyHostCompileError::InvalidCertificatePolicy),
        AutomaticHttps::Managed => {
            let policy = context
                .managed_https
                .ok_or(ProxyHostCompileError::InvalidCertificatePolicy)?;
            let listener = context
                .base_config
                .listeners
                .iter()
                .find(|listener| {
                    listener.id == policy.listener_id
                        && listener.protocol == "https"
                        && listener.certificates.contains(&policy.certificate_id)
                })
                .ok_or(ProxyHostCompileError::InvalidCertificatePolicy)?;
            certificate_covers(
                context.base_config,
                &policy.certificate_id,
                &object.spec.domain,
            )
            .then(|| listener.id.clone())
            .ok_or(ProxyHostCompileError::InvalidCertificatePolicy)
        }
    }
}

fn compile_endpoint(
    object: &ApiObject<ProxyHostSpec>,
    mut endpoint: EndpointConfig,
    endpoint_id: String,
) -> Result<EndpointConfig, ProxyHostCompileError> {
    let scheme = match object.spec.forward_protocol {
        ForwardProtocol::Http => "http",
        ForwardProtocol::Https => "https",
    };
    endpoint.id = endpoint_id;
    endpoint
        .url
        .set_scheme(scheme)
        .map_err(|_| ProxyHostCompileError::UnsupportedProtocol)?;
    endpoint
        .url
        .set_host(Some(&object.spec.forward_host))
        .map_err(|_| ProxyHostCompileError::InvalidUpstreamHost)?;
    endpoint
        .url
        .set_port(Some(object.spec.forward_port))
        .map_err(|_| ProxyHostCompileError::InvalidPort)?;
    endpoint.url.set_path("");
    endpoint.url.set_query(None);
    endpoint.url.set_fragment(None);
    endpoint.server_name = match object.spec.forward_protocol {
        ForwardProtocol::Http => None,
        ForwardProtocol::Https => Some(object.spec.forward_host.clone()),
    };
    if matches!(object.spec.forward_protocol, ForwardProtocol::Http) {
        endpoint.ca_bundle = None;
    }
    Ok(endpoint)
}

pub(super) fn namespace(owner: &ObjectId, object: &ObjectId) -> String {
    let mut digest = Sha256::new();
    digest.update(owner.as_str().as_bytes());
    digest.update([0]);
    digest.update(object.as_str().as_bytes());
    let digest = digest.finalize();
    let mut output = String::from("ph-");
    for byte in &digest[..16] {
        output.push_str(&format!("{byte:02x}"));
    }
    output
}

fn host_matches(configured: &str, domain: &str) -> bool {
    configured == domain
        || configured
            .strip_prefix("*.")
            .and_then(|suffix| domain.strip_suffix(suffix))
            .is_some_and(|prefix| {
                prefix.ends_with('.') && !prefix[..prefix.len() - 1].contains('.')
            })
}

fn certificate_covers(config: &Config, certificate_id: &str, domain: &str) -> bool {
    config
        .certificates
        .iter()
        .find(|certificate| certificate.id == certificate_id)
        .map(|certificate| &certificate.hosts)
        .or_else(|| {
            config
                .acme
                .certificates
                .iter()
                .find(|certificate| certificate.id == certificate_id)
                .map(|certificate| &certificate.hosts)
        })
        .is_some_and(|hosts| hosts.iter().any(|host| host_matches(host, domain)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use aegisproxy_config::{
        CertificateConfig, ListenerConfig, MiddlewareConfig, revision::RevisionStore,
    };
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn base_config() -> Config {
        let mut config =
            aegisproxy_config::load_bytes(include_bytes!("../../../config/examples/minimal.toml"))
                .expect("valid base config");
        config.tls.identity = Some("env://TEST_AGE_IDENTITY".into());
        config.certificates.push(CertificateConfig {
            id: "managed-new-example".into(),
            hosts: vec!["new.example.test".into()],
            certificate_chain: "file:///test/cert.pem".into(),
            private_key: "file:///test/key.age".into(),
        });
        config.listeners.push(ListenerConfig {
            id: "secure".into(),
            bind: "127.0.0.1:8443".parse().expect("socket address"),
            protocol: "https".into(),
            certificates: vec!["managed-new-example".into()],
        });
        config.middlewares.insert(
            "private-policy".into(),
            MiddlewareConfig::IpPolicy {
                allow: vec!["10.0.0.0/8".parse().expect("CIDR")],
                deny: Vec::new(),
            },
        );
        validate(&config).expect("valid extended base");
        config
    }

    fn object() -> ApiObject<ProxyHostSpec> {
        serde_json::from_str(
            r#"{
                "api_version":"v1",
                "metadata":{"id":"proxy-new","owner_id":"alice"},
                "spec":{
                    "domain":"new.example.test",
                    "forward_host":"upstream.example.test",
                    "forward_port":8080,
                    "forward_protocol":"http",
                    "automatic_https":"disabled",
                    "access_policy_ref":null,
                    "enabled":true
                }
            }"#,
        )
        .expect("typed object")
    }

    struct Parts {
        owner: ObjectId,
        policies: BTreeMap<ObjectId, AccessPolicyMetadata>,
        objects: BTreeSet<(ObjectId, ObjectId)>,
        domains: BTreeMap<String, (ObjectId, ObjectId)>,
    }

    fn parts() -> Parts {
        Parts {
            owner: "alice".parse().expect("owner"),
            policies: BTreeMap::new(),
            objects: BTreeSet::new(),
            domains: BTreeMap::new(),
        }
    }

    fn context<'a>(
        config: &'a Config,
        parts: &'a Parts,
        https: Option<&'a ManagedHttpsPolicy>,
    ) -> CompileContext<'a> {
        CompileContext {
            base_config: config,
            owner_id: &parts.owner,
            http_listener_id: "public",
            upstream_template_id: "app",
            access_policies: &parts.policies,
            claimed_objects: &parts.objects,
            claimed_domains: &parts.domains,
            managed_https: https,
        }
    }

    fn set_context<'a>(
        config: &'a Config,
        policies: &'a BTreeMap<ObjectId, AccessPolicyMetadata>,
        https: &'a BTreeMap<(ObjectId, ObjectId), ManagedHttpsPolicy>,
    ) -> ProxyHostSetCompileContext<'a> {
        ProxyHostSetCompileContext {
            base_config: config,
            http_listener_id: "public",
            upstream_template_id: "app",
            access_policies: policies,
            managed_https: https,
        }
    }

    #[test]
    fn compiles_valid_variants_deterministically() {
        let config = base_config();
        let mut parts = parts();
        parts.policies.insert(
            "private".parse().expect("policy ID"),
            AccessPolicyMetadata {
                owner_id: parts.owner.clone(),
                shared_with: BTreeSet::new(),
                enabled: true,
                middleware_ids: vec!["private-policy".into()],
            },
        );
        let https = ManagedHttpsPolicy {
            listener_id: "secure".into(),
            certificate_id: "managed-new-example".into(),
        };
        let compile = |value: &ApiObject<ProxyHostSpec>| {
            compile_proxy_host(value, &context(&config, &parts, Some(&https)))
                .expect("compiled candidate")
        };

        let http = object();
        let first = compile(&http);
        let second = compile(&http);
        assert_eq!(
            serde_json::to_vec(first.config()).expect("serialize candidate"),
            serde_json::to_vec(second.config()).expect("serialize candidate")
        );
        validate(first.config()).expect("semantic validation");
        assert_eq!(
            first.config().routes.last().expect("generated route").id,
            "ph-4e2643bcdffd306e42206db2e8bdc69f-route"
        );

        let mut upstream_tls = http.clone();
        upstream_tls.spec.forward_protocol = ForwardProtocol::Https;
        let upstream_tls = compile(&upstream_tls);
        let endpoint = &upstream_tls
            .config()
            .upstream_groups
            .last()
            .expect("generated group")
            .endpoints[0];
        assert_eq!(endpoint.url.scheme(), "https");
        assert_eq!(
            endpoint.server_name.as_deref(),
            Some("upstream.example.test")
        );

        let mut managed = http.clone();
        managed.spec.automatic_https = AutomaticHttps::Managed;
        assert_eq!(
            compile(&managed)
                .config()
                .routes
                .last()
                .expect("generated route")
                .listeners,
            ["secure"]
        );

        let mut protected = http.clone();
        protected.spec.access_policy_ref =
            Some(serde_json::from_str("\"private\"").expect("policy reference"));
        assert_eq!(
            compile(&protected)
                .config()
                .routes
                .last()
                .expect("generated route")
                .middlewares,
            ["private-policy"]
        );

        let mut disabled = http;
        disabled.spec.enabled = false;
        let disabled = compile(&disabled);
        assert_eq!(disabled.config().routes.len(), config.routes.len());
        assert_eq!(
            disabled.config().upstream_groups.len(),
            config.upstream_groups.len()
        );
        assert!(!disabled.object().spec.enabled);
    }

    #[test]
    fn compiles_complete_desired_state_deterministically_and_preserves_pending_objects() {
        let config = base_config();
        let policies = BTreeMap::new();
        let https = BTreeMap::new();
        let first = object();
        let mut second = object();
        second.metadata.owner_id = "bob".parse().expect("owner");
        second.metadata.id = "proxy-second".parse().expect("object ID");
        second.spec.domain = "second.example.test".into();

        let ordered = compile_proxy_hosts(
            &[],
            &[second.clone(), first.clone()],
            &set_context(&config, &policies, &https),
        )
        .expect("aggregate candidate");
        let repeated = compile_proxy_hosts(
            &[],
            &[first.clone(), second.clone()],
            &set_context(&config, &policies, &https),
        )
        .expect("repeat aggregate candidate");
        assert_eq!(ordered.objects()[0].metadata.owner_id.as_str(), "alice");
        assert_eq!(ordered.objects()[1].metadata.owner_id.as_str(), "bob");
        assert_eq!(
            serde_json::to_vec(ordered.config()).expect("ordered config"),
            serde_json::to_vec(repeated.config()).expect("repeated config")
        );
        assert_eq!(ordered.config().routes.len(), config.routes.len() + 2);

        let pending = compile_proxy_hosts(
            std::slice::from_ref(&first),
            &[first.clone(), second],
            &set_context(&config, &policies, &https),
        )
        .expect("pending desired state");
        assert_eq!(pending.config().routes.len(), config.routes.len() + 2);
        validate(pending.config()).expect("semantic validation");
    }

    #[test]
    fn aggregate_replaces_only_reserved_managed_resources() {
        let config = base_config();
        let parts = parts();
        let policies = BTreeMap::new();
        let https = BTreeMap::new();
        let current = object();
        let active = compile_proxy_host(&current, &context(&config, &parts, None))
            .expect("active generated config")
            .config()
            .clone();
        let mut desired = current.clone();
        desired.spec.domain = "replacement.example.test".into();

        let replacement = compile_proxy_hosts(
            std::slice::from_ref(&current),
            std::slice::from_ref(&desired),
            &set_context(&active, &policies, &https),
        )
        .expect("replacement candidate");
        assert_eq!(replacement.config().routes.len(), config.routes.len() + 1);
        assert!(
            replacement
                .config()
                .routes
                .iter()
                .any(|route| route.hosts == ["replacement.example.test"])
        );
        assert!(
            !replacement
                .config()
                .routes
                .iter()
                .any(|route| { route.hosts == ["new.example.test"] })
        );

        desired.spec.enabled = false;
        let disabled = compile_proxy_hosts(
            std::slice::from_ref(&current),
            std::slice::from_ref(&desired),
            &set_context(&active, &policies, &https),
        )
        .expect("disabled candidate");
        assert_eq!(disabled.config().routes.len(), config.routes.len());
        assert_eq!(
            disabled.config().upstream_groups.len(),
            config.upstream_groups.len()
        );
    }

    #[test]
    fn aggregate_rejects_manual_takeover_partial_resources_and_duplicate_state() {
        let config = base_config();
        let parts = parts();
        let policies = BTreeMap::new();
        let https = BTreeMap::new();
        let current = object();
        let active = compile_proxy_host(&current, &context(&config, &parts, None))
            .expect("active generated config")
            .config()
            .clone();

        assert_eq!(
            compile_proxy_hosts(
                &[],
                std::slice::from_ref(&current),
                &set_context(&active, &policies, &https),
            )
            .expect_err("unreserved manual collision"),
            ProxyHostCompileError::ConflictingDomain
        );

        let mut partial = active.clone();
        partial
            .routes
            .iter_mut()
            .find(|route| route.id == ManagedIds::new(&current).route)
            .expect("managed route")
            .paths
            .push("/tampered".into());
        validate(&partial).expect("structurally valid tamper");
        assert_eq!(
            compile_proxy_hosts(
                std::slice::from_ref(&current),
                std::slice::from_ref(&current),
                &set_context(&partial, &policies, &https),
            )
            .expect_err("partial managed shape"),
            ProxyHostCompileError::ManagedResourceConflict
        );

        assert_eq!(
            compile_proxy_hosts(
                &[],
                &[current.clone(), current],
                &set_context(&config, &policies, &https),
            )
            .expect_err("duplicate objects"),
            ProxyHostCompileError::ConflictingObjectId
        );
    }

    #[test]
    fn rejects_invalid_conflicting_and_unauthorized_inputs() {
        let config = base_config();
        let mut parts = parts();
        let mut value = object();

        let mut unsupported = config.clone();
        unsupported.schema_version = 2;
        assert_eq!(
            compile_proxy_host(&value, &context(&unsupported, &parts, None))
                .expect_err("unsupported configuration version"),
            ProxyHostCompileError::UnsupportedConfigurationVersion
        );

        for (domain, expected) in [
            ("", ProxyHostCompileError::InvalidDomain),
            ("bad..example", ProxyHostCompileError::InvalidDomain),
            (
                "*.example.test",
                ProxyHostCompileError::UnsupportedDomainForm,
            ),
            ("täst.example", ProxyHostCompileError::UnsupportedDomainForm),
            (
                "example.test.",
                ProxyHostCompileError::UnsupportedDomainForm,
            ),
        ] {
            value.spec.domain = domain.into();
            assert_eq!(
                compile_proxy_host(&value, &context(&config, &parts, None))
                    .expect_err("invalid domain"),
                expected
            );
        }

        value = object();
        value.spec.forward_host = "bad host".into();
        assert_eq!(
            compile_proxy_host(&value, &context(&config, &parts, None))
                .expect_err("invalid upstream"),
            ProxyHostCompileError::InvalidUpstreamHost
        );
        value = object();
        value.spec.forward_port = 0;
        assert_eq!(
            compile_proxy_host(&value, &context(&config, &parts, None)).expect_err("invalid port"),
            ProxyHostCompileError::InvalidPort
        );
        value = object();
        value.spec.automatic_https = AutomaticHttps::Managed;
        assert_eq!(
            compile_proxy_host(&value, &context(&config, &parts, None))
                .expect_err("missing HTTPS policy"),
            ProxyHostCompileError::InvalidCertificatePolicy
        );

        value = object();
        value.metadata.owner_id = "bob".parse().expect("owner");
        assert_eq!(
            compile_proxy_host(&value, &context(&config, &parts, None)).expect_err("wrong owner"),
            ProxyHostCompileError::UnauthorizedOwner
        );

        value = object();
        value.spec.access_policy_ref =
            Some(serde_json::from_str("\"missing\"").expect("reference"));
        assert_eq!(
            compile_proxy_host(&value, &context(&config, &parts, None))
                .expect_err("missing policy"),
            ProxyHostCompileError::MissingAccessPolicy
        );
        parts.policies.insert(
            "disabled".parse().expect("policy ID"),
            AccessPolicyMetadata {
                owner_id: parts.owner.clone(),
                shared_with: BTreeSet::new(),
                enabled: false,
                middleware_ids: vec!["private-policy".into()],
            },
        );
        value.spec.access_policy_ref =
            Some(serde_json::from_str("\"disabled\"").expect("reference"));
        assert_eq!(
            compile_proxy_host(&value, &context(&config, &parts, None))
                .expect_err("disabled policy"),
            ProxyHostCompileError::MissingAccessPolicy
        );
        parts.policies.insert(
            "private".parse().expect("policy ID"),
            AccessPolicyMetadata {
                owner_id: "bob".parse().expect("owner"),
                shared_with: BTreeSet::new(),
                enabled: true,
                middleware_ids: vec!["private-policy".into()],
            },
        );
        value.spec.access_policy_ref =
            Some(serde_json::from_str("\"private\"").expect("reference"));
        assert_eq!(
            compile_proxy_host(&value, &context(&config, &parts, None))
                .expect_err("unauthorized policy"),
            ProxyHostCompileError::UnauthorizedAccessPolicy
        );

        value = object();
        parts
            .objects
            .insert((parts.owner.clone(), value.metadata.id.clone()));
        assert_eq!(
            compile_proxy_host(&value, &context(&config, &parts, None))
                .expect_err("object collision"),
            ProxyHostCompileError::ConflictingObjectId
        );
        parts.objects.clear();
        value.spec.domain = "example.test".into();
        assert_eq!(
            compile_proxy_host(&value, &context(&config, &parts, None))
                .expect_err("existing route domain"),
            ProxyHostCompileError::ConflictingDomain
        );
        value.spec.domain = "new.example.test".into();
        parts.domains.insert(
            value.spec.domain.clone(),
            ("bob".parse().expect("owner"), "other".parse().expect("ID")),
        );
        assert_eq!(
            compile_proxy_host(&value, &context(&config, &parts, None))
                .expect_err("domain collision"),
            ProxyHostCompileError::ConflictingDomain
        );
    }

    #[test]
    fn revision_candidate_does_not_activate_or_leak_plaintext() {
        let config = base_config();
        let parts = parts();
        let candidate = compile_proxy_host(&object(), &context(&config, &parts, None))
            .expect("compiled candidate");
        let state = temp_state();
        let store = RevisionStore::open(&state).expect("revision store");
        let mut rejected = object();
        rejected.spec.domain = "*.example.test".into();
        assert!(compile_proxy_host(&rejected, &context(&config, &parts, None)).is_err());
        assert!(store.list().expect("revision list").is_empty());
        assert!(store.active().expect("active pointer").is_none());
        let revision = store
            .create_candidate(candidate.config(), "typed-proxy-host")
            .expect("persist candidate");
        assert!(store.active().expect("active pointer").is_none());
        assert_eq!(
            store
                .load(&revision.id)
                .expect("load candidate")
                .routes
                .len(),
            config.routes.len() + 1
        );
        let serialized = serde_json::to_string(candidate.config()).expect("serialize candidate");
        for secret in [
            "plaintext-password",
            "private-key-canary",
            "api-token-canary",
        ] {
            assert!(!serialized.contains(secret));
        }
        let debug = format!("{candidate:?}");
        assert!(!debug.contains("file:///"));
        for error in [
            ProxyHostCompileError::MissingAccessPolicy,
            ProxyHostCompileError::UnauthorizedAccessPolicy,
            ProxyHostCompileError::InvalidCertificatePolicy,
            ProxyHostCompileError::SemanticValidation,
        ] {
            assert!(!error.to_string().contains("canary"));
        }
        fs::remove_dir_all(state).expect("remove test state");
    }

    fn temp_state() -> PathBuf {
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system time")
            .as_nanos();
        std::env::temp_dir().join(format!("aegisproxy-compile-{}-{nonce}", std::process::id()))
    }
}
