//! Secret-free typed ownership metadata for canonical access-policy middleware.

use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

use aegisproxy_config::{Config, MiddlewareConfig, RateLimitKey, validate};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{AccessPolicySpec, ApiObject, ContractError, ObjectId};

const STORE_SCHEMA_VERSION: u32 = 1;
const MAX_ACCESS_POLICIES: usize = 1_024;
const MAX_STORE_BYTES: u64 = 1024 * 1024;

static OWNED_STORES: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

#[derive(Debug)]
struct StoreRegistration(PathBuf);

impl Drop for StoreRegistration {
    fn drop(&mut self) {
        OWNED_STORES
            .get_or_init(Default::default)
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&self.0);
    }
}

/// Validated metadata allowed to influence Proxy Host access-policy resolution.
#[derive(Clone, Eq, PartialEq)]
pub struct AccessPolicyMetadata {
    owner_id: ObjectId,
    shared_with: BTreeSet<ObjectId>,
    enabled: bool,
    middleware_ids: Vec<String>,
}

impl fmt::Debug for AccessPolicyMetadata {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessPolicyMetadata")
            .field("enabled", &self.enabled)
            .field("shared_owner_count", &self.shared_with.len())
            .field("middleware_count", &self.middleware_ids.len())
            .finish()
    }
}

impl AccessPolicyMetadata {
    /// Return policy owner.
    #[must_use]
    pub const fn owner_id(&self) -> &ObjectId {
        &self.owner_id
    }

    /// Return owners explicitly allowed to reference the policy.
    #[must_use]
    pub const fn shared_with(&self) -> &BTreeSet<ObjectId> {
        &self.shared_with
    }

    /// Return whether references may compile.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }

    pub(crate) fn permits(&self, owner_id: &ObjectId) -> bool {
        &self.owner_id == owner_id || self.shared_with.contains(owner_id)
    }

    /// Return canonical middleware IDs in stable order.
    #[must_use]
    pub fn middleware_ids(&self) -> &[String] {
        &self.middleware_ids
    }
}

/// Stable fail-closed access-policy metadata compilation error.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum AccessPolicyCompileError {
    /// Typed ownership or middleware-reference shape is invalid.
    #[error("access policy contract is invalid")]
    InvalidContract,
    /// Canonical configuration is not semantically valid.
    #[error("access policy configuration is invalid")]
    InvalidConfiguration,
    /// Referenced middleware does not exist.
    #[error("access policy middleware is unavailable")]
    MissingMiddleware,
    /// Referenced middleware is not an access-control stage.
    #[error("access policy middleware is incompatible")]
    IncompatibleMiddleware,
}

/// Compile one secret-free typed policy into immutable Proxy Host resolution metadata.
pub fn compile_access_policy_metadata(
    object: &ApiObject<AccessPolicySpec>,
    config: &Config,
) -> Result<AccessPolicyMetadata, AccessPolicyCompileError> {
    validate(config).map_err(|_| AccessPolicyCompileError::InvalidConfiguration)?;
    compile_access_policy_metadata_validated(object, config)
}

fn compile_access_policy_metadata_validated(
    object: &ApiObject<AccessPolicySpec>,
    config: &Config,
) -> Result<AccessPolicyMetadata, AccessPolicyCompileError> {
    object
        .spec
        .validate_shape(&object.metadata.owner_id)
        .map_err(|_error: ContractError| AccessPolicyCompileError::InvalidContract)?;

    let mut middleware_ids = Vec::with_capacity(object.spec.middlewares.len());
    let mut ip_policies = 0_usize;
    let mut edge_rate_limits = 0_usize;
    let mut principal_rate_limits = 0_usize;
    let mut in_flight_limits = 0_usize;
    let mut authentication = 0_usize;
    for reference in &object.spec.middlewares {
        let middleware = config
            .middlewares
            .get(reference.as_str())
            .ok_or(AccessPolicyCompileError::MissingMiddleware)?;
        match middleware {
            MiddlewareConfig::IpPolicy { .. } => ip_policies += 1,
            MiddlewareConfig::RateLimit { key, .. } => match key {
                RateLimitKey::ClientIp => edge_rate_limits += 1,
                RateLimitKey::Principal => principal_rate_limits += 1,
            },
            MiddlewareConfig::InFlightLimit { .. } => in_flight_limits += 1,
            MiddlewareConfig::BasicAuth { .. } | MiddlewareConfig::ForwardAuth { .. } => {
                authentication += 1;
            }
            _ => return Err(AccessPolicyCompileError::IncompatibleMiddleware),
        }
        middleware_ids.push(reference.as_str().to_owned());
    }
    if ip_policies > 1
        || edge_rate_limits > 1
        || principal_rate_limits > 1
        || in_flight_limits > 1
        || authentication > 1
        || (principal_rate_limits == 1 && authentication != 1)
    {
        return Err(AccessPolicyCompileError::IncompatibleMiddleware);
    }
    middleware_ids.sort_unstable();

    Ok(AccessPolicyMetadata {
        owner_id: object.metadata.owner_id.clone(),
        shared_with: object.spec.shared_with.iter().cloned().collect(),
        enabled: object.spec.enabled,
        middleware_ids,
    })
}

/// One persisted Access Policy generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredAccessPolicy {
    /// Monotonic object-local generation, starting at one.
    pub generation: u64,
    /// Strict secret-free desired state.
    pub object: ApiObject<AccessPolicySpec>,
}

/// Durable Access Policy storage failure.
#[derive(Debug, Error)]
pub enum AccessPolicyStoreError {
    /// Filesystem operation failed.
    #[error("Access Policy storage I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Atomic replacement completed but directory durability could not be confirmed.
    #[error("Access Policy storage durability is indeterminate")]
    Indeterminate(#[source] std::io::Error),
    /// A prior indeterminate replacement requires restart reconciliation.
    #[error("Access Policy storage requires recovery")]
    RecoveryRequired,
    /// Another store instance owns this file.
    #[error("Access Policy storage is already locked")]
    Locked,
    /// Stored bytes, schema, object, or permissions are invalid.
    #[error("stored Access Policy state is invalid")]
    Invalid,
    /// Object count or durable byte size reached its hard bound.
    #[error("Access Policy storage reached its hard limit")]
    Limit,
    /// Globally unique ID, owner, or expected generation conflicts.
    #[error("Access Policy storage conflict")]
    Conflict,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AccessPolicyFile {
    schema_version: u32,
    policies: Vec<StoredAccessPolicy>,
}

/// Exclusively owned, globally indexed durable Access Policy store.
pub struct AccessPolicyStore {
    path: PathBuf,
    _registration: StoreRegistration,
    _lock: File,
    recovery_required: AtomicBool,
    policies: Mutex<BTreeMap<ObjectId, StoredAccessPolicy>>,
}

impl fmt::Debug for AccessPolicyStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AccessPolicyStore")
            .field(
                "policy_count",
                &self
                    .policies
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .len(),
            )
            .finish_non_exhaustive()
    }
}

impl AccessPolicyStore {
    /// Open and strictly validate a private Access Policy state file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, AccessPolicyStoreError> {
        let path = path.as_ref().to_path_buf();
        let parent = path.parent().ok_or(AccessPolicyStoreError::Invalid)?;
        create_private_directory(parent)?;
        let registration = register_store(&path)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(parent.join(".access-policies-owner.lock"))?;
        secure_file_permissions(&lock)?;
        FileExt::try_lock_exclusive(&lock).map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                AccessPolicyStoreError::Locked
            } else {
                AccessPolicyStoreError::Io(error)
            }
        })?;
        Ok(Self {
            policies: Mutex::new(load_store(&path)?),
            path,
            _registration: registration,
            _lock: lock,
            recovery_required: AtomicBool::new(false),
        })
    }

    /// Create one globally unique policy at generation one.
    pub fn create(
        &self,
        object: ApiObject<AccessPolicySpec>,
    ) -> Result<StoredAccessPolicy, AccessPolicyStoreError> {
        let object = canonical_policy_object(object)?;
        let id = object.metadata.id.clone();
        let mut policies = self
            .policies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_mutable()?;
        if policies.len() >= MAX_ACCESS_POLICIES {
            return Err(AccessPolicyStoreError::Limit);
        }
        if policies.contains_key(&id) {
            return Err(AccessPolicyStoreError::Conflict);
        }
        let stored = StoredAccessPolicy {
            generation: 1,
            object,
        };
        policies.insert(id.clone(), stored.clone());
        if let Err(error) = persist_store(&self.path, &policies) {
            if !matches!(error, AccessPolicyStoreError::Indeterminate(_)) {
                policies.remove(&id);
            } else {
                self.recovery_required.store(true, Ordering::Release);
            }
            return Err(error);
        }
        Ok(stored)
    }

    /// Replace one owned policy at its exact generation.
    pub fn update(
        &self,
        object: ApiObject<AccessPolicySpec>,
        expected_generation: u64,
    ) -> Result<StoredAccessPolicy, AccessPolicyStoreError> {
        let object = canonical_policy_object(object)?;
        let id = object.metadata.id.clone();
        let owner = object.metadata.owner_id.clone();
        let mut policies = self
            .policies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_mutable()?;
        let previous = policies
            .get(&id)
            .filter(|stored| {
                stored.generation == expected_generation && stored.object.metadata.owner_id == owner
            })
            .cloned()
            .ok_or(AccessPolicyStoreError::Conflict)?;
        if previous.object == object {
            return Ok(previous);
        }
        let stored = StoredAccessPolicy {
            generation: expected_generation
                .checked_add(1)
                .ok_or(AccessPolicyStoreError::Limit)?,
            object,
        };
        policies.insert(id.clone(), stored.clone());
        if let Err(error) = persist_store(&self.path, &policies) {
            if !matches!(error, AccessPolicyStoreError::Indeterminate(_)) {
                policies.insert(id, previous);
            } else {
                self.recovery_required.store(true, Ordering::Release);
            }
            return Err(error);
        }
        Ok(stored)
    }

    /// Delete one owned policy at its exact generation.
    pub fn delete(
        &self,
        owner_id: &ObjectId,
        object_id: &ObjectId,
        expected_generation: u64,
    ) -> Result<StoredAccessPolicy, AccessPolicyStoreError> {
        let mut policies = self
            .policies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_mutable()?;
        let previous = policies
            .get(object_id)
            .filter(|stored| {
                stored.generation == expected_generation
                    && &stored.object.metadata.owner_id == owner_id
            })
            .cloned()
            .ok_or(AccessPolicyStoreError::Conflict)?;
        policies.remove(object_id);
        if let Err(error) = persist_store(&self.path, &policies) {
            if !matches!(error, AccessPolicyStoreError::Indeterminate(_)) {
                policies.insert(object_id.clone(), previous.clone());
            } else {
                self.recovery_required.store(true, Ordering::Release);
            }
            return Err(error);
        }
        Ok(previous)
    }

    /// Return one policy only within the requested owner namespace.
    #[must_use]
    pub fn get(&self, owner_id: &ObjectId, object_id: &ObjectId) -> Option<StoredAccessPolicy> {
        self.policies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(object_id)
            .filter(|stored| &stored.object.metadata.owner_id == owner_id)
            .cloned()
    }

    /// Return stable policy-ID ordering within the requested owner namespace.
    #[must_use]
    pub fn list(&self, owner_id: &ObjectId) -> Vec<StoredAccessPolicy> {
        self.policies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter(|stored| &stored.object.metadata.owner_id == owner_id)
            .cloned()
            .collect()
    }

    /// Compile every stored policy into a globally unique metadata index.
    pub fn metadata(
        &self,
        config: &Config,
    ) -> Result<BTreeMap<ObjectId, AccessPolicyMetadata>, AccessPolicyStoreError> {
        validate(config).map_err(|_| AccessPolicyStoreError::Invalid)?;
        let policies = self
            .policies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .map(|(id, stored)| (id.clone(), stored.object.clone()))
            .collect::<Vec<_>>();
        policies
            .into_iter()
            .map(|(id, stored)| {
                compile_access_policy_metadata_validated(&stored, config)
                    .map(|metadata| (id, metadata))
                    .map_err(|_| AccessPolicyStoreError::Invalid)
            })
            .collect()
    }

    /// Whether a post-rename durability failure blocks further mutation until restart.
    #[must_use]
    pub fn recovery_required(&self) -> bool {
        self.recovery_required.load(Ordering::Acquire)
    }

    fn ensure_mutable(&self) -> Result<(), AccessPolicyStoreError> {
        if self.recovery_required() {
            Err(AccessPolicyStoreError::RecoveryRequired)
        } else {
            Ok(())
        }
    }
}

fn register_store(path: &Path) -> Result<StoreRegistration, AccessPolicyStoreError> {
    let parent = path.parent().ok_or(AccessPolicyStoreError::Invalid)?;
    let canonical = parent
        .canonicalize()?
        .join(path.file_name().ok_or(AccessPolicyStoreError::Invalid)?);
    let mut owned = OWNED_STORES
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !owned.insert(canonical.clone()) {
        return Err(AccessPolicyStoreError::Locked);
    }
    Ok(StoreRegistration(canonical))
}

fn validate_policy_object(
    object: &ApiObject<AccessPolicySpec>,
) -> Result<(), AccessPolicyStoreError> {
    object
        .spec
        .validate_shape(&object.metadata.owner_id)
        .map_err(|_| AccessPolicyStoreError::Invalid)
}

fn canonical_policy_object(
    mut object: ApiObject<AccessPolicySpec>,
) -> Result<ApiObject<AccessPolicySpec>, AccessPolicyStoreError> {
    validate_policy_object(&object)?;
    object.spec.shared_with.sort_unstable();
    object.spec.middlewares.sort_unstable();
    Ok(object)
}

fn load_store(
    path: &Path,
) -> Result<BTreeMap<ObjectId, StoredAccessPolicy>, AccessPolicyStoreError> {
    let file = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() > MAX_STORE_BYTES
                || insecure_file_permissions(&metadata)
            {
                return Err(AccessPolicyStoreError::Invalid);
            }
            let mut bytes = Vec::new();
            File::open(path)?
                .take(MAX_STORE_BYTES + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_STORE_BYTES {
                return Err(AccessPolicyStoreError::Limit);
            }
            serde_json::from_slice::<AccessPolicyFile>(&bytes)
                .map_err(|_| AccessPolicyStoreError::Invalid)?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => AccessPolicyFile {
            schema_version: STORE_SCHEMA_VERSION,
            policies: Vec::new(),
        },
        Err(error) => return Err(error.into()),
    };
    if file.schema_version != STORE_SCHEMA_VERSION || file.policies.len() > MAX_ACCESS_POLICIES {
        return Err(AccessPolicyStoreError::Invalid);
    }
    let mut policies = BTreeMap::new();
    for stored in file.policies {
        if stored.generation == 0
            || validate_policy_object(&stored.object).is_err()
            || !stored.object.spec.shared_with.is_sorted()
            || !stored.object.spec.middlewares.is_sorted()
        {
            return Err(AccessPolicyStoreError::Invalid);
        }
        let id = stored.object.metadata.id.clone();
        if policies.insert(id, stored).is_some() {
            return Err(AccessPolicyStoreError::Invalid);
        }
    }
    Ok(policies)
}

fn persist_store(
    path: &Path,
    policies: &BTreeMap<ObjectId, StoredAccessPolicy>,
) -> Result<(), AccessPolicyStoreError> {
    let parent = path.parent().ok_or(AccessPolicyStoreError::Invalid)?;
    create_private_directory(parent)?;
    let bytes = serde_json::to_vec_pretty(&AccessPolicyFile {
        schema_version: STORE_SCHEMA_VERSION,
        policies: policies.values().cloned().collect(),
    })
    .map_err(|_| AccessPolicyStoreError::Invalid)?;
    if bytes.len() as u64 > MAX_STORE_BYTES {
        return Err(AccessPolicyStoreError::Limit);
    }
    let mut suffix = [0_u8; 8];
    getrandom::fill(&mut suffix).map_err(|_| AccessPolicyStoreError::Invalid)?;
    let temporary = parent.join(format!(
        ".access-policies-{}.tmp",
        URL_SAFE_NO_PAD.encode(suffix)
    ));
    if let Err(error) = write_private_file(&temporary, &bytes) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    sync_parent(parent).map_err(AccessPolicyStoreError::Indeterminate)
}

#[cfg(not(test))]
fn sync_parent(parent: &Path) -> Result<(), std::io::Error> {
    File::open(parent)?.sync_all()
}

#[cfg(test)]
thread_local! {
    static FAIL_PARENT_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn sync_parent(parent: &Path) -> Result<(), std::io::Error> {
    if FAIL_PARENT_SYNC.get() {
        return Err(std::io::Error::other("injected parent sync failure"));
    }
    File::open(parent)?.sync_all()
}

#[cfg(unix)]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_private_file(path: &Path, bytes: &[u8]) -> Result<(), std::io::Error> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

fn create_private_directory(path: &Path) -> Result<(), std::io::Error> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && !insecure_directory_permissions(&metadata) =>
        {
            Ok(())
        }
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Access Policy parent is not a private directory",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
            set_private_directory_permissions(path)
        }
        Err(error) => Err(error),
    }
}

fn secure_file_permissions(file: &File) -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

#[cfg(unix)]
fn set_private_directory_permissions(path: &Path) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn set_private_directory_permissions(_path: &Path) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(unix)]
fn insecure_directory_permissions(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o077 != 0
}

#[cfg(not(unix))]
fn insecure_directory_permissions(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(unix)]
fn insecure_file_permissions(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o077 != 0
}

#[cfg(not(unix))]
fn insecure_file_permissions(_metadata: &fs::Metadata) -> bool {
    false
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU64, Ordering};

    use super::*;

    static NONCE: AtomicU64 = AtomicU64::new(0);

    fn owned_policy(id: &str, owner: &str, middlewares: &[&str]) -> ApiObject<AccessPolicySpec> {
        let shared_owner = if owner == "bob" { "alice" } else { "bob" };
        serde_json::from_value(serde_json::json!({
            "api_version": "v1",
            "metadata": {"id": id, "owner_id": owner},
            "spec": {
                "enabled": true,
                "shared_with": [shared_owner],
                "middlewares": middlewares
            }
        }))
        .expect("access policy")
    }

    fn policy(middlewares: &[&str]) -> ApiObject<AccessPolicySpec> {
        owned_policy("private-lan", "alice", middlewares)
    }

    fn maximal_policy(index: usize) -> ApiObject<AccessPolicySpec> {
        let mut object = owned_policy(&format!("policy-{index:04}"), "alice", &["edge-ip"]);
        object.spec.shared_with = (0..128)
            .map(|item| {
                format!("owner-{item:03}-{}", "x".repeat(53))
                    .parse()
                    .expect("owner")
            })
            .collect();
        object.spec.middlewares = (0..64)
            .map(|item| {
                format!("middleware-{item:02}-{}", "x".repeat(47))
                    .parse()
                    .expect("middleware")
            })
            .collect();
        object
    }

    fn config() -> Config {
        aegisproxy_config::load_bytes(include_bytes!("../../../config/examples/phase7.toml"))
            .expect("middleware config")
    }

    fn store_path(name: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "aegisproxy-access-policy-store-{}-{name}-{}",
            std::process::id(),
            NONCE.fetch_add(1, Ordering::Relaxed)
        ));
        (root.join("admin/access-policies.json"), root)
    }

    #[test]
    fn compiles_canonical_secret_free_ownership_metadata() {
        let mut config = config();
        let MiddlewareConfig::BasicAuth { users, .. } = config
            .middlewares
            .get_mut("basic")
            .expect("Basic auth middleware")
        else {
            panic!("expected Basic auth middleware");
        };
        users.insert("canary".into(), "env://ACCESS_POLICY_SECRET_CANARY".into());
        let object = policy(&["edge-rate", "basic", "edge-ip"]);
        let metadata = compile_access_policy_metadata(&object, &config).expect("compiled metadata");

        assert!(metadata.permits(&"alice".parse().expect("owner")));
        assert!(metadata.permits(&"bob".parse().expect("shared owner")));
        assert!(!metadata.permits(&"charlie".parse().expect("other owner")));
        assert_eq!(metadata.middleware_ids(), ["basic", "edge-ip", "edge-rate"]);
        let debug = format!("{metadata:?}");
        assert!(!debug.contains("ACCESS_POLICY_SECRET_CANARY"));
        assert!(!debug.contains("env://"));
        assert!(!debug.contains("alice"));
        assert!(!debug.contains("bob"));
        assert!(
            !serde_json::to_string(&object)
                .expect("policy JSON")
                .contains("ACCESS_POLICY_SECRET_CANARY")
        );
        for error in [
            AccessPolicyCompileError::InvalidContract,
            AccessPolicyCompileError::InvalidConfiguration,
            AccessPolicyCompileError::MissingMiddleware,
            AccessPolicyCompileError::IncompatibleMiddleware,
        ] {
            assert!(!error.to_string().contains("ACCESS_POLICY_SECRET_CANARY"));
        }
    }

    #[test]
    fn canonicalizes_input_order_and_accepts_each_access_stage() {
        let config = config();
        let first = policy(&["edge-rate", "edge-ip", "route-cap"]);
        let mut second = policy(&["route-cap", "edge-ip", "edge-rate"]);
        second.spec.shared_with = vec![
            "carol".parse().expect("owner"),
            "bob".parse().expect("owner"),
        ];
        let mut first = first;
        first.spec.shared_with = vec![
            "bob".parse().expect("owner"),
            "carol".parse().expect("owner"),
        ];
        assert_eq!(
            compile_access_policy_metadata(&first, &config).expect("first"),
            compile_access_policy_metadata(&second, &config).expect("second")
        );

        for middlewares in [
            &["route-cap"][..],
            &["authentik"][..],
            &["basic", "principal-rate"][..],
        ] {
            compile_access_policy_metadata(&policy(middlewares), &config)
                .expect("compatible access stage");
        }
    }

    #[test]
    fn rejects_missing_incompatible_and_invalid_policy_bindings() {
        let config = config();
        assert_eq!(
            compile_access_policy_metadata(&policy(&["missing"]), &config),
            Err(AccessPolicyCompileError::MissingMiddleware)
        );
        assert_eq!(
            compile_access_policy_metadata(&policy(&["cors"]), &config),
            Err(AccessPolicyCompileError::IncompatibleMiddleware)
        );
        assert_eq!(
            compile_access_policy_metadata(&policy(&["basic", "authentik"]), &config),
            Err(AccessPolicyCompileError::IncompatibleMiddleware)
        );
        assert_eq!(
            compile_access_policy_metadata(&policy(&["principal-rate"]), &config),
            Err(AccessPolicyCompileError::IncompatibleMiddleware)
        );

        let mut invalid = policy(&["edge-ip"]);
        invalid
            .spec
            .shared_with
            .push("alice".parse().expect("owner"));
        assert_eq!(
            compile_access_policy_metadata(&invalid, &config),
            Err(AccessPolicyCompileError::InvalidContract)
        );

        let mut invalid_config = config;
        invalid_config.schema_version = 2;
        assert_eq!(
            compile_access_policy_metadata(&policy(&["edge-ip"]), &invalid_config),
            Err(AccessPolicyCompileError::InvalidConfiguration)
        );
    }

    #[test]
    fn store_persists_global_ids_owner_reads_and_generation_cas() {
        let (path, root) = store_path("round-trip");
        let store = AccessPolicyStore::open(&path).expect("store");
        let alice = store
            .create(owned_policy("private-lan", "alice", &["edge-ip"]))
            .expect("create Alice policy");
        assert_eq!(alice.generation, 1);
        store
            .create(owned_policy("bob-policy", "bob", &["edge-rate"]))
            .expect("create Bob policy");
        assert!(matches!(
            store.create(owned_policy("private-lan", "carol", &["route-cap"])),
            Err(AccessPolicyStoreError::Conflict)
        ));
        let alice_owner: ObjectId = "alice".parse().expect("owner");
        let bob_owner: ObjectId = "bob".parse().expect("owner");
        let id: ObjectId = "private-lan".parse().expect("ID");
        assert_eq!(store.list(&alice_owner).len(), 1);
        assert!(store.get(&bob_owner, &id).is_none());

        let mut changed = alice.object;
        changed.spec.enabled = false;
        let changed = store.update(changed, 1).expect("update");
        assert_eq!(changed.generation, 2);
        assert!(matches!(
            store.update(changed.object.clone(), 1),
            Err(AccessPolicyStoreError::Conflict)
        ));
        let mut wrong_owner = changed.object.clone();
        wrong_owner.metadata.owner_id = "carol".parse().expect("owner");
        assert!(matches!(
            store.update(wrong_owner, 2),
            Err(AccessPolicyStoreError::Conflict)
        ));
        assert!(matches!(
            store.delete(&bob_owner, &id, 2),
            Err(AccessPolicyStoreError::Conflict)
        ));
        assert!(matches!(
            store.delete(&alice_owner, &id, 1),
            Err(AccessPolicyStoreError::Conflict)
        ));
        drop(store);

        let reopened = AccessPolicyStore::open(&path).expect("reopen");
        assert_eq!(
            reopened
                .get(&alice_owner, &id)
                .expect("stored policy")
                .generation,
            2
        );
        assert_eq!(reopened.metadata(&config()).expect("metadata").len(), 2);
        reopened
            .delete(&alice_owner, &id, 2)
            .expect("delete policy");
        assert!(reopened.get(&alice_owner, &id).is_none());
        drop(reopened);
        let after_delete = AccessPolicyStore::open(&path).expect("reopen after delete");
        assert!(after_delete.get(&alice_owner, &id).is_none());
        drop(after_delete);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn store_canonicalizes_equivalent_policy_order() {
        let (path, root) = store_path("canonical");
        let store = AccessPolicyStore::open(&path).expect("store");
        let mut object = policy(&["edge-rate", "edge-ip"]);
        object.spec.shared_with = vec![
            "carol".parse().expect("owner"),
            "bob".parse().expect("owner"),
        ];
        let stored = store.create(object).expect("create");
        assert_eq!(
            stored
                .object
                .spec
                .shared_with
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["bob", "carol"]
        );
        assert_eq!(
            stored
                .object
                .spec
                .middlewares
                .iter()
                .map(|reference| reference.as_str())
                .collect::<Vec<_>>(),
            ["edge-ip", "edge-rate"]
        );
        let before = fs::read(&path).expect("canonical bytes");
        let mut equivalent = stored.object.clone();
        equivalent.spec.shared_with.reverse();
        equivalent.spec.middlewares.reverse();
        let unchanged = store.update(equivalent, 1).expect("idempotent update");
        assert_eq!(unchanged.generation, 1);
        assert_eq!(fs::read(&path).expect("unchanged bytes"), before);
        drop(store);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn store_serializes_same_generation_updates() {
        use std::sync::{Arc, Barrier};

        let (path, root) = store_path("concurrent-cas");
        let store = Arc::new(AccessPolicyStore::open(&path).expect("store"));
        let stored = store
            .create(owned_policy("private-lan", "alice", &["edge-ip"]))
            .expect("create");
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();
        for enabled in [false, true] {
            let store = Arc::clone(&store);
            let barrier = Arc::clone(&barrier);
            let mut object = stored.object.clone();
            object.spec.enabled = enabled;
            object.spec.middlewares = vec!["edge-rate".parse().expect("middleware")];
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                store.update(object, 1)
            }));
        }
        barrier.wait();
        let results = threads
            .into_iter()
            .map(|thread| thread.join().expect("update thread"))
            .collect::<Vec<_>>();
        assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|result| matches!(result, Err(AccessPolicyStoreError::Conflict)))
                .count(),
            1
        );
        drop(store);
        let reopened = AccessPolicyStore::open(&path).expect("reopen");
        let owner: ObjectId = "alice".parse().expect("owner");
        let id: ObjectId = "private-lan".parse().expect("ID");
        assert_eq!(
            reopened
                .get(&owner, &id)
                .expect("winner persisted")
                .generation,
            2
        );
        drop(reopened);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn store_rejects_tampering_duplicates_and_invalid_generations() {
        let (path, root) = store_path("tamper");
        let store = AccessPolicyStore::open(&path).expect("store");
        store
            .create(owned_policy("private-lan", "alice", &["edge-ip"]))
            .expect("create policy");
        drop(store);
        let bytes = fs::read(&path).expect("stored bytes");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("stored JSON");
        let mutations: [fn(&mut serde_json::Value); 4] = [
            |value: &mut serde_json::Value| value["unknown"] = serde_json::json!(true),
            |value: &mut serde_json::Value| value["schema_version"] = serde_json::json!(2),
            |value: &mut serde_json::Value| {
                value["policies"][0]["generation"] = serde_json::json!(0)
            },
            |value: &mut serde_json::Value| {
                let duplicate = value["policies"][0].clone();
                value["policies"]
                    .as_array_mut()
                    .expect("policies")
                    .push(duplicate);
            },
        ];
        for mutate in mutations {
            let mut tampered = value.clone();
            mutate(&mut tampered);
            fs::write(&path, serde_json::to_vec(&tampered).expect("tampered JSON"))
                .expect("tamper store");
            assert!(matches!(
                AccessPolicyStore::open(&path),
                Err(AccessPolicyStoreError::Invalid)
            ));
        }
        fs::write(&path, &bytes).expect("restore store");

        #[cfg(unix)]
        {
            use std::os::unix::fs::{PermissionsExt, symlink};

            fs::set_permissions(&path, fs::Permissions::from_mode(0o644))
                .expect("broaden permissions");
            assert!(matches!(
                AccessPolicyStore::open(&path),
                Err(AccessPolicyStoreError::Invalid)
            ));
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600))
                .expect("restore permissions");
            let symlink_path = root.join("admin/access-policies-link.json");
            symlink(&path, &symlink_path).expect("symlink");
            assert!(matches!(
                AccessPolicyStore::open(&symlink_path),
                Err(AccessPolicyStoreError::Invalid)
            ));

            let parent = path.parent().expect("parent");
            fs::set_permissions(parent, fs::Permissions::from_mode(0o755))
                .expect("broaden parent permissions");
            assert!(AccessPolicyStore::open(&path).is_err());
            fs::set_permissions(parent, fs::Permissions::from_mode(0o700))
                .expect("restore parent permissions");

            let linked_parent = root.join("linked-admin");
            symlink(parent, &linked_parent).expect("parent symlink");
            assert!(AccessPolicyStore::open(linked_parent.join("access-policies.json")).is_err());
        }
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn store_has_exclusive_ownership_and_enforces_capacity() {
        let (path, root) = store_path("ownership-capacity");
        let store = AccessPolicyStore::open(&path).expect("store");
        assert!(matches!(
            AccessPolicyStore::open(&path),
            Err(AccessPolicyStoreError::Locked)
        ));
        drop(store);

        let mut policies = BTreeMap::new();
        for index in 0..MAX_ACCESS_POLICIES {
            let object = owned_policy(&format!("policy-{index:04}"), "alice", &["edge-ip"]);
            policies.insert(
                object.metadata.id.clone(),
                StoredAccessPolicy {
                    generation: 1,
                    object,
                },
            );
        }
        persist_store(&path, &policies).expect("persist capacity");
        let full = AccessPolicyStore::open(&path).expect("full store");
        assert!(matches!(
            full.create(owned_policy("one-too-many", "alice", &["edge-ip"])),
            Err(AccessPolicyStoreError::Limit)
        ));
        drop(full);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn store_rolls_back_when_serialized_byte_limit_is_reached() {
        let (path, root) = store_path("byte-capacity");
        let store = AccessPolicyStore::open(&path).expect("store");
        let mut index = 0;
        loop {
            let before_count = store.list(&"alice".parse().expect("owner")).len();
            let before_bytes = fs::read(&path).ok();
            match store.create(maximal_policy(index)) {
                Ok(_) => index += 1,
                Err(AccessPolicyStoreError::Limit) => {
                    assert!(index < MAX_ACCESS_POLICIES);
                    assert_eq!(
                        store.list(&"alice".parse().expect("owner")).len(),
                        before_count
                    );
                    assert_eq!(fs::read(&path).ok(), before_bytes);
                    break;
                }
                Err(error) => panic!("unexpected storage failure: {error}"),
            }
        }
        drop(store);
        let reopened = AccessPolicyStore::open(&path).expect("reopen bounded store");
        assert_eq!(reopened.list(&"alice".parse().expect("owner")).len(), index);
        drop(reopened);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn store_restores_memory_for_precommit_write_failures() {
        let (path, root) = store_path("write-failure");
        let store = AccessPolicyStore::open(&path).expect("store");
        fs::create_dir(&path).expect("block initial replacement");
        assert!(matches!(
            store.create(owned_policy("new-policy", "alice", &["edge-ip"])),
            Err(AccessPolicyStoreError::Io(_))
        ));
        let owner: ObjectId = "alice".parse().expect("owner");
        let new_id: ObjectId = "new-policy".parse().expect("ID");
        assert!(store.get(&owner, &new_id).is_none());
        fs::remove_dir(&path).expect("unblock replacement");

        let stored = store
            .create(owned_policy("private-lan", "alice", &["edge-ip"]))
            .expect("create policy");
        fs::remove_file(&path).expect("remove backing file");
        fs::create_dir(&path).expect("block replacement");
        let mut changed = stored.object;
        changed.spec.enabled = false;
        assert!(matches!(
            store.update(changed, 1),
            Err(AccessPolicyStoreError::Io(_))
        ));
        let id: ObjectId = "private-lan".parse().expect("ID");
        let retained = store.get(&owner, &id).expect("retained memory");
        assert_eq!(retained.generation, 1);
        assert!(retained.object.spec.enabled);

        fs::remove_dir(&path).expect("unblock replacement");
        persist_store(
            &path,
            &store
                .policies
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
        .expect("restore backing file");
        fs::remove_file(&path).expect("remove backing file");
        fs::create_dir(&path).expect("block delete replacement");
        assert!(matches!(
            store.delete(&owner, &id, 1),
            Err(AccessPolicyStoreError::Io(_))
        ));
        assert!(store.get(&owner, &id).is_some());
        assert!(!store.recovery_required());
        drop(store);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn store_keeps_memory_aligned_after_each_post_commit_sync_failure() {
        let (path, root) = store_path("post-commit");
        let store = AccessPolicyStore::open(&path).expect("store");
        FAIL_PARENT_SYNC.set(true);
        let result = store.create(owned_policy("private-lan", "alice", &["edge-ip"]));
        FAIL_PARENT_SYNC.set(false);
        assert!(matches!(
            result,
            Err(AccessPolicyStoreError::Indeterminate(_))
        ));
        assert!(store.recovery_required());
        assert!(matches!(
            store.create(owned_policy("blocked", "alice", &["edge-ip"])),
            Err(AccessPolicyStoreError::RecoveryRequired)
        ));
        let owner: ObjectId = "alice".parse().expect("owner");
        let id: ObjectId = "private-lan".parse().expect("ID");
        assert!(store.get(&owner, &id).is_some());
        drop(store);
        let reopened = AccessPolicyStore::open(&path).expect("reopen committed create");
        let mut changed = reopened.get(&owner, &id).expect("created state").object;
        changed.spec.enabled = false;
        FAIL_PARENT_SYNC.set(true);
        let result = reopened.update(changed, 1);
        FAIL_PARENT_SYNC.set(false);
        assert!(matches!(
            result,
            Err(AccessPolicyStoreError::Indeterminate(_))
        ));
        assert!(reopened.recovery_required());
        assert!(matches!(
            reopened.update(reopened.get(&owner, &id).expect("updated state").object, 2),
            Err(AccessPolicyStoreError::RecoveryRequired)
        ));
        assert_eq!(
            reopened
                .get(&owner, &id)
                .expect("updated memory")
                .generation,
            2
        );
        drop(reopened);
        let reopened = AccessPolicyStore::open(&path).expect("reopen committed update");
        assert_eq!(
            reopened.get(&owner, &id).expect("updated disk").generation,
            2
        );
        FAIL_PARENT_SYNC.set(true);
        let result = reopened.delete(&owner, &id, 2);
        FAIL_PARENT_SYNC.set(false);
        assert!(matches!(
            result,
            Err(AccessPolicyStoreError::Indeterminate(_))
        ));
        assert!(reopened.recovery_required());
        assert!(matches!(
            reopened.delete(&owner, &id, 2),
            Err(AccessPolicyStoreError::RecoveryRequired)
        ));
        assert!(reopened.get(&owner, &id).is_none());
        drop(reopened);
        let reopened = AccessPolicyStore::open(&path).expect("reopen committed delete");
        assert!(reopened.get(&owner, &id).is_none());
        drop(reopened);
        fs::remove_dir_all(root).expect("cleanup");
    }
}
