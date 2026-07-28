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
pub(crate) const MAX_ACCESS_POLICIES: usize = 1_024;
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
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.recovery_required() {
            return Err(AccessPolicyStoreError::RecoveryRequired);
        }
        let policies = policies
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

    /// Compile one globally identified policy for a side-effect-free reference check.
    pub fn metadata_for(
        &self,
        config: &Config,
        id: &ObjectId,
    ) -> Result<Option<AccessPolicyMetadata>, AccessPolicyStoreError> {
        validate(config).map_err(|_| AccessPolicyStoreError::Invalid)?;
        let policies = self
            .policies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.recovery_required() {
            return Err(AccessPolicyStoreError::RecoveryRequired);
        }
        policies
            .get(id)
            .map(|stored| {
                compile_access_policy_metadata_validated(&stored.object, config)
                    .map_err(|_| AccessPolicyStoreError::Invalid)
            })
            .transpose()
    }

    pub(crate) fn candidate_dependencies(
        &self,
        config: &Config,
        ids: &BTreeSet<ObjectId>,
    ) -> Result<
        (
            Vec<StoredAccessPolicy>,
            BTreeMap<ObjectId, AccessPolicyMetadata>,
        ),
        AccessPolicyStoreError,
    > {
        validate(config).map_err(|_| AccessPolicyStoreError::Invalid)?;
        let policies = self
            .policies
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if self.recovery_required() {
            return Err(AccessPolicyStoreError::RecoveryRequired);
        }
        let mut records = Vec::with_capacity(ids.len());
        let mut metadata = BTreeMap::new();
        for id in ids {
            let Some(stored) = policies.get(id) else {
                continue;
            };
            let compiled = compile_access_policy_metadata_validated(&stored.object, config)
                .map_err(|_| AccessPolicyStoreError::Invalid)?;
            records.push(stored.clone());
            metadata.insert(id.clone(), compiled);
        }
        Ok((records, metadata))
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
#[path = "access_policy_tests.rs"]
mod tests;
