//! Bounded durable storage for typed Proxy Host desired state.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
};

use aegisproxy_config::revision::RevisionMetadata;
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    ApiObject, DiscoverySourceSpec, ObjectId, ProxyHostSpec, StoredAccessPolicy, StoredCertificate,
    StreamHostSpec, access_policy::MAX_ACCESS_POLICIES,
};

const STORE_SCHEMA_VERSION: u32 = 1;
const PROXY_HOST_FILE_SCHEMA_VERSION: u32 = 2;
pub(crate) const MAX_PROXY_HOSTS: usize = 4_096;
const MAX_STORE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_TRANSACTION_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CANDIDATE_SNAPSHOTS: usize = 1_000;
const CANDIDATE_SCHEMA_V1: u32 = 1;
const CANDIDATE_SCHEMA_V2: u32 = 2;

/// One persisted Proxy Host desired-state generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredProxyHost {
    /// Monotonic object-local generation, starting at one.
    pub generation: u64,
    /// Strict typed desired state.
    pub object: ApiObject<ProxyHostSpec>,
}

/// One intentional, durable Proxy Host draft generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredProxyHostDraft {
    /// Monotonic draft-local generation, starting at one.
    pub generation: u64,
    /// Applied object generation on which this draft was based, or none for a new object.
    pub base_generation: Option<u64>,
    /// Strict typed draft state. Drafts are excluded from desired-state snapshots.
    pub object: ApiObject<ProxyHostSpec>,
}

/// Immutable object/domain claims used during candidate compilation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProxyHostClaims {
    /// Claimed owner/object identities.
    pub objects: BTreeSet<(ObjectId, ObjectId)>,
    /// Claimed exact domains and their owner/object identities.
    pub domains: BTreeMap<String, (ObjectId, ObjectId)>,
}

/// Immutable complete desired-state snapshot used for optimistic compilation.
#[derive(Clone, Eq, PartialEq)]
pub struct ProxyHostSnapshot {
    epoch: u64,
    objects: Vec<StoredProxyHost>,
}

/// Immutable typed desired state bound to one configuration revision.
#[derive(Clone, Eq, PartialEq)]
pub struct BoundProxyHostCandidate {
    schema_version: u32,
    binding_hash: String,
    objects: Vec<ApiObject<ProxyHostSpec>>,
    stream_hosts: Vec<ApiObject<StreamHostSpec>>,
    discovery_sources: Vec<ApiObject<DiscoverySourceSpec>>,
    access_policies: Vec<StoredAccessPolicy>,
    certificates: Vec<StoredCertificate>,
}

impl fmt::Debug for BoundProxyHostCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundProxyHostCandidate")
            .field("schema_version", &self.schema_version)
            .field("binding_hash", &self.binding_hash)
            .field("object_count", &self.objects.len())
            .field("access_policy_count", &self.access_policies.len())
            .field("stream_host_count", &self.stream_hosts.len())
            .field("discovery_source_count", &self.discovery_sources.len())
            .field("certificate_count", &self.certificates.len())
            .finish()
    }
}

impl BoundProxyHostCandidate {
    /// Return private typed snapshot schema version.
    #[must_use]
    pub const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Return the canonical desired-state binding hash.
    #[must_use]
    pub fn binding_hash(&self) -> &str {
        &self.binding_hash
    }

    /// Return stable owner/object-ordered desired state.
    #[must_use]
    pub fn objects(&self) -> &[ApiObject<ProxyHostSpec>] {
        &self.objects
    }

    /// Return canonical referenced Access Policy generations.
    #[must_use]
    pub fn access_policies(&self) -> &[StoredAccessPolicy] {
        &self.access_policies
    }

    /// Return stable complete Stream Host desired state.
    #[must_use]
    pub fn stream_hosts(&self) -> &[ApiObject<StreamHostSpec>] {
        &self.stream_hosts
    }

    /// Return stable complete Discovery Source desired state.
    #[must_use]
    pub fn discovery_sources(&self) -> &[ApiObject<DiscoverySourceSpec>] {
        &self.discovery_sources
    }

    /// Return canonical referenced Certificate generations.
    #[must_use]
    pub fn certificates(&self) -> &[StoredCertificate] {
        &self.certificates
    }
}

impl fmt::Debug for ProxyHostSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyHostSnapshot")
            .field("epoch", &self.epoch)
            .field("object_count", &self.objects.len())
            .finish()
    }
}

impl ProxyHostSnapshot {
    /// Return process-local store epoch captured with objects.
    #[must_use]
    pub const fn epoch(&self) -> u64 {
        self.epoch
    }

    /// Return stable owner/object-ordered stored records.
    #[must_use]
    pub fn objects(&self) -> &[StoredProxyHost] {
        &self.objects
    }
}

/// Durable typed-object storage failure.
#[derive(Debug, Error)]
pub enum ProxyHostStoreError {
    /// Filesystem operation failed.
    #[error("Proxy Host storage I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Atomic replacement completed but directory durability could not be confirmed.
    #[error("Proxy Host storage durability is indeterminate")]
    Indeterminate(#[source] std::io::Error),
    /// Immutable candidate binding is visible but directory durability is uncertain.
    #[error("candidate binding durability is indeterminate")]
    CandidateIndeterminate(#[source] std::io::Error),
    /// A prior indeterminate replacement requires restart reconciliation.
    #[error("Proxy Host storage requires recovery")]
    RecoveryRequired,
    /// Stored bytes, schema, object, or permissions are invalid.
    #[error("stored Proxy Host state is invalid")]
    Invalid,
    /// Object count or durable byte size reached its hard bound.
    #[error("Proxy Host storage reached its hard limit")]
    Limit,
    /// Object identity, domain, or expected generation conflicts.
    #[error("Proxy Host storage conflict")]
    Conflict,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProxyHostFileV1 {
    schema_version: u32,
    objects: Vec<StoredProxyHost>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProxyHostFileV2 {
    schema_version: u32,
    objects: Vec<StoredProxyHost>,
    drafts: Vec<StoredProxyHostDraft>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProxyHostCandidateFile {
    schema_version: u32,
    revision_id: String,
    binding_hash: String,
    objects: Vec<ApiObject<ProxyHostSpec>>,
    #[serde(default)]
    access_policies: Vec<StoredAccessPolicy>,
    #[serde(default)]
    stream_hosts: Vec<ApiObject<StreamHostSpec>>,
    #[serde(default)]
    discovery_sources: Vec<ApiObject<DiscoverySourceSpec>>,
    #[serde(default)]
    certificates: Vec<StoredCertificate>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProxyHostTransactionFile {
    schema_version: u32,
    target_revision: String,
    previous: Vec<StoredProxyHost>,
    target: Vec<StoredProxyHost>,
}

#[derive(Serialize)]
struct ProxyHostBinding<'a> {
    schema_version: u32,
    objects: &'a [ApiObject<ProxyHostSpec>],
}

#[derive(Serialize)]
struct ProxyHostPolicyBinding<'a> {
    schema_version: u32,
    objects: &'a [ApiObject<ProxyHostSpec>],
    access_policies: &'a [StoredAccessPolicy],
}

#[derive(Serialize)]
struct UnifiedBinding<'a> {
    schema_version: u32,
    proxy_hosts: &'a [ApiObject<ProxyHostSpec>],
    stream_hosts: &'a [ApiObject<StreamHostSpec>],
    discovery_sources: &'a [ApiObject<DiscoverySourceSpec>],
    access_policies: &'a [StoredAccessPolicy],
    certificates: &'a [StoredCertificate],
}

/// Complete schema-2 typed desired state and exact dependencies.
#[derive(Debug)]
pub struct UnifiedCandidateState<'a> {
    /// Complete Proxy Host desired state.
    pub proxy_hosts: &'a [ApiObject<ProxyHostSpec>],
    /// Complete Stream Host desired state.
    pub stream_hosts: &'a [ApiObject<StreamHostSpec>],
    /// Complete Discovery Source desired state.
    pub discovery_sources: &'a [ApiObject<DiscoverySourceSpec>],
    /// Exact referenced Access Policy records.
    pub access_policies: &'a [StoredAccessPolicy],
    /// Exact referenced Certificate records.
    pub certificates: &'a [StoredCertificate],
}

type ObjectIndex = BTreeMap<ObjectId, BTreeMap<ObjectId, StoredProxyHost>>;
type DraftIndex = BTreeMap<ObjectId, BTreeMap<ObjectId, StoredProxyHostDraft>>;

/// Single-process, owner-indexed typed Proxy Host store.
pub struct ProxyHostStore {
    path: PathBuf,
    candidate_dir: PathBuf,
    objects: Mutex<ObjectIndex>,
    drafts: Mutex<DraftIndex>,
    epoch: AtomicU64,
    rollback_pending: AtomicBool,
    recovery_required: AtomicBool,
}

impl fmt::Debug for ProxyHostStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyHostStore")
            .field(
                "object_count",
                &self
                    .objects
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .values()
                    .map(BTreeMap::len)
                    .sum::<usize>(),
            )
            .finish_non_exhaustive()
    }
}

impl ProxyHostStore {
    /// Open and strictly validate a private typed-object file.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, ProxyHostStoreError> {
        let path = path.as_ref().to_path_buf();
        let candidate_dir = path
            .parent()
            .ok_or(ProxyHostStoreError::Invalid)?
            .join("proxy-host-candidates");
        let (objects, drafts) = load_file(&path)?;
        let rollback_pending = match fs::symlink_metadata(
            path.parent()
                .ok_or(ProxyHostStoreError::Invalid)?
                .join("proxy-host-rollback.json"),
        ) {
            Ok(_) => true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
            Err(error) => return Err(error.into()),
        };
        Ok(Self {
            path,
            candidate_dir,
            objects: Mutex::new(index_objects(objects)?),
            drafts: Mutex::new(index_drafts(drafts)?),
            epoch: AtomicU64::new(0),
            rollback_pending: AtomicBool::new(rollback_pending),
            recovery_required: AtomicBool::new(false),
        })
    }

    /// Create one object at generation one and persist it atomically.
    pub fn create(
        &self,
        object: ApiObject<ProxyHostSpec>,
    ) -> Result<StoredProxyHost, ProxyHostStoreError> {
        self.create_inner(object, None)
    }

    /// Create only when complete desired state still matches `expected_epoch`.
    pub fn create_if_epoch(
        &self,
        object: ApiObject<ProxyHostSpec>,
        expected_epoch: u64,
    ) -> Result<StoredProxyHost, ProxyHostStoreError> {
        self.create_inner(object, Some(expected_epoch))
    }

    fn create_inner(
        &self,
        object: ApiObject<ProxyHostSpec>,
        expected_epoch: Option<u64>,
    ) -> Result<StoredProxyHost, ProxyHostStoreError> {
        self.ensure_mutable()?;
        validate_object(&object)?;
        let owner_id = object.metadata.owner_id.clone();
        let object_id = object.metadata.id.clone();
        let mut objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let drafts = self
            .drafts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_mutable()?;
        self.ensure_no_transaction()?;
        let next_epoch = self.next_epoch(expected_epoch)?;
        let count = object_count(&objects);
        if count >= MAX_PROXY_HOSTS
            || objects
                .get(&owner_id)
                .is_some_and(|owned| owned.contains_key(&object_id))
            || domain_claimed(&objects, &object.spec.domain, None)
        {
            return Err(if count >= MAX_PROXY_HOSTS {
                ProxyHostStoreError::Limit
            } else {
                ProxyHostStoreError::Conflict
            });
        }
        let stored = StoredProxyHost {
            generation: 1,
            object,
        };
        objects
            .entry(owner_id.clone())
            .or_default()
            .insert(object_id.clone(), stored.clone());
        if let Err(error) = persist(&self.path, &objects, &drafts) {
            if self.mark_indeterminate(&error) {
                return Err(error);
            }
            remove_indexed(&mut objects, &owner_id, &object_id);
            return Err(error);
        }
        self.epoch.store(next_epoch, Ordering::Release);
        Ok(stored)
    }

    /// Replace one matching object generation and persist it atomically.
    pub fn update(
        &self,
        object: ApiObject<ProxyHostSpec>,
        expected_generation: u64,
    ) -> Result<StoredProxyHost, ProxyHostStoreError> {
        self.update_inner(object, expected_generation, None)
    }

    /// Replace only when object generation and complete desired-state epoch both match.
    pub fn update_if_epoch(
        &self,
        object: ApiObject<ProxyHostSpec>,
        expected_generation: u64,
        expected_epoch: u64,
    ) -> Result<StoredProxyHost, ProxyHostStoreError> {
        self.update_inner(object, expected_generation, Some(expected_epoch))
    }

    fn update_inner(
        &self,
        object: ApiObject<ProxyHostSpec>,
        expected_generation: u64,
        expected_epoch: Option<u64>,
    ) -> Result<StoredProxyHost, ProxyHostStoreError> {
        self.ensure_mutable()?;
        validate_object(&object)?;
        let owner_id = object.metadata.owner_id.clone();
        let object_id = object.metadata.id.clone();
        let mut objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let drafts = self
            .drafts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_mutable()?;
        self.ensure_no_transaction()?;
        let next_epoch = self.next_epoch(expected_epoch)?;
        let previous = objects
            .get(&owner_id)
            .and_then(|owned| owned.get(&object_id))
            .filter(|stored| stored.generation == expected_generation)
            .cloned()
            .ok_or(ProxyHostStoreError::Conflict)?;
        if domain_claimed(&objects, &object.spec.domain, Some((&owner_id, &object_id))) {
            return Err(ProxyHostStoreError::Conflict);
        }
        let stored = StoredProxyHost {
            generation: expected_generation
                .checked_add(1)
                .ok_or(ProxyHostStoreError::Limit)?,
            object,
        };
        objects
            .entry(owner_id.clone())
            .or_default()
            .insert(object_id.clone(), stored.clone());
        if let Err(error) = persist(&self.path, &objects, &drafts) {
            if self.mark_indeterminate(&error) {
                return Err(error);
            }
            objects
                .entry(owner_id)
                .or_default()
                .insert(object_id, previous);
            return Err(error);
        }
        self.epoch.store(next_epoch, Ordering::Release);
        Ok(stored)
    }

    /// Delete one matching object generation and persist removal atomically.
    pub fn delete(
        &self,
        owner_id: &ObjectId,
        object_id: &ObjectId,
        expected_generation: u64,
    ) -> Result<StoredProxyHost, ProxyHostStoreError> {
        self.delete_inner(owner_id, object_id, expected_generation, None)
    }

    /// Delete only when object generation and complete desired-state epoch both match.
    pub fn delete_if_epoch(
        &self,
        owner_id: &ObjectId,
        object_id: &ObjectId,
        expected_generation: u64,
        expected_epoch: u64,
    ) -> Result<StoredProxyHost, ProxyHostStoreError> {
        self.delete_inner(
            owner_id,
            object_id,
            expected_generation,
            Some(expected_epoch),
        )
    }

    fn delete_inner(
        &self,
        owner_id: &ObjectId,
        object_id: &ObjectId,
        expected_generation: u64,
        expected_epoch: Option<u64>,
    ) -> Result<StoredProxyHost, ProxyHostStoreError> {
        let mut objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let drafts = self
            .drafts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_mutable()?;
        self.ensure_no_transaction()?;
        let next_epoch = self.next_epoch(expected_epoch)?;
        let previous = objects
            .get(owner_id)
            .and_then(|owned| owned.get(object_id))
            .filter(|stored| stored.generation == expected_generation)
            .cloned()
            .ok_or(ProxyHostStoreError::Conflict)?;
        remove_indexed(&mut objects, owner_id, object_id);
        if let Err(error) = persist(&self.path, &objects, &drafts) {
            if self.mark_indeterminate(&error) {
                return Err(error);
            }
            objects
                .entry(owner_id.clone())
                .or_default()
                .insert(object_id.clone(), previous.clone());
            return Err(error);
        }
        self.epoch.store(next_epoch, Ordering::Release);
        Ok(previous)
    }

    /// Return one object only within requested owner namespace.
    #[must_use]
    pub fn get(&self, owner_id: &ObjectId, object_id: &ObjectId) -> Option<StoredProxyHost> {
        self.objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(owner_id)
            .and_then(|owned| owned.get(object_id))
            .cloned()
    }

    /// Return stable object-ID ordering within requested owner namespace.
    #[must_use]
    pub fn list(&self, owner_id: &ObjectId) -> Vec<StoredProxyHost> {
        self.objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(owner_id)
            .into_iter()
            .flat_map(BTreeMap::values)
            .cloned()
            .collect()
    }

    /// Return one intentional draft within the requested owner namespace.
    #[must_use]
    pub fn get_draft(
        &self,
        owner_id: &ObjectId,
        object_id: &ObjectId,
    ) -> Option<StoredProxyHostDraft> {
        self.drafts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(owner_id)
            .and_then(|owned| owned.get(object_id))
            .cloned()
    }

    /// Return stable draft object-ID ordering within the requested owner namespace.
    #[must_use]
    pub fn list_drafts(&self, owner_id: &ObjectId) -> Vec<StoredProxyHostDraft> {
        self.drafts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(owner_id)
            .into_iter()
            .flat_map(BTreeMap::values)
            .cloned()
            .collect()
    }

    /// Create an inactive draft based on one exact applied generation.
    pub fn create_draft(
        &self,
        object: ApiObject<ProxyHostSpec>,
        expected_applied_generation: Option<u64>,
    ) -> Result<StoredProxyHostDraft, ProxyHostStoreError> {
        self.ensure_mutable()?;
        validate_object(&object)?;
        let owner_id = object.metadata.owner_id.clone();
        let object_id = object.metadata.id.clone();
        let objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut drafts = self
            .drafts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_mutable()?;
        self.ensure_no_transaction()?;
        let current_generation = objects
            .get(&owner_id)
            .and_then(|owned| owned.get(&object_id))
            .map(|stored| stored.generation);
        if current_generation != expected_applied_generation
            || draft_count(&drafts) >= MAX_PROXY_HOSTS
            || drafts
                .get(&owner_id)
                .is_some_and(|owned| owned.contains_key(&object_id))
        {
            return Err(if draft_count(&drafts) >= MAX_PROXY_HOSTS {
                ProxyHostStoreError::Limit
            } else {
                ProxyHostStoreError::Conflict
            });
        }
        let stored = StoredProxyHostDraft {
            generation: 1,
            base_generation: current_generation,
            object,
        };
        drafts
            .entry(owner_id.clone())
            .or_default()
            .insert(object_id.clone(), stored.clone());
        if let Err(error) = persist(&self.path, &objects, &drafts) {
            if self.mark_indeterminate(&error) {
                return Err(error);
            }
            remove_draft(&mut drafts, &owner_id, &object_id);
            return Err(error);
        }
        Ok(stored)
    }

    /// Replace one inactive draft under draft-local CAS.
    pub fn update_draft(
        &self,
        object: ApiObject<ProxyHostSpec>,
        expected_generation: u64,
    ) -> Result<StoredProxyHostDraft, ProxyHostStoreError> {
        self.ensure_mutable()?;
        validate_object(&object)?;
        let owner_id = object.metadata.owner_id.clone();
        let object_id = object.metadata.id.clone();
        let objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut drafts = self
            .drafts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_mutable()?;
        self.ensure_no_transaction()?;
        let previous = drafts
            .get(&owner_id)
            .and_then(|owned| owned.get(&object_id))
            .filter(|stored| stored.generation == expected_generation)
            .cloned()
            .ok_or(ProxyHostStoreError::Conflict)?;
        if applied_generation(&objects, &owner_id, &object_id) != previous.base_generation {
            return Err(ProxyHostStoreError::Conflict);
        }
        let stored = StoredProxyHostDraft {
            generation: expected_generation
                .checked_add(1)
                .ok_or(ProxyHostStoreError::Limit)?,
            base_generation: previous.base_generation,
            object,
        };
        drafts
            .entry(owner_id.clone())
            .or_default()
            .insert(object_id.clone(), stored.clone());
        if let Err(error) = persist(&self.path, &objects, &drafts) {
            if self.mark_indeterminate(&error) {
                return Err(error);
            }
            drafts
                .entry(owner_id)
                .or_default()
                .insert(object_id, previous);
            return Err(error);
        }
        Ok(stored)
    }

    /// Discard one exact draft without changing applied or active state.
    pub fn discard_draft(
        &self,
        owner_id: &ObjectId,
        object_id: &ObjectId,
        expected_generation: u64,
    ) -> Result<StoredProxyHostDraft, ProxyHostStoreError> {
        let objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut drafts = self
            .drafts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_mutable()?;
        self.ensure_no_transaction()?;
        let previous = drafts
            .get(owner_id)
            .and_then(|owned| owned.get(object_id))
            .filter(|stored| stored.generation == expected_generation)
            .cloned()
            .ok_or(ProxyHostStoreError::Conflict)?;
        remove_draft(&mut drafts, owner_id, object_id);
        if let Err(error) = persist(&self.path, &objects, &drafts) {
            if self.mark_indeterminate(&error) {
                return Err(error);
            }
            drafts
                .entry(owner_id.clone())
                .or_default()
                .insert(object_id.clone(), previous.clone());
            return Err(error);
        }
        Ok(previous)
    }

    /// Promote one exact draft into desired state under complete-state CAS.
    pub fn promote_draft_if_epoch(
        &self,
        owner_id: &ObjectId,
        object_id: &ObjectId,
        expected_draft_generation: u64,
        expected_epoch: u64,
    ) -> Result<StoredProxyHost, ProxyHostStoreError> {
        let mut objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut drafts = self
            .drafts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_mutable()?;
        self.ensure_no_transaction()?;
        let next_epoch = self.next_epoch(Some(expected_epoch))?;
        let draft = drafts
            .get(owner_id)
            .and_then(|owned| owned.get(object_id))
            .filter(|stored| stored.generation == expected_draft_generation)
            .cloned()
            .ok_or(ProxyHostStoreError::Conflict)?;
        let current = objects
            .get(owner_id)
            .and_then(|owned| owned.get(object_id))
            .cloned();
        if current.as_ref().map(|stored| stored.generation) != draft.base_generation
            || domain_claimed(
                &objects,
                &draft.object.spec.domain,
                Some((owner_id, object_id)),
            )
        {
            return Err(ProxyHostStoreError::Conflict);
        }
        let stored = StoredProxyHost {
            generation: current.as_ref().map_or(Ok(1), |stored| {
                stored
                    .generation
                    .checked_add(1)
                    .ok_or(ProxyHostStoreError::Limit)
            })?,
            object: draft.object.clone(),
        };
        objects
            .entry(owner_id.clone())
            .or_default()
            .insert(object_id.clone(), stored.clone());
        remove_draft(&mut drafts, owner_id, object_id);
        if let Err(error) = persist(&self.path, &objects, &drafts) {
            if self.mark_indeterminate(&error) {
                return Err(error);
            }
            match current {
                Some(previous) => {
                    objects
                        .entry(owner_id.clone())
                        .or_default()
                        .insert(object_id.clone(), previous);
                }
                None => remove_indexed(&mut objects, owner_id, object_id),
            }
            drafts
                .entry(owner_id.clone())
                .or_default()
                .insert(object_id.clone(), draft);
            return Err(error);
        }
        self.epoch.store(next_epoch, Ordering::Release);
        Ok(stored)
    }

    /// Snapshot bounded identity and domain claims without object contents.
    #[must_use]
    pub fn claims(&self) -> ProxyHostClaims {
        let objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut claims = ProxyHostClaims::default();
        for (owner_id, owned) in &*objects {
            for (object_id, stored) in owned {
                let identity = (owner_id.clone(), object_id.clone());
                claims.objects.insert(identity.clone());
                claims
                    .domains
                    .insert(stored.object.spec.domain.clone(), identity);
            }
        }
        claims
    }

    /// Capture complete bounded state and epoch under one store lock.
    #[must_use]
    pub fn snapshot(&self) -> ProxyHostSnapshot {
        let objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        ProxyHostSnapshot {
            epoch: self.epoch.load(Ordering::Acquire),
            objects: objects
                .values()
                .flat_map(BTreeMap::values)
                .cloned()
                .collect(),
        }
    }

    /// Capture state only when persistence is known and mutation may proceed.
    pub fn mutation_snapshot(&self) -> Result<ProxyHostSnapshot, ProxyHostStoreError> {
        let objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_mutable()?;
        Ok(ProxyHostSnapshot {
            epoch: self.epoch.load(Ordering::Acquire),
            objects: objects
                .values()
                .flat_map(BTreeMap::values)
                .cloned()
                .collect(),
        })
    }

    /// Whether restart reconciliation is required after an indeterminate replacement.
    #[must_use]
    pub fn recovery_required(&self) -> bool {
        self.recovery_required.load(Ordering::Acquire)
    }

    /// Whether an interrupted typed rollback blocks all administrative mutation.
    #[must_use]
    pub fn rollback_pending(&self) -> bool {
        self.rollback_pending.load(Ordering::Acquire)
    }
}

mod candidate_store;

impl ProxyHostStore {
    /// Durably replace complete desired state under a recovery journal.
    pub fn begin_rollback(
        &self,
        target_revision: &str,
        target_objects: &[ApiObject<ProxyHostSpec>],
        expected_epoch: u64,
    ) -> Result<(), ProxyHostStoreError> {
        validate_revision_id(target_revision)?;
        let canonical = canonical_objects(target_objects)?;
        let mut objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let drafts = self
            .drafts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_mutable()?;
        let next_epoch = self.next_epoch(Some(expected_epoch))?;
        let transaction_path = self.transaction_path()?;
        match fs::symlink_metadata(&transaction_path) {
            Ok(_) => return Err(ProxyHostStoreError::Conflict),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        let target = rollback_index(&objects, canonical)?;
        let journal = ProxyHostTransactionFile {
            schema_version: STORE_SCHEMA_VERSION,
            target_revision: target_revision.to_owned(),
            previous: flatten_index(&objects),
            target: flatten_index(&target),
        };
        persist_transaction(&transaction_path, &journal)?;
        self.rollback_pending.store(true, Ordering::Release);
        if let Err(error) = persist(&self.path, &target, &drafts) {
            self.mark_indeterminate(&error);
            if remove_private_file(&transaction_path).is_ok() {
                self.rollback_pending.store(false, Ordering::Release);
            }
            return Err(error);
        }
        *objects = target;
        self.epoch.store(next_epoch, Ordering::Release);
        Ok(())
    }

    /// Commit a rollback desired-state transaction after runtime activation succeeds.
    pub fn commit_rollback(&self, target_revision: &str) -> Result<(), ProxyHostStoreError> {
        let journal = self
            .load_transaction()?
            .ok_or(ProxyHostStoreError::Conflict)?;
        if journal.target_revision != target_revision {
            return Err(ProxyHostStoreError::Conflict);
        }
        remove_private_file(&self.transaction_path()?)?;
        self.rollback_pending.store(false, Ordering::Release);
        Ok(())
    }

    /// Restore pre-rollback desired state after runtime activation fails.
    pub fn abort_rollback(&self, target_revision: &str) -> Result<(), ProxyHostStoreError> {
        let journal = self
            .load_transaction()?
            .ok_or(ProxyHostStoreError::Conflict)?;
        if journal.target_revision != target_revision {
            return Err(ProxyHostStoreError::Conflict);
        }
        let previous = index_objects(journal.previous)?;
        let mut objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let drafts = self
            .drafts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(error) = persist(&self.path, &previous, &drafts) {
            self.mark_indeterminate(&error);
            return Err(error);
        }
        *objects = previous;
        let next = self.next_epoch(None)?;
        self.epoch.store(next, Ordering::Release);
        remove_private_file(&self.transaction_path()?)?;
        self.rollback_pending.store(false, Ordering::Release);
        Ok(())
    }

    /// Recover an interrupted rollback according to the durably active revision.
    pub fn recover_rollback(&self, active_revision: &str) -> Result<(), ProxyHostStoreError> {
        let Some(journal) = self.load_transaction()? else {
            return Ok(());
        };
        let recovered = if journal.target_revision == active_revision {
            index_objects(journal.target)?
        } else {
            index_objects(journal.previous)?
        };
        let mut objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let drafts = self
            .drafts
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Err(error) = persist(&self.path, &recovered, &drafts) {
            self.mark_indeterminate(&error);
            return Err(error);
        }
        *objects = recovered;
        let next = self.next_epoch(None)?;
        self.epoch.store(next, Ordering::Release);
        remove_private_file(&self.transaction_path()?)?;
        self.rollback_pending.store(false, Ordering::Release);
        Ok(())
    }

    fn load_transaction(&self) -> Result<Option<ProxyHostTransactionFile>, ProxyHostStoreError> {
        let path = self.transaction_path()?;
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.into()),
        };
        if !metadata.is_file()
            || metadata.file_type().is_symlink()
            || metadata.len() > MAX_TRANSACTION_BYTES
        {
            return Err(ProxyHostStoreError::Invalid);
        }
        reject_insecure_file_permissions(&metadata)?;
        let mut bytes = Vec::new();
        File::open(path)?
            .take(MAX_TRANSACTION_BYTES.saturating_add(1))
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_TRANSACTION_BYTES {
            return Err(ProxyHostStoreError::Limit);
        }
        let journal: ProxyHostTransactionFile =
            serde_json::from_slice(&bytes).map_err(|_| ProxyHostStoreError::Invalid)?;
        if journal.schema_version != STORE_SCHEMA_VERSION {
            return Err(ProxyHostStoreError::Invalid);
        }
        validate_revision_id(&journal.target_revision)?;
        index_objects(journal.previous.clone())?;
        index_objects(journal.target.clone())?;
        Ok(Some(journal))
    }

    fn transaction_path(&self) -> Result<PathBuf, ProxyHostStoreError> {
        Ok(self
            .path
            .parent()
            .ok_or(ProxyHostStoreError::Invalid)?
            .join("proxy-host-rollback.json"))
    }

    fn ensure_no_transaction(&self) -> Result<(), ProxyHostStoreError> {
        match fs::symlink_metadata(self.transaction_path()?) {
            Ok(_) => Err(ProxyHostStoreError::Conflict),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    fn ensure_mutable(&self) -> Result<(), ProxyHostStoreError> {
        if self.recovery_required() {
            Err(ProxyHostStoreError::RecoveryRequired)
        } else {
            Ok(())
        }
    }

    fn mark_indeterminate(&self, error: &ProxyHostStoreError) -> bool {
        if matches!(error, ProxyHostStoreError::Indeterminate(_)) {
            self.recovery_required.store(true, Ordering::Release);
            true
        } else {
            false
        }
    }

    fn next_epoch(&self, expected: Option<u64>) -> Result<u64, ProxyHostStoreError> {
        let current = self.epoch.load(Ordering::Acquire);
        if expected.is_some_and(|expected| expected != current) {
            return Err(ProxyHostStoreError::Conflict);
        }
        current.checked_add(1).ok_or(ProxyHostStoreError::Limit)
    }
}

fn canonical_objects(
    objects: &[ApiObject<ProxyHostSpec>],
) -> Result<Vec<ApiObject<ProxyHostSpec>>, ProxyHostStoreError> {
    if objects.len() > MAX_PROXY_HOSTS {
        return Err(ProxyHostStoreError::Limit);
    }
    let mut objects = objects.to_vec();
    objects.sort_by(|left, right| {
        (&left.metadata.owner_id, &left.metadata.id)
            .cmp(&(&right.metadata.owner_id, &right.metadata.id))
    });
    let mut identities = BTreeSet::new();
    let mut domains = BTreeSet::new();
    for object in &objects {
        validate_object(object)?;
        if !identities.insert((&object.metadata.owner_id, &object.metadata.id))
            || !domains.insert(&object.spec.domain)
        {
            return Err(ProxyHostStoreError::Conflict);
        }
    }
    Ok(objects)
}

fn canonical_access_policies(
    policies: &[StoredAccessPolicy],
) -> Result<Vec<StoredAccessPolicy>, ProxyHostStoreError> {
    if policies.len() > MAX_ACCESS_POLICIES {
        return Err(ProxyHostStoreError::Limit);
    }
    let mut policies = policies.to_vec();
    policies.sort_by(|left, right| left.object.metadata.id.cmp(&right.object.metadata.id));
    let mut ids = BTreeSet::new();
    for stored in &policies {
        if stored.generation == 0
            || stored
                .object
                .spec
                .validate_shape(&stored.object.metadata.owner_id)
                .is_err()
            || !ids.insert(&stored.object.metadata.id)
        {
            return Err(ProxyHostStoreError::Invalid);
        }
    }
    Ok(policies)
}

fn canonical_stream_hosts(
    objects: &[ApiObject<StreamHostSpec>],
) -> Result<Vec<ApiObject<StreamHostSpec>>, ProxyHostStoreError> {
    if objects.len() > 128 {
        return Err(ProxyHostStoreError::Limit);
    }
    let mut objects = objects.to_vec();
    objects.sort_by(|left, right| {
        (&left.metadata.owner_id, &left.metadata.id)
            .cmp(&(&right.metadata.owner_id, &right.metadata.id))
    });
    let mut identities = BTreeSet::new();
    for object in &objects {
        if object.spec.validate_shape().is_err()
            || !object.spec.sni_hosts.is_sorted()
            || !identities.insert((&object.metadata.owner_id, &object.metadata.id))
        {
            return Err(ProxyHostStoreError::Invalid);
        }
    }
    Ok(objects)
}

fn canonical_discovery_sources(
    objects: &[ApiObject<DiscoverySourceSpec>],
) -> Result<Vec<ApiObject<DiscoverySourceSpec>>, ProxyHostStoreError> {
    if objects.len() > 64 {
        return Err(ProxyHostStoreError::Limit);
    }
    let mut objects = objects.to_vec();
    objects.sort_by(|left, right| {
        (&left.metadata.owner_id, &left.metadata.id)
            .cmp(&(&right.metadata.owner_id, &right.metadata.id))
    });
    let mut identities = BTreeSet::new();
    for object in &objects {
        if object.spec.validate_shape().is_err()
            || !identities.insert((&object.metadata.owner_id, &object.metadata.id))
        {
            return Err(ProxyHostStoreError::Invalid);
        }
    }
    Ok(objects)
}

fn canonical_certificates(
    certificates: &[StoredCertificate],
) -> Result<Vec<StoredCertificate>, ProxyHostStoreError> {
    if certificates.len() > 1_024 {
        return Err(ProxyHostStoreError::Limit);
    }
    let mut certificates = certificates.to_vec();
    certificates.sort_by(|left, right| left.object.metadata.id.cmp(&right.object.metadata.id));
    let mut ids = BTreeSet::new();
    for stored in &certificates {
        if stored.generation == 0
            || stored
                .object
                .spec
                .validate_shape(&stored.object.metadata.owner_id)
                .is_err()
            || !stored.object.spec.shared_with.is_sorted()
            || !ids.insert(&stored.object.metadata.id)
        {
            return Err(ProxyHostStoreError::Invalid);
        }
    }
    Ok(certificates)
}

fn validate_revision_id(id: &str) -> Result<(), ProxyHostStoreError> {
    if id.len() != 85
        || id.as_bytes().get(20) != Some(&b'-')
        || !id[..20].bytes().all(|byte| byte.is_ascii_digit())
        || !id[21..]
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ProxyHostStoreError::Invalid);
    }
    Ok(())
}

fn valid_binding_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

fn directory_entry_count(path: &Path) -> Result<usize, ProxyHostStoreError> {
    Ok(fs::read_dir(path)?
        .take(MAX_CANDIDATE_SNAPSHOTS + 1)
        .count())
}

fn object_count(objects: &ObjectIndex) -> usize {
    objects.values().map(BTreeMap::len).sum()
}

fn draft_count(drafts: &DraftIndex) -> usize {
    drafts.values().map(BTreeMap::len).sum()
}

fn applied_generation(
    objects: &ObjectIndex,
    owner_id: &ObjectId,
    object_id: &ObjectId,
) -> Option<u64> {
    objects
        .get(owner_id)
        .and_then(|owned| owned.get(object_id))
        .map(|stored| stored.generation)
}

fn flatten_index(objects: &ObjectIndex) -> Vec<StoredProxyHost> {
    objects
        .values()
        .flat_map(BTreeMap::values)
        .cloned()
        .collect()
}

fn rollback_index(
    current: &ObjectIndex,
    target: Vec<ApiObject<ProxyHostSpec>>,
) -> Result<ObjectIndex, ProxyHostStoreError> {
    let mut stored = Vec::with_capacity(target.len());
    for object in target {
        let generation = current
            .get(&object.metadata.owner_id)
            .and_then(|owned| owned.get(&object.metadata.id))
            .map_or(Ok(1), |value| {
                value
                    .generation
                    .checked_add(1)
                    .ok_or(ProxyHostStoreError::Limit)
            })?;
        stored.push(StoredProxyHost { generation, object });
    }
    index_objects(stored)
}

fn validate_object(object: &ApiObject<ProxyHostSpec>) -> Result<(), ProxyHostStoreError> {
    object
        .spec
        .validate_shape()
        .map_err(|_| ProxyHostStoreError::Invalid)
}

fn index_objects(objects: Vec<StoredProxyHost>) -> Result<ObjectIndex, ProxyHostStoreError> {
    if objects.len() > MAX_PROXY_HOSTS {
        return Err(ProxyHostStoreError::Limit);
    }
    let mut indexed = ObjectIndex::new();
    let mut domains = BTreeSet::new();
    for stored in objects {
        if stored.generation == 0 || validate_object(&stored.object).is_err() {
            return Err(ProxyHostStoreError::Invalid);
        }
        let owner_id = stored.object.metadata.owner_id.clone();
        let object_id = stored.object.metadata.id.clone();
        if !domains.insert(stored.object.spec.domain.clone())
            || indexed
                .entry(owner_id)
                .or_default()
                .insert(object_id, stored)
                .is_some()
        {
            return Err(ProxyHostStoreError::Invalid);
        }
    }
    Ok(indexed)
}

fn index_drafts(drafts: Vec<StoredProxyHostDraft>) -> Result<DraftIndex, ProxyHostStoreError> {
    if drafts.len() > MAX_PROXY_HOSTS {
        return Err(ProxyHostStoreError::Limit);
    }
    let mut indexed = DraftIndex::new();
    for stored in drafts {
        if stored.generation == 0
            || stored.base_generation == Some(0)
            || validate_object(&stored.object).is_err()
        {
            return Err(ProxyHostStoreError::Invalid);
        }
        let owner_id = stored.object.metadata.owner_id.clone();
        let object_id = stored.object.metadata.id.clone();
        if indexed
            .entry(owner_id)
            .or_default()
            .insert(object_id, stored)
            .is_some()
        {
            return Err(ProxyHostStoreError::Invalid);
        }
    }
    Ok(indexed)
}

fn domain_claimed(
    objects: &ObjectIndex,
    domain: &str,
    excluded: Option<(&ObjectId, &ObjectId)>,
) -> bool {
    objects
        .iter()
        .flat_map(|(owner_id, owned)| {
            owned
                .iter()
                .map(move |(object_id, stored)| (owner_id, object_id, stored))
        })
        .any(|(owner_id, object_id, stored)| {
            excluded != Some((owner_id, object_id)) && stored.object.spec.domain == domain
        })
}

fn remove_indexed(objects: &mut ObjectIndex, owner_id: &ObjectId, object_id: &ObjectId) {
    let remove_owner = objects.get_mut(owner_id).is_some_and(|owned| {
        owned.remove(object_id);
        owned.is_empty()
    });
    if remove_owner {
        objects.remove(owner_id);
    }
}

fn remove_draft(drafts: &mut DraftIndex, owner_id: &ObjectId, object_id: &ObjectId) {
    let remove_owner = drafts.get_mut(owner_id).is_some_and(|owned| {
        owned.remove(object_id);
        owned.is_empty()
    });
    if remove_owner {
        drafts.remove(owner_id);
    }
}

fn load_file(
    path: &Path,
) -> Result<(Vec<StoredProxyHost>, Vec<StoredProxyHostDraft>), ProxyHostStoreError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() > MAX_STORE_BYTES
            {
                return Err(ProxyHostStoreError::Invalid);
            }
            reject_insecure_file_permissions(&metadata)?;
            let mut bytes = Vec::new();
            File::open(path)?
                .take(MAX_STORE_BYTES.saturating_add(1))
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > MAX_STORE_BYTES {
                return Err(ProxyHostStoreError::Limit);
            }
            if let Ok(file) = serde_json::from_slice::<ProxyHostFileV2>(&bytes)
                && file.schema_version == PROXY_HOST_FILE_SCHEMA_VERSION
            {
                return Ok((file.objects, file.drafts));
            }
            let file: ProxyHostFileV1 =
                serde_json::from_slice(&bytes).map_err(|_| ProxyHostStoreError::Invalid)?;
            if file.schema_version != STORE_SCHEMA_VERSION {
                return Err(ProxyHostStoreError::Invalid);
            }
            Ok((file.objects, Vec::new()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok((Vec::new(), Vec::new())),
        Err(error) => Err(error.into()),
    }
}

fn persist(
    path: &Path,
    objects: &ObjectIndex,
    drafts: &DraftIndex,
) -> Result<(), ProxyHostStoreError> {
    let parent = path.parent().ok_or(ProxyHostStoreError::Invalid)?;
    create_private_directory(parent)?;
    let bytes = serde_json::to_vec_pretty(&ProxyHostFileV2 {
        schema_version: PROXY_HOST_FILE_SCHEMA_VERSION,
        objects: objects
            .values()
            .flat_map(BTreeMap::values)
            .cloned()
            .collect(),
        drafts: drafts
            .values()
            .flat_map(BTreeMap::values)
            .cloned()
            .collect(),
    })
    .map_err(|_| ProxyHostStoreError::Invalid)?;
    if bytes.len() as u64 > MAX_STORE_BYTES {
        return Err(ProxyHostStoreError::Limit);
    }
    let mut suffix = [0_u8; 8];
    getrandom::fill(&mut suffix).map_err(|_| ProxyHostStoreError::Invalid)?;
    let temporary = parent.join(format!(
        ".proxy-hosts-{}.tmp",
        URL_SAFE_NO_PAD.encode(suffix)
    ));
    if let Err(error) = write_private_file(&temporary, &bytes) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    if let Err(error) = rename_store(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    sync_parent(parent).map_err(ProxyHostStoreError::Indeterminate)
}

#[cfg(not(test))]
fn rename_store(temporary: &Path, path: &Path) -> Result<(), std::io::Error> {
    fs::rename(temporary, path)
}

#[cfg(test)]
thread_local! {
    static FAIL_BEFORE_RENAME: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static FAIL_PARENT_SYNC: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

#[cfg(test)]
fn rename_store(temporary: &Path, path: &Path) -> Result<(), std::io::Error> {
    if FAIL_BEFORE_RENAME.get() {
        return Err(std::io::Error::other("injected pre-rename failure"));
    }
    fs::rename(temporary, path)
}

#[cfg(not(test))]
fn sync_parent(parent: &Path) -> Result<(), std::io::Error> {
    File::open(parent)?.sync_all()
}

#[cfg(test)]
fn sync_parent(parent: &Path) -> Result<(), std::io::Error> {
    if FAIL_PARENT_SYNC.get() {
        return Err(std::io::Error::other("injected parent sync failure"));
    }
    File::open(parent)?.sync_all()
}

fn persist_transaction(
    path: &Path,
    journal: &ProxyHostTransactionFile,
) -> Result<(), ProxyHostStoreError> {
    let parent = path.parent().ok_or(ProxyHostStoreError::Invalid)?;
    create_private_directory(parent)?;
    let bytes = serde_json::to_vec_pretty(journal).map_err(|_| ProxyHostStoreError::Invalid)?;
    if bytes.len() as u64 > MAX_TRANSACTION_BYTES {
        return Err(ProxyHostStoreError::Limit);
    }
    let mut suffix = [0_u8; 8];
    getrandom::fill(&mut suffix).map_err(|_| ProxyHostStoreError::Invalid)?;
    let temporary = parent.join(format!(
        ".proxy-host-rollback-{}.tmp",
        URL_SAFE_NO_PAD.encode(suffix)
    ));
    let result = write_private_file(&temporary, &bytes).and_then(|()| {
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()
    });
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(ProxyHostStoreError::Io)
}

fn remove_private_file(path: &Path) -> Result<(), ProxyHostStoreError> {
    match fs::remove_file(path) {
        Ok(()) => File::open(path.parent().ok_or(ProxyHostStoreError::Invalid)?)
            .and_then(|directory| directory.sync_all())
            .map_err(ProxyHostStoreError::Io),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
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
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {
            reject_insecure_directory_permissions(&metadata)
        }
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Proxy Host parent is not a private directory",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path)?;
            set_private_directory_permissions(path)
        }
        Err(error) => Err(error),
    }
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
fn reject_insecure_directory_permissions(metadata: &fs::Metadata) -> Result<(), std::io::Error> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            "Proxy Host parent permissions are too broad",
        ));
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_insecure_directory_permissions(_metadata: &fs::Metadata) -> Result<(), std::io::Error> {
    Ok(())
}

#[cfg(unix)]
fn reject_insecure_file_permissions(metadata: &fs::Metadata) -> Result<(), ProxyHostStoreError> {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
        return Err(ProxyHostStoreError::Invalid);
    }
    Ok(())
}

#[cfg(not(unix))]
fn reject_insecure_file_permissions(_metadata: &fs::Metadata) -> Result<(), ProxyHostStoreError> {
    Ok(())
}

#[cfg(test)]
#[path = "object_store_tests.rs"]
mod tests;
