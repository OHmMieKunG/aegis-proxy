//! Bounded durable storage for typed Proxy Host desired state.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{ApiObject, ObjectId, ProxyHostSpec};

const STORE_SCHEMA_VERSION: u32 = 1;
pub(crate) const MAX_PROXY_HOSTS: usize = 4_096;
const MAX_STORE_BYTES: u64 = 2 * 1024 * 1024;
const MAX_CANDIDATE_SNAPSHOTS: usize = 1_000;

/// One persisted Proxy Host desired-state generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredProxyHost {
    /// Monotonic object-local generation, starting at one.
    pub generation: u64,
    /// Strict typed desired state.
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
    binding_hash: String,
    objects: Vec<ApiObject<ProxyHostSpec>>,
}

impl fmt::Debug for BoundProxyHostCandidate {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BoundProxyHostCandidate")
            .field("binding_hash", &self.binding_hash)
            .field("object_count", &self.objects.len())
            .finish()
    }
}

impl BoundProxyHostCandidate {
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
struct ProxyHostFile {
    schema_version: u32,
    objects: Vec<StoredProxyHost>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProxyHostCandidateFile {
    schema_version: u32,
    revision_id: String,
    binding_hash: String,
    objects: Vec<ApiObject<ProxyHostSpec>>,
}

#[derive(Serialize)]
struct ProxyHostBinding<'a> {
    schema_version: u32,
    objects: &'a [ApiObject<ProxyHostSpec>],
}

type ObjectIndex = BTreeMap<ObjectId, BTreeMap<ObjectId, StoredProxyHost>>;

/// Single-process, owner-indexed typed Proxy Host store.
pub struct ProxyHostStore {
    path: PathBuf,
    candidate_dir: PathBuf,
    objects: Mutex<ObjectIndex>,
    epoch: AtomicU64,
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
        let objects = load_file(&path)?;
        Ok(Self {
            path,
            candidate_dir,
            objects: Mutex::new(index_objects(objects)?),
            epoch: AtomicU64::new(0),
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
        validate_object(&object)?;
        let owner_id = object.metadata.owner_id.clone();
        let object_id = object.metadata.id.clone();
        let mut objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        if let Err(error) = persist(&self.path, &objects) {
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
        validate_object(&object)?;
        let owner_id = object.metadata.owner_id.clone();
        let object_id = object.metadata.id.clone();
        let mut objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        if let Err(error) = persist(&self.path, &objects) {
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
        let next_epoch = self.next_epoch(expected_epoch)?;
        let previous = objects
            .get(owner_id)
            .and_then(|owned| owned.get(object_id))
            .filter(|stored| stored.generation == expected_generation)
            .cloned()
            .ok_or(ProxyHostStoreError::Conflict)?;
        remove_indexed(&mut objects, owner_id, object_id);
        if let Err(error) = persist(&self.path, &objects) {
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

    /// Return the canonical typed desired-state hash used by revision metadata.
    pub fn binding_hash(
        objects: &[ApiObject<ProxyHostSpec>],
    ) -> Result<String, ProxyHostStoreError> {
        let objects = canonical_objects(objects)?;
        let bytes = serde_json::to_vec(&ProxyHostBinding {
            schema_version: STORE_SCHEMA_VERSION,
            objects: &objects,
        })
        .map_err(|_| ProxyHostStoreError::Invalid)?;
        if bytes.len() as u64 > MAX_STORE_BYTES {
            return Err(ProxyHostStoreError::Limit);
        }
        Ok(format!("{:x}", Sha256::digest(bytes)))
    }

    /// Persist one immutable typed desired-state snapshot for a revision.
    pub fn bind_candidate(
        &self,
        revision_id: &str,
        expected_hash: &str,
        objects: &[ApiObject<ProxyHostSpec>],
    ) -> Result<BoundProxyHostCandidate, ProxyHostStoreError> {
        validate_revision_id(revision_id)?;
        let objects = canonical_objects(objects)?;
        let binding_hash = Self::binding_hash(&objects)?;
        if binding_hash != expected_hash {
            return Err(ProxyHostStoreError::Invalid);
        }
        create_private_directory(&self.candidate_dir)?;
        let path = self.candidate_path(revision_id);
        if path.exists() {
            let existing = self.load_candidate(revision_id, expected_hash)?;
            if existing.objects == objects {
                return Ok(existing);
            }
            return Err(ProxyHostStoreError::Conflict);
        }
        if directory_entry_count(&self.candidate_dir)? >= MAX_CANDIDATE_SNAPSHOTS {
            return Err(ProxyHostStoreError::Limit);
        }
        let bytes = serde_json::to_vec_pretty(&ProxyHostCandidateFile {
            schema_version: STORE_SCHEMA_VERSION,
            revision_id: revision_id.to_owned(),
            binding_hash: binding_hash.clone(),
            objects: objects.clone(),
        })
        .map_err(|_| ProxyHostStoreError::Invalid)?;
        if bytes.len() as u64 > MAX_STORE_BYTES {
            return Err(ProxyHostStoreError::Limit);
        }
        write_private_file(&path, &bytes)?;
        File::open(&self.candidate_dir)?.sync_all()?;
        Ok(BoundProxyHostCandidate {
            binding_hash,
            objects,
        })
    }

    /// Load and verify a revision-bound typed desired-state snapshot.
    pub fn load_candidate(
        &self,
        revision_id: &str,
        expected_hash: &str,
    ) -> Result<BoundProxyHostCandidate, ProxyHostStoreError> {
        validate_revision_id(revision_id)?;
        let path = self.candidate_path(revision_id);
        let metadata = fs::symlink_metadata(&path)?;
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
        let file: ProxyHostCandidateFile =
            serde_json::from_slice(&bytes).map_err(|_| ProxyHostStoreError::Invalid)?;
        let objects = canonical_objects(&file.objects)?;
        let binding_hash = Self::binding_hash(&objects)?;
        if file.schema_version != STORE_SCHEMA_VERSION
            || file.revision_id != revision_id
            || file.binding_hash != expected_hash
            || binding_hash != expected_hash
        {
            return Err(ProxyHostStoreError::Invalid);
        }
        Ok(BoundProxyHostCandidate {
            binding_hash,
            objects,
        })
    }

    fn candidate_path(&self, revision_id: &str) -> PathBuf {
        self.candidate_dir.join(format!("{revision_id}.json"))
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

fn directory_entry_count(path: &Path) -> Result<usize, ProxyHostStoreError> {
    Ok(fs::read_dir(path)?
        .take(MAX_CANDIDATE_SNAPSHOTS + 1)
        .count())
}

fn object_count(objects: &ObjectIndex) -> usize {
    objects.values().map(BTreeMap::len).sum()
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

fn load_file(path: &Path) -> Result<Vec<StoredProxyHost>, ProxyHostStoreError> {
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
            let file: ProxyHostFile =
                serde_json::from_slice(&bytes).map_err(|_| ProxyHostStoreError::Invalid)?;
            if file.schema_version != STORE_SCHEMA_VERSION {
                return Err(ProxyHostStoreError::Invalid);
            }
            Ok(file.objects)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(error) => Err(error.into()),
    }
}

fn persist(path: &Path, objects: &ObjectIndex) -> Result<(), ProxyHostStoreError> {
    let parent = path.parent().ok_or(ProxyHostStoreError::Invalid)?;
    create_private_directory(parent)?;
    let bytes = serde_json::to_vec_pretty(&ProxyHostFile {
        schema_version: STORE_SCHEMA_VERSION,
        objects: objects
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
    let result = write_private_file(&temporary, &bytes).and_then(|()| {
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()
    });
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(ProxyHostStoreError::Io)
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
mod tests {
    use std::{
        fs,
        path::PathBuf,
        sync::atomic::{AtomicU64, Ordering},
    };

    use super::*;

    static NONCE: AtomicU64 = AtomicU64::new(0);

    fn temporary_store(name: &str) -> (PathBuf, PathBuf) {
        let root = std::env::temp_dir().join(format!(
            "aegisproxy-proxy-host-store-{}-{name}-{}",
            std::process::id(),
            NONCE.fetch_add(1, Ordering::Relaxed)
        ));
        (root.join("admin/proxy-hosts.json"), root)
    }

    fn object(id: &str, owner: &str, domain: &str) -> ApiObject<ProxyHostSpec> {
        serde_json::from_value(serde_json::json!({
            "api_version": "v1",
            "metadata": {"id": id, "owner_id": owner},
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
        .expect("typed object")
    }

    #[test]
    fn persists_owner_indexed_objects_in_stable_order() {
        let (path, root) = temporary_store("round-trip");
        let store = ProxyHostStore::open(&path).expect("store");
        assert_eq!(store.snapshot().epoch(), 0);
        let alice: ObjectId = "alice".parse().expect("owner");
        let bob: ObjectId = "bob".parse().expect("owner");
        store
            .create_if_epoch(object("proxy-z", "alice", "z.example.test"), 0)
            .expect("create z");
        assert_eq!(store.snapshot().epoch(), 1);
        assert!(matches!(
            store.create_if_epoch(object("stale", "alice", "stale.example.test"), 0),
            Err(ProxyHostStoreError::Conflict)
        ));
        store
            .create(object("proxy-a", "alice", "a.example.test"))
            .expect("create a");
        store
            .create(object("proxy-b", "bob", "b.example.test"))
            .expect("create bob");
        assert_eq!(
            store
                .list(&alice)
                .iter()
                .map(|stored| stored.object.metadata.id.as_str())
                .collect::<Vec<_>>(),
            ["proxy-a", "proxy-z"]
        );
        assert_eq!(store.list(&bob).len(), 1);
        assert!(store.get(&bob, &"proxy-a".parse().expect("id")).is_none());
        let claims = store.claims();
        assert_eq!(claims.objects.len(), 3);
        assert_eq!(
            claims
                .domains
                .get("a.example.test")
                .map(|(owner, object)| (owner.as_str(), object.as_str())),
            Some(("alice", "proxy-a"))
        );
        let snapshot = store.snapshot();
        assert_eq!(snapshot.epoch(), 3);
        assert_eq!(snapshot.objects().len(), 3);
        drop(store);

        let reopened = ProxyHostStore::open(&path).expect("reopen");
        assert_eq!(reopened.snapshot().epoch(), 0);
        assert_eq!(reopened.list(&alice).len(), 2);
        let bytes = fs::read(&path).expect("stored bytes");
        let first = bytes
            .windows(b"proxy-a".len())
            .position(|window| window == b"proxy-a")
            .expect("proxy a");
        let second = bytes
            .windows(b"proxy-z".len())
            .position(|window| window == b"proxy-z")
            .expect("proxy z");
        assert!(first < second);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn update_delete_require_exact_generation_and_restore_after_write_failure() {
        let (path, root) = temporary_store("cas");
        let store = ProxyHostStore::open(&path).expect("store");
        let owner: ObjectId = "alice".parse().expect("owner");
        let id: ObjectId = "proxy-a".parse().expect("id");
        store
            .create(object("proxy-a", "alice", "a.example.test"))
            .expect("create");
        let mut updated = object("proxy-a", "alice", "updated.example.test");
        updated.spec.enabled = false;
        assert!(matches!(
            store.update_if_epoch(updated.clone(), 1, 0),
            Err(ProxyHostStoreError::Conflict)
        ));
        let stored = store.update_if_epoch(updated, 1, 1).expect("update");
        assert_eq!(stored.generation, 2);
        assert_eq!(store.snapshot().epoch(), 2);
        assert!(matches!(
            store.update(stored.object.clone(), 1),
            Err(ProxyHostStoreError::Conflict)
        ));
        assert!(matches!(
            store.delete_if_epoch(&owner, &id, 2, 1),
            Err(ProxyHostStoreError::Conflict)
        ));

        fs::remove_file(&path).expect("remove backing file");
        fs::create_dir(&path).expect("block replacement");
        assert!(matches!(
            store.delete_if_epoch(&owner, &id, 2, 2),
            Err(ProxyHostStoreError::Io(_))
        ));
        assert_eq!(
            store.get(&owner, &id).map(|value| value.generation),
            Some(2)
        );
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn rejects_conflicts_tampering_and_broad_permissions() {
        let (path, root) = temporary_store("invalid");
        let store = ProxyHostStore::open(&path).expect("store");
        store
            .create(object("proxy-a", "alice", "a.example.test"))
            .expect("create");
        assert!(matches!(
            store.create(object("proxy-a", "alice", "other.example.test")),
            Err(ProxyHostStoreError::Conflict)
        ));
        assert!(matches!(
            store.create(object("proxy-b", "bob", "a.example.test")),
            Err(ProxyHostStoreError::Conflict)
        ));
        drop(store);

        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).expect("bytes")).expect("JSON");
        value["unknown"] = serde_json::json!(true);
        fs::write(&path, serde_json::to_vec(&value).expect("JSON bytes")).expect("tamper");
        assert!(matches!(
            ProxyHostStore::open(&path),
            Err(ProxyHostStoreError::Invalid)
        ));

        value.as_object_mut().expect("object").remove("unknown");
        value["schema_version"] = serde_json::json!(2);
        fs::write(&path, serde_json::to_vec(&value).expect("JSON bytes")).expect("future schema");
        assert!(matches!(
            ProxyHostStore::open(&path),
            Err(ProxyHostStoreError::Invalid)
        ));

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut value = value;
            value["schema_version"] = serde_json::json!(1);
            fs::write(&path, serde_json::to_vec(&value).expect("JSON bytes")).expect("rewrite");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("broad mode");
            assert!(matches!(
                ProxyHostStore::open(&path),
                Err(ProxyHostStoreError::Invalid)
            ));
        }
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn candidate_binding_is_stable_private_and_tamper_evident() {
        let (path, root) = temporary_store("candidate-binding");
        let store = ProxyHostStore::open(&path).expect("store");
        let revision = format!("{:020}-{}", 1, "ab".repeat(32));
        let first = object("proxy-b", "bob", "b.example.test");
        let second = object("proxy-a", "alice", "a.example.test");
        let objects = vec![first.clone(), second.clone()];
        let reversed = vec![second, first];
        let binding_hash = ProxyHostStore::binding_hash(&objects).expect("binding hash");
        assert_eq!(
            binding_hash,
            ProxyHostStore::binding_hash(&reversed).expect("stable hash")
        );
        let bound = store
            .bind_candidate(&revision, &binding_hash, &objects)
            .expect("bind candidate");
        assert_eq!(bound.binding_hash(), binding_hash);
        assert_eq!(bound.objects()[0].metadata.owner_id.as_str(), "alice");
        assert_eq!(
            store
                .bind_candidate(&revision, &binding_hash, &reversed)
                .expect("idempotent binding"),
            bound
        );
        drop(store);

        let reopened = ProxyHostStore::open(&path).expect("reopen");
        assert_eq!(
            reopened
                .load_candidate(&revision, &binding_hash)
                .expect("load binding"),
            bound
        );
        assert!(matches!(
            reopened.load_candidate(&revision, &"cd".repeat(32)),
            Err(ProxyHostStoreError::Invalid)
        ));
        assert!(matches!(
            reopened.load_candidate("../candidate", &binding_hash),
            Err(ProxyHostStoreError::Invalid)
        ));

        let candidate_path = root
            .join("admin/proxy-host-candidates")
            .join(format!("{revision}.json"));
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&candidate_path).expect("candidate bytes"))
                .expect("candidate JSON");
        value["objects"][0]["spec"]["enabled"] = serde_json::json!(false);
        fs::write(
            &candidate_path,
            serde_json::to_vec(&value).expect("tampered JSON"),
        )
        .expect("tamper candidate");
        assert!(matches!(
            reopened.load_candidate(&revision, &binding_hash),
            Err(ProxyHostStoreError::Invalid)
        ));

        fs::remove_dir_all(root).expect("cleanup");
    }
}
