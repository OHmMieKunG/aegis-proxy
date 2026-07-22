//! Bounded durable storage for typed Proxy Host desired state.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::Mutex,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ApiObject, ObjectId, ProxyHostSpec};

const STORE_SCHEMA_VERSION: u32 = 1;
pub(crate) const MAX_PROXY_HOSTS: usize = 4_096;
const MAX_STORE_BYTES: u64 = 2 * 1024 * 1024;

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

type ObjectIndex = BTreeMap<ObjectId, BTreeMap<ObjectId, StoredProxyHost>>;

/// Single-process, owner-indexed typed Proxy Host store.
pub struct ProxyHostStore {
    path: PathBuf,
    objects: Mutex<ObjectIndex>,
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
        let objects = load_file(&path)?;
        Ok(Self {
            path,
            objects: Mutex::new(index_objects(objects)?),
        })
    }

    /// Create one object at generation one and persist it atomically.
    pub fn create(
        &self,
        object: ApiObject<ProxyHostSpec>,
    ) -> Result<StoredProxyHost, ProxyHostStoreError> {
        validate_object(&object)?;
        let owner_id = object.metadata.owner_id.clone();
        let object_id = object.metadata.id.clone();
        let mut objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        Ok(stored)
    }

    /// Replace one matching object generation and persist it atomically.
    pub fn update(
        &self,
        object: ApiObject<ProxyHostSpec>,
        expected_generation: u64,
    ) -> Result<StoredProxyHost, ProxyHostStoreError> {
        validate_object(&object)?;
        let owner_id = object.metadata.owner_id.clone();
        let object_id = object.metadata.id.clone();
        let mut objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        Ok(stored)
    }

    /// Delete one matching object generation and persist removal atomically.
    pub fn delete(
        &self,
        owner_id: &ObjectId,
        object_id: &ObjectId,
        expected_generation: u64,
    ) -> Result<StoredProxyHost, ProxyHostStoreError> {
        let mut objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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
        let alice: ObjectId = "alice".parse().expect("owner");
        let bob: ObjectId = "bob".parse().expect("owner");
        store
            .create(object("proxy-z", "alice", "z.example.test"))
            .expect("create z");
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
        drop(store);

        let reopened = ProxyHostStore::open(&path).expect("reopen");
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
        let stored = store.update(updated, 1).expect("update");
        assert_eq!(stored.generation, 2);
        assert!(matches!(
            store.update(stored.object.clone(), 1),
            Err(ProxyHostStoreError::Conflict)
        ));

        fs::remove_file(&path).expect("remove backing file");
        fs::create_dir(&path).expect("block replacement");
        assert!(matches!(
            store.delete(&owner, &id, 2),
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
}
