//! Shared bounded persistence for strict owner-scoped typed objects.

use std::{
    collections::{BTreeMap, HashSet},
    fmt,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
    sync::{
        Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fs2::FileExt;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use thiserror::Error;

use crate::{ApiObject, ObjectId};

const STORE_SCHEMA_VERSION: u32 = 1;
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

/// One persisted typed object generation.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct StoredObject<T> {
    /// Monotonic object-local generation, starting at one.
    pub generation: u64,
    /// Strict typed desired state.
    pub object: ApiObject<T>,
}

/// Shared durable typed-object storage failure.
#[derive(Debug, Error)]
pub enum TypedStoreError {
    /// Filesystem operation failed.
    #[error("typed object storage I/O failed: {0}")]
    Io(#[from] std::io::Error),
    /// Atomic replacement completed but directory durability could not be confirmed.
    #[error("typed object storage durability is indeterminate")]
    Indeterminate(#[source] std::io::Error),
    /// A prior indeterminate replacement requires restart reconciliation.
    #[error("typed object storage requires recovery")]
    RecoveryRequired,
    /// Another store instance owns this file.
    #[error("typed object storage is already locked")]
    Locked,
    /// Stored bytes, schema, object, or permissions are invalid.
    #[error("stored typed object state is invalid")]
    Invalid,
    /// Object count or durable byte size reached its hard bound.
    #[error("typed object storage reached its hard limit")]
    Limit,
    /// Globally unique ID, owner, or expected generation conflicts.
    #[error("typed object storage conflict")]
    Conflict,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TypedFile<T> {
    schema_version: u32,
    objects: Vec<StoredObject<T>>,
}

pub(crate) struct TypedStore<T> {
    path: PathBuf,
    _registration: StoreRegistration,
    _lock: File,
    recovery_required: AtomicBool,
    objects: Mutex<BTreeMap<ObjectId, StoredObject<T>>>,
    canonicalize: fn(&mut ApiObject<T>) -> bool,
    max_objects: usize,
    max_bytes: u64,
}

impl<T> fmt::Debug for TypedStore<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TypedStore")
            .field(
                "object_count",
                &self
                    .objects
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .len(),
            )
            .finish_non_exhaustive()
    }
}

impl<T> TypedStore<T>
where
    T: Clone + DeserializeOwned + Eq + Serialize,
{
    pub(crate) fn open(
        path: impl AsRef<Path>,
        lock_name: &str,
        max_objects: usize,
        max_bytes: u64,
        canonicalize: fn(&mut ApiObject<T>) -> bool,
    ) -> Result<Self, TypedStoreError> {
        let path = path.as_ref().to_path_buf();
        let parent = path.parent().ok_or(TypedStoreError::Invalid)?;
        create_private_directory(parent)?;
        let registration = register_store(&path)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(parent.join(lock_name))?;
        secure_file_permissions(&lock)?;
        FileExt::try_lock_exclusive(&lock).map_err(|error| {
            if error.kind() == std::io::ErrorKind::WouldBlock {
                TypedStoreError::Locked
            } else {
                TypedStoreError::Io(error)
            }
        })?;
        Ok(Self {
            objects: Mutex::new(load_store(&path, max_objects, max_bytes, canonicalize)?),
            path,
            _registration: registration,
            _lock: lock,
            recovery_required: AtomicBool::new(false),
            canonicalize,
            max_objects,
            max_bytes,
        })
    }

    pub(crate) fn create(
        &self,
        mut object: ApiObject<T>,
    ) -> Result<StoredObject<T>, TypedStoreError> {
        if !(self.canonicalize)(&mut object) {
            return Err(TypedStoreError::Invalid);
        }
        let id = object.metadata.id.clone();
        let mut objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_mutable()?;
        if objects.len() >= self.max_objects {
            return Err(TypedStoreError::Limit);
        }
        if objects.contains_key(&id) {
            return Err(TypedStoreError::Conflict);
        }
        let stored = StoredObject {
            generation: 1,
            object,
        };
        objects.insert(id.clone(), stored.clone());
        if let Err(error) = persist_store(&self.path, &objects, self.max_bytes) {
            if matches!(error, TypedStoreError::Indeterminate(_)) {
                self.recovery_required.store(true, Ordering::Release);
            } else {
                objects.remove(&id);
            }
            return Err(error);
        }
        Ok(stored)
    }

    pub(crate) fn update(
        &self,
        mut object: ApiObject<T>,
        expected_generation: u64,
    ) -> Result<StoredObject<T>, TypedStoreError> {
        if !(self.canonicalize)(&mut object) {
            return Err(TypedStoreError::Invalid);
        }
        let id = object.metadata.id.clone();
        let owner = object.metadata.owner_id.clone();
        let mut objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_mutable()?;
        let previous = objects
            .get(&id)
            .filter(|stored| {
                stored.generation == expected_generation && stored.object.metadata.owner_id == owner
            })
            .cloned()
            .ok_or(TypedStoreError::Conflict)?;
        if previous.object == object {
            return Ok(previous);
        }
        let stored = StoredObject {
            generation: expected_generation
                .checked_add(1)
                .ok_or(TypedStoreError::Limit)?,
            object,
        };
        objects.insert(id.clone(), stored.clone());
        if let Err(error) = persist_store(&self.path, &objects, self.max_bytes) {
            if matches!(error, TypedStoreError::Indeterminate(_)) {
                self.recovery_required.store(true, Ordering::Release);
            } else {
                objects.insert(id, previous);
            }
            return Err(error);
        }
        Ok(stored)
    }

    pub(crate) fn delete(
        &self,
        owner_id: &ObjectId,
        object_id: &ObjectId,
        expected_generation: u64,
    ) -> Result<StoredObject<T>, TypedStoreError> {
        let mut objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_mutable()?;
        let previous = objects
            .get(object_id)
            .filter(|stored| {
                stored.generation == expected_generation
                    && &stored.object.metadata.owner_id == owner_id
            })
            .cloned()
            .ok_or(TypedStoreError::Conflict)?;
        objects.remove(object_id);
        if let Err(error) = persist_store(&self.path, &objects, self.max_bytes) {
            if matches!(error, TypedStoreError::Indeterminate(_)) {
                self.recovery_required.store(true, Ordering::Release);
            } else {
                objects.insert(object_id.clone(), previous.clone());
            }
            return Err(error);
        }
        Ok(previous)
    }

    pub(crate) fn get(&self, owner_id: &ObjectId, object_id: &ObjectId) -> Option<StoredObject<T>> {
        self.objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(object_id)
            .filter(|stored| &stored.object.metadata.owner_id == owner_id)
            .cloned()
    }

    pub(crate) fn list(&self, owner_id: &ObjectId) -> Vec<StoredObject<T>> {
        self.objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .filter(|stored| &stored.object.metadata.owner_id == owner_id)
            .cloned()
            .collect()
    }

    pub(crate) fn all(&self) -> Result<Vec<StoredObject<T>>, TypedStoreError> {
        self.ensure_mutable()?;
        Ok(self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .cloned()
            .collect())
    }

    pub(crate) fn replace_all(
        &self,
        mut desired: Vec<ApiObject<T>>,
    ) -> Result<Vec<StoredObject<T>>, TypedStoreError> {
        if desired.len() > self.max_objects {
            return Err(TypedStoreError::Limit);
        }
        let mut objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_mutable()?;
        let previous = objects.clone();
        let mut replacement = BTreeMap::new();
        for mut object in desired.drain(..) {
            if !(self.canonicalize)(&mut object) {
                return Err(TypedStoreError::Invalid);
            }
            let id = object.metadata.id.clone();
            let generation = match objects.get(&id) {
                Some(stored) if stored.object == object => stored.generation,
                Some(stored) => stored
                    .generation
                    .checked_add(1)
                    .ok_or(TypedStoreError::Limit)?,
                None => 1,
            };
            if replacement
                .insert(id, StoredObject { generation, object })
                .is_some()
            {
                return Err(TypedStoreError::Conflict);
            }
        }
        persist_store(&self.path, &replacement, self.max_bytes)?;
        *objects = replacement;
        Ok(previous.into_values().collect())
    }

    pub(crate) fn restore_all(
        &self,
        previous: Vec<StoredObject<T>>,
    ) -> Result<(), TypedStoreError> {
        let mut replacement = BTreeMap::new();
        for stored in previous {
            let mut canonical = stored.object.clone();
            if stored.generation == 0
                || !(self.canonicalize)(&mut canonical)
                || canonical != stored.object
                || replacement
                    .insert(stored.object.metadata.id.clone(), stored)
                    .is_some()
            {
                return Err(TypedStoreError::Invalid);
            }
        }
        let mut objects = self
            .objects
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        self.ensure_mutable()?;
        persist_store(&self.path, &replacement, self.max_bytes)?;
        *objects = replacement;
        Ok(())
    }

    fn ensure_mutable(&self) -> Result<(), TypedStoreError> {
        if self.recovery_required.load(Ordering::Acquire) {
            Err(TypedStoreError::RecoveryRequired)
        } else {
            Ok(())
        }
    }
}

fn register_store(path: &Path) -> Result<StoreRegistration, TypedStoreError> {
    let parent = path.parent().ok_or(TypedStoreError::Invalid)?;
    let canonical = parent
        .canonicalize()?
        .join(path.file_name().ok_or(TypedStoreError::Invalid)?);
    let mut owned = OWNED_STORES
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if !owned.insert(canonical.clone()) {
        return Err(TypedStoreError::Locked);
    }
    Ok(StoreRegistration(canonical))
}

fn load_store<T>(
    path: &Path,
    max_objects: usize,
    max_bytes: u64,
    canonicalize: fn(&mut ApiObject<T>) -> bool,
) -> Result<BTreeMap<ObjectId, StoredObject<T>>, TypedStoreError>
where
    T: Clone + DeserializeOwned + Eq + Serialize,
{
    let file = match fs::symlink_metadata(path) {
        Ok(metadata) => {
            if !metadata.is_file()
                || metadata.file_type().is_symlink()
                || metadata.len() > max_bytes
                || insecure_file_permissions(&metadata)
            {
                return Err(TypedStoreError::Invalid);
            }
            let mut bytes = Vec::new();
            File::open(path)
                .map_err(TypedStoreError::Io)?
                .take(max_bytes + 1)
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > max_bytes {
                return Err(TypedStoreError::Limit);
            }
            serde_json::from_slice::<TypedFile<T>>(&bytes).map_err(|_| TypedStoreError::Invalid)?
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => TypedFile {
            schema_version: STORE_SCHEMA_VERSION,
            objects: Vec::new(),
        },
        Err(error) => return Err(error.into()),
    };
    if file.schema_version != STORE_SCHEMA_VERSION || file.objects.len() > max_objects {
        return Err(TypedStoreError::Invalid);
    }
    let mut objects = BTreeMap::new();
    for stored in file.objects {
        let mut canonical = stored.object.clone();
        if stored.generation == 0
            || !canonicalize(&mut canonical)
            || canonical != stored.object
            || objects
                .insert(stored.object.metadata.id.clone(), stored)
                .is_some()
        {
            return Err(TypedStoreError::Invalid);
        }
    }
    Ok(objects)
}

fn persist_store<T>(
    path: &Path,
    objects: &BTreeMap<ObjectId, StoredObject<T>>,
    max_bytes: u64,
) -> Result<(), TypedStoreError>
where
    T: Clone + Serialize,
{
    let parent = path.parent().ok_or(TypedStoreError::Invalid)?;
    create_private_directory(parent)?;
    let bytes = serde_json::to_vec_pretty(&TypedFile {
        schema_version: STORE_SCHEMA_VERSION,
        objects: objects.values().cloned().collect(),
    })
    .map_err(|_| TypedStoreError::Invalid)?;
    if bytes.len() as u64 > max_bytes {
        return Err(TypedStoreError::Limit);
    }
    let mut suffix = [0_u8; 8];
    getrandom::fill(&mut suffix).map_err(|_| TypedStoreError::Invalid)?;
    let temporary = parent.join(format!(".typed-{}.tmp", URL_SAFE_NO_PAD.encode(suffix)));
    if let Err(error) = write_private_file(&temporary, &bytes) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    if let Err(error) = fs::rename(&temporary, path) {
        let _ = fs::remove_file(&temporary);
        return Err(error.into());
    }
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(TypedStoreError::Indeterminate)
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
            "typed object parent is not a private directory",
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
