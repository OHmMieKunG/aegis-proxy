use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Mutex,
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use fs2::FileExt;
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{ApiObject, ObjectId, Role, UserSpec, UserStore};

const SCHEMA_VERSION: u32 = 1;
const MAX_BINDINGS: usize = 1_024;
const MAX_BYTES: u64 = 256 * 1024;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct OidcBinding {
    pub(super) fingerprint: String,
    pub(super) user_id: ObjectId,
    pub(super) owner_id: ObjectId,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct BindingFile {
    schema_version: u32,
    bindings: Vec<OidcBinding>,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RecoveryJournal {
    schema_version: u32,
    binding: OidcBinding,
    user: ApiObject<UserSpec>,
}

#[derive(Debug, Error)]
pub(super) enum BindingError {
    #[error("OIDC binding storage I/O failed")]
    Io,
    #[error("OIDC binding state is invalid")]
    Invalid,
    #[error("OIDC binding state reached its limit")]
    Limit,
    #[error("OIDC binding conflicts with durable state")]
    Conflict,
}

#[derive(Debug)]
pub(super) struct OidcBindingStore {
    path: PathBuf,
    journal_path: PathBuf,
    _lock: File,
    bindings: Mutex<BTreeMap<String, OidcBinding>>,
}

impl OidcBindingStore {
    pub(super) fn open(path: PathBuf, users: &UserStore) -> Result<Self, BindingError> {
        let parent = path.parent().ok_or(BindingError::Invalid)?;
        private_directory(parent)?;
        let lock = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .mode(0o600)
            .open(parent.join(".oidc-bindings-owner.lock"))
            .map_err(|_| BindingError::Io)?;
        lock.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|_| BindingError::Io)?;
        lock.try_lock_exclusive().map_err(|_| BindingError::Io)?;
        let journal_path = parent.join("oidc-binding-recovery.json");
        let mut bindings = load_bindings(&path)?;
        if let Some(journal) = load_journal(&journal_path)? {
            validate_target(&bindings, &journal.binding)?;
            users
                .apply_oidc_target(journal.user)
                .map_err(|_| BindingError::Invalid)?;
            bindings.insert(journal.binding.fingerprint.clone(), journal.binding);
            persist_bindings(&path, &bindings)?;
            remove_journal(&journal_path)?;
        }
        Ok(Self {
            path,
            journal_path,
            _lock: lock,
            bindings: Mutex::new(bindings),
        })
    }

    pub(super) fn is_empty(&self) -> bool {
        self.bindings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
    }

    pub(super) fn get(&self, fingerprint: &str) -> Option<OidcBinding> {
        self.bindings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(fingerprint)
            .cloned()
    }

    pub(super) fn user_is_bound(&self, user_id: &ObjectId) -> bool {
        self.bindings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .values()
            .any(|binding| &binding.user_id == user_id)
    }

    pub(super) fn bind(
        &self,
        binding: OidcBinding,
        role: Role,
        users: &UserStore,
        allow_user_create: bool,
    ) -> Result<(), BindingError> {
        let mut bindings = self
            .bindings
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        validate_target(&bindings, &binding)?;
        let user = users
            .oidc_target(&binding.user_id, &binding.owner_id, role, allow_user_create)
            .map_err(|_| BindingError::Conflict)?;
        let journal = RecoveryJournal {
            schema_version: SCHEMA_VERSION,
            binding: binding.clone(),
            user: user.clone(),
        };
        persist_json(&self.journal_path, &journal, MAX_BYTES)?;
        users
            .apply_oidc_target(user)
            .map_err(|_| BindingError::Io)?;
        bindings.insert(binding.fingerprint.clone(), binding);
        persist_bindings(&self.path, &bindings)?;
        remove_journal(&self.journal_path)?;
        Ok(())
    }
}

fn validate_target(
    bindings: &BTreeMap<String, OidcBinding>,
    binding: &OidcBinding,
) -> Result<(), BindingError> {
    if !valid_fingerprint(&binding.fingerprint) || binding.user_id != binding.owner_id {
        return Err(BindingError::Invalid);
    }
    if bindings
        .get(&binding.fingerprint)
        .is_some_and(|stored| stored != binding)
        || bindings.values().any(|stored| {
            stored.fingerprint != binding.fingerprint && stored.user_id == binding.user_id
        })
    {
        return Err(BindingError::Conflict);
    }
    if !bindings.contains_key(&binding.fingerprint) && bindings.len() >= MAX_BINDINGS {
        return Err(BindingError::Limit);
    }
    Ok(())
}

fn load_bindings(path: &Path) -> Result<BTreeMap<String, OidcBinding>, BindingError> {
    let Some(bytes) = read_private(path, MAX_BYTES)? else {
        return Ok(BTreeMap::new());
    };
    let file: BindingFile = serde_json::from_slice(&bytes).map_err(|_| BindingError::Invalid)?;
    if file.schema_version != SCHEMA_VERSION || file.bindings.len() > MAX_BINDINGS {
        return Err(BindingError::Invalid);
    }
    let mut bindings = BTreeMap::new();
    let mut previous = None;
    for binding in file.bindings {
        if previous
            .as_ref()
            .is_some_and(|fingerprint: &String| fingerprint >= &binding.fingerprint)
            || !valid_fingerprint(&binding.fingerprint)
            || binding.user_id != binding.owner_id
            || bindings
                .values()
                .any(|stored: &OidcBinding| stored.user_id == binding.user_id)
        {
            return Err(BindingError::Invalid);
        }
        previous = Some(binding.fingerprint.clone());
        bindings.insert(binding.fingerprint.clone(), binding);
    }
    Ok(bindings)
}

fn load_journal(path: &Path) -> Result<Option<RecoveryJournal>, BindingError> {
    let Some(bytes) = read_private(path, MAX_BYTES)? else {
        return Ok(None);
    };
    let journal: RecoveryJournal =
        serde_json::from_slice(&bytes).map_err(|_| BindingError::Invalid)?;
    if journal.schema_version != SCHEMA_VERSION
        || journal.binding.user_id != journal.user.metadata.id
        || journal.binding.owner_id != journal.user.metadata.owner_id
        || !valid_fingerprint(&journal.binding.fingerprint)
    {
        return Err(BindingError::Invalid);
    }
    Ok(Some(journal))
}

fn read_private(path: &Path, max_bytes: u64) -> Result<Option<Vec<u8>>, BindingError> {
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(BindingError::Io),
    };
    if !metadata.is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > max_bytes
        || metadata.permissions().mode() & 0o777 != 0o600
    {
        return Err(BindingError::Invalid);
    }
    let mut bytes = Vec::new();
    File::open(path)
        .map_err(|_| BindingError::Io)?
        .take(max_bytes + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| BindingError::Io)?;
    (bytes.len() as u64 <= max_bytes)
        .then_some(Some(bytes))
        .ok_or(BindingError::Limit)
}

fn persist_bindings(
    path: &Path,
    bindings: &BTreeMap<String, OidcBinding>,
) -> Result<(), BindingError> {
    persist_json(
        path,
        &BindingFile {
            schema_version: SCHEMA_VERSION,
            bindings: bindings.values().cloned().collect(),
        },
        MAX_BYTES,
    )
}

fn persist_json(path: &Path, value: &impl Serialize, max_bytes: u64) -> Result<(), BindingError> {
    if fs::symlink_metadata(path).is_ok_and(|metadata| metadata.file_type().is_symlink()) {
        return Err(BindingError::Invalid);
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| BindingError::Invalid)?;
    if bytes.len() as u64 > max_bytes {
        return Err(BindingError::Limit);
    }
    let parent = path.parent().ok_or(BindingError::Invalid)?;
    private_directory(parent)?;
    let mut suffix = [0_u8; 8];
    getrandom::fill(&mut suffix).map_err(|_| BindingError::Io)?;
    let temporary = parent.join(format!(".oidc-{}.tmp", URL_SAFE_NO_PAD.encode(suffix)));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&temporary)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        fs::rename(&temporary, path)?;
        File::open(parent)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result.map_err(|_| BindingError::Io)
}

fn remove_journal(path: &Path) -> Result<(), BindingError> {
    match fs::remove_file(path) {
        Ok(()) => File::open(path.parent().ok_or(BindingError::Invalid)?)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| BindingError::Io),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(_) => Err(BindingError::Io),
    }
}

fn private_directory(path: &Path) -> Result<(), BindingError> {
    match fs::symlink_metadata(path) {
        Ok(metadata)
            if metadata.is_dir()
                && !metadata.file_type().is_symlink()
                && metadata.permissions().mode() & 0o077 == 0 =>
        {
            Ok(())
        }
        Ok(_) => Err(BindingError::Invalid),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            fs::create_dir_all(path).map_err(|_| BindingError::Io)?;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700))
                .map_err(|_| BindingError::Io)
        }
        Err(_) => Err(BindingError::Io),
    }
}

fn valid_fingerprint(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "aegisproxy-oidc-binding-{name}-{}",
            std::process::id()
        ))
    }

    fn binding(byte: char, id: &str) -> OidcBinding {
        OidcBinding {
            fingerprint: byte.to_string().repeat(64),
            user_id: id.parse().expect("ID"),
            owner_id: id.parse().expect("owner"),
        }
    }

    #[test]
    fn persists_canonical_private_bindings_and_rejects_collisions() {
        let root = root("store");
        let _ = fs::remove_dir_all(&root);
        let users = UserStore::open(root.join("admin/users.json")).expect("users");
        let store =
            OidcBindingStore::open(root.join("admin/oidc-bindings.json"), &users).expect("store");
        store
            .bind(binding('b', "oidc-b"), Role::Viewer, &users, true)
            .expect("bind");
        store
            .bind(binding('a', "oidc-a"), Role::Admin, &users, true)
            .expect("bind");
        assert!(matches!(
            store.bind(binding('c', "oidc-a"), Role::Admin, &users, true),
            Err(BindingError::Conflict)
        ));
        let text = fs::read_to_string(root.join("admin/oidc-bindings.json")).expect("bytes");
        assert!(text.find(&"a".repeat(64)) < text.find(&"b".repeat(64)));
        assert!(!text.contains("issuer") && !text.contains("subject") && !text.contains("token"));
        assert_eq!(
            fs::metadata(root.join("admin/oidc-bindings.json"))
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        drop(store);
        drop(users);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn recovery_finishes_user_and_binding_target() {
        let root = root("recovery");
        let _ = fs::remove_dir_all(&root);
        let users = UserStore::open(root.join("admin/users.json")).expect("users");
        let target = users
            .oidc_target(
                &"oidc-a".parse().expect("user"),
                &"oidc-a".parse().expect("owner"),
                Role::Operator,
                true,
            )
            .expect("target");
        private_directory(&root.join("admin")).expect("directory");
        persist_json(
            &root.join("admin/oidc-binding-recovery.json"),
            &RecoveryJournal {
                schema_version: SCHEMA_VERSION,
                binding: binding('a', "oidc-a"),
                user: target,
            },
            MAX_BYTES,
        )
        .expect("journal");
        let store =
            OidcBindingStore::open(root.join("admin/oidc-bindings.json"), &users).expect("recover");
        assert!(store.get(&"a".repeat(64)).is_some());
        assert_eq!(
            users
                .get(&"oidc-a".parse().expect("ID"))
                .expect("user")
                .object
                .spec
                .role,
            Role::Operator
        );
        assert!(!root.join("admin/oidc-binding-recovery.json").exists());
        drop(store);
        drop(users);
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn rejects_noncanonical_oversized_insecure_symlinked_and_secret_state() {
        use std::os::unix::fs::symlink;

        for (name, bytes, mode) in [
            (
                "schema",
                br#"{"schema_version":2,"bindings":[]}"#.to_vec(),
                0o600,
            ),
            (
                "order",
                serde_json::to_vec(&BindingFile {
                    schema_version: SCHEMA_VERSION,
                    bindings: vec![binding('b', "oidc-b"), binding('a', "oidc-a")],
                })
                .expect("JSON"),
                0o600,
            ),
            (
                "secret",
                format!(
                    r#"{{"schema_version":1,"bindings":[{{"fingerprint":"{}","user_id":"oidc-a","owner_id":"oidc-a","issuer":"canary","token":"canary"}}]}}"#,
                    "a".repeat(64)
                )
                .into_bytes(),
                0o600,
            ),
            (
                "capacity",
                serde_json::to_vec(&BindingFile {
                    schema_version: SCHEMA_VERSION,
                    bindings: (0..=MAX_BINDINGS)
                        .map(|index| OidcBinding {
                            fingerprint: format!("{index:064x}"),
                            user_id: format!("u{index}").parse().expect("ID"),
                            owner_id: format!("u{index}").parse().expect("owner"),
                        })
                        .collect(),
                })
                .expect("JSON"),
                0o600,
            ),
            (
                "permissions",
                br#"{"schema_version":1,"bindings":[]}"#.to_vec(),
                0o644,
            ),
        ] {
            let root = root(name);
            let _ = fs::remove_dir_all(&root);
            private_directory(&root.join("admin")).expect("directory");
            let path = root.join("admin/oidc-bindings.json");
            fs::write(&path, bytes).expect("state");
            fs::set_permissions(&path, fs::Permissions::from_mode(mode)).expect("mode");
            let users = UserStore::open(root.join("admin/users.json")).expect("users");
            assert!(OidcBindingStore::open(path, &users).is_err(), "{name}");
            drop(users);
            fs::remove_dir_all(root).expect("cleanup");
        }

        let root = root("symlink");
        let _ = fs::remove_dir_all(&root);
        private_directory(&root.join("admin")).expect("directory");
        fs::write(
            root.join("target"),
            b"{\"schema_version\":1,\"bindings\":[]}",
        )
        .expect("target");
        symlink(root.join("target"), root.join("admin/oidc-bindings.json")).expect("symlink");
        let users = UserStore::open(root.join("admin/users.json")).expect("users");
        assert!(OidcBindingStore::open(root.join("admin/oidc-bindings.json"), &users).is_err());
        drop(users);
        fs::remove_dir_all(root).expect("cleanup");
    }
}
