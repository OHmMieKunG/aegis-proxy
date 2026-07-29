//! Durable built-in-role user identities.

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{
    ApiObject, ApiVersion, ObjectId, ObjectMetadata, Role,
    typed_store::{StoredObject, TypedStore, TypedStoreError},
};

const MAX_USERS: usize = 1_024;
const MAX_STORE_BYTES: u64 = 1024 * 1024;

/// Strict user desired state. The object ID and owner ID must be identical.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserSpec {
    /// Display-only name.
    pub display_name: String,
    /// Immutable built-in authorization role.
    pub role: Role,
    /// Whether subject-bound tokens may authenticate.
    pub enabled: bool,
}

/// One persisted user generation.
pub type StoredUser = StoredObject<UserSpec>;
/// Durable user-store failure.
pub type UserStoreError = TypedStoreError;

/// Bounded durable user store.
#[derive(Debug)]
pub struct UserStore(TypedStore<UserSpec>);

impl UserStore {
    /// Open strict private user state.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, UserStoreError> {
        TypedStore::open(
            path,
            ".users-owner.lock",
            MAX_USERS,
            MAX_STORE_BYTES,
            canonicalize,
        )
        .map(Self)
    }

    /// Create one user.
    pub fn create(&self, object: ApiObject<UserSpec>) -> Result<StoredUser, UserStoreError> {
        self.0.create(object)
    }

    /// Replace one user at its exact generation.
    pub fn update(
        &self,
        object: ApiObject<UserSpec>,
        generation: u64,
    ) -> Result<StoredUser, UserStoreError> {
        if self
            .0
            .get(&object.metadata.id, &object.metadata.id)
            .is_none_or(|stored| stored.object.spec.role != object.spec.role)
        {
            return Err(TypedStoreError::Conflict);
        }
        self.0.update(object, generation)
    }

    /// Return one user by subject identity.
    #[must_use]
    pub fn get(&self, id: &ObjectId) -> Option<StoredUser> {
        self.0.get(id, id)
    }

    /// Return every user in stable ID order.
    pub fn all(&self) -> Result<Vec<StoredUser>, UserStoreError> {
        self.0.all()
    }

    pub(crate) fn oidc_target(
        &self,
        user_id: &ObjectId,
        owner_id: &ObjectId,
        role: Role,
        allow_create: bool,
    ) -> Result<ApiObject<UserSpec>, UserStoreError> {
        if user_id != owner_id {
            return Err(TypedStoreError::Invalid);
        }
        match self.get(user_id) {
            Some(stored) => {
                let mut object = stored.object;
                object.spec.role = role;
                Ok(object)
            }
            None if allow_create => Ok(ApiObject {
                api_version: ApiVersion,
                metadata: ObjectMetadata {
                    id: user_id.clone(),
                    owner_id: owner_id.clone(),
                },
                spec: UserSpec {
                    display_name: user_id.to_string(),
                    role,
                    enabled: true,
                },
            }),
            None => Err(TypedStoreError::Conflict),
        }
    }

    pub(crate) fn apply_oidc_target(
        &self,
        target: ApiObject<UserSpec>,
    ) -> Result<StoredUser, UserStoreError> {
        if target.metadata.id != target.metadata.owner_id || !canonicalize(&mut target.clone()) {
            return Err(TypedStoreError::Invalid);
        }
        match self.get(&target.metadata.id) {
            Some(stored) if stored.object == target => Ok(stored),
            Some(stored) => self.0.update(target, stored.generation),
            None => self.0.create(target),
        }
    }
}

fn canonicalize(object: &mut ApiObject<UserSpec>) -> bool {
    object.metadata.id == object.metadata.owner_id
        && !object.spec.display_name.is_empty()
        && object.spec.display_name.len() <= 128
        && !object.spec.display_name.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn requires_identity_owner_equality_and_generation_cas() {
        let root = std::env::temp_dir().join(format!("aegisproxy-users-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let store = UserStore::open(root.join("admin/users.json")).expect("store");
        let user: ApiObject<UserSpec> = serde_json::from_value(serde_json::json!({
            "api_version": "v1",
            "metadata": {"id": "alice", "owner_id": "alice"},
            "spec": {"display_name": "Alice", "role": "operator", "enabled": true}
        }))
        .expect("user");
        assert_eq!(store.create(user.clone()).expect("create").generation, 1);
        let mut disabled = user;
        disabled.spec.enabled = false;
        assert_eq!(store.update(disabled, 1).expect("disable").generation, 2);
        assert!(
            !store
                .get(&"alice".parse().expect("id"))
                .expect("user")
                .object
                .spec
                .enabled
        );
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn oidc_sync_creates_stable_users_and_preserves_disabled_state() {
        let root =
            std::env::temp_dir().join(format!("aegisproxy-oidc-users-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let store = UserStore::open(root.join("admin/users.json")).expect("store");
        let id: ObjectId = "oidc-alice".parse().expect("ID");
        let target = store
            .oidc_target(&id, &id, Role::Viewer, true)
            .expect("target");
        assert_eq!(target.spec.display_name, "oidc-alice");
        store.apply_oidc_target(target).expect("create");
        let mut disabled = store.get(&id).expect("user").object;
        disabled.spec.enabled = false;
        store.0.update(disabled, 1).expect("disable");
        let target = store
            .oidc_target(&id, &id, Role::Admin, false)
            .expect("role target");
        assert!(!target.spec.enabled);
        store.apply_oidc_target(target).expect("role sync");
        let synced = store.get(&id).expect("synced");
        assert_eq!(synced.object.spec.role, Role::Admin);
        assert!(!synced.object.spec.enabled);
        fs::remove_dir_all(root).expect("cleanup");
    }
}
