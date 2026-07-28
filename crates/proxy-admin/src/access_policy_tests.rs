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
        |value: &mut serde_json::Value| value["policies"][0]["generation"] = serde_json::json!(0),
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

        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).expect("broaden permissions");
        assert!(matches!(
            AccessPolicyStore::open(&path),
            Err(AccessPolicyStoreError::Invalid)
        ));
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).expect("restore permissions");
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
    assert!(matches!(
        store.metadata(&config()),
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
