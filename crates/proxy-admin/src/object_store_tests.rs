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

fn access_policy(id: &str, generation: u64) -> StoredAccessPolicy {
    StoredAccessPolicy {
        generation,
        object: serde_json::from_value(serde_json::json!({
            "api_version": "v1",
            "metadata": {"id": id, "owner_id": "alice"},
            "spec": {
                "enabled": true,
                "shared_with": [],
                "middlewares": ["edge-ip"]
            }
        }))
        .expect("Access Policy"),
    }
}

fn stream_host(id: &str, owner: &str) -> ApiObject<StreamHostSpec> {
    serde_json::from_value(serde_json::json!({
        "api_version": "v1",
        "metadata": {"id": id, "owner_id": owner},
        "spec": {
            "listen_port": 8443,
            "protocol": "tcp",
            "forward_host": "127.0.0.1",
            "forward_port": 9443,
            "sni_hosts": [],
            "enabled": false
        }
    }))
    .expect("Stream Host")
}

fn revision_metadata(id: &str, binding_hash: Option<&str>) -> RevisionMetadata {
    RevisionMetadata {
        id: id.into(),
        sequence: id[..20].parse().expect("revision sequence"),
        hash: id[21..].into(),
        created_unix_secs: 1,
        source: "test".into(),
        binding_hash: binding_hash.map(str::to_owned),
    }
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

    let candidate_path = root
        .join("admin/proxy-host-candidates")
        .join(format!("{revision}.json"));
    let mut legacy: serde_json::Value =
        serde_json::from_slice(&fs::read(&candidate_path).expect("candidate bytes"))
            .expect("candidate JSON");
    legacy
        .as_object_mut()
        .expect("candidate object")
        .remove("access_policies");
    fs::write(
        &candidate_path,
        serde_json::to_vec(&legacy).expect("legacy candidate JSON"),
    )
    .expect("legacy candidate");

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

#[test]
fn candidate_binding_attests_access_policy_generation_and_content() {
    let (path, root) = temporary_store("policy-binding");
    let store = ProxyHostStore::open(&path).expect("store");
    let revision = format!("{:020}-{}", 1, "ab".repeat(32));
    let objects = vec![object("proxy-a", "alice", "a.example.test")];
    let policy = access_policy("private-lan", 2);
    let hash =
        ProxyHostStore::binding_hash_with_access_policies(&objects, std::slice::from_ref(&policy))
            .expect("policy binding hash");
    assert_ne!(
        hash,
        ProxyHostStore::binding_hash(&objects).expect("legacy binding")
    );
    let bound = store
        .bind_candidate_with_access_policies(
            &revision,
            &hash,
            &objects,
            std::slice::from_ref(&policy),
        )
        .expect("bind policy candidate");
    assert_eq!(bound.access_policies(), std::slice::from_ref(&policy));

    let mut changed = policy.clone();
    changed.generation += 1;
    assert_ne!(
        hash,
        ProxyHostStore::binding_hash_with_access_policies(&objects, &[changed])
            .expect("changed generation hash")
    );
    let mut changed = policy.clone();
    changed.object.spec.enabled = false;
    assert_ne!(
        hash,
        ProxyHostStore::binding_hash_with_access_policies(&objects, &[changed])
            .expect("changed content hash")
    );
    let second = access_policy("second-policy", 1);
    assert_eq!(
        ProxyHostStore::binding_hash_with_access_policies(
            &objects,
            &[policy.clone(), second.clone()]
        )
        .expect("ordered policy hash"),
        ProxyHostStore::binding_hash_with_access_policies(&objects, &[second, policy.clone()])
            .expect("reversed policy hash")
    );

    let candidate_path = root
        .join("admin/proxy-host-candidates")
        .join(format!("{revision}.json"));
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&candidate_path).expect("candidate bytes"))
            .expect("candidate JSON");
    value["access_policies"][0]["generation"] = serde_json::json!(3);
    fs::write(
        &candidate_path,
        serde_json::to_vec(&value).expect("tampered JSON"),
    )
    .expect("tamper candidate");
    assert!(matches!(
        store.load_candidate(&revision, &hash),
        Err(ProxyHostStoreError::Invalid)
    ));
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn unified_candidate_is_schema_two_ordered_and_tamper_evident() {
    let (path, root) = temporary_store("unified-binding");
    let store = ProxyHostStore::open(&path).expect("store");
    let revision = format!("{:020}-{}", 1, "ab".repeat(32));
    let proxy_hosts = vec![object("proxy-a", "alice", "a.example.test")];
    let stream_hosts = vec![
        stream_host("stream-z", "bob"),
        stream_host("stream-a", "alice"),
    ];
    let reversed = stream_hosts.iter().cloned().rev().collect::<Vec<_>>();
    let hash = ProxyHostStore::unified_binding_hash(&proxy_hosts, &stream_hosts, &[], &[], &[])
        .expect("schema-2 hash");
    assert_eq!(
        hash,
        ProxyHostStore::unified_binding_hash(&proxy_hosts, &reversed, &[], &[], &[])
            .expect("stable hash")
    );
    let bound = store
        .bind_unified_candidate(
            &revision,
            &hash,
            UnifiedCandidateState {
                proxy_hosts: &proxy_hosts,
                stream_hosts: &stream_hosts,
                discovery_sources: &[],
                access_policies: &[],
                certificates: &[],
            },
        )
        .expect("bind unified candidate");
    assert_eq!(bound.schema_version(), 2);
    assert_eq!(bound.stream_hosts()[0].metadata.id.as_str(), "stream-a");
    assert_ne!(
        hash,
        ProxyHostStore::binding_hash(&proxy_hosts).expect("schema-1 hash")
    );

    let candidate_path = root
        .join("admin/proxy-host-candidates")
        .join(format!("{revision}.json"));
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&candidate_path).expect("candidate bytes"))
            .expect("candidate JSON");
    value["stream_hosts"][0]["spec"]["enabled"] = serde_json::json!(true);
    fs::write(
        &candidate_path,
        serde_json::to_vec(&value).expect("tampered JSON"),
    )
    .expect("tamper candidate");
    assert!(matches!(
        store.load_candidate(&revision, &hash),
        Err(ProxyHostStoreError::Invalid)
    ));
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn candidate_reconciliation_prunes_only_valid_unretained_snapshots() {
    let (path, root) = temporary_store("candidate-retention");
    let store = ProxyHostStore::open(&path).expect("store");
    let objects = vec![object("proxy-a", "alice", "a.example.test")];
    let binding_hash = ProxyHostStore::binding_hash(&objects).expect("binding hash");
    let retained = format!("{:020}-{}", 1, "ab".repeat(32));
    let stale = format!("{:020}-{}", 2, "cd".repeat(32));
    store
        .bind_candidate(&retained, &binding_hash, &objects)
        .expect("retained binding");
    store
        .bind_candidate(&stale, &binding_hash, &objects)
        .expect("stale binding");

    assert_eq!(
        store
            .reconcile_candidates(&[revision_metadata(&retained, Some(&binding_hash))])
            .expect("reconcile"),
        1
    );
    assert!(
        store.load_candidate(&retained, &binding_hash).is_ok(),
        "retained snapshot must remain"
    );
    assert!(matches!(
        store.load_candidate(&stale, &binding_hash),
        Err(ProxyHostStoreError::Io(error))
            if error.kind() == std::io::ErrorKind::NotFound
    ));
    drop(store);

    let reopened = ProxyHostStore::open(&path).expect("reopen");
    assert_eq!(
        reopened
            .reconcile_candidates(&[revision_metadata(&retained, Some(&binding_hash))])
            .expect("idempotent reconcile"),
        0
    );
    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn candidate_reconciliation_fails_closed_before_deleting_on_tamper() {
    let (path, root) = temporary_store("candidate-retention-tamper");
    let store = ProxyHostStore::open(&path).expect("store");
    let objects = vec![object("proxy-a", "alice", "a.example.test")];
    let binding_hash = ProxyHostStore::binding_hash(&objects).expect("binding hash");
    let retained = format!("{:020}-{}", 1, "ab".repeat(32));
    let stale = format!("{:020}-{}", 2, "cd".repeat(32));
    store
        .bind_candidate(&retained, &binding_hash, &objects)
        .expect("retained binding");
    store
        .bind_candidate(&stale, &binding_hash, &objects)
        .expect("stale binding");
    let stale_path = store.candidate_path(&stale);
    let original = fs::read(&stale_path).expect("stale bytes");
    let mut value: serde_json::Value = serde_json::from_slice(&original).expect("candidate JSON");
    value["binding_hash"] = serde_json::json!("00".repeat(32));
    fs::write(
        &stale_path,
        serde_json::to_vec(&value).expect("tampered JSON"),
    )
    .expect("tamper stale snapshot");

    assert!(matches!(
        store.reconcile_candidates(&[revision_metadata(&retained, Some(&binding_hash))]),
        Err(ProxyHostStoreError::Invalid)
    ));
    assert!(store.candidate_path(&retained).exists());
    assert!(stale_path.exists());
    fs::write(&stale_path, original).expect("restore stale snapshot");

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let symlink_id = format!("{:020}-{}", 3, "ef".repeat(32));
        let symlink_path = store.candidate_path(&symlink_id);
        symlink(&stale_path, &symlink_path).expect("candidate symlink");
        assert!(matches!(
            store.reconcile_candidates(&[revision_metadata(&retained, Some(&binding_hash))]),
            Err(ProxyHostStoreError::Invalid)
        ));
        assert!(stale_path.exists());
        fs::remove_file(symlink_path).expect("remove symlink");
    }

    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn candidate_reconciliation_frees_capacity_after_revision_pruning() {
    let (path, root) = temporary_store("candidate-retention-cap");
    let store = ProxyHostStore::open(&path).expect("store");
    let objects = vec![object("proxy-a", "alice", "a.example.test")];
    let binding_hash = ProxyHostStore::binding_hash(&objects).expect("binding hash");
    let retained = format!("{:020}-{}", 1, "ab".repeat(32));
    store
        .bind_candidate(&retained, &binding_hash, &objects)
        .expect("retained binding");
    for sequence in 2..=MAX_CANDIDATE_SNAPSHOTS {
        let revision = format!("{sequence:020}-{}", "cd".repeat(32));
        store
            .bind_candidate(&revision, &binding_hash, &objects)
            .expect("fill candidate capacity");
    }
    let next = format!("{:020}-{}", MAX_CANDIDATE_SNAPSHOTS + 1, "ef".repeat(32));
    assert!(matches!(
        store.bind_candidate(&next, &binding_hash, &objects),
        Err(ProxyHostStoreError::Limit)
    ));

    assert_eq!(
        store
            .reconcile_candidates(&[revision_metadata(&retained, Some(&binding_hash))])
            .expect("prune stale snapshots"),
        MAX_CANDIDATE_SNAPSHOTS - 1
    );
    store
        .bind_candidate(&next, &binding_hash, &objects)
        .expect("bind after pruning");
    assert!(store.load_candidate(&retained, &binding_hash).is_ok());
    assert!(store.load_candidate(&next, &binding_hash).is_ok());

    fs::remove_dir_all(root).expect("cleanup");
}

#[test]
fn rollback_journal_aborts_and_recovers_by_active_revision() {
    let (path, root) = temporary_store("rollback-journal");
    let store = ProxyHostStore::open(&path).expect("store");
    let owner: ObjectId = "alice".parse().expect("owner");
    let id: ObjectId = "proxy-a".parse().expect("id");
    store
        .create(object("proxy-a", "alice", "a.example.test"))
        .expect("create");
    let target_revision = format!("{:020}-{}", 1, "ab".repeat(32));
    let other_revision = format!("{:020}-{}", 2, "cd".repeat(32));
    let target = vec![object("proxy-a", "alice", "target.example.test")];

    store
        .begin_rollback(&target_revision, &target, 1)
        .expect("begin rollback");
    assert!(store.rollback_pending());
    assert!(matches!(
        store.create(object("blocked", "alice", "blocked.example.test")),
        Err(ProxyHostStoreError::Conflict)
    ));
    assert_eq!(
        store
            .get(&owner, &id)
            .map(|stored| (stored.generation, stored.object.spec.domain)),
        Some((2, "target.example.test".into()))
    );
    store
        .abort_rollback(&target_revision)
        .expect("abort rollback");
    assert!(!store.rollback_pending());
    assert_eq!(
        store
            .get(&owner, &id)
            .map(|stored| (stored.generation, stored.object.spec.domain)),
        Some((1, "a.example.test".into()))
    );

    let epoch = store.snapshot().epoch();
    store
        .begin_rollback(&target_revision, &target, epoch)
        .expect("begin interrupted rollback");
    drop(store);
    let reopened = ProxyHostStore::open(&path).expect("reopen");
    reopened
        .recover_rollback(&other_revision)
        .expect("recover previous");
    assert_eq!(
        reopened
            .get(&owner, &id)
            .map(|stored| stored.object.spec.domain),
        Some("a.example.test".into())
    );

    let epoch = reopened.snapshot().epoch();
    reopened
        .begin_rollback(&target_revision, &target, epoch)
        .expect("begin committed rollback");
    drop(reopened);
    let committed = ProxyHostStore::open(&path).expect("reopen committed");
    committed
        .recover_rollback(&target_revision)
        .expect("recover target");
    assert_eq!(
        committed
            .get(&owner, &id)
            .map(|stored| stored.object.spec.domain),
        Some("target.example.test".into())
    );
    assert!(!root.join("admin/proxy-host-rollback.json").exists());

    fs::remove_dir_all(root).expect("cleanup");
}
