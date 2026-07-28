use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use super::*;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct TestSpec {
    enabled: bool,
}

static NONCE: AtomicU64 = AtomicU64::new(0);

fn object(id: &str, owner: &str) -> ApiObject<TestSpec> {
    serde_json::from_value(serde_json::json!({
        "api_version": "v1",
        "metadata": {"id": id, "owner_id": owner},
        "spec": {"enabled": true}
    }))
    .expect("test object")
}

#[test]
fn shared_store_hides_cross_owner_objects_for_every_typed_domain() {
    let root = std::env::temp_dir().join(format!(
        "aegisproxy-typed-owner-{}-{}",
        std::process::id(),
        NONCE.fetch_add(1, Ordering::Relaxed)
    ));
    let store = TypedStore::open(
        root.join("admin/objects.json"),
        "objects.lock",
        8,
        16 * 1024,
        |_| true,
    )
    .expect("store");
    let id: ObjectId = "shared-id".parse().expect("id");
    let alice: ObjectId = "alice".parse().expect("owner");
    let bob: ObjectId = "bob".parse().expect("owner");
    store
        .create(object(id.as_str(), alice.as_str()))
        .expect("create");

    assert!(store.get(&bob, &id).is_none());
    assert!(store.list(&bob).is_empty());
    assert!(matches!(
        store.delete(&bob, &id, 1),
        Err(TypedStoreError::Conflict)
    ));
    assert!(matches!(
        store.update(object(id.as_str(), bob.as_str()), 1),
        Err(TypedStoreError::Conflict)
    ));
    assert!(store.get(&alice, &id).is_some());

    drop(store);
    fs::remove_dir_all(root).expect("cleanup");
}
