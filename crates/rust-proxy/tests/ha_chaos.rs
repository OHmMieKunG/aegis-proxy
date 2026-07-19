#![forbid(unsafe_code)]

use std::{fs, path::PathBuf, process::Command, time::SystemTime};

use serde_json::{Value, json};

fn root() -> PathBuf {
    std::env::temp_dir().join(format!(
        "aegisproxy-ha-chaos-{}-{:?}",
        std::process::id(),
        SystemTime::now()
    ))
}

fn status(node: &str, hash: &str, owner: bool) -> Value {
    json!({
        "request_id": "request-1",
        "version": "0.1.0",
        "uptime_secs": 30,
        "node_id": node,
        "fleet_generation": 9,
        "active_revision": format!("{:020}-{hash}", 2),
        "active_hash": hash,
        "administration_ready": true,
        "audit_ready": true,
        "draining": false,
        "certificate_owner": owner,
        "managed_certificates": 1,
        "actor_type": "unix_peer",
        "actor_id": "1000"
    })
}

fn write(root: &std::path::Path, name: &str, value: &Value) -> PathBuf {
    let path = root.join(name);
    fs::write(&path, serde_json::to_vec(value).expect("JSON")).expect("status");
    path
}

fn check(hash: &str, generation: &str, paths: &[PathBuf]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_rust-proxy"));
    command.args([
        "fleet",
        "check",
        "--expected-hash",
        hash,
        "--generation",
        generation,
        "--node",
        "node-a",
        "--node",
        "node-b",
    ]);
    for path in paths {
        command.arg("--status").arg(path);
    }
    command.output().expect("fleet check")
}

#[test]
fn fleet_gate_fails_closed_during_ha_faults() {
    let root = root();
    fs::create_dir(&root).expect("root");
    let hash = "a".repeat(64);
    let a = write(&root, "a.json", &status("node-a", &hash, true));
    let b = write(&root, "b.json", &status("node-b", &hash, false));
    assert!(check(&hash, "9", &[a.clone(), b.clone()]).status.success());

    assert!(!check(&hash, "9", std::slice::from_ref(&a)).status.success());
    assert!(!check(&hash, "8", &[a.clone(), b.clone()]).status.success());

    let mut fault = status("node-b", &hash, false);
    fault["active_hash"] = json!("b".repeat(64));
    let drift = write(&root, "drift.json", &fault);
    assert!(!check(&hash, "9", &[a.clone(), drift]).status.success());

    fault = status("node-b", &hash, true);
    let duplicate_owner = write(&root, "duplicate-owner.json", &fault);
    assert!(
        !check(&hash, "9", &[a.clone(), duplicate_owner])
            .status
            .success()
    );

    fault = status("node-b", &hash, false);
    fault["draining"] = json!(true);
    let draining = write(&root, "draining.json", &fault);
    assert!(!check(&hash, "9", &[a.clone(), draining]).status.success());

    fault = status("node-b", &hash, false);
    fault["audit_ready"] = json!(false);
    let audit_outage = write(&root, "audit-outage.json", &fault);
    assert!(!check(&hash, "9", &[a, audit_outage]).status.success());
    fs::remove_dir_all(root).expect("cleanup");
}
