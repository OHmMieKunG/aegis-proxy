//! Bounded offline verification of authenticated fleet status exports.

use std::{collections::BTreeSet, fs::File, io, io::Read, path::PathBuf};

use serde::Deserialize;

const MAX_NODES: usize = 256;
const MAX_STATUS_BYTES: u64 = 16 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeStatus {
    #[serde(rename = "request_id")]
    _request_id: String,
    #[serde(rename = "version")]
    _version: String,
    #[serde(rename = "uptime_secs")]
    _uptime_secs: u64,
    node_id: String,
    fleet_generation: u64,
    active_revision: String,
    active_hash: String,
    administration_ready: bool,
    audit_ready: bool,
    draining: bool,
    certificate_owner: bool,
    managed_certificates: usize,
    #[serde(rename = "actor_type")]
    _actor_type: String,
    #[serde(rename = "actor_id")]
    _actor_id: String,
}

/// Redacted successful fleet verification summary.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct FleetSummary {
    pub(crate) nodes: usize,
    pub(crate) certificate_owner: Option<String>,
}

/// Verify a complete inventory against one exact rollout generation and content hash.
pub(crate) fn check(
    expected_hash: &str,
    expected_generation: u64,
    expected_nodes: &[String],
    status_paths: &[PathBuf],
) -> io::Result<FleetSummary> {
    validate_hash(expected_hash)?;
    if expected_generation == 0 {
        return invalid("fleet generation must be greater than zero");
    }
    let inventory = expected_nodes.iter().cloned().collect::<BTreeSet<_>>();
    if inventory.is_empty()
        || inventory.len() != expected_nodes.len()
        || inventory.len() > MAX_NODES
        || status_paths.len() != inventory.len()
        || inventory.iter().any(|id| !valid_id(id))
    {
        return invalid("fleet inventory is invalid or incomplete");
    }

    let mut observed = BTreeSet::new();
    let mut owners = Vec::new();
    let mut managed_certificates = None;
    for path in status_paths {
        let status = load(path)?;
        if !inventory.contains(&status.node_id) || !observed.insert(status.node_id.clone()) {
            return invalid("fleet status contains an unexpected or duplicate node");
        }
        if status.fleet_generation != expected_generation {
            return invalid("fleet status generation diverged");
        }
        validate_hash(&status.active_hash)?;
        if status.active_hash != expected_hash
            || status
                .active_revision
                .rsplit_once('-')
                .map(|(_, hash)| hash)
                != Some(expected_hash)
        {
            return invalid("fleet status content hash diverged");
        }
        if !status.administration_ready || !status.audit_ready || status.draining {
            return invalid("fleet node is not ready");
        }
        if let Some(expected) = managed_certificates {
            if status.managed_certificates != expected {
                return invalid("fleet managed-certificate policy diverged");
            }
        } else {
            managed_certificates = Some(status.managed_certificates);
        }
        if status.certificate_owner {
            owners.push(status.node_id);
        }
    }
    if observed != inventory {
        return invalid("fleet inventory is incomplete");
    }
    let managed = managed_certificates.unwrap_or_default();
    if (managed == 0 && !owners.is_empty()) || (managed > 0 && owners.len() != 1) {
        return invalid("fleet certificate renewal owner count is invalid");
    }
    Ok(FleetSummary {
        nodes: observed.len(),
        certificate_owner: owners.pop(),
    })
}

fn load(path: &PathBuf) -> io::Result<NodeStatus> {
    let mut bytes = Vec::new();
    File::open(path)?
        .take(MAX_STATUS_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_STATUS_BYTES {
        return invalid("fleet status exceeds size limit");
    }
    serde_json::from_slice(&bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "fleet status is invalid"))
}

fn validate_hash(hash: &str) -> io::Result<()> {
    if hash.len() == 64
        && hash
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        Ok(())
    } else {
        invalid("fleet content hash is invalid")
    }
}

fn valid_id(value: &str) -> bool {
    let bytes = value.as_bytes();
    bytes.first().is_some_and(u8::is_ascii_lowercase)
        && value.len() <= 63
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'_' | b'-')
        })
}

fn invalid<T>(message: &'static str) -> io::Result<T> {
    Err(io::Error::new(io::ErrorKind::InvalidData, message))
}

#[cfg(test)]
mod tests {
    use std::{fs, time::SystemTime};

    use serde_json::json;

    use super::*;

    fn status(node: &str, hash: &str, owner: bool) -> serde_json::Value {
        json!({
            "request_id": "request-1",
            "version": "0.1.0",
            "uptime_secs": 10,
            "node_id": node,
            "fleet_generation": 7,
            "active_revision": format!("{:020}-{hash}", 1),
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

    fn files(values: &[serde_json::Value]) -> (PathBuf, Vec<PathBuf>) {
        let root = std::env::temp_dir().join(format!(
            "aegisproxy-fleet-{}-{:?}",
            std::process::id(),
            SystemTime::now()
        ));
        fs::create_dir(&root).expect("root");
        let paths = values
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let path = root.join(format!("node-{index}.json"));
                fs::write(&path, serde_json::to_vec(value).expect("JSON")).expect("status");
                path
            })
            .collect();
        (root, paths)
    }

    #[test]
    fn accepts_exact_complete_fleet_and_one_owner() {
        let hash = "a".repeat(64);
        let (root, paths) = files(&[
            status("node-a", &hash, true),
            status("node-b", &hash, false),
        ]);
        let summary = check(&hash, 7, &["node-a".into(), "node-b".into()], &paths).expect("fleet");
        assert_eq!(summary.nodes, 2);
        assert_eq!(summary.certificate_owner.as_deref(), Some("node-a"));
        fs::remove_dir_all(root).expect("cleanup");
    }

    #[test]
    fn rejects_drift_missing_nodes_duplicate_owner_and_drain() {
        let hash = "a".repeat(64);
        let mut drift = status("node-b", &hash, false);
        drift["active_hash"] = json!("b".repeat(64));
        let (root, paths) = files(&[status("node-a", &hash, true), drift]);
        assert!(check(&hash, 7, &["node-a".into(), "node-b".into()], &paths).is_err());
        fs::remove_dir_all(root).expect("cleanup");

        let mut drained = status("node-b", &hash, true);
        drained["draining"] = json!(true);
        let (root, paths) = files(&[status("node-a", &hash, true), drained]);
        assert!(check(&hash, 7, &["node-a".into(), "node-b".into()], &paths).is_err());
        assert!(check(&hash, 7, &["node-a".into()], &paths).is_err());
        fs::remove_dir_all(root).expect("cleanup");
    }
}
