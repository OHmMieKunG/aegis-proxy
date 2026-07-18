#![forbid(unsafe_code)]

use std::{path::PathBuf, process::Command};

fn example() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/examples/tls.toml")
}

fn workspace_file(path: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join(path)
}

#[test]
fn preview_redacts_references_and_format_preserves_them() {
    let preview = Command::new(env!("CARGO_BIN_EXE_rust-proxy"))
        .args(["preview", "--config"])
        .arg(example())
        .output()
        .expect("run preview");
    assert!(preview.status.success());
    let preview = String::from_utf8(preview.stdout).expect("preview UTF-8");
    assert!(preview.contains("# route_fingerprint = "));
    assert_eq!(preview.matches("<redacted-secret-reference>").count(), 4);
    assert!(!preview.contains("/run/secrets"));
    assert!(!preview.contains("/var/lib/aegisproxy/certificates"));

    let formatted = Command::new(env!("CARGO_BIN_EXE_rust-proxy"))
        .args(["fmt", "--config"])
        .arg(example())
        .output()
        .expect("run fmt");
    assert!(formatted.status.success());
    let formatted = String::from_utf8(formatted.stdout).expect("formatted UTF-8");
    assert!(formatted.contains("schema_version = 1"));
    assert!(formatted.contains("file:///run/secrets/aegisproxy-age-identity"));
    assert!(!formatted.contains("<redacted-secret-reference>"));
}

#[test]
fn shipped_valid_and_invalid_corpus_has_expected_result() {
    for path in [
        "config/examples/minimal.toml",
        "config/examples/tls.toml",
        "config/examples/phase7.toml",
        "config/examples/default-route.toml",
        "config/examples/tcp.toml",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rust-proxy"))
            .args(["validate", "--config"])
            .arg(workspace_file(path))
            .output()
            .expect("run validator");
        assert!(output.status.success(), "valid fixture failed: {path}");
    }
    for path in [
        "config/invalid/unknown-field.toml",
        "config/invalid/encoded-route-path.toml",
        "config/invalid/ambiguous-routes.toml",
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_rust-proxy"))
            .args(["validate", "--config"])
            .arg(workspace_file(path))
            .output()
            .expect("run validator");
        assert!(!output.status.success(), "invalid fixture passed: {path}");
        assert_eq!(output.status.code(), Some(3), "wrong invalid-config code");
    }
}

#[test]
fn last_known_good_requires_explicit_state_directory() {
    let output = Command::new(env!("CARGO_BIN_EXE_rust-proxy"))
        .args([
            "run",
            "--config",
            "missing.toml",
            "--resume-last-known-good",
        ])
        .output()
        .expect("run recovery argument validation");
    assert!(!output.status.success());
    assert_eq!(output.status.code(), Some(2));
    let error = String::from_utf8(output.stderr).expect("stderr UTF-8");
    assert!(error.contains("--state-dir"));
}

#[test]
fn unavailable_private_socket_has_stable_exit_code() {
    let output = Command::new(env!("CARGO_BIN_EXE_rust-proxy"))
        .args([
            "health",
            "--socket",
            "/tmp/aegisproxy-test-does-not-exist/admin.sock",
        ])
        .output()
        .expect("run health");
    assert_eq!(output.status.code(), Some(6));
}

#[test]
fn revisions_lists_offline_active_state() {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    let state = std::env::temp_dir().join(format!(
        "aegisproxy-cli-revisions-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_nanos()
    ));
    let store = aegisproxy_config::revision::RevisionStore::open(&state).expect("revision store");
    let config = aegisproxy_config::load_file(workspace_file("config/examples/minimal.toml"))
        .expect("example config");
    let revision = store
        .create_candidate(&config, "cli-test")
        .expect("candidate");
    store
        .begin_activation(&revision.id, None)
        .expect("activation intent");
    store.mark_probation(&revision.id).expect("probation");
    store.commit_activation(&revision.id).expect("commit");
    drop(store);

    let output = Command::new(env!("CARGO_BIN_EXE_rust-proxy"))
        .args(["config", "revisions", "--state-dir"])
        .arg(&state)
        .output()
        .expect("run revisions");
    assert!(output.status.success());
    let output = String::from_utf8(output.stdout).expect("stdout UTF-8");
    assert!(output.contains(&revision.id));
    assert!(output.contains("\tcli-test\tactive"));
    fs::remove_dir_all(state).expect("cleanup");
}
