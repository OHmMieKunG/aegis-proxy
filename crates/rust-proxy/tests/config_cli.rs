#![forbid(unsafe_code)]

use std::{path::PathBuf, process::Command};

fn example() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../config/examples/tls.toml")
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
