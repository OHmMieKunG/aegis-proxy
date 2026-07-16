#![forbid(unsafe_code)]

use std::{
    fs,
    path::Path,
    process::Command,
    time::{SystemTime, UNIX_EPOCH},
};

use age::secrecy::ExposeSecret;

fn private_file(path: &Path, contents: &[u8]) {
    fs::write(path, contents).expect("write test file");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("secure test file");
    }
}

#[test]
fn imports_lists_and_inspects_encrypted_certificate() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "aegisproxy-cert-cli-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("create root");
    let generated = rcgen::generate_simple_self_signed(vec!["example.test".into()])
        .expect("generate certificate");
    let certificate_path = root.join("certificate.pem");
    let private_key_path = root.join("private-key.pem");
    private_file(&certificate_path, generated.cert.pem().as_bytes());
    private_file(
        &private_key_path,
        generated.signing_key.serialize_pem().as_bytes(),
    );
    let identity = age::x25519::Identity::generate();
    let binary = env!("CARGO_BIN_EXE_rust-proxy");
    let imported = Command::new(binary)
        .args([
            "cert",
            "import",
            "--state-dir",
            root.to_str().expect("root path"),
            "--id",
            "site",
            "--host",
            "example.test",
            "--certificate-chain",
            &format!("file://{}", certificate_path.display()),
            "--private-key",
            &format!("file://{}", private_key_path.display()),
            "--recipient",
            &identity.to_public().to_string(),
        ])
        .output()
        .expect("run import");
    assert!(imported.status.success(), "{:?}", imported.stderr);
    assert!(
        !imported
            .stdout
            .windows(11)
            .any(|window| window == b"PRIVATE KEY")
    );
    fs::remove_file(private_key_path).expect("remove plaintext key");

    let listed = Command::new(binary)
        .args([
            "cert",
            "list",
            "--state-dir",
            root.to_str().expect("root path"),
        ])
        .output()
        .expect("run list");
    assert!(listed.status.success(), "{:?}", listed.stderr);
    assert!(String::from_utf8_lossy(&listed.stdout).starts_with("site\t"));

    let inspected = Command::new(binary)
        .args([
            "cert",
            "inspect",
            "--state-dir",
            root.to_str().expect("root path"),
            "site",
        ])
        .output()
        .expect("run inspect");
    assert!(inspected.status.success(), "{:?}", inspected.stderr);
    let inspection = String::from_utf8_lossy(&inspected.stdout);
    assert!(inspection.contains("id = \"site\""));
    assert!(inspection.contains("hosts = [\"example.test\"]"));

    let identity_text = identity.to_string();
    let identity_path = root.join("identity.txt");
    private_file(&identity_path, identity_text.expose_secret().as_bytes());
    let verified = Command::new(binary)
        .args([
            "cert",
            "inspect",
            "--state-dir",
            root.to_str().expect("root path"),
            "--identity",
            &format!("file://{}", identity_path.display()),
            "site",
        ])
        .output()
        .expect("run recovery verification");
    assert!(verified.status.success(), "{:?}", verified.stderr);
    assert!(String::from_utf8_lossy(&verified.stdout).contains("private_key_verified = true"));
    let stored = aegisproxy_tls::inspect_certificate(&root, "site").expect("stored metadata");
    let generation = root
        .join("certificates")
        .join("site")
        .join("generations")
        .join(stored.generation);
    aegisproxy_tls::load_identity(
        "site".into(),
        vec!["example.test".into()],
        &format!("file://{}", generation.join("chain.pem").display()),
        &format!("file://{}", generation.join("key.age").display()),
        &format!("file://{}", identity_path.display()),
    )
    .expect("restart load");
    fs::remove_dir_all(root).expect("remove test root");
}

#[test]
fn reports_and_requests_managed_certificate_renewal() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let root = std::env::temp_dir().join(format!(
        "aegisproxy-renew-cli-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir(&root).expect("create root");
    let identity = age::x25519::Identity::generate();
    let identity_path = root.join("identity.txt");
    private_file(
        &identity_path,
        identity.to_string().expose_secret().as_bytes(),
    );
    let state = root.display().to_string();
    let identity_ref = format!("file://{}", identity_path.display());
    let config = format!(
        r#"schema_version = 1

[runtime]
state_dir = {state:?}

[tls]
identity = {identity_ref:?}
state_encryption_recipients = [{recipient:?}]

[[listeners]]
id = "public"
bind = "127.0.0.1:8080"
protocol = "http"

[[acme.issuers]]
id = "pebble"
directory_url = "https://127.0.0.1:14000/dir"
environment = "staging"
terms_of_service_agreed = true
ca_bundle = "file:///pebble-ca.pem"

[[acme.certificates]]
id = "managed"
hosts = ["example.test"]
issuer = "pebble"
challenge = "http-01"
challenge_listener = "public"
renew_before_days = 30
"#,
        recipient = identity.to_public().to_string(),
    );
    let config_path = root.join("proxy.toml");
    fs::write(&config_path, config).expect("write config");
    let binary = env!("CARGO_BIN_EXE_rust-proxy");

    let before = Command::new(binary)
        .args([
            "cert",
            "status",
            "--config",
            config_path.to_str().expect("config path"),
        ])
        .output()
        .expect("status before request");
    assert!(before.status.success(), "{:?}", before.stderr);
    assert!(String::from_utf8_lossy(&before.stdout).contains("managed\tmissing\t-\t-\tfalse"));

    let renew = Command::new(binary)
        .args([
            "cert",
            "renew",
            "--config",
            config_path.to_str().expect("config path"),
            "--id",
            "managed",
        ])
        .output()
        .expect("request renewal");
    assert!(renew.status.success(), "{:?}", renew.stderr);
    assert!(String::from_utf8_lossy(&renew.stdout).contains("renewal requested"));

    let after = Command::new(binary)
        .args([
            "cert",
            "status",
            "--config",
            config_path.to_str().expect("config path"),
        ])
        .output()
        .expect("status after request");
    assert!(after.status.success(), "{:?}", after.stderr);
    assert!(String::from_utf8_lossy(&after.stdout).contains("managed\tmissing\t-\t-\ttrue"));

    let unknown = Command::new(binary)
        .args([
            "cert",
            "renew",
            "--config",
            config_path.to_str().expect("config path"),
            "--id",
            "unknown",
        ])
        .output()
        .expect("reject unknown certificate");
    assert!(!unknown.status.success());
    fs::remove_dir_all(root).expect("remove test root");
}
