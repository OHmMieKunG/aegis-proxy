#![forbid(unsafe_code)]
#![cfg(unix)]

use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[test]
fn typed_startup_reconciles_provider_resumes_and_keeps_drafts_inactive() {
    let root = std::env::temp_dir().join(format!(
        "aegisproxy-sigterm-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("test clock")
            .as_nanos()
    ));
    fs::create_dir(&root).expect("test directory");
    let reservation = TcpListener::bind("127.0.0.1:0").expect("port reservation");
    let address = reservation.local_addr().expect("reserved address");
    drop(reservation);
    let (first_upstream, first_address) = upstream("first");
    let (second_upstream, second_address) = upstream("second");
    let state = root.join("state");
    let audit_key = root.join("audit.key");
    fs::write(&audit_key, [0_u8; 32]).expect("audit key");
    fs::set_permissions(&audit_key, fs::Permissions::from_mode(0o600)).expect("audit key mode");
    let object = serde_json::from_value(serde_json::json!({
        "api_version": "v1",
        "metadata": {"id": "restart-host", "owner_id": "alice"},
        "spec": {
            "domain": "restart.example.test",
            "forward_host": "127.0.0.1",
            "forward_port": 9,
            "forward_protocol": "http",
            "automatic_https": "disabled",
            "access_policy_ref": null,
            "enabled": true
        }
    }))
    .expect("Proxy Host");
    aegisproxy_admin::ProxyHostStore::open(state.join("admin/proxy-hosts.json"))
        .expect("Proxy Host store")
        .create(object)
        .expect("durable Proxy Host");
    let provider_path = root.join("endpoints.toml");
    let source = serde_json::from_value(serde_json::json!({
        "api_version": "v1",
        "metadata": {"id": "app-source", "owner_id": "alice"},
        "spec": {
            "kind": "file",
            "enabled": true,
            "upstream_group": "app",
            "path": provider_path,
            "scheme": "http",
            "server_name": null,
            "refresh_secs": 1,
            "debounce_millis": 50,
            "stale_after_secs": 5,
            "max_endpoints": 4
        }
    }))
    .expect("Discovery Source");
    aegisproxy_admin::DiscoverySourceStore::open(state.join("admin/discovery-sources.json"))
        .expect("Discovery Source store")
        .create(source)
        .expect("durable Discovery Source");
    let config = root.join("proxy.toml");
    fs::write(
        &config,
        format!(
            r#"schema_version = 1

[runtime]
state_dir = "{}"
config_poll_secs = 1

[admin]
audit_key = "file://{}"

[[listeners]]
id = "public"
bind = "{address}"
protocol = "http"

[[upstream_groups]]
id = "app"
algorithm = "round_robin"
allowed_cidrs = ["127.0.0.1/32"]

[[upstream_groups.endpoints]]
id = "app-1"
url = "http://127.0.0.1:9"
weight = 1

[[routes]]
id = "app"
listeners = ["public"]
hosts = ["example.test"]
path_prefixes = ["/"]
upstream_group = "app"
"#,
            state.display(),
            audit_key.display()
        ),
    )
    .expect("test configuration");
    let startup_config = aegisproxy_config::load_file(&config).expect("startup configuration");
    let startup = aegisproxy_admin::reconcile_startup(&startup_config)
        .expect("typed reconcile")
        .expect("typed startup");
    let provider_id = startup.config().providers[0].id().to_owned();
    write_provider(&provider_path, &provider_id, first_address);

    let mut child = start_proxy(&root, &config, address);
    let response = request(address, "restart.example.test");
    assert!(
        response.starts_with("HTTP/1.1 502"),
        "typed route was not restored: {response}"
    );
    wait_for_response(address, "example.test", "first");
    stop_proxy(&mut child);

    let draft = serde_json::from_value(serde_json::json!({
        "api_version": "v1",
        "metadata": {"id": "newer-draft", "owner_id": "alice"},
        "spec": {
            "domain": "draft.example.test",
            "forward_host": "127.0.0.1",
            "forward_port": 9,
            "forward_protocol": "http",
            "automatic_https": "disabled",
            "access_policy_ref": null,
            "enabled": true
        }
    }))
    .expect("draft Proxy Host");
    aegisproxy_admin::ProxyHostStore::open(state.join("admin/proxy-hosts.json"))
        .expect("Proxy Host store")
        .create(draft)
        .expect("durable inactive draft");
    fs::write(
        &provider_path,
        format!(
            "schema_version=1\nprovider_id=\"{provider_id}\"\n[[endpoints]]\nid=\"outside-policy\"\naddress=\"192.0.2.1:80\"\n"
        ),
    )
    .expect("invalid provider result");

    let mut child = start_proxy(&root, &config, address);
    assert!(
        request(address, "example.test").contains("first"),
        "restart did not recover the exact provider last-known-good"
    );
    thread::sleep(Duration::from_millis(2_200));
    assert!(
        request(address, "example.test").contains("first"),
        "failed provider fetch replaced the recovered last-known-good"
    );
    write_provider(&provider_path, &provider_id, second_address);
    wait_for_response(address, "example.test", "second");
    assert!(
        request(address, "draft.example.test").starts_with("HTTP/1.1 404"),
        "newer desired-state draft became active during restart"
    );

    let changed = fs::read_to_string(&config)
        .expect("read configuration")
        .replace(
            "hosts = [\"example.test\"]",
            "hosts = [\"changed.example.test\"]",
        );
    fs::write(&config, changed).expect("change restart-only TOML");
    thread::sleep(Duration::from_millis(1_200));
    assert!(
        request(address, "example.test").contains("second"),
        "typed startup unexpectedly enabled live TOML reload"
    );
    assert!(
        request(address, "changed.example.test").starts_with("HTTP/1.1 404"),
        "typed startup applied a live TOML edit"
    );

    stop_proxy(&mut child);
    let audit = fs::read_to_string(state.join("audit/admin.jsonl")).expect("provider audit");
    for action in [
        "provider_reconciliation",
        "provider_candidate_create",
        "provider_activate",
        "provider_reconciliation_skip",
    ] {
        assert!(audit.contains(&format!("\"action\":\"{action}\"")));
    }
    assert!(audit.contains("\"actor_type\":\"system_provider\""));
    assert!(audit.contains("\"actor_id\":\"provider-coordinator\""));
    assert!(audit.contains("\"error_code\":\"provider_validation_rejected\""));
    assert!(!audit.contains(provider_path.to_string_lossy().as_ref()));
    first_upstream.stop();
    second_upstream.stop();
    fs::remove_dir_all(root).expect("cleanup test directory");
}

fn start_proxy(
    root: &std::path::Path,
    config: &std::path::Path,
    address: std::net::SocketAddr,
) -> std::process::Child {
    let mut child = Command::new(env!("CARGO_BIN_EXE_rust-proxy"))
        .args(["run", "--config"])
        .arg(config)
        .current_dir(root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start proxy");
    let started = Instant::now();
    loop {
        if TcpStream::connect(address).is_ok() {
            return child;
        }
        if let Some(status) = child.try_wait().expect("proxy status") {
            panic!("proxy exited before signal: {status}");
        }
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "proxy did not bind before timeout"
        );
        thread::sleep(Duration::from_millis(20));
    }
}

fn request(address: std::net::SocketAddr, host: &str) -> String {
    let mut stream = TcpStream::connect(address).expect("connect to proxy");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    write!(
        stream,
        "GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
    )
    .expect("send request");
    let mut response = String::new();
    stream.read_to_string(&mut response).expect("read response");
    response
}

fn wait_for_response(address: std::net::SocketAddr, host: &str, body: &str) {
    let started = Instant::now();
    loop {
        if request(address, host).contains(body) {
            return;
        }
        assert!(
            started.elapsed() < Duration::from_secs(6),
            "provider output did not become active"
        );
        thread::sleep(Duration::from_millis(50));
    }
}

fn write_provider(path: &std::path::Path, provider_id: &str, address: std::net::SocketAddr) {
    fs::write(
        path,
        format!(
            "schema_version=1\nprovider_id=\"{provider_id}\"\n[[endpoints]]\nid=\"node\"\naddress=\"{address}\"\n"
        ),
    )
    .expect("provider document");
}

fn stop_proxy(child: &mut std::process::Child) {
    let signal = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status()
        .expect("send SIGTERM");
    assert!(signal.success(), "kill command failed: {signal}");
    let signaled = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().expect("proxy status") {
            break status;
        }
        if signaled.elapsed() >= Duration::from_secs(10) {
            child.kill().expect("kill stuck proxy");
            let _status = child.wait().expect("reap stuck proxy");
            panic!("proxy did not drain after SIGTERM");
        }
        thread::sleep(Duration::from_millis(20));
    };
    assert!(status.success(), "proxy exited unsuccessfully: {status}");
}

struct Upstream {
    stop: Arc<AtomicBool>,
    task: Option<thread::JoinHandle<()>>,
}

impl Upstream {
    fn stop(mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(task) = self.task.take() {
            task.join().expect("join upstream");
        }
    }
}

fn upstream(body: &'static str) -> (Upstream, std::net::SocketAddr) {
    let listener = TcpListener::bind("127.0.0.1:0").expect("upstream listener");
    let address = listener.local_addr().expect("upstream address");
    listener
        .set_nonblocking(true)
        .expect("nonblocking upstream");
    let stop = Arc::new(AtomicBool::new(false));
    let task_stop = Arc::clone(&stop);
    let task = thread::spawn(move || {
        while !task_stop.load(Ordering::Acquire) {
            match listener.accept() {
                Ok((mut stream, _)) => {
                    let _ = stream.set_read_timeout(Some(Duration::from_secs(1)));
                    let mut request = [0_u8; 1024];
                    let _ = stream.read(&mut request);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    stream.write_all(response.as_bytes()).expect("response");
                }
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(error) => panic!("upstream accept: {error}"),
            }
        }
    });
    (
        Upstream {
            stop,
            task: Some(task),
        },
        address,
    )
}
