#![forbid(unsafe_code)]
#![cfg(unix)]

use std::{
    fs,
    io::{Read, Write},
    net::{TcpListener, TcpStream},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[test]
fn startup_restores_typed_route_and_sigterm_drains() {
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
    let state = root.join("state");
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
    let config = root.join("proxy.toml");
    fs::write(
        &config,
        format!(
            r#"schema_version = 1

[runtime]
state_dir = "{}"

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
            state.display()
        ),
    )
    .expect("test configuration");

    let mut child = Command::new(env!("CARGO_BIN_EXE_rust-proxy"))
        .args(["run", "--config"])
        .arg(&config)
        .current_dir(&root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start proxy");

    let started = Instant::now();
    loop {
        if TcpStream::connect(address).is_ok() {
            break;
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

    let mut request = TcpStream::connect(address).expect("connect to proxy");
    request
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("read timeout");
    request
        .write_all(b"GET / HTTP/1.1\r\nHost: restart.example.test\r\nConnection: close\r\n\r\n")
        .expect("send request");
    let mut response = String::new();
    request
        .read_to_string(&mut response)
        .expect("read response");
    assert!(
        response.starts_with("HTTP/1.1 502"),
        "typed route was not restored: {response}"
    );

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
    fs::remove_dir_all(root).expect("cleanup test directory");
}
