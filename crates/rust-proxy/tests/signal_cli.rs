#![forbid(unsafe_code)]
#![cfg(unix)]

use std::{
    fs,
    net::{TcpListener, TcpStream},
    process::{Command, Stdio},
    thread,
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

#[test]
fn sigterm_drains_and_exits_successfully() {
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
    let config = root.join("proxy.toml");
    fs::write(
        &config,
        format!(
            r#"schema_version = 1

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
"#
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
