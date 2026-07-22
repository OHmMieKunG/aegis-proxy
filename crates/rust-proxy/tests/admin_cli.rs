#![forbid(unsafe_code)]

#[cfg(unix)]
mod unix {
    use std::{
        fs,
        io::{Read, Write},
        net::TcpListener,
        os::unix::fs::PermissionsExt,
        path::{Path, PathBuf},
        process::{Child, Command, Output, Stdio},
        thread,
        time::{Duration, SystemTime, UNIX_EPOCH},
    };

    struct Daemon {
        child: Child,
        root: PathBuf,
    }

    impl Drop for Daemon {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
            let _ = fs::remove_dir_all(&self.root);
        }
    }

    fn binary() -> &'static str {
        env!("CARGO_BIN_EXE_rust-proxy")
    }

    fn root() -> PathBuf {
        std::env::temp_dir().join(format!(
            "aegisproxy-admin-cli-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("test clock")
                .as_nanos()
        ))
    }

    fn write_config(
        path: &Path,
        state: &Path,
        audit_key: &Path,
        port: u16,
        telemetry_port: u16,
        priority: i32,
    ) {
        let config = format!(
            r#"schema_version = 1

[runtime]
state_dir = {state:?}
config_poll_secs = 60

[admin]
audit_key = {audit:?}
requests_per_second = 100
burst = 200

[observability.otlp_traces]
endpoint = "http://127.0.0.1:{telemetry_port}/v1/traces"
sample_per_million = 1000000
max_queue_size = 4
max_export_batch_size = 2
export_timeout_secs = 1

[[listeners]]
id = "public"
bind = "127.0.0.1:{port}"
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
priority = {priority}
upstream_group = "app"
"#,
            state = state.display().to_string(),
            audit = format!("file://{}", audit_key.display()),
        );
        fs::write(path, config).expect("write config");
    }

    fn wait_for_socket(child: &mut Child, socket: &Path) {
        for _ in 0..200 {
            assert!(child.try_wait().expect("daemon status").is_none());
            if socket.exists() {
                return;
            }
            thread::sleep(Duration::from_millis(25));
        }
        panic!("administrative socket did not appear");
    }

    fn active_revision(state: &Path) -> String {
        let bytes = fs::read(state.join("config/active.json")).expect("active pointer");
        let value: serde_json::Value = serde_json::from_slice(&bytes).expect("active JSON");
        value["active"]["id"]
            .as_str()
            .expect("active ID")
            .to_owned()
    }

    fn run(args: &[&str]) -> Output {
        Command::new(binary()).args(args).output().expect("run CLI")
    }

    #[test]
    fn private_cli_enforces_cas_rbac_token_and_audit_contracts() {
        let root = root();
        fs::create_dir(&root).expect("test root");
        let state = root.join("state");
        let audit_key = root.join("audit.key");
        fs::write(&audit_key, [0_u8; 32]).expect("audit key");
        fs::set_permissions(&audit_key, fs::Permissions::from_mode(0o600)).expect("key mode");
        let port = TcpListener::bind("127.0.0.1:0")
            .expect("ephemeral listener")
            .local_addr()
            .expect("ephemeral address")
            .port();
        let slow_telemetry = TcpListener::bind("127.0.0.1:0").expect("slow telemetry bind");
        let telemetry_port = slow_telemetry
            .local_addr()
            .expect("slow telemetry address")
            .port();
        thread::spawn(move || {
            if slow_telemetry.accept().is_ok() {
                thread::sleep(Duration::from_secs(5));
            }
        });
        let configured = root.join("proxy.toml");
        let first = root.join("first.toml");
        let second = root.join("second.toml");
        write_config(&configured, &state, &audit_key, port, telemetry_port, 0);
        write_config(&first, &state, &audit_key, port, telemetry_port, 1);
        write_config(&second, &state, &audit_key, port, telemetry_port, 2);

        let log_path = root.join("daemon.jsonl");
        let log = fs::File::create(&log_path).expect("log file");
        let error_log = log.try_clone().expect("log clone");
        let child = Command::new(binary())
            .args(["run", "--config"])
            .arg(&configured)
            .args(["--node-id", "node-a", "--fleet-generation", "7"])
            .stdout(Stdio::from(log))
            .stderr(Stdio::from(error_log))
            .spawn()
            .expect("start daemon");
        let mut daemon = Daemon { child, root };
        let socket = state.join("admin/admin.sock");
        wait_for_socket(&mut daemon.child, &socket);
        let socket = socket.to_str().expect("socket UTF-8");
        assert!(run(&["health", "--socket", socket]).status.success());

        let expected = active_revision(&state);
        let first_activation = Command::new(binary())
            .args(["config", "activate", "--socket", socket, "--file"])
            .arg(&first)
            .args(["--expect", &expected])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("first activation");
        let second_activation = Command::new(binary())
            .args(["config", "activate", "--socket", socket, "--file"])
            .arg(&second)
            .args(["--expect", &expected])
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("second activation");
        let first_output = first_activation.wait_with_output().expect("first output");
        let second_output = second_activation.wait_with_output().expect("second output");
        let mut codes = [first_output.status.code(), second_output.status.code()];
        codes.sort_unstable();
        assert_eq!(codes, [Some(0), Some(4)]);
        let request_started = std::time::Instant::now();
        let mut client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("proxy");
        client
            .write_all(b"GET /private?token=QUERY_CANARY HTTP/1.1\r\nHost: example.test\r\nAuthorization: Bearer AUTH_CANARY\r\nCookie: session=COOKIE_CANARY\r\nUser-Agent: AGENT_CANARY\r\nX-Secret: HEADER_CANARY\r\nConnection: close\r\n\r\n")
            .expect("request");
        let mut response = String::new();
        client.read_to_string(&mut response).expect("response");
        assert!(response.starts_with("HTTP/1.1 502"));
        assert!(request_started.elapsed() < Duration::from_secs(2));
        thread::sleep(Duration::from_millis(1_500));
        let request_started = std::time::Instant::now();
        let mut client = std::net::TcpStream::connect(("127.0.0.1", port)).expect("proxy");
        client
            .write_all(
                b"GET /while-exporter-is-slow HTTP/1.1\r\nHost: example.test\r\nConnection: close\r\n\r\n",
            )
            .expect("request during slow export");
        let mut response = String::new();
        client.read_to_string(&mut response).expect("response");
        assert!(response.starts_with("HTTP/1.1 502"));
        assert!(request_started.elapsed() < Duration::from_secs(2));
        let metrics = run(&["metrics", "--socket", socket]);
        assert!(metrics.status.success());
        let metrics = String::from_utf8(metrics.stdout).expect("OpenMetrics UTF-8");
        assert!(metrics.contains("aegisproxy_config_reloads_total{outcome=\"success\"} 1"));
        assert!(metrics.contains("aegisproxy_http_requests_total"));
        assert!(metrics.contains("route=\"app\""));
        assert!(metrics.contains("aegisproxy_upstream_attempts_total"));
        assert!(metrics.contains("aegisproxy_upstream_active_connections"));
        assert!(metrics.contains("aegisproxy_upstream_healthy"));
        assert!(metrics.contains("aegisproxy_config_reload_duration_seconds"));
        assert!(metrics.contains("outcome=\"connect_error\""));
        assert!(!metrics.contains("example.test"));
        for canary in [
            "QUERY_CANARY",
            "AUTH_CANARY",
            "COOKIE_CANARY",
            "AGENT_CANARY",
            "HEADER_CANARY",
        ] {
            assert!(!metrics.contains(canary));
        }

        let current = active_revision(&state);
        let escalation = run(&[
            "token",
            "create",
            "--socket",
            socket,
            "--expect",
            &current,
            "--role",
            "viewer",
            "--scope",
            "activate-config",
            "--ttl-secs",
            "600",
        ]);
        assert_eq!(escalation.status.code(), Some(3));
        let token = run(&[
            "token",
            "create",
            "--socket",
            socket,
            "--expect",
            &current,
            "--role",
            "operator",
            "--scope",
            "read-status",
            "--ttl-secs",
            "600",
        ]);
        assert!(token.status.success());
        let token_json: serde_json::Value =
            serde_json::from_slice(&token.stdout).expect("issued token JSON");
        let plaintext = token_json["token"].as_str().expect("plaintext token");
        let token_id = token_json["metadata"]["id"].as_str().expect("token ID");
        let token_file = daemon.root.join("operator.token");
        fs::write(&token_file, plaintext).expect("token file");
        fs::set_permissions(&token_file, fs::Permissions::from_mode(0o600)).expect("token mode");
        let token_ref = format!("file://{}", token_file.display());
        let scoped_status = run(&[
            "fleet",
            "status",
            "--socket",
            socket,
            "--token-ref",
            &token_ref,
        ]);
        assert!(scoped_status.status.success());
        let denied = run(&[
            "token",
            "revoke",
            "--socket",
            socket,
            "--token-ref",
            &token_ref,
            "--expect",
            &current,
            token_id,
        ]);
        assert_eq!(denied.status.code(), Some(5));

        let revoke = run(&[
            "token", "revoke", "--socket", socket, "--expect", &current, token_id,
        ]);
        assert!(revoke.status.success());
        let token_store = fs::read_to_string(state.join("admin/tokens.json")).expect("token store");
        assert!(!token_store.contains(plaintext));
        assert!(!token_store.contains("operator.token"));

        let status = run(&["fleet", "status", "--socket", socket]);
        assert!(status.status.success(), "{:?}", status.stderr);
        let status_json: serde_json::Value =
            serde_json::from_slice(&status.stdout).expect("node status JSON");
        assert_eq!(status_json["node_id"], "node-a");
        assert_eq!(status_json["fleet_generation"], 7);
        let active_hash = status_json["active_hash"]
            .as_str()
            .expect("active hash")
            .to_owned();
        let status_path = daemon.root.join("node-a.json");
        fs::write(&status_path, &status.stdout).expect("status export");
        let fleet = Command::new(binary())
            .args([
                "fleet",
                "check",
                "--expected-hash",
                &active_hash,
                "--generation",
                "7",
                "--node",
                "node-a",
                "--status",
            ])
            .arg(&status_path)
            .output()
            .expect("fleet check");
        assert!(fleet.status.success(), "{:?}", fleet.stderr);

        let drain = run(&["drain", "--socket", socket, "--expect", &current]);
        assert!(drain.status.success(), "{:?}", drain.stderr);
        assert!(String::from_utf8_lossy(&drain.stdout).contains("\"draining\":true"));
        assert!(!run(&["health", "--socket", socket]).status.success());

        let audit = fs::read_to_string(state.join("audit/admin.jsonl")).expect("audit log");
        assert!(audit.contains("\"outcome\":\"intent\""));
        assert!(audit.contains("\"outcome\":\"success\""));
        assert!(audit.contains("\"outcome\":\"failed\""));
        assert!(audit.contains("\"outcome\":\"denied\""));
        assert!(audit.contains("\"action\":\"node_drain\""));
        assert!(
            audit
                .lines()
                .all(|line| line.contains("\"node_id\":\"node-a\""))
        );
        assert!(!audit.contains(plaintext));
        let logs = fs::read_to_string(log_path).expect("structured logs");
        assert!(
            logs.lines()
                .all(|line| serde_json::from_str::<serde_json::Value>(line).is_ok())
        );
        for canary in [
            "QUERY_CANARY",
            "AUTH_CANARY",
            "COOKIE_CANARY",
            "AGENT_CANARY",
            "HEADER_CANARY",
            plaintext,
        ] {
            assert!(!logs.contains(canary));
        }
    }
}
