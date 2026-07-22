#![forbid(unsafe_code)]

#[cfg(unix)]
mod unix {
    use std::{
        fs,
        io::{Read, Write},
        net::TcpListener,
        os::unix::fs::{MetadataExt, PermissionsExt},
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
        let owner = format!(
            "uid-{}",
            fs::metadata("/proc/self").expect("self metadata").uid()
        );
        let admin_state = state.join("admin");
        fs::create_dir_all(&admin_state).expect("admin state");
        fs::set_permissions(&admin_state, fs::Permissions::from_mode(0o700))
            .expect("admin state mode");
        let proxy_host_store = serde_json::json!({
            "schema_version": 1,
            "objects": [
                {
                    "generation": 3,
                    "object": {
                        "api_version": "v1",
                        "metadata": {"id": "stored-cli", "owner_id": owner.clone()},
                        "spec": {
                            "domain": "stored.example.test",
                            "forward_host": "127.0.0.1",
                            "forward_port": 9001,
                            "forward_protocol": "http",
                            "automatic_https": "disabled",
                            "access_policy_ref": null,
                            "enabled": false
                        }
                    }
                },
                {
                    "generation": 1,
                    "object": {
                        "api_version": "v1",
                        "metadata": {"id": "other-owner", "owner_id": "other"},
                        "spec": {
                            "domain": "other.example.test",
                            "forward_host": "127.0.0.1",
                            "forward_port": 9002,
                            "forward_protocol": "http",
                            "automatic_https": "disabled",
                            "access_policy_ref": null,
                            "enabled": false
                        }
                    }
                }
            ]
        });
        let proxy_host_store_path = admin_state.join("proxy-hosts.json");
        fs::write(
            &proxy_host_store_path,
            serde_json::to_vec_pretty(&proxy_host_store).expect("Proxy Host store JSON"),
        )
        .expect("Proxy Host store");
        fs::set_permissions(&proxy_host_store_path, fs::Permissions::from_mode(0o600))
            .expect("Proxy Host store mode");
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
        let typed_list = run(&["proxy-host", "list", "--socket", socket]);
        assert!(typed_list.status.success(), "{:?}", typed_list.stderr);
        let typed_list_json: serde_json::Value =
            serde_json::from_slice(&typed_list.stdout).expect("typed list JSON");
        assert_eq!(typed_list_json.as_array().map(Vec::len), Some(1));
        assert_eq!(typed_list_json[0]["object"]["metadata"]["id"], "stored-cli");
        let typed_get = run(&["proxy-host", "get", "--socket", socket, "stored-cli"]);
        assert!(typed_get.status.success(), "{:?}", typed_get.stderr);
        let typed_get_json: serde_json::Value =
            serde_json::from_slice(&typed_get.stdout).expect("typed get JSON");
        assert_eq!(typed_get_json["generation"], 3);

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
        let proxy_host_path = daemon.root.join("proxy-host.json");
        let proxy_host = serde_json::json!({
            "api_version": "v1",
            "metadata": {"id": "proxy-cli", "owner_id": owner},
            "spec": {
                "domain": "typed.example.test",
                "forward_host": "127.0.0.1",
                "forward_port": 9001,
                "forward_protocol": "http",
                "automatic_https": "disabled",
                "access_policy_ref": null,
                "enabled": true
            }
        });
        fs::write(
            &proxy_host_path,
            serde_json::to_vec_pretty(&proxy_host).expect("proxy host JSON"),
        )
        .expect("proxy host file");
        let validate = run(&[
            "proxy-host",
            "validate",
            "--socket",
            socket,
            proxy_host_path.to_str().expect("proxy host path"),
        ]);
        assert!(validate.status.success(), "{:?}", validate.stderr);
        let preview = run(&[
            "proxy-host",
            "preview",
            "--socket",
            socket,
            proxy_host_path.to_str().expect("proxy host path"),
        ]);
        assert!(preview.status.success(), "{:?}", preview.stderr);
        let preview_json: serde_json::Value =
            serde_json::from_slice(&preview.stdout).expect("preview JSON");
        assert_eq!(preview_json["preview"]["summary"]["owner_id"], owner);
        assert_eq!(
            preview_json["diff"]["changes"].as_array().map(Vec::len),
            Some(8)
        );
        assert_eq!(active_revision(&state), current);

        let mut claimed_domain = proxy_host.clone();
        claimed_domain["spec"]["domain"] = serde_json::json!("stored.example.test");
        let claimed_domain_path = daemon.root.join("claimed-domain.json");
        fs::write(
            &claimed_domain_path,
            serde_json::to_vec_pretty(&claimed_domain).expect("claimed domain JSON"),
        )
        .expect("claimed domain file");
        let claimed = run(&[
            "proxy-host",
            "validate",
            "--socket",
            socket,
            claimed_domain_path.to_str().expect("claimed domain path"),
        ]);
        assert_eq!(claimed.status.code(), Some(3));

        let mut cross_owner = proxy_host.clone();
        cross_owner["metadata"]["owner_id"] = serde_json::json!("uid-unauthorized");
        let cross_owner_path = daemon.root.join("cross-owner.json");
        fs::write(
            &cross_owner_path,
            serde_json::to_vec_pretty(&cross_owner).expect("cross-owner JSON"),
        )
        .expect("cross-owner file");
        let denied_owner = run(&[
            "proxy-host",
            "preview",
            "--socket",
            socket,
            cross_owner_path.to_str().expect("cross-owner path"),
        ]);
        assert_eq!(denied_owner.status.code(), Some(5));

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
            "--scope",
            "preview-config",
            "--scope",
            "read-proxy-hosts",
            "--ttl-secs",
            "600",
        ]);
        assert!(token.status.success());
        let token_json: serde_json::Value =
            serde_json::from_slice(&token.stdout).expect("issued token JSON");
        let plaintext = token_json["token"].as_str().expect("plaintext token");
        let token_id = token_json["metadata"]["id"].as_str().expect("token ID");
        assert_eq!(token_json["metadata"]["owner_id"], owner);
        let token_file = daemon.root.join("operator.token");
        fs::write(&token_file, plaintext).expect("token file");
        fs::set_permissions(&token_file, fs::Permissions::from_mode(0o600)).expect("token mode");
        let token_ref = format!("file://{}", token_file.display());
        let unauthorized_config = daemon.root.join("unauthorized.toml");
        write_config(
            &unauthorized_config,
            &state,
            &audit_key,
            port,
            telemetry_port,
            99,
        );
        let revisions_before = fs::read_dir(state.join("config/revisions"))
            .expect("revision directory")
            .count();
        let denied_candidate = Command::new(binary())
            .args(["config", "activate", "--socket", socket, "--file"])
            .arg(&unauthorized_config)
            .args(["--expect", &current, "--token-ref", &token_ref])
            .output()
            .expect("denied candidate");
        assert_eq!(denied_candidate.status.code(), Some(5));
        assert_eq!(
            fs::read_dir(state.join("config/revisions"))
                .expect("revision directory")
                .count(),
            revisions_before
        );
        let scoped_status = run(&[
            "fleet",
            "status",
            "--socket",
            socket,
            "--token-ref",
            &token_ref,
        ]);
        assert!(scoped_status.status.success());
        let scoped_list = run(&[
            "proxy-host",
            "list",
            "--socket",
            socket,
            "--token-ref",
            &token_ref,
        ]);
        assert!(scoped_list.status.success(), "{:?}", scoped_list.stderr);
        let scoped_preview = run(&[
            "proxy-host",
            "preview",
            "--socket",
            socket,
            "--token-ref",
            &token_ref,
            proxy_host_path.to_str().expect("proxy host path"),
        ]);
        assert!(
            scoped_preview.status.success(),
            "{:?}",
            scoped_preview.stderr
        );
        let denied_create = Command::new(binary())
            .args([
                "proxy-host",
                "create",
                "--socket",
                socket,
                "--token-ref",
                &token_ref,
                "--expect",
                &current,
            ])
            .arg(&proxy_host_path)
            .output()
            .expect("denied Proxy Host create");
        assert_eq!(denied_create.status.code(), Some(5));
        assert_eq!(
            fs::read_dir(state.join("config/revisions"))
                .expect("revision directory")
                .count(),
            revisions_before
        );
        let create = Command::new(binary())
            .args([
                "proxy-host",
                "create",
                "--socket",
                socket,
                "--expect",
                &current,
            ])
            .arg(&proxy_host_path)
            .output()
            .expect("Proxy Host create");
        assert!(create.status.success(), "{:?}", create.stderr);
        let create_json: serde_json::Value =
            serde_json::from_slice(&create.stdout).expect("Proxy Host create JSON");
        assert_eq!(create_json["object"]["generation"], 1);
        assert_eq!(create_json["object"]["object"], proxy_host);
        let candidate_id = create_json["candidate"]["id"]
            .as_str()
            .expect("candidate ID");
        assert!(
            state
                .join("config/revisions")
                .join(format!("{candidate_id}.toml"))
                .is_file()
        );
        assert_eq!(active_revision(&state), current);
        let created_list = run(&["proxy-host", "list", "--socket", socket]);
        assert!(created_list.status.success(), "{:?}", created_list.stderr);
        let created_list_json: serde_json::Value =
            serde_json::from_slice(&created_list.stdout).expect("created list JSON");
        assert_eq!(created_list_json.as_array().map(Vec::len), Some(2));
        let malformed_path = daemon.root.join("malformed-proxy-host.json");
        fs::write(&malformed_path, b"{").expect("malformed file");
        let authorization_first = run(&[
            "proxy-host",
            "validate",
            "--socket",
            socket,
            "--token-ref",
            &token_ref,
            malformed_path.to_str().expect("malformed path"),
        ]);
        assert_eq!(authorization_first.status.code(), Some(5));
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
