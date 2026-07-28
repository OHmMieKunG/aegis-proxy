#![forbid(unsafe_code)]

#[cfg(unix)]
mod unix {
    use std::{
        fs,
        io::{Read, Write},
        net::TcpListener,
        os::unix::{
            fs::{MetadataExt, PermissionsExt},
            net::UnixStream,
        },
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
config_poll_secs = 300

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

[middlewares.edge-ip]
type = "ip_policy"
allow = ["127.0.0.1/32"]
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

    fn raw_get(socket: &str, path: &str) -> String {
        let mut stream = UnixStream::connect(socket).expect("connect admin socket");
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
        )
        .expect("write request");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read response");
        response
    }

    fn raw_post(socket: &str, path: &str, expected_revision: &str) -> String {
        let mut stream = UnixStream::connect(socket).expect("connect admin socket");
        write!(
            stream,
            "POST {path} HTTP/1.1\r\nHost: localhost\r\nIf-Match: \"{expected_revision}\"\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .expect("write request");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read response");
        response
    }

    fn raw_json_post(
        socket: &str,
        path: &str,
        expected_revision: &str,
        token: Option<&str>,
        content_type: &str,
        body: &str,
    ) -> String {
        let mut stream = UnixStream::connect(socket).expect("connect admin socket");
        let authorization = token
            .map(|token| format!("Authorization: Bearer {token}\r\n"))
            .unwrap_or_default();
        write!(
            stream,
            "POST {path} HTTP/1.1\r\nHost: localhost\r\n{authorization}If-Match: \"{expected_revision}\"\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len()
        )
        .expect("write request");
        let mut response = String::new();
        stream.read_to_string(&mut response).expect("read response");
        response
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
        let access_policy_store = serde_json::json!({
            "schema_version": 1,
            "policies": [
                {
                    "generation": 1,
                    "object": {
                        "api_version": "v1",
                        "metadata": {"id": "other-policy", "owner_id": "other"},
                        "spec": {
                            "enabled": true,
                            "shared_with": [owner.clone()],
                            "middlewares": ["edge-ip"]
                        }
                    }
                },
                {
                    "generation": 2,
                    "object": {
                        "api_version": "v1",
                        "metadata": {"id": "private-lan", "owner_id": owner.clone()},
                        "spec": {
                            "enabled": true,
                            "shared_with": ["other"],
                            "middlewares": ["edge-ip"]
                        }
                    }
                },
                {
                    "generation": 1,
                    "object": {
                        "api_version": "v1",
                        "metadata": {"id": "z-policy", "owner_id": owner.clone()},
                        "spec": {
                            "enabled": false,
                            "shared_with": [],
                            "middlewares": ["edge-rate"]
                        }
                    }
                }
            ]
        });
        let access_policy_store_path = admin_state.join("access-policies.json");
        fs::write(
            &access_policy_store_path,
            serde_json::to_vec_pretty(&access_policy_store).expect("Access Policy store JSON"),
        )
        .expect("Access Policy store");
        fs::set_permissions(&access_policy_store_path, fs::Permissions::from_mode(0o600))
            .expect("Access Policy store mode");
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
        let owned_policies = run(&["access-policy", "list", "--socket", socket]);
        assert!(owned_policies.status.success());
        let policies: serde_json::Value =
            serde_json::from_slice(&owned_policies.stdout).expect("policy list");
        assert_eq!(policies.as_array().expect("policy array").len(), 2);
        assert_eq!(policies[0]["object"]["metadata"]["id"], "private-lan");
        assert_eq!(policies[1]["object"]["metadata"]["id"], "z-policy");
        let owned_policy = run(&["access-policy", "get", "--socket", socket, "private-lan"]);
        assert!(owned_policy.status.success());
        let raw_policy = raw_get(socket, "/v1/access-policies/private-lan");
        assert!(raw_policy.starts_with("HTTP/1.1 200 "));
        assert!(raw_policy.contains("\r\netag: \"2\"\r\n"));
        let hidden_policy = run(&["access-policy", "get", "--socket", socket, "other-policy"]);
        assert_eq!(hidden_policy.status.code(), Some(6));
        assert_eq!(
            run(&["access-policy", "get", "--socket", socket, "Bad!"])
                .status
                .code(),
            Some(6)
        );
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
        for (command, object) in [
            (
                "stream-host",
                serde_json::json!({
                    "api_version": "v1",
                    "metadata": {"id": "stream-cli", "owner_id": owner.clone()},
                    "spec": {
                        "listen_port": 9443,
                        "protocol": "tls_passthrough",
                        "forward_host": "127.0.0.1",
                        "forward_port": 9000,
                        "sni_hosts": ["stream.example.test"],
                        "enabled": false
                    }
                }),
            ),
            (
                "discovery-source",
                serde_json::json!({
                    "api_version": "v1",
                    "metadata": {"id": "discovery-cli", "owner_id": owner.clone()},
                    "spec": {
                        "kind": "dns",
                        "enabled": false,
                        "upstream_group": "app",
                        "hostname": "nodes.example.test",
                        "port": 9000,
                        "scheme": "http",
                        "server_name": null,
                        "weight": 1,
                        "refresh_secs": 30,
                        "stale_after_secs": 300,
                        "max_answers": 16
                    }
                }),
            ),
        ] {
            let path = daemon.root.join(format!("{command}.json"));
            fs::write(
                &path,
                serde_json::to_vec_pretty(&object).expect("typed domain JSON"),
            )
            .expect("typed domain file");
            let create = Command::new(binary())
                .args([command, "create", "--socket", socket, "--expect", &expected])
                .arg(&path)
                .output()
                .expect("typed domain create");
            assert!(create.status.success(), "{:?}", create.stderr);
            let list = run(&[command, "list", "--socket", socket]);
            assert!(list.status.success(), "{:?}", list.stderr);
            let listed: serde_json::Value =
                serde_json::from_slice(&list.stdout).expect("typed domain list");
            assert_eq!(listed.as_array().map(Vec::len), Some(1));
        }
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

        let mut current = active_revision(&state);
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
                "access_policy_ref": "private-lan",
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

        let mut protected_proxy_host = proxy_host.clone();
        protected_proxy_host["spec"]["access_policy_ref"] = serde_json::json!("other-policy");
        let protected_proxy_host_path = daemon.root.join("protected-proxy-host.json");
        fs::write(
            &protected_proxy_host_path,
            serde_json::to_vec_pretty(&protected_proxy_host).expect("protected Proxy Host JSON"),
        )
        .expect("protected Proxy Host file");
        let protected_preview = run(&[
            "proxy-host",
            "preview",
            "--socket",
            socket,
            protected_proxy_host_path
                .to_str()
                .expect("protected Proxy Host path"),
        ]);
        assert!(
            protected_preview.status.success(),
            "{:?}",
            protected_preview.stderr
        );
        let protected_preview: serde_json::Value =
            serde_json::from_slice(&protected_preview.stdout).expect("protected preview JSON");
        let protected_route = protected_preview["preview"]["redacted_config"]["routes"]
            .as_array()
            .and_then(|routes| {
                routes
                    .iter()
                    .find(|route| route["hosts"] == serde_json::json!(["typed.example.test"]))
            })
            .expect("protected route");
        assert_eq!(
            protected_route["middlewares"],
            serde_json::json!(["edge-ip"])
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

        for (id, role) in [("viewer-user", "viewer"), (owner.as_str(), "operator")] {
            let path = daemon.root.join(format!("{id}.json"));
            fs::write(
                &path,
                serde_json::to_vec(&serde_json::json!({
                    "api_version": "v1",
                    "metadata": {"id": id, "owner_id": id},
                    "spec": {"display_name": id, "role": role, "enabled": true}
                }))
                .expect("user JSON"),
            )
            .expect("user file");
            assert!(
                Command::new(binary())
                    .args(["user", "create", "--socket", socket, "--expect", &current])
                    .arg(path)
                    .output()
                    .expect("create user")
                    .status
                    .success()
            );
        }
        let stale_user_update = Command::new(binary())
            .args([
                "user",
                "update",
                "--socket",
                socket,
                "--expect",
                &current,
                "--generation",
                "2",
                &owner,
            ])
            .arg(daemon.root.join(format!("{owner}.json")))
            .output()
            .expect("stale user update");
        assert_eq!(stale_user_update.status.code(), Some(4));

        let escalation = run(&[
            "token",
            "create",
            "--socket",
            socket,
            "--expect",
            &current,
            "--user-ref",
            "viewer-user",
            "--scope",
            "activate-config",
            "--ttl-secs",
            "600",
        ]);
        assert_eq!(escalation.status.code(), Some(3));
        let limited = run(&[
            "token",
            "create",
            "--socket",
            socket,
            "--expect",
            &current,
            "--user-ref",
            "viewer-user",
            "--scope",
            "read-status",
            "--ttl-secs",
            "600",
        ]);
        assert!(limited.status.success());
        let limited_json: serde_json::Value =
            serde_json::from_slice(&limited.stdout).expect("limited token JSON");
        let limited_file = daemon.root.join("limited.token");
        fs::write(
            &limited_file,
            limited_json["token"].as_str().expect("limited plaintext"),
        )
        .expect("limited token file");
        fs::set_permissions(&limited_file, fs::Permissions::from_mode(0o600))
            .expect("limited token mode");
        let limited_ref = format!("file://{}", limited_file.display());
        let limited_plaintext = limited_json["token"].as_str().expect("limited plaintext");
        for path in ["/v1/tokens", "/v1/backups", "/v1/restore/validate"] {
            let denied = raw_json_post(
                socket,
                path,
                &current,
                Some(limited_plaintext),
                "application/json",
                "{",
            );
            assert!(denied.starts_with("HTTP/1.1 403 "), "{denied}");
        }
        let noncanonical_content_type = raw_json_post(
            socket,
            "/v1/backups",
            &current,
            None,
            "application/json; charset=utf-8",
            "{}",
        );
        assert!(
            noncanonical_content_type.starts_with("HTTP/1.1 400 "),
            "{noncanonical_content_type}"
        );
        let invalid_policy_path = daemon.root.join("invalid-policy.json");
        fs::write(&invalid_policy_path, b"{").expect("invalid policy file");
        let denied_policy_create = Command::new(binary())
            .args([
                "access-policy",
                "create",
                "--socket",
                socket,
                "--token-ref",
                &limited_ref,
                "--expect",
                &current,
            ])
            .arg(&invalid_policy_path)
            .output()
            .expect("denied Access Policy create");
        assert_eq!(denied_policy_create.status.code(), Some(5));
        let denied_policy_update = Command::new(binary())
            .args([
                "access-policy",
                "update",
                "--socket",
                socket,
                "--token-ref",
                &limited_ref,
                "--expect",
                &current,
                "--generation",
                "2",
                "private-lan",
            ])
            .arg(&invalid_policy_path)
            .output()
            .expect("denied Access Policy update");
        assert_eq!(denied_policy_update.status.code(), Some(5));
        let denied_policy_delete = run(&[
            "access-policy",
            "delete",
            "--socket",
            socket,
            "--token-ref",
            &limited_ref,
            "--expect",
            &current,
            "--generation",
            "2",
            "private-lan",
        ]);
        assert_eq!(denied_policy_delete.status.code(), Some(5));
        let denied_policy_list = run(&[
            "access-policy",
            "list",
            "--socket",
            socket,
            "--token-ref",
            &limited_ref,
        ]);
        assert_eq!(denied_policy_list.status.code(), Some(5));
        let denied_policy_get = run(&[
            "access-policy",
            "get",
            "--socket",
            socket,
            "--token-ref",
            &limited_ref,
            "private-lan",
        ]);
        assert_eq!(denied_policy_get.status.code(), Some(5));
        let token = run(&[
            "token",
            "create",
            "--socket",
            socket,
            "--expect",
            &current,
            "--user-ref",
            &owner,
            "--scope",
            "read-status",
            "--scope",
            "preview-config",
            "--scope",
            "read-proxy-hosts",
            "--scope",
            "read-access-policies",
            "--scope",
            "create-access-policy",
            "--scope",
            "update-access-policy",
            "--scope",
            "delete-access-policy",
            "--ttl-secs",
            "600",
        ]);
        assert!(token.status.success());
        let token_json: serde_json::Value =
            serde_json::from_slice(&token.stdout).expect("issued token JSON");
        let plaintext = token_json["token"].as_str().expect("plaintext token");
        let token_id = token_json["metadata"]["id"].as_str().expect("token ID");
        assert_eq!(token_json["metadata"]["owner_id"], owner);
        assert_eq!(
            token_json["metadata"]["scopes"],
            serde_json::json!([
                "read_status",
                "preview_config",
                "read_proxy_hosts",
                "read_access_policies",
                "create_access_policy",
                "update_access_policy",
                "delete_access_policy"
            ])
        );
        let token_file = daemon.root.join("operator.token");
        fs::write(&token_file, plaintext).expect("token file");
        fs::set_permissions(&token_file, fs::Permissions::from_mode(0o600)).expect("token mode");
        let token_ref = format!("file://{}", token_file.display());
        let policy_revisions_before = fs::read_dir(state.join("config/revisions"))
            .expect("revision directory")
            .count();
        let access_policy_path = daemon.root.join("access-policy.json");
        let access_policy = serde_json::json!({
            "api_version": "v1",
            "metadata": {"id": "created-policy", "owner_id": owner},
            "spec": {
                "enabled": true,
                "shared_with": [],
                "middlewares": ["edge-ip"]
            }
        });
        fs::write(
            &access_policy_path,
            serde_json::to_vec_pretty(&access_policy).expect("Access Policy JSON"),
        )
        .expect("Access Policy file");
        let policy_create = Command::new(binary())
            .args([
                "access-policy",
                "create",
                "--socket",
                socket,
                "--token-ref",
                &token_ref,
                "--expect",
                &current,
            ])
            .arg(&access_policy_path)
            .output()
            .expect("Access Policy create");
        assert!(policy_create.status.success(), "{:?}", policy_create.stderr);
        let policy_create_json: serde_json::Value =
            serde_json::from_slice(&policy_create.stdout).expect("Access Policy create JSON");
        assert_eq!(policy_create_json["generation"], 1);
        assert_eq!(policy_create_json["object"], access_policy);
        let raw_created_policy = raw_get(socket, "/v1/access-policies/created-policy");
        assert!(raw_created_policy.starts_with("HTTP/1.1 200 "));
        assert!(raw_created_policy.contains("\r\netag: \"1\"\r\n"));
        assert_eq!(active_revision(&state), current);
        assert_eq!(
            fs::read_dir(state.join("config/revisions"))
                .expect("revision directory")
                .count(),
            policy_revisions_before
        );
        let duplicate_policy = Command::new(binary())
            .args([
                "access-policy",
                "create",
                "--socket",
                socket,
                "--token-ref",
                &token_ref,
                "--expect",
                &current,
            ])
            .arg(&access_policy_path)
            .output()
            .expect("duplicate Access Policy create");
        assert_eq!(duplicate_policy.status.code(), Some(4));
        let mut missing_middleware = access_policy.clone();
        missing_middleware["metadata"]["id"] = serde_json::json!("missing-middleware");
        missing_middleware["spec"]["middlewares"] = serde_json::json!(["missing"]);
        let missing_middleware_path = daemon.root.join("missing-middleware.json");
        fs::write(
            &missing_middleware_path,
            serde_json::to_vec_pretty(&missing_middleware).expect("missing middleware JSON"),
        )
        .expect("missing middleware file");
        let invalid_policy = Command::new(binary())
            .args([
                "access-policy",
                "create",
                "--socket",
                socket,
                "--token-ref",
                &token_ref,
                "--expect",
                &current,
            ])
            .arg(&missing_middleware_path)
            .output()
            .expect("invalid Access Policy create");
        assert_eq!(invalid_policy.status.code(), Some(3));
        let stale_policy = Command::new(binary())
            .args([
                "access-policy",
                "create",
                "--socket",
                socket,
                "--token-ref",
                &token_ref,
                "--expect",
                "00000000000000000000-0000000000000000000000000000000000000000000000000000000000000000",
            ])
            .arg(&missing_middleware_path)
            .output()
            .expect("stale Access Policy create");
        assert_eq!(stale_policy.status.code(), Some(4));
        let mut wrong_owner_policy = access_policy.clone();
        wrong_owner_policy["metadata"]["id"] = serde_json::json!("wrong-owner-policy");
        wrong_owner_policy["metadata"]["owner_id"] = serde_json::json!("other");
        let wrong_owner_policy_path = daemon.root.join("wrong-owner-policy.json");
        fs::write(
            &wrong_owner_policy_path,
            serde_json::to_vec_pretty(&wrong_owner_policy).expect("wrong owner policy JSON"),
        )
        .expect("wrong owner policy file");
        let wrong_owner_create = Command::new(binary())
            .args([
                "access-policy",
                "create",
                "--socket",
                socket,
                "--token-ref",
                &token_ref,
                "--expect",
                &current,
            ])
            .arg(&wrong_owner_policy_path)
            .output()
            .expect("wrong-owner Access Policy create");
        assert_eq!(wrong_owner_create.status.code(), Some(5));
        let mut updated_policy = access_policy.clone();
        updated_policy["spec"]["enabled"] = serde_json::json!(false);
        let updated_policy_path = daemon.root.join("updated-access-policy.json");
        fs::write(
            &updated_policy_path,
            serde_json::to_vec_pretty(&updated_policy).expect("updated Access Policy JSON"),
        )
        .expect("updated Access Policy file");
        let stale_policy_update = Command::new(binary())
            .args([
                "access-policy",
                "update",
                "--socket",
                socket,
                "--token-ref",
                &token_ref,
                "--expect",
                &current,
                "--generation",
                "2",
                "created-policy",
            ])
            .arg(&updated_policy_path)
            .output()
            .expect("stale Access Policy update");
        assert_eq!(stale_policy_update.status.code(), Some(4));
        let policy_update = Command::new(binary())
            .args([
                "access-policy",
                "update",
                "--socket",
                socket,
                "--token-ref",
                &token_ref,
                "--expect",
                &current,
                "--generation",
                "1",
                "created-policy",
            ])
            .arg(&updated_policy_path)
            .output()
            .expect("Access Policy update");
        assert!(policy_update.status.success(), "{:?}", policy_update.stderr);
        let policy_update_json: serde_json::Value =
            serde_json::from_slice(&policy_update.stdout).expect("Access Policy update JSON");
        assert_eq!(policy_update_json["generation"], 2);
        assert_eq!(policy_update_json["object"], updated_policy);
        let raw_updated_policy = raw_get(socket, "/v1/access-policies/created-policy");
        assert!(raw_updated_policy.contains("\r\netag: \"2\"\r\n"));
        let mut invalid_update_policy = updated_policy.clone();
        invalid_update_policy["spec"]["middlewares"] = serde_json::json!(["missing"]);
        let invalid_update_path = daemon.root.join("invalid-updated-access-policy.json");
        fs::write(
            &invalid_update_path,
            serde_json::to_vec_pretty(&invalid_update_policy)
                .expect("invalid updated Access Policy JSON"),
        )
        .expect("invalid updated Access Policy file");
        let invalid_policy_update = Command::new(binary())
            .args([
                "access-policy",
                "update",
                "--socket",
                socket,
                "--token-ref",
                &token_ref,
                "--expect",
                &current,
                "--generation",
                "2",
                "created-policy",
            ])
            .arg(&invalid_update_path)
            .output()
            .expect("invalid Access Policy update");
        assert_eq!(invalid_policy_update.status.code(), Some(3));
        let retained_policy = run(&["access-policy", "get", "--socket", socket, "created-policy"]);
        assert!(retained_policy.status.success());
        let retained_policy: serde_json::Value =
            serde_json::from_slice(&retained_policy.stdout).expect("retained Access Policy JSON");
        assert_eq!(retained_policy["generation"], 2);
        assert_eq!(retained_policy["object"], updated_policy);
        let wrong_id_update = Command::new(binary())
            .args([
                "access-policy",
                "update",
                "--socket",
                socket,
                "--token-ref",
                &token_ref,
                "--expect",
                &current,
                "--generation",
                "2",
                "private-lan",
            ])
            .arg(&updated_policy_path)
            .output()
            .expect("wrong-ID Access Policy update");
        assert_eq!(wrong_id_update.status.code(), Some(3));
        let mut wrong_owner_update = updated_policy.clone();
        wrong_owner_update["metadata"]["owner_id"] = serde_json::json!("other");
        let wrong_owner_update_path = daemon.root.join("wrong-owner-update.json");
        fs::write(
            &wrong_owner_update_path,
            serde_json::to_vec_pretty(&wrong_owner_update).expect("wrong-owner update JSON"),
        )
        .expect("wrong-owner update file");
        let wrong_owner_update = Command::new(binary())
            .args([
                "access-policy",
                "update",
                "--socket",
                socket,
                "--token-ref",
                &token_ref,
                "--expect",
                &current,
                "--generation",
                "2",
                "created-policy",
            ])
            .arg(&wrong_owner_update_path)
            .output()
            .expect("wrong-owner Access Policy update");
        assert_eq!(wrong_owner_update.status.code(), Some(5));
        let cross_owner_delete = run(&[
            "access-policy",
            "delete",
            "--socket",
            socket,
            "--token-ref",
            &token_ref,
            "--expect",
            &current,
            "--generation",
            "1",
            "other-policy",
        ]);
        assert_eq!(cross_owner_delete.status.code(), Some(6));
        let stale_revision =
            "00000000000000000000-0000000000000000000000000000000000000000000000000000000000000000";
        let stale_revision_update = Command::new(binary())
            .args([
                "access-policy",
                "update",
                "--socket",
                socket,
                "--token-ref",
                &token_ref,
                "--expect",
                stale_revision,
                "--generation",
                "2",
                "created-policy",
            ])
            .arg(&updated_policy_path)
            .output()
            .expect("stale-revision Access Policy update");
        assert_eq!(stale_revision_update.status.code(), Some(4));
        let stale_revision_delete = run(&[
            "access-policy",
            "delete",
            "--socket",
            socket,
            "--token-ref",
            &token_ref,
            "--expect",
            stale_revision,
            "--generation",
            "2",
            "created-policy",
        ]);
        assert_eq!(stale_revision_delete.status.code(), Some(4));
        let stale_policy_delete = run(&[
            "access-policy",
            "delete",
            "--socket",
            socket,
            "--token-ref",
            &token_ref,
            "--expect",
            &current,
            "--generation",
            "1",
            "created-policy",
        ]);
        assert_eq!(stale_policy_delete.status.code(), Some(4));
        let policy_delete = run(&[
            "access-policy",
            "delete",
            "--socket",
            socket,
            "--token-ref",
            &token_ref,
            "--expect",
            &current,
            "--generation",
            "2",
            "created-policy",
        ]);
        assert!(policy_delete.status.success(), "{:?}", policy_delete.stderr);
        let policy_delete_json: serde_json::Value =
            serde_json::from_slice(&policy_delete.stdout).expect("Access Policy delete JSON");
        assert_eq!(policy_delete_json["generation"], 2);
        assert_eq!(policy_delete_json["object"], updated_policy);
        assert_eq!(
            run(&["access-policy", "get", "--socket", socket, "created-policy"])
                .status
                .code(),
            Some(6)
        );
        assert_eq!(active_revision(&state), current);
        assert_eq!(
            fs::read_dir(state.join("config/revisions"))
                .expect("revision directory")
                .count(),
            policy_revisions_before
        );
        let policy_store_after_failures: serde_json::Value = serde_json::from_slice(
            &fs::read(&access_policy_store_path).expect("Access Policy store after failures"),
        )
        .expect("Access Policy store JSON after failures");
        let policy_records = policy_store_after_failures["policies"]
            .as_array()
            .expect("Access Policy records");
        assert_eq!(policy_records.len(), 3);
        assert!(policy_records.iter().all(|record| {
            !matches!(
                record["object"]["metadata"]["id"].as_str(),
                Some("created-policy" | "missing-middleware" | "wrong-owner-policy")
            )
        }));
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
        let scoped_policy_list = run(&[
            "access-policy",
            "list",
            "--socket",
            socket,
            "--token-ref",
            &token_ref,
        ]);
        assert!(
            scoped_policy_list.status.success(),
            "{:?}",
            scoped_policy_list.stderr
        );
        let scoped_policy_get = run(&[
            "access-policy",
            "get",
            "--socket",
            socket,
            "--token-ref",
            &token_ref,
            "private-lan",
        ]);
        assert!(
            scoped_policy_get.status.success(),
            "{:?}",
            scoped_policy_get.stderr
        );
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
        let enabled_z_policy = serde_json::json!({
            "api_version": "v1",
            "metadata": {"id": "z-policy", "owner_id": owner},
            "spec": {
                "enabled": true,
                "shared_with": [],
                "middlewares": ["edge-ip"]
            }
        });
        let enabled_z_policy_path = daemon.root.join("enabled-z-policy.json");
        fs::write(
            &enabled_z_policy_path,
            serde_json::to_vec_pretty(&enabled_z_policy).expect("enabled policy JSON"),
        )
        .expect("enabled policy file");
        let enable_z_policy = Command::new(binary())
            .args([
                "access-policy",
                "update",
                "--socket",
                socket,
                "--expect",
                &current,
                "--generation",
                "1",
                "z-policy",
            ])
            .arg(&enabled_z_policy_path)
            .output()
            .expect("enable z policy");
        assert!(
            enable_z_policy.status.success(),
            "{:?}",
            enable_z_policy.stderr
        );
        let temporary_proxy = serde_json::json!({
            "api_version": "v1",
            "metadata": {"id": "policy-drift", "owner_id": owner},
            "spec": {
                "domain": "policy-drift.example.test",
                "forward_host": "127.0.0.1",
                "forward_port": 9001,
                "forward_protocol": "http",
                "automatic_https": "disabled",
                "access_policy_ref": "z-policy",
                "enabled": false
            }
        });
        let temporary_proxy_path = daemon.root.join("policy-drift-proxy.json");
        fs::write(
            &temporary_proxy_path,
            serde_json::to_vec_pretty(&temporary_proxy).expect("temporary Proxy Host JSON"),
        )
        .expect("temporary Proxy Host file");
        let temporary_create = Command::new(binary())
            .args([
                "proxy-host",
                "create",
                "--socket",
                socket,
                "--expect",
                &current,
            ])
            .arg(&temporary_proxy_path)
            .output()
            .expect("temporary Proxy Host create");
        assert!(
            temporary_create.status.success(),
            "{:?}",
            temporary_create.stderr
        );
        let temporary_create: serde_json::Value =
            serde_json::from_slice(&temporary_create.stdout).expect("temporary create JSON");
        let stale_policy_candidate = temporary_create["candidate"]["id"]
            .as_str()
            .expect("temporary candidate ID");
        let mut advanced_z_policy = enabled_z_policy.clone();
        advanced_z_policy["spec"]["shared_with"] = serde_json::json!(["other"]);
        fs::write(
            &enabled_z_policy_path,
            serde_json::to_vec_pretty(&advanced_z_policy).expect("advanced policy JSON"),
        )
        .expect("advanced policy file");
        let advance_z_policy = Command::new(binary())
            .args([
                "access-policy",
                "update",
                "--socket",
                socket,
                "--expect",
                &current,
                "--generation",
                "2",
                "z-policy",
            ])
            .arg(&enabled_z_policy_path)
            .output()
            .expect("advance z policy generation");
        assert!(
            advance_z_policy.status.success(),
            "{:?}",
            advance_z_policy.stderr
        );
        let stale_policy_activation = run(&[
            "proxy-host",
            "activate",
            "--socket",
            socket,
            "--expect",
            &current,
            stale_policy_candidate,
        ]);
        assert_eq!(stale_policy_activation.status.code(), Some(4));
        assert_eq!(active_revision(&state), current);
        let temporary_delete = run(&[
            "proxy-host",
            "delete",
            "--socket",
            socket,
            "--expect",
            &current,
            "--generation",
            "1",
            "policy-drift",
        ]);
        assert!(
            temporary_delete.status.success(),
            "{:?}",
            temporary_delete.stderr
        );
        assert_eq!(active_revision(&state), current);
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
        let candidate_metadata: serde_json::Value = serde_json::from_slice(
            &fs::read(
                state
                    .join("config/metadata")
                    .join(format!("{candidate_id}.json")),
            )
            .expect("candidate metadata"),
        )
        .expect("candidate metadata JSON");
        let binding_hash = candidate_metadata["binding_hash"]
            .as_str()
            .expect("typed binding hash");
        assert_eq!(binding_hash.len(), 64);
        let candidate_binding: serde_json::Value = serde_json::from_slice(
            &fs::read(
                state
                    .join("admin/proxy-host-candidates")
                    .join(format!("{candidate_id}.json")),
            )
            .expect("candidate binding"),
        )
        .expect("candidate binding JSON");
        assert_eq!(candidate_binding["revision_id"], candidate_id);
        assert_eq!(candidate_binding["binding_hash"], binding_hash);
        assert_eq!(
            candidate_binding["objects"].as_array().map(Vec::len),
            Some(3)
        );
        assert_eq!(
            candidate_binding["access_policies"]
                .as_array()
                .map(Vec::len),
            Some(1)
        );
        assert_eq!(
            candidate_binding["access_policies"][0]["object"]["metadata"]["id"],
            "private-lan"
        );
        assert_eq!(candidate_binding["access_policies"][0]["generation"], 2);
        assert_eq!(active_revision(&state), current);
        for path in [
            format!("/v1/config/candidates/{candidate_id}/activate"),
            format!("/v1/config/revisions/{candidate_id}/rollback"),
        ] {
            let bypass = raw_post(socket, &path, &current);
            assert!(bypass.starts_with("HTTP/1.1 409 "), "{bypass}");
            assert_eq!(active_revision(&state), current);
        }
        let created_list = run(&["proxy-host", "list", "--socket", socket]);
        assert!(created_list.status.success(), "{:?}", created_list.stderr);
        let created_list_json: serde_json::Value =
            serde_json::from_slice(&created_list.stdout).expect("created list JSON");
        assert_eq!(created_list_json.as_array().map(Vec::len), Some(2));
        let mut updated_proxy_host = proxy_host.clone();
        updated_proxy_host["spec"]["domain"] = serde_json::json!("updated.example.test");
        let updated_proxy_host_path = daemon.root.join("updated-proxy-host.json");
        fs::write(
            &updated_proxy_host_path,
            serde_json::to_vec_pretty(&updated_proxy_host).expect("updated Proxy Host JSON"),
        )
        .expect("updated Proxy Host file");
        let revisions_after_create = fs::read_dir(state.join("config/revisions"))
            .expect("revision directory")
            .count();
        for operation in ["update", "delete"] {
            let mut command = Command::new(binary());
            command.args([
                "proxy-host",
                operation,
                "--socket",
                socket,
                "--token-ref",
                &token_ref,
                "--expect",
                &current,
                "--generation",
                "1",
                "proxy-cli",
            ]);
            if operation == "update" {
                command.arg(&updated_proxy_host_path);
            }
            let denied = command.output().expect("denied Proxy Host mutation");
            assert_eq!(denied.status.code(), Some(5));
        }
        assert_eq!(
            fs::read_dir(state.join("config/revisions"))
                .expect("revision directory")
                .count(),
            revisions_after_create
        );
        let stale_update = Command::new(binary())
            .args([
                "proxy-host",
                "update",
                "--socket",
                socket,
                "--expect",
                &current,
                "--generation",
                "2",
                "proxy-cli",
            ])
            .arg(&updated_proxy_host_path)
            .output()
            .expect("stale Proxy Host update");
        assert_eq!(stale_update.status.code(), Some(4));
        let denied_owner_update = Command::new(binary())
            .args([
                "proxy-host",
                "update",
                "--socket",
                socket,
                "--expect",
                &current,
                "--generation",
                "1",
                "proxy-cli",
            ])
            .arg(&cross_owner_path)
            .output()
            .expect("cross-owner Proxy Host update");
        assert_eq!(denied_owner_update.status.code(), Some(5));
        assert_eq!(
            fs::read_dir(state.join("config/revisions"))
                .expect("revision directory")
                .count(),
            revisions_after_create
        );
        let update = Command::new(binary())
            .args([
                "proxy-host",
                "update",
                "--socket",
                socket,
                "--expect",
                &current,
                "--generation",
                "1",
                "proxy-cli",
            ])
            .arg(&updated_proxy_host_path)
            .output()
            .expect("Proxy Host update");
        assert!(update.status.success(), "{:?}", update.stderr);
        let update_json: serde_json::Value =
            serde_json::from_slice(&update.stdout).expect("Proxy Host update JSON");
        assert_eq!(update_json["object"]["generation"], 2);
        assert_eq!(update_json["object"]["object"], updated_proxy_host);
        assert_eq!(active_revision(&state), current);
        let updated_candidate_id = update_json["candidate"]["id"]
            .as_str()
            .expect("updated candidate ID");
        let updated_binding_path = state
            .join("admin/proxy-host-candidates")
            .join(format!("{updated_candidate_id}.json"));
        let updated_binding_bytes = fs::read(&updated_binding_path).expect("updated binding bytes");
        let updated_binding: serde_json::Value =
            serde_json::from_slice(&updated_binding_bytes).expect("updated candidate binding JSON");
        assert!(
            updated_binding["objects"]
                .as_array()
                .is_some_and(|objects| {
                    objects
                        .iter()
                        .any(|object| object["spec"]["domain"] == "updated.example.test")
                })
        );
        let stale_candidate = run(&[
            "proxy-host",
            "activate",
            "--socket",
            socket,
            "--expect",
            &current,
            candidate_id,
        ]);
        assert_eq!(stale_candidate.status.code(), Some(4));
        assert_eq!(active_revision(&state), current);
        let mut tampered_binding = updated_binding.clone();
        tampered_binding["binding_hash"] = serde_json::json!("00".repeat(32));
        fs::write(
            &updated_binding_path,
            serde_json::to_vec(&tampered_binding).expect("tampered binding JSON"),
        )
        .expect("tamper binding");
        let tampered_activation = run(&[
            "proxy-host",
            "activate",
            "--socket",
            socket,
            "--expect",
            &current,
            updated_candidate_id,
        ]);
        assert_eq!(tampered_activation.status.code(), Some(6));
        assert_eq!(active_revision(&state), current);
        fs::write(&updated_binding_path, &updated_binding_bytes).expect("restore binding");
        let denied_activation = Command::new(binary())
            .args([
                "proxy-host",
                "activate",
                "--socket",
                socket,
                "--token-ref",
                &token_ref,
                "--expect",
                &current,
                updated_candidate_id,
            ])
            .output()
            .expect("denied typed activation");
        assert_eq!(denied_activation.status.code(), Some(5));
        let activation = run(&[
            "proxy-host",
            "activate",
            "--socket",
            socket,
            "--expect",
            &current,
            updated_candidate_id,
        ]);
        assert!(activation.status.success(), "{:?}", activation.stderr);
        current = active_revision(&state);
        assert_eq!(current, updated_candidate_id);
        let active_config = aegisproxy_config::load_bytes(
            &fs::read(
                state
                    .join("config/revisions")
                    .join(format!("{updated_candidate_id}.toml")),
            )
            .expect("active revision"),
        )
        .expect("active revision config");
        let active_route = active_config
            .routes
            .iter()
            .find(|route| route.hosts == ["updated.example.test"])
            .expect("activated Proxy Host route");
        assert_eq!(active_route.middlewares, ["edge-ip"]);
        let repeated_activation = run(&[
            "proxy-host",
            "activate",
            "--socket",
            socket,
            "--expect",
            &current,
            updated_candidate_id,
        ]);
        assert_eq!(repeated_activation.status.code(), Some(4));
        assert_eq!(active_revision(&state), current);
        let unbound_revision = fs::read_dir(state.join("config/metadata"))
            .expect("metadata directory")
            .filter_map(Result::ok)
            .filter_map(|entry| fs::read(entry.path()).ok())
            .filter_map(|bytes| serde_json::from_slice::<serde_json::Value>(&bytes).ok())
            .find(|metadata| metadata["binding_hash"].is_null() && metadata["id"] != current)
            .and_then(|metadata| metadata["id"].as_str().map(str::to_owned))
            .expect("unbound revision");
        let unbound_rollback = run(&[
            "proxy-host",
            "rollback",
            "--socket",
            socket,
            "--expect",
            &current,
            &unbound_revision,
        ]);
        assert_eq!(unbound_rollback.status.code(), Some(4));
        assert_eq!(active_revision(&state), current);
        let denied_rollback = Command::new(binary())
            .args([
                "proxy-host",
                "rollback",
                "--socket",
                socket,
                "--token-ref",
                &token_ref,
                "--expect",
                &current,
                candidate_id,
            ])
            .output()
            .expect("denied typed rollback");
        assert_eq!(denied_rollback.status.code(), Some(5));
        let rollback = run(&[
            "proxy-host",
            "rollback",
            "--socket",
            socket,
            "--expect",
            &current,
            candidate_id,
        ]);
        assert!(rollback.status.success(), "{:?}", rollback.stderr);
        current = active_revision(&state);
        assert_ne!(current, candidate_id);
        assert_ne!(current, updated_candidate_id);
        let rolled_back = run(&["proxy-host", "get", "--socket", socket, "proxy-cli"]);
        assert!(rolled_back.status.success(), "{:?}", rolled_back.stderr);
        let rolled_back_json: serde_json::Value =
            serde_json::from_slice(&rolled_back.stdout).expect("rolled back Proxy Host JSON");
        assert_eq!(rolled_back_json["generation"], 3);
        assert_eq!(
            rolled_back_json["object"]["spec"]["domain"],
            "typed.example.test"
        );
        let stale_delete = run(&[
            "proxy-host",
            "delete",
            "--socket",
            socket,
            "--expect",
            &current,
            "--generation",
            "1",
            "proxy-cli",
        ]);
        assert_eq!(stale_delete.status.code(), Some(4));
        let delete = run(&[
            "proxy-host",
            "delete",
            "--socket",
            socket,
            "--expect",
            &current,
            "--generation",
            "3",
            "proxy-cli",
        ]);
        assert!(delete.status.success(), "{:?}", delete.stderr);
        let delete_json: serde_json::Value =
            serde_json::from_slice(&delete.stdout).expect("Proxy Host delete JSON");
        assert_eq!(delete_json["deleted"]["generation"], 3);
        assert_eq!(active_revision(&state), current);
        let deleted_list = run(&["proxy-host", "list", "--socket", socket]);
        assert!(deleted_list.status.success(), "{:?}", deleted_list.stderr);
        let deleted_list_json: serde_json::Value =
            serde_json::from_slice(&deleted_list.stdout).expect("deleted list JSON");
        assert_eq!(deleted_list_json.as_array().map(Vec::len), Some(1));
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
        assert_eq!(denied.status.code(), Some(5), "{:?}", denied.stderr);

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
        assert!(audit.contains("\"action\":\"proxy_host_create\""));
        assert!(audit.contains("\"action\":\"proxy_host_update\""));
        assert!(audit.contains("\"action\":\"proxy_host_delete\""));
        assert!(audit.contains("\"action\":\"typed_candidate_activate\""));
        assert!(audit.contains("\"action\":\"typed_revision_rollback\""));
        assert!(audit.contains("\"action\":\"access_policy_create\""));
        assert!(audit.contains("\"action\":\"access_policy_update\""));
        assert!(audit.contains("\"action\":\"access_policy_delete\""));
        let audit_records = audit
            .lines()
            .map(|line| serde_json::from_str::<serde_json::Value>(line).expect("audit JSON"))
            .collect::<Vec<_>>();
        for action in ["access_policy_update", "access_policy_delete"] {
            let outcomes = audit_records
                .iter()
                .filter(|record| record["action"] == action)
                .filter_map(|record| record["outcome"].as_str())
                .collect::<Vec<_>>();
            for outcome in ["intent", "success", "failed", "denied"] {
                assert!(
                    outcomes.contains(&outcome),
                    "missing {action} {outcome} audit"
                );
            }
        }
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
