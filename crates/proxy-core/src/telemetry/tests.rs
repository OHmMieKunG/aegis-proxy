use super::*;

#[test]
fn labels_are_bounded_and_raw_values_never_create_series() {
    let config = toml::from_str(
        r#"
            schema_version = 1
            [[listeners]]
            id = "public"
            bind = "127.0.0.1:8080"
            protocol = "http"
            [[routes]]
            id = "app"
            listeners = ["public"]
            hosts = ["example.test"]
            upstream_group = "app"
            [[upstream_groups]]
            id = "app"
            allowed_cidrs = ["127.0.0.1/32"]
            [[upstream_groups.endpoints]]
            id = "app-1"
            url = "http://127.0.0.1:9000"
            [[providers]]
            kind = "file"
            id = "nodes"
            upstream_group = "app"
            path = "/run/aegisproxy/nodes.toml"
            scheme = "http"
            [[certificates]]
            id = "edge-cert"
            hosts = ["example.test"]
            certificate_chain = "file:///run/aegis/cert.pem"
            private_key = "file:///run/aegis/key.age"
            "#,
    )
    .expect("config");
    let telemetry = Telemetry::new(&config);
    telemetry.request_finished(RequestMetric {
        listener: "public",
        route: "app",
        protocol: "http1",
        status: 200,
        response_bytes: 12,
        duration: Duration::from_millis(5),
    });
    telemetry.request_finished(RequestMetric {
        listener: "attacker.example",
        route: "/raw/path?secret=canary",
        protocol: "attacker-controlled",
        status: 777,
        response_bytes: 1,
        duration: Duration::ZERO,
    });
    telemetry.update_certificate_expiry("edge-cert", 2_000_000_000);
    telemetry.update_certificate_expiry("attacker-cert", 2_000_000_001);
    telemetry.certificate_renewal("edge-cert", "requested");
    telemetry.audit_ready(true);
    telemetry.audit_operation("success");
    telemetry.update_provider(&crate::ProviderStatus {
        id: "nodes".into(),
        kind: "file",
        state: "fresh",
        source_hash: Some("0".repeat(64)),
        last_success_unix_secs: Some(1_700_000_000),
        stale_at_unix_secs: Some(1_700_000_300),
        endpoint_count: 2,
        error: None,
    });
    telemetry.update_provider(&crate::ProviderStatus {
        id: "attacker".into(),
        kind: "file",
        state: "fresh",
        source_hash: None,
        last_success_unix_secs: None,
        stale_at_unix_secs: None,
        endpoint_count: 1,
        error: None,
    });
    telemetry.update_upstream_state("app", "app-1", 2, true);
    telemetry.upstream_retry("app", "app-1");
    telemetry.reload("success", Duration::from_millis(10));
    let output = telemetry.render().expect("metrics");
    assert!(output.contains("listener=\"public\""));
    assert!(output.contains("route=\"app\""));
    assert!(!output.contains("attacker.example"));
    assert!(!output.contains("raw/path"));
    assert!(!output.contains("canary"));
    assert!(output.contains("certificate=\"edge-cert\""));
    assert!(output.contains("issuer=\"manual\""));
    assert!(output.contains("aegisproxy_admin_audit_ready 1"));
    assert!(output.contains("aegisproxy_upstream_healthy"));
    assert!(output.contains("endpoint=\"app-1\""));
    assert!(output.contains("aegisproxy_upstream_retries_total"));
    assert!(!output.contains("attacker-cert"));
    assert!(output.contains("aegisproxy_provider_fresh{provider=\"nodes\"} 1"));
    assert!(output.contains("aegisproxy_provider_endpoints{provider=\"nodes\"} 2"));
    assert!(!output.contains("provider=\"attacker\""));

    let guard = telemetry
        .request_started("public", "app", "http1")
        .expect("active request metric");
    let mut replacement = config.clone();
    replacement.routes[0].id = "replacement".into();
    telemetry.reconcile(&replacement);
    assert!(
        telemetry
            .render()
            .expect("metrics")
            .contains("route=\"app\"")
    );
    drop(guard);
    assert!(
        !telemetry
            .render()
            .expect("metrics")
            .contains("route=\"app\"")
    );
}
