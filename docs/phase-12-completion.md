# Phase 12: High availability and fleet operation

## 1. Phase title

Externally load-balanced independent nodes, exact fleet drift detection, load-balancer drain integration, and single-owner certificate renewal.

## 2. Original objectives

- Support independent nodes behind an external L4 load balancer.
- Distribute and verify one content-addressed declarative revision.
- Export node identity, revision, generation, readiness, and ownership state.
- Provide safe canary/rolling rollout, drain, rollback, and recovery procedures.
- Prevent duplicate ACME renewal ownership without shared mutable storage.
- Verify HA failure behavior through local tests and define the required production-topology drill.

## 3. Implemented scope

- Accepted ADR 0023 now defines the external-LB model, bootstrap node identity, exact content hash, external monotonic generation, private local administration, one-way audited drain, one named ACME owner, off-host audit attribution, and rejected consensus/shared-state alternatives.
- `rust-proxy run` accepts validated `--node-id` and `--fleet-generation` bootstrap values. They remain outside TOML so byte-identical fleet configuration has one canonical hash.
- Authenticated `/v1/status` exports node ID, fleet generation, active revision and SHA-256 hash, live administrative/audit readiness, drain state, managed-certificate count, and certificate-owner state.
- `rust-proxy fleet hash` calculates the exact canonical hash used by durable revisions without persistence.
- `rust-proxy fleet status` exports authenticated private status JSON.
- Bounded `rust-proxy fleet check` verifies an explicit inventory of at most 256 nodes and reads at most 16 KiB per status file. It rejects missing/unexpected/duplicate nodes, invalid identities, generation mismatch, revision/hash mismatch, unready/audit-failed/draining nodes, managed-certificate policy drift, and zero/multiple ACME owners.
- Audited `POST /v1/node/drain` and `rust-proxy drain` make readiness return 503 `draining`. Data listeners remain available during external-LB convergence; normal supervisor cancellation retains existing stop-accepting and bounded request/connection drain behavior.
- Optional strict TOML `acme.renewal_owner` names the only node allowed to reconcile or request managed renewals. Fleet startup with managed ACME, a nonzero generation, and no owner fails before revision persistence or listener preparation.
- Audit schema v2 adds HMAC-covered node identity. Schema-v1 chains reopen and continue with v2; legacy records receive `standalone` attribution.
- Status now reports the live audit-writer readiness flag, not merely presence of audit configuration.
- ACME and TLS fields missing from the companion JSON Schema were added, including `renewal_owner` and bounded encryption recipients. Runtime TOML validation remains authoritative.
- Hardened systemd fleet template and generation environment example were added.
- HA runbook documents source-address policy, authenticated artifact transport, exact canary/rolling rollout, drain/restart, monotonic rollback, stopped-owner certificate transfer, encrypted generation distribution, controller/node/partition/audit faults, and compromise response.

## 4. Deferred scope

- Embedded consensus, clustering protocol, distributed database, shared writable state, and global rate limiting remain deferred.
- Remote fleet controller, public/TCP administration, mTLS control plane, and built-in asymmetric snapshot distribution remain deferred. Any such split plane requires a new ADR and security review.
- PROXY protocol remains unsupported until trusted-peer policy, parsing, integration tests, and fuzzing are implemented.
- Automated certificate-bundle transport is operator infrastructure. Repository code enforces one writer and validates encrypted generations; the runbook defines stopped-replica distribution.
- Production load-balancer, SIEM, certificate-distributor, and host-orchestrator integration cannot be created or exercised in this local repository.

## 5. Architecture decisions

- ADR 0023: independent content-hash nodes behind an external L4 load balancer.
- Node identity/generation are bootstrap values, not declarative configuration, preventing node-local false drift.
- Control remains Unix-socket-only; remote authenticated transport is external.
- Drain is one-way until restart and changes readiness before supervisor shutdown.
- ACME uses exactly one named renewal owner and no shared writable storage.
- Fleet correctness is a complete-inventory exact-hash gate, not quorum interpretation.
- Audit sequences remain node-local; off-host correlation uses node ID plus sequence.

## 6. Files created

- `crates/rust-proxy/src/fleet.rs`
- `crates/rust-proxy/tests/ha_chaos.rs`
- `deploy/ha/aegisproxy@.service`
- `deploy/ha/fleet.env.example`
- `docs/operations/high-availability.md`
- `docs/phase-12-completion.md`

## 7. Files modified

- `README.md`
- `config/schema-v1.json`
- `config/schema/admin-openapi.yaml`
- `crates/proxy-admin/src/audit.rs`
- `crates/proxy-admin/src/server.rs`
- `crates/proxy-config/src/lib.rs`
- `crates/proxy-config/src/redact.rs`
- `crates/proxy-config/src/revision.rs`
- `crates/proxy-core/src/acme_manager.rs`
- `crates/proxy-core/src/lib.rs`
- `crates/proxy-core/src/runtime.rs`
- `crates/rust-proxy/src/main.rs`
- `crates/rust-proxy/tests/admin_cli.rs`
- `docs/adr/0023-high-availability.md`
- `docs/configuration-v1.md`
- `docs/operations/acme.md`
- `docs/operations/admin.md`
- `docs/operations/siem.md`

## 8. Dependencies added

None. Existing standard library, Serde, SHA-256 revision code, Tokio runtime state, and private admin client were reused. `Cargo.toml`, `Cargo.lock`, and `docs/dependencies.md` did not change.

## 9. Configuration introduced

- Optional `[acme].renewal_owner = "node-id"`.
- Process arguments `--node-id` and `--fleet-generation`; these intentionally are not TOML fields.
- systemd `AEGISPROXY_FLEET_GENERATION` deployment environment value.
- New private admin route `POST /v1/node/drain`, requiring authorization, durable audit intent, and exact `If-Match`.

Existing single-node configuration remains compatible: default identity is `standalone`, generation is zero, and omitted renewal owner preserves local single-owner behavior.

## 10. Tests added

- Strict ACME renewal-owner ID validation.
- Node identity bounds and character policy.
- Owner/replica renewal-role selection.
- Fleet ACME missing-owner failure before persistence/preparation.
- One-way drain and exact revision-hash extraction.
- Live audit-readiness state.
- Audit schema-v1 reopen followed by node-attributed schema-v2 append.
- Real-daemon authenticated node status, exact fleet check, audited drain, readiness failure, and node-attributed audit record.
- Fleet checker success for exact complete inventory and one owner.
- HA fault gate for missing node/controller evidence, stale generation/rollback, divergent hash, duplicate owner, draining node, and audit outage.
- Canonical offline hash equality with durable candidate metadata.

Existing tests continue to cover local last-known-good startup, controller-independent serving, failed reload isolation, crash recovery, listener/request drain, atomic activation/rollback, ACME single-flight locks, invalid certificate rejection, encrypted state, audit failure, and backup tamper detection.

## 11. Commands executed

Focused commands included:

```text
RUSTUP_TOOLCHAIN=stable cargo test -p aegisproxy-config
RUSTUP_TOOLCHAIN=stable cargo test -p aegisproxy-core runtime::tests
RUSTUP_TOOLCHAIN=stable cargo test -p aegisproxy-admin
RUSTUP_TOOLCHAIN=stable cargo test -p rust-proxy --test admin_cli --test ha_chaos
RUSTUP_TOOLCHAIN=stable cargo clippy -p aegisproxy-core -p aegisproxy-admin -p rust-proxy --all-targets --all-features -- -D warnings
python3 -c '... Draft202012Validator.check_schema(...)'
RUSTUP_TOOLCHAIN=stable cargo run -q -p rust-proxy -- validate --config config/examples/minimal.toml
RUSTUP_TOOLCHAIN=stable cargo run -q -p rust-proxy -- fleet hash --config config/examples/minimal.toml
systemd-analyze verify deploy/ha/aegisproxy@.service
```

Final workspace gates:

```text
RUSTUP_TOOLCHAIN=stable cargo fmt --all -- --check
RUSTUP_TOOLCHAIN=stable cargo check --workspace --all-targets
RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --all-targets --all-features -- -D warnings
RUSTUP_TOOLCHAIN=stable cargo test --workspace --all-features
RUSTUP_TOOLCHAIN=stable cargo tree -e features
cargo audit
cargo deny check
cargo fuzz --help
gitleaks version
```

## 12. Actual command results

- Formatting: passed.
- Workspace all-target check: passed.
- Workspace all-target/all-feature Clippy with warnings denied: passed.
- Workspace all-feature tests: 266 passed, 0 failed, 2 intentionally ignored.
  - Manual release reload benchmark remains ignored by default.
  - Pebble integration remains ignored unless its disposable Compose fixture is started.
- Dependency feature tree: passed.
- Draft 2020-12 schema meta-validation: passed.
- Minimal TOML validation: passed.
- Canonical hash command: passed and returned one 64-character lowercase SHA-256 value.
- `cargo audit`: unavailable (`cargo: no such command: audit`).
- `cargo deny check`: unavailable (`cargo: no such command: deny`).
- `cargo fuzz`: unavailable (`cargo: no such command: fuzz`).
- `gitleaks`: unavailable (`command not found`).
- `jq` and `shellcheck`: unavailable. JSON parsing used Node; meta-schema checking used installed Python `jsonschema`.
- `systemd-analyze verify`: parsed the template, then exited 1 because `/usr/local/bin/rust-proxy` is not installed in this development host. No unit syntax error was reported. This is not claimed as a passed deployment check.
- Existing `proc-macro-error2 v2.0.1` future-incompatibility warning remains emitted by Cargo. It is transitive and did not become a denied compiler/Clippy warning.

## 13. Security checks

- No public administration listener or fleet control port was added.
- Node IDs are bounded and restricted before runtime use.
- Status contains stable IDs/hashes and redacted operational state; no configuration or secret value is returned.
- Fleet status input is strict JSON, bounded by file and fleet count, and tied to an explicit expected inventory.
- Configuration hashes use the same validated canonical bytes as durable revisions.
- Drain requires RBAC, exact CAS, and durable audit intent.
- Replica renewal requests fail closed; replica reconciliation clears local retry bookkeeping and performs no ACME work.
- Managed-ACME HA startup without a named owner fails before durable state mutation.
- Audit node identity is HMAC-covered; legacy verification remains exact.
- Live audit failure is visible to fleet status and blocks rollout completion.
- No plaintext certificate key, ACME credential, API token, or audit key was added.
- No unsafe Rust, shared writable certificate path, arbitrary plugin, shell execution, UDP, HTTP/3, or database was introduced.

Two defects found during implementation were fixed before completion:

1. Fleet owner validation initially occurred after revision persistence and listener binding. It now occurs before both normal and last-known-good preparation.
2. Status initially reported audit configuration presence rather than the live failure flag. It now exports the atomic runtime audit readiness state.

No critical or high-severity unresolved security finding was identified by available local checks. Dependency advisory and dedicated secret-scan tools were unavailable, so this is not a vulnerability-free claim.

## 14. Performance checks

No performance claim or new benchmark result was produced. Fleet checking is deliberately bounded to 256 files and 16 KiB each. Node status uses existing private administration budgets. Existing manual reload benchmark remains ignored by the normal suite. Real LB failover latency, drain time, and capacity require the production-topology drill.

## 15. Known limitations

- PROXY protocol is unsupported; the L4 load balancer must preserve source addresses directly.
- Fleet generation monotonicity is an external rollout invariant. The daemon reports it; the full-inventory gate checks equality but does not maintain a distributed history.
- Status authenticity depends on the private Unix API and authenticated host transport used to collect each file. The checker does not authenticate arbitrary JSON by itself.
- Drain changes readiness but intentionally leaves data acceptance active until supervisor cancellation. Correctness during that interval depends on the documented external-LB policy.
- Certificate distribution between local state directories is external, stopped-replica automation. There is no built-in remote certificate controller.
- Node-local health, circuit, rate-limit, DNS, pool, audit sequence, and revision sequence state are not globally consistent.
- A named renewal owner is an operational dependency; working certificates remain but failover must complete before expiry margin is exhausted.
- The systemd template was not verified against an installed release binary on the target host.

## 16. Residual risks

- Incorrect load-balancer drain/health behavior can admit direct work after node readiness changes.
- Operator inventory omission can weaken fleet evidence; rollout tooling must source inventory from an independently controlled system.
- A compromised host can forge its local status after taking its administrative/audit credentials; off-host artifact, audit, and transport verification remain necessary.
- Direct owner changes during mixed rollout can create overlapping ACME ownership. The stopped-owner transfer procedure is mandatory.
- Manual or faulty certificate distribution can leave replicas on an older valid generation. Expiry and generation monitoring must detect drift.
- Real network partitions, LB propagation, host crashes, certificate distribution, and SIEM outages can differ from local simulations.
- Missing audit/deny/fuzz/secret-scan tooling leaves assurance gaps.

## 17. Acceptance-criteria checklist

- [x] Independent nodes require no controller to continue serving their local active/LKG state; existing managed-runtime and LKG tests pass.
- [x] Exact canonical revision hash is exported and every supplied divergent hash fails the complete-inventory fleet gate.
- [x] Missing, duplicate, unexpected, stale-generation, unready, draining, and audit-failed node evidence fails closed.
- [x] One named ACME node performs renewal; replicas neither reconcile orders nor accept renewal mutations.
- [x] Full-inventory verification requires exactly one owner when managed certificates exist and rejects duplicates.
- [x] Drain becomes unready before normal existing graceful process drain/restart behavior.
- [x] Audit records identify nodes and retain legacy chain compatibility.
- [x] Canary, rolling rollout, rollback, node loss, partition, controller outage, certificate ownership, distribution, and compromise procedures are documented.
- [ ] Actual external-LB accepted-request/error-budget behavior was not exercised; no production topology was authorized or available.
- [ ] Real certificate distribution and owner-failover drill was not exercised against production-equivalent storage/orchestration.

## 18. Exit-criteria checklist

- [x] Local HA fault and drift suite passes.
- [x] Existing node-local crash, LKG, rollback, drain, certificate, audit, and backup controls pass.
- [x] Deployment/runbook artifacts exist and are internally consistent with implemented CLI/API behavior.
- [x] Full Rust quality gates pass.
- [ ] Production-topology chaos/recovery drill remains a release gate.
- [ ] Independent security and protocol interoperability review remains required.

Phase 12 repository implementation is complete. The unchecked external criteria prevent a production-readiness claim but do not require adding a built-in cluster or accessing production systems.

## 19. Commit list

- `038c064` — `docs(adr): define external-lb ha model`
- `3ff4db2` — `feat(config): name acme renewal owner`
- `40c8938` — `feat(ha): enforce node certificate ownership`
- `ef629af` — `feat(ha): expose status and audited drain`
- `5856413` — `feat(audit): attribute records to fleet nodes`
- `6d31d16` — `feat(ha): verify exact fleet rollout state`
- `3bda44c` — `feat(config): print canonical fleet hash`
- `e51ede5` — `fix(ha): validate ownership before persistence`
- `1310b85` — `fix(ha): export live audit readiness`
- `2989a80` — `docs(ha): add fleet rollout and recovery runbook`

This completion report is committed separately after the list above.

## 20. Readiness for the next phase

Repository may proceed to Phase 13 only when requested. Phase 12 leaves one-process/one-binary nodes, strict TOML, local LKG, private administration, and no shared cluster state intact. Phase 13 must not infer production readiness from local HA tests and must carry forward the external topology drill, unavailable security tools, PROXY-protocol deferral, transitive future-incompatibility warning, and independent review requirements.
