# Phase 11 completion: bounded service discovery

> Historical document — records phase evidence at completion time. See [`STATUS.md`](../../../STATUS.md) for current verification.

Date: 2026-07-19

## 1. Phase title

Phase 11: Service discovery.

## 2. Original objectives

Add file and DNS dynamic providers first, with provider coordination/status,
strict namespace/conflict rules, fixtures, default-deny exposure, bounded
debounce/stale behavior, destination validation, and safe Phase 5 activation.
Evaluate an isolated Docker metadata helper only after explicit approval and
leave Kubernetes Gateway API/Consul for later decisions.

## 3. Implemented scope

- Added recursively strict typed `file` and `dns` provider schema to config v1.
- Providers default disabled and may own exactly one predeclared upstream group;
  duplicate IDs and group ownership fail validation.
- Static group endpoints are mandatory startup and post-stale fallback.
- File documents are capped at 1 MiB and contain only version, matching provider
  ID, literal socket addresses, endpoint IDs, and weights.
- File loading rejects symlinks/non-files, rechecks opened device/inode on Unix,
  caps read bytes, and requires one stable hash through configured debounce.
- DNS provider fixes A/AAAA hostname, port, transport/TLS template, weight,
  answer bound, refresh, and stale policy in trusted base configuration.
- Normalized endpoints pass complete existing config/egress validation before
  entering immutable revision creation and Phase 5 CAS/prepare/atomic
  publication/probation/drain activation.
- Failed/invalid sources retain last valid provider endpoints until hard stale
  deadline, then activate static fallback. Recovery needs a new stable valid
  result.
- Added private `GET /v1/providers`, using upstream-read RBAC, with only ID,
  kind, bounded state/error, SHA-256 source hash, timestamps, and endpoint count.
- Added four bounded OpenMetrics gauges per configured provider and included
  them in cardinality estimation/reconciliation.
- Added file/DNS fixtures, operator guide, and repository-maintainer threat
  review.

## 4. Deferred scope

- Docker discovery/helper/spike: no approval exists, so no helper, client,
  socket access, feature, crate, or binary was added.
- Kubernetes Gateway API implementation and its separate ADR.
- Consul, SRV, registry plugins, label-driven policy, arbitrary metadata, and
  runtime extension mechanisms.
- Independent provider security review and environment-specific long-duration
  failure soak remain release evidence, not local implementation.

## 5. Architecture decisions

- ADR-0017 now selects provider-normalized desired state: untrusted records can
  replace endpoints only; trusted base config owns every policy field.
- One provider per upstream-group namespace removes merge-order ambiguity.
- Polling reuses current Tokio/Hyper/Hickory/Phase 5 facilities; no dependency
  or event-watcher abstraction was added.
- Static endpoints provide deterministic fail-closed fallback after stale
  provider output.
- Provider status and metrics expose configured IDs and hashes, never raw source
  contents, file paths, DNS records, hostnames, or secrets.
- No PLAN correction was required.

## 6. Files created

- `crates/proxy-config/src/provider/{mod,file,dns}.rs`
- `crates/proxy-core/src/provider.rs`
- `config/examples/phase11-{file,dns}.toml`
- `config/providers/app-nodes.toml`
- `docs/operations/service-discovery.md`
- `docs/security/provider-threat-review.md`
- `docs/phase-11-completion.md`

## 7. Files modified

- `config/schema-v1.json`
- `config/schema/admin-openapi.yaml`
- `crates/proxy-config/src/{lib,redact,revision}.rs`
- `crates/proxy-core/src/{lib,route,runtime,telemetry}.rs`
- `crates/proxy-core/tests/grpc.rs`
- `crates/proxy-admin/src/server.rs`
- `docs/adr/0017-service-discovery.md`
- `docs/configuration-v1.md`
- `docs/implementation-readiness-review.md`

## 8. Dependencies added

None. File parsing uses existing TOML/Serde/SHA-256. DNS uses already-inventoried
Hickory resolver. Runtime activation and metrics reuse existing crates. Cargo
manifests and lockfile are unchanged.

## 9. Configuration introduced

- Top-level `[[providers]]`, maximum 64.
- Common: tagged `kind`, ID, disabled-by-default `enabled`, one
  `upstream_group`, fixed `scheme`, bounded refresh/stale policy.
- File: absolute path, optional trusted HTTPS SNI/CA, 50..=5000 ms debounce,
  1..=256 endpoints.
- DNS: canonical non-literal hostname, fixed nonzero port, optional trusted
  HTTPS SNI/CA, weight 1..=10000, 1..=64 answers.
- Provider file schema version 1 with a complete non-empty replacement endpoint
  list. Inline policy, hostname, listener, route, label, Docker socket, shell,
  secret, and unknown fields are rejected.

## 10. Tests added

- Strict provider parsing, disabled default, unknown/malicious metadata, Docker
  kind/socket rejection, duplicate provider/namespace, missing group, unsafe
  path, transport/TLS escape, secret redaction, and metric cardinality.
- File size/schema/identity normalization, stable endpoint identity, symlink
  rejection, opened-file identity defense, partial-write retention, recovery,
  debounce storms, and 100,000-event bounded-state simulation.
- DNS answer dedup/order/fixed template and raw answer bounds.
- Disabled provider performs no read/replacement.
- Cloud-metadata/private address, duplicate endpoint, and existing DNS rebinding
  tests prove whole candidate rejection through egress policy.
- Real RevisionStore/ActivationCoordinator regression proves invalid provider
  update cannot change active snapshot.
- Provider metric label allowlist, status redaction, and checked OpenAPI route.

## 11. Commands executed

Environment: WSL2 kernel `7.1.3-microsoft-standard-WSL2`, x86_64, stable
`rustc 1.97.1 (8bab26f4f 2026-07-14)`.

- `RUSTUP_TOOLCHAIN=stable cargo fmt --all -- --check` — exit 0.
- `RUSTUP_TOOLCHAIN=stable cargo check --workspace --all-targets` — exit 0.
- `RUSTUP_TOOLCHAIN=stable cargo clippy --workspace --all-targets --all-features -- -D warnings` — exit 0.
- `RUSTUP_TOOLCHAIN=stable cargo test --workspace --all-features` — exit 0.
- Focused config/core/admin provider, activation, redaction, telemetry, OpenAPI,
  and event-storm tests — exit 0.
- `RUSTUP_TOOLCHAIN=stable cargo tree -e features` — exit 0.
- Both Phase 11 `rust-proxy validate` fixture commands — exit 0, `valid`.
- Node JSON parse of `config/schema-v1.json` — exit 0.
- Tracked private-key/cloud-key pattern scan — exit 1 because no match.
- Cargo-manifest Docker dependency scan — exit 1 because no match.
- Runtime/config Docker-socket reference scan — only the negative rejection test
  matched.
- `cargo audit --version` — exit 101, command unavailable.
- `cargo deny --version` — exit 101, command unavailable.
- `cargo fuzz --version` — exit 101, command unavailable.
- `gitleaks version` — exit 127, command unavailable.

## 12. Actual command results

Current workspace suite passed 258 tests and ignored two:

- `aegisproxy-admin`: 16 passed.
- `aegisproxy-config`: 64 passed.
- `aegisproxy-core`: 123 passed, one ignored manual release reload benchmark.
- gRPC integration: one passed.
- `aegisproxy-secrets`: six passed.
- `aegisproxy-tls`: 40 passed.
- Pebble integration: one ignored because its Compose fixture is absent.
- Admin CLI integration: one passed.
- Certificate CLI integration: two passed.
- Configuration CLI integration: five passed.
- All doc-test targets passed.

Project code produced no compiler or Clippy warning. Existing transitive
`proc-macro-error2 v2.0.1` future-incompatibility warning remains.

## 13. Security checks

- Provider data cannot select hostname/port policy, create routes/listeners,
  supply secrets, change TLS/egress/health policy, or choose arbitrary upstream
  scheme.
- Whole normalized candidate passes validation before durable activation; an
  invalid update retained exact active revision in the activation regression.
- Link-local, multicast, unspecified, cloud metadata, denied, and unallowlisted
  private addresses remain rejected at activation and existing immediate
  pre-connect policy.
- File TOCTOU surface is reduced with regular-file and opened device/inode
  identity checks on Unix; symlink regression passes.
- Provider status/metrics contain configured bounded labels only; canary path,
  hostname, secret, and attacker labels did not export.
- No Docker dependency/socket code exists. Sole socket string is a test proving
  schema rejection.
- Repository-maintainer threat review found no unresolved critical/high local
  finding. This is not an independent security claim.
- Advisory, license-policy, full secret, and fuzz scanners were unavailable;
  no pass is claimed.

## 14. Performance checks

The 100,000-event debounce-state simulation passed in approximately 0.01 s in
debug test execution and retained one pending hash with no endpoints. This is a
bounded-state stress regression, not a production benchmark. No DNS latency,
throughput, memory, CPU, or long-duration performance claim is made.

## 15. Known limitations

- Poll coordination is serial; many providers experiencing maximum DNS timeout
  can delay later refreshes. Bounds prevent unbounded work, but operators should
  keep lookup timeout short.
- File discovery is polling, not kernel event notification; activation latency
  is poll plus debounce.
- Initial startup serves static endpoints until first provider refresh.
- DNS provider is A/AAAA only and follows resolver cache behavior; no SRV.
- Non-Unix file identity fallback is weaker than Unix device/inode comparison.
- No direct CLI `providers` subcommand exists; private API endpoint is available
  through standard Unix-socket API tooling.
- Docker, Kubernetes, Consul, registry plugins, clustering, UDP, and HTTP/3 are
  absent.

## 16. Residual risks

- **Medium:** serial worst-case DNS timeouts can delay provider convergence;
  monitor freshness and constrain provider/timeout counts.
- **Medium:** recursive resolver integrity and DNS cache behavior remain
  environmental dependencies despite answer/egress checks.
- **Medium:** unavailable advisory/license/secret/fuzz tooling leaves supply
  chain evidence incomplete.
- **Medium:** independent provider security review and long representative soak
  are not complete.
- **Low:** static fallback may be reachable but unhealthy; operators must test
  and alert on it.
- **Low:** source hash reveals equality/change timing, but no source content.

## 17. Acceptance-criteria checklist

- [x] File and DNS A/AAAA providers implemented first.
- [x] Invalid provider update cannot change active snapshot.
- [x] Provider status identifies source hash, last success, stale deadline,
  state, and endpoint count.
- [x] No provider object is applied without explicit enable.
- [x] Every destination passes allow/deny/template and full config validation.
- [x] Providers populate only declared single-group namespaces.
- [x] Partial writes, storms, duplicates/conflicts, stale/recovery, malicious
  metadata, Docker socket denial, private/rebinding, and rollback are covered.
- [x] Proxy process has no Docker dependency or socket access.
- [x] Docker helper was not built because required approval is absent.
- [x] Kubernetes and Consul remain deferred.

## 18. Exit-criteria checklist

- [x] Repository-maintainer provider threat review completed with traceable
  controls/tests and no unresolved critical/high local finding.
- [x] Bounded 100,000-event failure/storm simulation passed.
- [x] Full workspace format/check/Clippy/test gates passed.
- [x] Fixtures validate and operations/failure/status guidance exists.
- [ ] Independent provider threat review and environment-specific long-duration
  soak were not performed; they remain Phase 13/14 release gates and prevent a
  production-readiness claim.

## 19. Commit list

- `44b54c4 docs(adr): bound file and DNS discovery`
- `f40e351 feat(config): add bounded discovery providers`
- `d6920ae fix(discovery): reject provider file swaps`
- `d14d318 feat(discovery): activate provider snapshots`
- `2017b97 test(discovery): bound provider event storms`
- `88cf2b2 docs(discovery): add provider operations guide`
- `2fa361b test(discovery): reject implicit metadata access`
- `9ef91cb test(admin): verify provider status redaction`
- `f396f8a test(discovery): retain output after deletion`
- Separate Phase 11 report commit follows this list.

## 20. Readiness for the next phase

Phase 11 implementation and local acceptance criteria are complete. Phase 12
high availability/clustering has not started and remains outside this request.
Per user direction, work stops after this report. Repository is not
production-ready: independent security/protocol review, long representative
soak, unavailable supply-chain scanners, Phase 13 hardening, and Phase 14
release evidence remain mandatory.
