# Phase 13 release-candidate evidence

> Historical security evidence
>
> Results apply to the candidate named below and are not current release approval. See [`STATUS.md`](../../../STATUS.md).

Evidence date: 2026-07-19

Candidate: `a3a005d7023bb0b5eb9a18112dffe29628bd632a`

Environment: WSL2 Ubuntu development distribution, Linux
`7.1.3-microsoft-standard-WSL2`, x86_64; stable Rust 1.97.0; declared/tested MSRV Rust
1.88.0. This is local evidence, not production-topology or independent-review evidence.

Lock/profile hashes:

- `Cargo.lock`: `af5638f9db5f8b3c03edd4959624bc4ce28d13c2de706cdc573a2bd4ab85c7bd`
- `fuzz/Cargo.lock`: `7ceb618c3316b9712bd68d7ae7522f0144dd481606ae2aa8b9ed73d1dfba6993`
- seccomp: `c6e88e18da0525e9038464d5cf4c15e2bdd3b656f954636ca31739cac8150f09`
- AppArmor: `d7f0826429d55685e7960278561cfe4a08e89d530f80ff8df7bb446994a3faf3`

## Rust gates

| Command | Result |
|---|---|
| `cargo fmt --all -- --check` | passed |
| `cargo check --workspace --all-targets` | passed |
| `cargo clippy --workspace --all-targets --all-features -- -D warnings` | passed |
| `cargo test --workspace --all-features` | passed: 267, failed: 0, ignored: 2 |
| `RUSTUP_TOOLCHAIN=1.88.0 cargo check --workspace --all-targets` | passed |
| `cargo check --manifest-path fuzz/Cargo.toml --all-targets` | passed |
| `cargo tree -e features` | passed; captured graph contained 2,439 lines |

The ignored tests are the manual release reload benchmark and Docker-backed Pebble integration.
They are not counted as passed. Stable compiler/Clippy produced no owned-code warning. Cargo reports
the documented future-incompatibility in transitive `proc-macro-error2`; nightly 1.99 additionally
warns that `Atomic*::fetch_update` will be renamed. The rename is unavailable at the Rust 1.88
MSRV, so production code remains on the stable API until the MSRV permits migration.

`rust-proxy validate --config config/examples/minimal.toml` and
`rust-proxy preview --config config/examples/minimal.toml` passed without activation; preview
emitted only redacted validated configuration. Candidate diff is provided by the authenticated
private administrative API rather than a top-level offline `diff` subcommand.

## Dependency and source gates

| Command/check | Result |
|---|---|
| `target/tools/bin/cargo-audit audit` | passed scan of 405 dependencies; no vulnerability; one allowed unmaintained warning |
| `target/tools/bin/cargo-deny -L error check` | advisories, bans, licenses and sources passed |
| first-party unsafe syntax scan | no unsafe block/function/impl/trait or unsafe-code allowance found |
| lockfile Git-source scan | no Git dependency found |
| bounded secret-pattern scan | no credential found; one intentional private-key marker assertion in a test |

The only advisory exception is RUSTSEC-2026-0173 for transitive build-time
`proc-macro-error2`; owner, exposure, mitigation, residual risk, blocker and 2026-10-19 expiry are
recorded in `docs/security/dependency-unsafe-review.md`. The direct unmaintained
`rustls-pemfile` dependency was removed before this candidate.

`cargo-geiger`, Gitleaks, Syft, Trivy, Grype, CycloneDX/SBOM tooling and Cosign are not installed;
their checks were not run and are not claimed. Artifact SBOM/signing belongs to Phase 14, but
independent source/unsafe and artifact scans remain release gates.

## Fuzz evidence

Eight safe fuzz hooks cover configuration parsing, route conflict analysis, host and path
canonicalization, header and forwarding processing, ClientHello inspection and certificate
metadata. Each corpus contains one reviewed seed. Corpus SHA-256 values:

```text
064b69c0e9d2953af47a991876c2d2893d009088ed805ca2cad0f53297f8d5e2  route_conflict/duplicate.toml
1c687df9386e60c2165f762a5fab848fbc62ccac17073aef69400e4a2f6323a2  forwarded_headers/chain
1edb17235876b66ef808ff1559af9f4c87430412f70d52e68dab37529b562a1d  client_hello/truncated
5d4fab1203a85cb255d285006ddbd9545cf33bb3e587e0e2491630e894fc7d1d  certificate_metadata/valid.toml
6318d7d5ba41f318f29221ba3a5dae818261a5ebe34d9ef7286f203d8f7fc3e1  path_normalization/path
6ca27c5ecca075574c9648eb89853e992b70277bc2b83088c859a144297ac453  config_parser/minimal.toml
91d2d603a055709567b35172f0c8b8475fe6b094a7bfec366ecfef3d8708cba7  header_processing/connection
991da3d985b5c0431c89e3f869a895b4d1467a23afb36ef570d13f056103207c  host_canonicalization/hostname
```

With cargo-fuzz 0.13.2 and `rustc 1.99.0-nightly (eff8269f7 2026-07-18)`, each target ran 500
cases under AddressSanitizer with its documented input/time bound. All exited zero; no crash
artifact remained. Mutations were isolated in `/tmp` and removed; reviewed repository seeds were
unchanged. This 4,000-case smoke does **not** satisfy the required 24 worker-hour campaign.

## Packaging and operational evidence

- seccomp JSON parsed and its default-deny/one explicit allowlist structure was asserted;
- both Compose YAML documents parsed and the override references the expected proxy service and
  three security options;
- `apparmor_parser -Q -T -W` exited zero; it warned that cache read/write was disabled because the
  WSL kernel lacks the expected AppArmor interface;
- Docker Compose validation/build/runtime and Pebble were unavailable. The Docker executable is a
  Windows WSL stub and returned: `The command 'docker' could not be found in this WSL 2 distro.`;
- AppArmor was not loaded: doing so requires privileged host mutation and target-host validation;
- a local single-maintainer backup/rollback/compromise tabletop completed. It is not the required
  independent live recovery drill.

The 24-hour soak was not run. Its exact workload, evidence, invalidation and signoff requirements
are in `docs/testing/phase-13-soak-plan.md`; shorter runs cannot be combined or substituted.

## Findings and disposition

| Finding | Severity | Disposition |
|---|---|---|
| declared Rust 1.85 could not resolve locked dependencies | medium | fixed by raising/test-verifying MSRV 1.88 in ADR-0028 |
| direct unmaintained PEM parser | medium | removed; strict replacement and focused regression test pass |
| deny policy rejected internal wildcard versions/root-data license | medium | exact versions and reviewed license policy now pass |
| transitive build macro unmaintained/future-incompatible | low | dated exception; monitor/remove before expiry |
| Docker/container/Pebble runtime evidence absent | release gate | run on supported target Linux CI/review host |
| long fuzz, 24-hour soak, independent pentest and owner signoff absent | release gate | candidate remains NO-GO |

No locally known critical/high finding remains. That is not an external-review result or a
vulnerability-free claim.

## Release recommendation

**NO-GO.** Local Phase 13 controls and evidence are ready for independent review. Release remains
blocked until qualified reviewers test the immutable candidate, critical/high findings close,
medium findings have owner/deadline/control, long fuzz and soak gates pass, target-host container
evidence passes, and the security owner signs the residual-risk recommendation.
