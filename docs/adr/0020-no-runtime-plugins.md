# ADR-0020: No runtime plugin system

Status: Accepted | Date: 2026-07-16

## Context
Dynamic plugins add ABI, signing, sandbox, update, and arbitrary-code risk.
## Constraints
Small auditable process; no runtime scripts or raw config.
## Options considered
Native plugins; Wasm; subprocess plugins; compile-time features.
## Decision
Use reviewed compile-time features and standard external protocols only.
## Rationale
No plugin marketplace is needed to ship the core proxy.
## Consequences
New integrations require a release/build.
## Security implications
No untrusted extension executes inside the proxy.
## Reliability implications
Feature combinations are tested in CI rather than loaded at runtime.
## Operational implications
SBOM shows all enabled code.
## Migration implications
Future extension ABI would need a new threat/compatibility design.
## Alternatives rejected
Unsigned native/Wasm/plugin downloads.
## Revisit conditions
Multiple concrete integrations cannot use compile-time or standard adapters.
