# Phase 15 Stream Host and Discovery Source review

Date: 2026-07-28

Status: contracts, persistence, preview, and candidate creation complete; unified activation pending

## Contracts

Stream Hosts expose only `listen_port`, `protocol`, `forward_host`, `forward_port`, exact
`sni_hosts`, and `enabled`. TCP rejects SNI; TLS passthrough requires bounded canonical exact ASCII
hosts and rejects wildcards. The listener IP derives from the unique HTTP listener. Compilation
clones only compatible upstream egress/resource policy, creates deterministic resources, and runs
normal semantic and egress validation. Disabled objects emit no resources.

Discovery Sources expose strict file and DNS A/AAAA variants mapped to existing bounded providers.
Compilation performs no file read, DNS lookup, or network access. Docker, Kubernetes, Consul, SRV,
custom providers, credentials, and custom CA references are absent. Existing provider validation
rejects missing groups, transport mismatches, namespace collisions, unsafe paths, and invalid
refresh/stale bounds.

Both stores use private schema-1 JSON, canonical ordering, exact generation CAS, atomic replacement,
exclusive ownership, owner-scoped reads, and recovery gating. Mutations require exact active
revision, create immutable typed-bound candidates, and never activate runtime.

## Authorization and routes

Each domain has exact read/create/update/delete actions enforced as role-and-explicit-token-scope
intersection. Authorization precedes JSON deserialization. Cross-owner reads and mutations are
not-found. API routes provide list/get/create/update/delete/validate/preview, with matching
`rust-proxy stream-host` and `rust-proxy discovery-source` commands. Runtime provider health remains
read-only.

## Evidence

- Stream TCP, TLS passthrough, disabled behavior, wildcard rejection, listener collision, and SSRF
  tests pass.
- File/DNS compilation-without-I/O and provider namespace/tamper collision tests pass.
- Strict contract and credential-canary tests pass.
- Admin unit tests, Clippy with denied warnings, OpenAPI YAML parsing, and Admin CLI integration
  pass.

## Residual boundary

Candidates are typed-bound so low-level activation rejects them. Schema-2 unified snapshots and
canonical typed activation/rollback must land before these candidates can be activated.
