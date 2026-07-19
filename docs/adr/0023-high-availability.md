# ADR-0023: External-load-balancer high availability

Status: Accepted | Date: 2026-07-19

## Context

Phase 12 adds multiple independently recoverable proxy nodes without turning the data plane into a distributed system. Fleet rollout must identify divergent configuration content, drain nodes through an external load balancer, and prevent concurrent ACME renewal ownership.

## Constraints

- One Rust process and one deployable binary per node.
- No embedded consensus, database, clustering protocol, shared mutable state, or global rate limiter in the initial release.
- Administrative access remains on a private Unix socket.
- Each node must retain and serve its own last-known-good revision during controller or deployment-system loss.
- Node-local identity must not change the content hash of the fleet configuration.
- Certificate private keys and administrative credentials must not be shared through a writable filesystem.

## Options considered

1. Independent nodes behind an external L4 load balancer, with exact content-hash rollout checks.
2. A built-in controller distributing signed snapshots over a new mTLS control port.
3. Embedded consensus with shared configuration and certificate state.
4. A shared filesystem or database used by every ACME scheduler.

## Decision

Run independent nodes behind an external L4 load balancer. Preserve the client source address directly; PROXY protocol remains disabled until its parser, trust boundary, and tests are implemented in a later phase.

Supply a unique node ID and monotonically increasing fleet generation as process bootstrap arguments. They are not configuration fields, so every node can activate byte-identical configuration and report the same SHA-256 revision hash. The authenticated status endpoint exports node ID, fleet generation, active revision/hash, readiness, drain state, and certificate ownership. A bounded offline fleet checker rejects missing nodes, duplicate identities, unexpected generations, divergent hashes, unready nodes, and any certificate-owner count other than exactly one when managed ACME certificates exist.

Administrative drain is an audited, one-way process state. It makes readiness fail immediately. The external load balancer must stop assigning new connections and complete its configured drain interval before the supervisor sends normal process shutdown. Accepted requests continue under existing graceful-shutdown behavior.

Managed ACME configuration names one renewal-owner node. Only that node starts renewal reconciliation and accepts renewal requests. Other nodes consume independently distributed encrypted certificate generations. Fleet checking proves exactly one reported owner before and after rollout. No node shares a writable ACME state directory.

Fleet transport and orchestration remain external. Operators use SSH, configuration management, or another authenticated host channel to copy the exact artifact and invoke each node's private Unix API. Introducing a remote controller would require a new ADR, mutually authenticated transport or asymmetric snapshot signatures, monotonic replay protection, and a split-plane privilege review.

Audit records include node identity. Off-host audit export is an operator deployment responsibility; local audit durability continues to fail administrative mutations closed without stopping the data plane.

## Rationale

External load balancing and local last-known-good state provide node-loss tolerance without consensus failure modes. Bootstrap identity avoids false drift caused by node-local configuration. Content hashes detect every declarative mismatch. One named ACME writer avoids CA races and shared-state corruption.

## Consequences

- Health, rate-limit, circuit-breaker, DNS, and connection-pool state remain node-local.
- Fleet generation monotonicity is enforced by rollout automation and reviewed manifests, not by cross-node coordination.
- Fleet checks require a complete bounded set of authenticated node-status exports.
- Drain completion depends on the external load balancer's documented policy and observability.
- Certificate distribution is operationally explicit and independently encrypted per node.

## Security implications

No public control port or cluster credential is added. Unique node IDs improve audit attribution. Exact hashes expose drift without exposing configuration. A compromised renewal owner requires ACME account and certificate-key rotation; compromise does not grant another node a shared writable state path. Host transport must authenticate both endpoint and artifact when snapshots leave the host boundary.

## Reliability implications

Controller loss does not affect serving. Each node can restart from local last-known-good state. One-writer renewal creates a deliberate certificate-control dependency, mitigated by ownership failover procedure and retention of working certificates. Global policies are approximate because state remains node-local.

## Operational implications

Operators must assign unique node IDs, increment fleet generation monotonically, verify all node hashes, configure load-balancer drain, ship audit records off-host, and keep certificate state directories private and separate. Rollout order is canary, verify, rolling nodes, then fleet verification.

## Migration implications

Single-node deployments keep bootstrap defaults and remain the ACME owner. Fleet adoption adds node/generation arguments and one `acme.renewal_owner` value. Existing configuration remains valid. No state migration or shared store is introduced.

## Alternatives rejected

- Built-in remote controller: adds a new network trust boundary without being required for initial HA.
- Embedded consensus/database: contradicts initial-release scope and expands recovery complexity.
- Shared filesystem/database ACME locking: makes storage availability and corruption fleet-wide concerns.
- Independent simultaneous ACME ownership: risks duplicate orders, challenge conflicts, and CA rate limits.
- PROXY protocol now: parser and trusted-peer policy are not yet implemented or fuzzed.

## Revisit conditions

Revisit if external orchestration cannot meet measured availability, exact fleet inventory cannot be obtained, a global policy requires strong consistency, one-writer certificate recovery misses the documented renewal margin, or a remote split control plane becomes an approved product requirement.
