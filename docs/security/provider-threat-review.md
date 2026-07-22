# Provider threat review

Date: 2026-07-19. Scope: current file and DNS A/AAAA providers. This is repository-maintainer review, not an independent penetration test.

| Threat | Control | Evidence | Residual risk |
|---|---|---|---|
| Metadata creates public route/listener | Provider schema contains endpoint records only; namespace/group/template fixed in base config | Strict unknown-field and policy-escape tests | Trusted base-config compromise remains total policy compromise |
| Default unintended exposure | `enabled` defaults false; provider cannot create route | Disabled-provider parse test and fixtures | Operator can explicitly enable wrong declared group |
| Partial file or rename storm | Regular non-symlink bounded read, identity recheck, stable-hash debounce, one pending hash | Partial-write, symlink, rename-storm, 100,000-event bounded-state tests | Polling detection latency; non-Unix identity check is weaker than Unix device/inode check |
| Duplicate/conflicting providers | Unique provider ID and single owner per upstream group | Namespace/conflict validator tests | None known within schema v1 |
| Malicious endpoint/metadata/SSRF | File accepts literal socket address only; DNS policy fixed; full validator and connect-time egress checks; link-local/metadata denied | Policy-escape, metadata IP, duplicate endpoint, DNS-rebind tests | Public addresses are allowed unless explicitly denied; operator must constrain sensitive deployments |
| DNS rebinding/private answer | Whole answer set capped and rejected on any forbidden address; literal normalized endpoints revalidated before connect | Provider normalization and upstream DNS rebind tests | Recursive resolver/cache integrity remains environmental dependency |
| Source deletion/outage | Last valid set has hard stale deadline, then static fallback | Stale/delete model and recovery tests | Static fallback may be intentionally unhealthy; alerting required |
| Invalid activation or race | Full candidate validation plus immutable revision/CAS/atomic snapshot path | Provider activation regression proves invalid update deduplicates to active revision | Durable storage failure can delay new topology but leaves data plane on LKG |
| Secret/log leakage | Provider docs cannot contain secret fields; errors are fixed classes; status is redacted | Strict schema/redaction tests | File path/hostname appear in trusted config preview only as non-secret operational metadata |
| Docker socket privilege | No Docker client/helper/socket code or configuration exists in proxy | Repository source/config inspection | Future helper needs separate ADR, filter contract, and independent review |
| Event/resource exhaustion | 64 providers, 1 MiB file, 256 file endpoints, 64 DNS answers, serial coordinator, resolver work cap, bounded status/metric labels | Limit validation and event-storm test | Serial worst-case DNS timeouts delay later provider refreshes; tune short lookup timeouts |

Local review found no path for provider data to change routes, listeners, transport, TLS identity, secrets, or egress policy. No critical/high repository-maintainer finding remains. Independent application/protocol security review and environment-specific long-duration failure soak remain release-level work; no production-readiness claim is made.
