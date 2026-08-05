# ADR-0032: Bounded exact domains on Proxy Hosts

Status: Accepted
Date: 2026-08-02

## Context

The original typed Proxy Host contract carried one canonical `domain`. NPMPlus-compatible daily
operation requires several exact DNS names to share one host configuration without introducing
raw matchers, per-domain upstreams, or per-domain policy. The migration must retain immutable old
candidate bindings and exact-active restart while applied and draft records move to a plural API.

## Decision

`ProxyHostSpec.domains` is an ordered list of 1–32 validated `DomainName` values. Input is
normalized once by the shared Rust validator to lowercase IDNA ASCII; one trailing root dot is
removed. IP literals, wildcards, schemes, ports, paths, userinfo, whitespace, invalid IDNA, empty
labels, and DNS length violations are rejected. Normalized duplicates reject the whole object.
The combined normalized domain bytes are bounded at 8,096.

User order is preserved because the first value is the primary display domain. Order therefore
participates in desired-state and candidate hashes. Reordering changes an object generation but
does not change its stable owner/object identity. The compiler emits one exact route per domain,
using the existing primary route ID and bounded positional suffixes for additional routes. Every
route references one shared generated upstream group and endpoint.

Only enabled applied hosts claim domains. Disabled applied hosts and inactive drafts may retain a
conflicting name, but enabling or promoting them fails closed against the complete current desired
state. There is no last-write-wins routing. Drafts remain outside compilation and providers.

One existing managed-HTTPS certificate must cover every domain using the existing exact/wildcard
matcher and owner/share rules. This decision does not add certificate issuance, SAN requests, or
per-domain certificate selection.

## Migration and compatibility

The strict Proxy Host store remains schema 2 because applied/draft namespace semantics are
unchanged. Its object decoder accepts exactly one of legacy `domain` or current `domains`; both is
invalid. Legacy singular records normalize to a one-element list in memory. Every subsequent
write serializes plural `domains`. Public OpenAPI reads and generated clients expose only the
plural form; the singular form is a persisted/input migration alias, not a continuing output
contract. Downgrade after a plural write is unsupported and requires a matching binary and backup.

Old schema-1 and schema-2 candidate files retain their recorded binding hash. Candidate loading
verifies either the current plural hash or the exact former one-domain serialization. Provider
revision cloning preserves a verified legacy binding rather than silently rebinding it. Startup
therefore recovers the exact old active revision and never activates migrated desired or draft
state. The next explicit Save and apply creates a normal plural binding.

Encrypted backup archives already capture the complete private store and candidates as bytes.
Restore validation remains non-mutating; compatibility is established when the restored store and
candidate files are strictly opened by the matching binary.

## Security and failure consequences

Normalization is server-authoritative and shared by API/persistence/compiler paths. All domains
are validated before any route is emitted; partial compilation is forbidden. Whole-state conflict
checks include manual configuration and enabled typed hosts. Bounded lists prevent audit, parser,
candidate, and route amplification. Audit keeps the stable object ID and action result; arbitrary
domain values are not metric labels or unbounded audit fields.

Existing applied/draft CAS, ownership, recovery gates, atomic persistence, immutable binding,
transactional activation, last-known-good retention, and exact-active restart are unchanged. An
old active candidate and a newer plural desired object can coexist until explicit application.

## Alternatives rejected

- `additional_domains` leaves two sources of truth and ambiguous primary behavior.
- Sorting domains would erase the familiar primary-domain choice and cause surprising display
  changes.
- One route containing several host matchers obscures per-domain route identity and evidence.
- Wildcard, regex, catch-all, path, or arbitrary matcher support expands security and precedence
  semantics beyond this unit.

## Future implications

Proxy Locations may attach to the Proxy Host target shared by these routes, but are not part of
this decision. Automatic SAN issuance, domain redirects, and NPMPlus import require separate
contracts and review.
