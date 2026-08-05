# ADR-0033: Embedded typed Proxy Locations

## Status

Accepted for Phase 17.2.

## Context

Proxy Hosts already own one bounded domain set, default upstream, applied generation, optional
inactive draft, immutable candidate binding, and activation lifecycle. NPMPlus-style custom
locations need path-specific upstreams without creating an independent lifecycle or accepting
Nginx directives.

The runtime already validates canonical route paths, matches exact paths before segment-aware
prefixes, selects the longest prefix, and uses a host-only route as fallback.

## Options considered

1. Embed position-only locations in `ProxyHostSpec`. This is simple but makes reorder, edit, audit,
   and browser identity unstable.
2. Store independent `ProxyLocation` objects. This adds ownership, CAS, draft, store, and activation
   coordination for state that cannot be activated without its parent.
3. Embed locations with stable typed IDs. The parent remains the persistence and activation
   boundary while nested identity remains stable.

## Decision

Use option 3. A Proxy Host contains zero to sixteen ordered `ProxyLocation` records. Each record
has a stable object-style ID, exact or prefix matcher, canonical path, explicit HTTP/HTTPS upstream,
optional Access Policy override, and enabled state. Array order is display-only. Location IDs do
not derive from the path or position; duplicating a host creates fresh location IDs.

`null` location policy means inherit the parent policy. An explicit reference must resolve to one
enabled policy permitted for the parent owner. Certificates, TLS termination, domains, ownership,
drafts, candidates, and activation remain host-level. WebSocket and gRPC use the existing automatic
HTTP runtime path and have no ignored per-location toggle.

## Path and precedence contract

- Paths are case-sensitive canonical ASCII, 2–2,048 bytes, and begin with `/`.
- Custom `/`, percent encoding, backslashes, repeated slashes, dot segments, queries, fragments,
  schemes, and authorities are rejected.
- Prefix paths cannot end in `/`; exact paths may.
- Duplicate paths in one host are rejected even when matcher kinds differ.
- Exact path beats prefix, the longest segment-aware prefix wins, and the parent route is fallback.
  `/api` matches `/api` and `/api/...`, never `/api2`.
- The runtime matches the once-canonicalized Hyper URI path; query strings do not participate.

## Compilation and identity

For every enabled location, the compiler creates one upstream group shared by that location's
domain routes and one route per parent domain. Generated location namespaces hash owner, parent ID,
and location ID. Existing parent route/group IDs remain unchanged. Enabled locations are sorted by
stable ID during compilation, so display reorder cannot change route precedence or output.

Disabled hosts and locations emit no routes. Drafts never enter the desired snapshot or compiler.
Any invalid path, upstream, duplicate, unauthorized policy, or generated-ID collision rejects the
whole host.

## Migration

ProxyHostStore remains file schema 2. Missing `locations` deserializes as an empty list for legacy
applied records, drafts, and API payloads; all new serialization writes the field. Applied and draft
generations are preserved. Old candidate files are not rewritten. Candidate verification accepts
both the pre-17.1 singular-domain binding and the Phase 17.1 plural-domain/no-location binding, so
exact-active restart never recompiles or activates migrated desired state. Downgrade after writing
locations is unsupported.

## Security and failure consequences

Locations inherit the parent owner and have no independent provider authority. Access Policy
dependencies, including location overrides, are bound into the immutable candidate. The existing
desired/draft recovery gate, candidate durability, active-pointer recovery, rollback, HMAC audit,
and last-known-good rules apply to the whole parent mutation. Audit records identify the parent
mutation; the bounded typed diff identifies changed location IDs and paths.

Regex paths, named locations, raw Nginx configuration, per-location certificates, arbitrary
middleware, headers, timeouts, and upstream TLS exceptions are rejected or deferred.

## Future implications

Future reviewed typed fields can extend the embedded record additively. A separate location store
should be reconsidered only if locations gain an independently authorized or activated lifecycle.
