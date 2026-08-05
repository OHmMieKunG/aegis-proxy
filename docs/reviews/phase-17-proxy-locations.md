# Phase 17.2 Proxy Locations evidence

## Scope

This unit adds embedded bounded custom locations to applied and draft Proxy Hosts. It does not add
regex routing, raw Nginx configuration, per-location certificates, generic middleware, providers,
Redirection Hosts, or Dead Hosts.

## Contract and migration

[ADR-0033](../adr/0033-embedded-proxy-locations.md) selects stable-ID embedded locations. Existing
records load as zero-location hosts without changing generations. Candidate verification preserves
both older singular-domain and Phase 17.1 plural-domain/no-location hashes; startup does not rewrite
or activate them.

## Runtime and control-plane evidence

- The [typed contract](../../crates/proxy-admin/src/api.rs) bounds IDs, paths, upstreams, count, and
  aggregate text and rejects unknown fields.
- The [canonical compiler](../../crates/proxy-admin/src/compile.rs) emits one route per domain and
  enabled location, shares one target per location, resolves inherited/overridden policies, and
  verifies managed namespaces before replacement.
- The [route matcher](../../crates/proxy-core/src/route.rs) selects exact paths, then longest
  segment-aware prefixes, then the host fallback after one request-path canonicalization.
- Applied/draft CAS, promotion, persistence recovery, candidate binding, activation, rollback,
  exact-active restart, provider exclusion, and durable audit remain parent Proxy Host operations.
- The [browser form](../../ui/src/pages.tsx) supplies structured add/remove/reorder/edit controls,
  fresh nested IDs on duplicate, and the existing draft/apply/error workflows.

## Validation record

The final workspace suite passed 394 tests with the Pebble and privileged-runtime fixtures
intentionally ignored. Focused and full Chromium runs in the digest-pinned Playwright Noble image
passed 6/6 and 10/10. The production image `aegisproxy:phase17-locations` built successfully after
its generated-client byte comparison, Router reachability gate, typecheck, and Vite build passed.
The real Unix-socket Admin integration covered create, update, rollback, and delete with locations.
Full command results are recorded in `STATUS.md`.

Production remains NO-GO. The React Router scanner finding remains under its documented
non-reachability disposition, and this local evidence is not independent certification.
