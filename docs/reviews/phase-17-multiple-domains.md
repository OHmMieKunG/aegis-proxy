# Phase 17.1 multiple-domain Proxy Host review

Date: 2026-08-02
Scope: bounded exact multiple domains only; Proxy Locations and other Phase 17 host families are
excluded.

## Contract and migration

[ADR-0032](../adr/0032-proxy-host-multiple-domains.md) defines an ordered 1–32 `domains` list with
the first value as primary. The server-authoritative validator performs lowercase IDNA ASCII
normalization and one-root-dot removal, then applies existing exact-host label and length checks.
The total normalized list is bounded to 8,096 bytes. A typed `DomainName` prevents unvalidated
strings from entering normal compiler paths.

Strict persisted/API decoding accepts either legacy `domain` or current `domains`, never both.
Applied and draft generations and draft base generations are retained. Writes emit plural form.
Candidate loading recomputes both the current binding and, only for one-domain objects, the exact
former serialization. A matching former hash remains the bound identity and can be cloned to a
provider-derived revision. No migration code creates or activates a revision.

## Runtime and security traceability

| Requirement | Code evidence | Test evidence | Result |
|---|---|---|---|
| Normalization and bounds | `proxy-config::normalize_exact_host`, `DomainName`, `ProxyHostSpec::validate_domains` | exact-host and contract tests | Pass |
| One route per domain, one target | aggregate compiler positional managed route IDs | `compiles_one_route_per_domain_with_one_shared_upstream` | Pass |
| Whole-state conflicts | enabled domain claims in store and compiler; retained manual route claims | enabled/disabled/store/compiler/Admin HTTP tests | Pass |
| Draft/CAS behavior | existing draft namespace and exact promotion now compare complete domain lists | draft promotion, conflict, failure, browser lifecycle | Pass |
| Certificate coverage | one selected authorized certificate must cover every domain; API uses `certificate_coverage_failed` | certificate selection, API-contract, and browser named-set rejection tests | Pass |
| Legacy desired migration | exclusive singular decoder and plural serializer | schema-1 and schema-2 applied/draft migration tests | Pass |
| Exact old active recovery | legacy candidate binding attestation and clone path | legacy active binding load/clone and startup exact-active tests | Pass |
| Browser workflow | repeatable fields with add/remove/reorder/primary/limit controls | pinned Playwright: 6 focused and 10 full-suite tests passed | Pass |
| Backup/restore representation | unchanged bounded byte archive captures stores and candidates | encrypted backup inspection proves plural applied and draft records are retained | Pass |
| Provider isolation | current providers emit endpoints only; legacy typed binding clone is preserved | provider/startup workspace regressions | Pass |

All domain values share the object owner, upstream, HTTPS/certificate selection, access policy, and
enabled state. Disabled applied objects and inactive drafts may retain conflicts but compile no
routes; enable/promotion fails before publication when an enabled claim exists. Manual/provider
runtime route conflicts fail whole-state compilation. Arbitrary domains remain absent from metric
labels and durable audit fields; audit identifies the stable object and bounded outcome.

## Limitations

Wildcards, regex/catch-all matchers, paths and Proxy Locations, per-domain upstreams/certificates,
automatic SAN issuance, redirects, and NPMPlus import are not implemented. Cross-owner conflict
errors stay deliberately generic to avoid disclosing another owner's domain inventory. Restore is
still validate-only and downgrade after plural persistence requires a matching binary/backup.

## Validation evidence

- Rust formatting, default/all-feature workspace checks, all-feature Clippy with warnings denied,
  the workspace test suite, doc tests, and `cargo tree -e features` passed. The suite executed 390
  passing tests and retained two explicitly ignored environment fixtures; the unchanged
  `proc-macro-error2` future-incompatibility warning remains.
- The generated client was byte-stable after regeneration. UI typecheck, the React Router
  reachability gate, and direct Vite production build passed; the bundle contains 26 modules and a
  281.67 kB JavaScript chunk (88.41 kB gzip).
- The digest-pinned Playwright Noble image passed all 6 focused Proxy Host scenarios and all 10
  browser scenarios with a real Chromium process.
- The production container build passed its own generated-client comparison, Router gate,
  typecheck, Vite build, and locked Rust release build. The local manifest-list digest was
  `sha256:f368e8ff2e294c3f90d6e1ce84356c9bf3208d517a706adb48b4503b85957027`.
- Repository-wide Markdown relative links and `git diff --check` passed.
- `npm audit --audit-level=high` exited 1 with two high package entries for
  GHSA-qwww-vcr4-c8h2. The unchanged client-only RSC non-reachability disposition and production
  module-graph gate remain the accepted Phase 16 condition; the scanner result is not suppressed.

## Conclusion

The multiple-domain row is complete as a bounded Phase 17.1 workflow. Overall Proxy Host parity
remains partial because Proxy Locations and other advanced NPMPlus workflows are separate units.
