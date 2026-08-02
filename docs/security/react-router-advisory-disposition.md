# React Router RSC advisory disposition

Disposition date: 2026-08-01
Classification: **affected package present; vulnerable functionality not reachable; accepted
temporarily pending a compatible upgrade**
Release effect: the local Phase 16 dependency finding is dispositioned, but production remains
**NO-GO** until an independent reviewer accepts this evidence and the other release gates close.

## Finding

`npm audit --audit-level=high` reports two high-severity package entries (`react-router` and its
direct dependent `react-router-dom`) for one advisory,
[GHSA-qwww-vcr4-c8h2](https://github.com/advisories/GHSA-qwww-vcr4-c8h2). The installed chain is:

```text
react-router-dom 7.18.2
└── react-router 7.18.2
```

The advisory affects `react-router >=7.12.0 <8.3.0`, has no assigned CVE, and is a follow-up to
CVE-2026-22030. It permits an RSC server action to execute before a cross-origin request is rejected.
The upstream advisory says that only unstable React Server Components APIs are affected. The
[upstream fix](https://github.com/remix-run/react-router/commit/7a71c728ad116bd78699a258b2014ce9585729f5)
changes the RSC server request path (`packages/react-router/lib/rsc/server.rsc.ts`) and its RSC
integration test.

## Upgrade decision

The patched package is `react-router 8.3.0`. As checked on 2026-08-01:

- `react-router-dom` has no 8.3.0 release; its latest registry version is 7.18.2;
- `react-router 8.3.0` requires React and React DOM `>=19.2.7`, while AegisProxy uses 18.3.1; and
- moving from the DOM compatibility package to the React Router 8 package would therefore combine
  a router-package migration with a React major upgrade.

That is not a bounded security patch. The `npm audit` suggestion to install
`react-router-dom 7.11.0` was also rejected: that version is in the affected range of the preceding
[GHSA-h5cw-625j-3rxh / CVE-2026-22030](https://github.com/advisories/GHSA-h5cw-625j-3rxh).
No dependency or lockfile version changed.

## Application and reachability evidence

AegisProxy uses React Router's client Data Mode. `ui/src/main.tsx` creates a static route array with
`createBrowserRouter` and renders it through `RouterProvider`. Route loaders and actions execute in
the browser and call the versioned AegisProxy HTTP API; they are not React server actions.

All production source imports are from `react-router-dom`:

| Source | Imports used |
|---|---|
| `ui/src/main.tsx` | `createBrowserRouter`, `RouterProvider` |
| `ui/src/App.tsx` | client navigation, outlet, loader, and route-error hooks/components |
| `ui/src/pages.tsx` | client form, link, redirect, action/loader, and navigation APIs |

There is no `@react-router/dev`, `@react-router/node`, `@react-router/serve`, server handler,
framework plugin, SSR entry, React server condition, `react-server-dom-*` dependency, or RSC route
configuration. `ui/vite.config.ts` is a normal client build with no SSR configuration.

Run the repeatable evidence gate with:

```bash
npm --prefix ui run security:router
```

The gate scans application imports, invokes the real Vite production build without writing output,
captures its resolved conditions and Rollup module graph, and rejects:

- any source import other than `react-router-dom`;
- SSR or the `react-server` package condition;
- an `index-react-server`, `react-server-client`, or `server.rsc` module;
- the affected RSC server handler symbols in any included module or generated chunk.

For 7.18.2 the client build resolves only `dom-export.mjs` (rendered export: `RouterProvider`) and
the shared client router chunk. The affected `index-react-server.mjs` and its
`matchRSCServerRequest`, `routeRSCServerRequest`, `throwIfPotentialCSRFAttack`, and
`processServerAction` functions are absent. The generated application has one JavaScript entry,
no dynamic imports, and no affected server symbol. A shared internal `RSCRouterContext` export is
retained by the client router; it is not the RSC server request/action handler changed by the fix.

The ordinary production build independently produced one 275,012-byte JavaScript asset
(86.82 kB gzip). This is unchanged because no dependency or application-runtime code changed.

## Deployment boundary and assumptions

The container builds the UI with Vite, copies only `ui/dist` into the Rust build, embeds those static
files with `rust-embed`, and ships only the `rust-proxy` binary. The final image has no Node runtime,
React Router package tree, server renderer, or JavaScript request handler. The Rust browser listener
serves a closed static-asset allowlist and the versioned API.

This disposition is valid only while all of these remain true:

1. the UI remains a client-only static Vite SPA;
2. no RSC, SSR, Framework Mode, React server action, or React Router server package is added;
3. the production build does not resolve the `react-server` condition or dynamically load a server
   entry; and
4. the final image continues to contain embedded static assets rather than a Node server.

Existing exact-origin, CSRF-token, session-cookie, CSP, RBAC, and typed API controls protect the
AegisProxy API, but are compensating defense in depth rather than the basis for non-reachability.

## Residual risk and reassessment

The vulnerable package version remains in the development/build dependency graph, so scanners will
continue to report two high package entries and the project must not describe the dependency as
patched. A future bundler or package-layout change could invalidate module-graph evidence; the gate
therefore fails on unexpected entry points or affected symbols.

Reassess immediately when React, React Router, Vite, routing imports, build conditions, deployment
packaging, SSR/RSC plans, or the advisory changes. Otherwise reassess by 2026-11-01 and before any
production release candidate. Upgrade to the first compatible patched line, remove this temporary
acceptance, and rerun all UI and browser gates.

## Independent reviewer checklist

An independent application-security reviewer should verify the advisory and fix, inspect the three
source import sites and Vite configuration, run `security:router` and the production build from a
clean lockfile install, inspect the final container contents, and decide whether the deployment
assumptions establish non-reachability. This document is implementation evidence, not a signature.
