# External-load-balancer high availability

Phase 12 runs independent AegisProxy nodes behind an operator-owned L4 load balancer. There is no cluster protocol, quorum, shared database, shared writable certificate directory, global rate limiter, or remote administration port. Every node serves its local last-known-good revision when orchestration is unavailable.

## Supported topology

- Send ports 80/443 through an external L4 load balancer to two or more nodes.
- Preserve the source address directly. PROXY protocol is not implemented; enabling it at the load balancer will send unparseable bytes and is unsupported.
- Keep each administrative Unix socket host-local. Use authenticated host transport such as SSH or configuration management to invoke the CLI locally. Do not expose or bridge the socket to TCP.
- Give every node a unique lowercase ID. Start it with `--node-id NODE --fleet-generation GENERATION`.
- Use one byte-identical validated TOML file across the fleet. Node identity and generation are bootstrap data, so they do not alter its content hash.
- Keep state directories local and separately backed up. Never mount one writable state directory on multiple nodes.
- Ship schema-v2 HMAC audit records off-host; each includes `node_id`. An off-host export outage does not stop traffic, but local audit failure blocks mutations and makes fleet verification fail.

`deploy/ha/aegisproxy@.service` is a hardened per-host template. Install one instance per host, for example `aegisproxy@edge-a.service`. Put the monotonically increasing generation in `/etc/aegisproxy/fleet.env`. One host should run one instance unless its ports, state directory, socket, and budgets are independently isolated.

## Fleet configuration and certificate owner

When managed ACME certificates exist, name exactly one node in the common configuration:

```toml
[acme]
max_concurrent_orders = 4
renewal_owner = "edge-a"
```

A fleet generation greater than zero fails startup if managed ACME certificates exist without `renewal_owner`. Only the named node reconciles ACME or accepts renewal requests. All others report `certificate_owner = false`. The offline fleet gate requires exactly one owner and identical managed-certificate counts.

Configure `tls.state_encryption_recipients` with the separately escrowed recipients authorized to consume distributed generations, up to the schema bound. The owner writes to its local state only. Distribution automation copies immutable encrypted generation files to a private staging directory on each replica, runs offline certificate inspection with that replica's identity, atomically installs the generation and pointer while the replica is stopped, then restarts it. Never copy plaintext keys or a live writable directory.

## Exact canary and rolling rollout

1. Validate the exact artifact once and calculate its canonical hash:

   ```text
   rust-proxy validate --config candidate.toml
   rust-proxy fleet hash --config candidate.toml
   ```

2. Choose a generation strictly greater than every prior rollout, including rollbacks. Record generation, hash, artifact signature/transport evidence, operator, and node inventory in the change record.
3. Copy the byte-identical file through authenticated host transport. If transport leaves the trusted host boundary, verify its asymmetric artifact signature or mutually authenticated transport before local activation.
4. Select one canary. Drain it using the exact current revision as `--expect`, wait for load-balancer removal, stop it, atomically install the reviewed file and generation environment, then restart it. Startup validates and activates the local revision before listening.
5. Export authenticated status locally after readiness returns:

   ```text
   rust-proxy fleet status --socket /var/lib/aegisproxy/admin/admin.sock > edge-a.json
   rust-proxy fleet check --expected-hash HASH --generation GENERATION \
     --node edge-a --status edge-a.json
   ```

6. Observe the canary for the approved interval. Check data-plane errors, latency, TLS, upstream health, certificate expiry, audit durability, and telemetry drops.
7. Roll one node at a time using the same drain, stop, atomic file/environment install, restart, status export, and verification sequence. Abort on the first mismatch. Do not overwrite every configured file at once: the file watcher would correctly activate it immediately and bypass the canary boundary.
8. Finish with a complete inventory gate. Every expected node and status file must be supplied:

   ```text
   rust-proxy fleet check --expected-hash HASH --generation GENERATION \
     --node edge-a --node edge-b \
     --status edge-a.json --status edge-b.json
   ```

The checker reads at most 256 status files and 16 KiB per file. It rejects invalid/duplicate identities, missing or unexpected nodes, stale generation, any divergent active hash, malformed revision/hash linkage, recovery-required state, audit failure, draining state, managed-certificate policy drift, and invalid renewal-owner count. Status files are evidence captured through authenticated local APIs; unauthenticated network JSON is not trusted input.

## Load-balancer drain and restart

1. Read current revision from `fleet status`.
2. Run `rust-proxy drain --socket SOCKET --expect REVISION`. This audited one-way action immediately changes readiness to HTTP 503 `draining`.
3. Confirm the load balancer observed failure and removed the node from new assignment. Wait its full configured propagation/drain interval and verify active connection/request metrics reached the approved threshold.
4. Stop or restart through the supervisor. Normal process cancellation stops listener acceptance and applies existing bounded graceful-shutdown deadlines to accepted work.
5. Start with the intended generation, verify readiness, export status, and add the node back only after the fleet gate passes.

Drain state deliberately does not close the data listener: this gives the load balancer time to converge without cutting accepted work. Direct traffic or a load balancer that ignores readiness can still create work during that interval and is outside the supported policy. A restart clears drain state.

## Rollback

Rollback is another forward, monotonic fleet rollout. Increment generation; do not reuse the failed generation. On each node, use `config rollback ... --expect CURRENT` to create a new local revision containing retained prior content, or activate the reviewed prior artifact. The local revision sequence may differ between nodes; the canonical content hash must match. Canary, drain, roll, and complete the same fleet gate.

If a node cannot activate the candidate, leave it on its serving last-known-good revision and out of the new-hash inventory. Do not reinterpret majority state as success. Abort or explicitly roll the already changed nodes forward to the prior content under a newer generation.

## Certificate-owner transfer

Never change `renewal_owner` with both old and new owners running mixed configuration.

1. Confirm expiry margin and no active issuance. Drain and stop the old owner; other nodes continue serving.
2. Change `renewal_owner`, validate, hash, sign/transport, and activate the new generation on the new owner first.
3. Verify it is the sole reported owner, then roll remaining non-owner nodes.
4. Restart the old owner only with the new configuration and generation.
5. Complete the full fleet gate and monitor renewal metrics/logs.

If the owner is unexpectedly lost, working certificates remain active. Recover or select a new owner using the stopped-owner procedure before the renewal margin is exhausted. Do not copy account state to a simultaneously running writer.

## Failure drills

| Fault | Expected behavior | Required proof |
|---|---|---|
| Deployment/controller outage | Nodes continue local active/LKG service; no remote control dependency | Proxy requests succeed while orchestration is stopped |
| One node loss | LB removes failed node; others serve node-local state | Error budget remains within LB policy; missing-node fleet gate fails |
| Network partition | Isolated node receives no mutation and keeps LKG | Mixed/missing status fails closed; no quorum activation |
| Mixed revisions | Traffic may see mixed policy until rollout abort | Complete fleet gate identifies every divergent hash |
| Rolling rollback | Prior content returns as a newer generation | New generation and exact prior hash pass all nodes |
| Drain/restart | Readiness fails before removal; accepted work drains to deadline | LB logs plus request/connection metrics |
| Duplicate ACME owner | Fleet gate blocks completion | Exactly one `certificate_owner` in full inventory |
| Certificate distribution failure | Replica retains previous valid generation or fails closed for missing identity | Wrong key/domain/identity fixture never replaces active material |
| Local audit failure | Mutation and fleet gate fail; data plane continues | Audit outage test plus serving probe |
| Off-host export outage | Local audit remains durable; alert fires | Queue/drop alert and later ordered export by node/sequence |

Run `cargo test -p rust-proxy --test ha_chaos` for local fleet-gate fault coverage. Existing reload, crash recovery, graceful drain, ACME validation, encrypted certificate, audit failure, backup tamper, and last-known-good tests cover node-local primitives. A production-topology drill with the actual load balancer, host transport, storage, supervisor, certificate distributor, and SIEM remains mandatory before production readiness.

## Compromise response

- Node compromise: remove it at the load balancer, revoke its admin tokens, rotate audit/age credentials exposed on that host, restore from independently verified artifacts, and reject its old status evidence.
- Renewal-owner compromise: also rotate or replace the ACME account, DNS/EAB credential, affected certificate keys, and owner assignment using the stopped-owner procedure. Follow the CA's external revocation process.
- Fleet artifact/transport compromise: stop rollout, preserve audit/change evidence, rotate transport signing credentials, recompute the canonical hash from reviewed source, and roll forward under a new generation.

No HA availability or security claim is established by local tests alone. Independent protocol, security, and production failure testing remains required.
