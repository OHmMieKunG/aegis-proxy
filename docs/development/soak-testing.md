# Release-candidate soak plan

Status: **not executed** | Required duration: at least 24 continuous hours

This procedure is a release gate, not a claim that the current WSL environment completed it. Run
on a representative supported Linux host with the release binary, container confinement, and
disposable upstreams. Record exact commit, lockfile hash, artifact digest, kernel, CPU, memory,
limits, network topology, configuration hash, start/end UTC, and load-generator version.

## Workload

Use a fixed replayable mix that covers:

- HTTP/1.1 keep-alive and HTTP/2 multiplexing with streaming request/response bodies and trailers;
- WebSocket and gRPC connections spanning multiple health-check/reload intervals;
- TLS 1.2/1.3 handshakes, valid SNI selection, malformed handshakes, and bounded slow clients;
- healthy, slow, failing, recovering, and intermittently unavailable upstreams;
- validated activation, deliberately invalid activation, rollback, last-known-good recovery, and
  certificate replacement/failure without replacing a working certificate;
- trusted and untrusted forwarded headers, rejected CONNECT/absolute form, oversize input,
  smuggling corpus, auth failures, prohibited SSRF destinations, and bounded rate-limit keys;
- admin read/mutation traffic, optimistic-concurrency failures, audit persistence failure, backup
  creation/verification, telemetry backpressure, SIGTERM drain, and restart.

Traffic destinations must be disposable local fixtures or an isolated test network. Do not use
production credentials, public targets, arbitrary client-selected upstreams, or real ACME CAs.

## Sampling and evidence

Capture at one-minute intervals and at every injected event:

- process/container CPU, RSS, virtual memory, threads/tasks, file descriptors and socket states;
- accepted/rejected connections, in-flight requests, body/queue/semaphore utilization and drops;
- latency/error counters by stable listener/route/upstream ID, without unbounded labels;
- upstream pools, health transitions, DNS answers/refresh failures and connect-policy rejection;
- TLS handshakes/failures, certificate expiry/reloads, activation/rollback and audit outcomes;
- disk use for state, revisions, audit, certificates, backup and temporary files;
- kernel OOM, seccomp/AppArmor denials, network retransmit/reset/drop and load-generator errors.

Store the command transcript, redacted configuration, metrics export, structured logs, event
timeline, artifact hashes and a final summary. Never store secrets or TLS key logs.

## Pass criteria

- 24 hours complete with no process crash, panic, deadlock, OOM, invariant violation, secret leak,
  audit-chain failure, invalid activation, working-certificate loss, open-proxy or SSRF bypass;
- memory, tasks, FDs, sockets, rate-limit keys, queues, state files and disk use stay within declared
  bounds and return near baseline after each burst/event;
- failed reload/audit/upstream/certificate operations behave as specified while the data plane
  remains within its supported availability envelope;
- graceful drains finish within configured deadlines and preserve in-scope long-lived traffic;
- every unexpected error, denial, resource trend or threshold breach is a tracked finding with
  severity, owner, deadline, control and retest evidence.

Any critical/high finding, uncontrolled monotonic resource growth, missing evidence interval, host
reboot, load-generator failure, configuration drift or test-harness uncertainty invalidates the
run. Fix and restart the full 24-hour window; do not concatenate shorter runs.

## Required signoff

The test operator and independent reviewer sign the immutable result bundle. The security owner
then accepts or rejects residual risks. A short smoke/benchmark run cannot substitute for this gate.
