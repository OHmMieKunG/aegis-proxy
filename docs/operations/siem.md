# SIEM and durable audit integration

The administrative audit file is `${state_dir}/audit/admin.jsonl`. Every
bounded record has a sequence number, prior-record link, and HMAC-SHA256. The
audit key is resolved from an environment or absolute file secret reference;
it must not be shipped with the log.

Ship audit records off host with a least-privilege reader after each append.
Use TLS with server verification and collector authentication, a finite local
spool, explicit retention, and alerts for lag, sequence gaps, HMAC failures,
disk pressure, and collector rejection. Preserve each JSON line exactly so
chain verification remains possible. A SIEM transformation should create a
derived copy and retain the original immutable record.

Before onboarding or after an outage:

1. Stop the shipper from modifying its cursor.
2. Verify the local chain by opening the audit API/store with the configured
   key; any schema, sequence, previous-HMAC, or record-HMAC mismatch fails.
3. Compare the SIEM's last accepted sequence and HMAC with the local record.
4. Backfill only the missing contiguous suffix.
5. Alert and investigate on a gap, duplicate sequence with different content,
   authentication failure, or local truncation. Never silently skip a record.

Audit append failure marks `aegisproxy_admin_audit_ready` zero and mutations
fail closed. The data plane continues serving. Best-effort JSON logs and traces
cannot substitute for the durable audit chain.

Do not ingest API tokens, authorization/cookie headers, private keys, ACME
credentials, secret references/values, sensitive query parameters, or full
identity claims. Stable action, resource, outcome, actor type/ID, revision, and
request ID fields are sufficient for audit correlation. Restrict SIEM access
because actor and resource identifiers remain operationally sensitive.
