# ADR-0009: Encrypted certificate storage

Status: Accepted; Phase 6 pointer format implemented
Date: 2026-07-16

## Context

BYO and managed private keys must survive restart without raw disk storage.

## Constraints

No plaintext key logging/export; prior valid generation retained.

## Options considered

Age-encrypted files; OS keyring only; plaintext PEM; external vault required.

## Decision

Use age-encrypted generation files with externally supplied decryption identity and an atomic, versioned `current.json` pointer containing current and optional previous generation IDs. Phase 2 imports activate a new certificate ID by atomically renaming its complete staged directory and reject replacement. Phase 6 readers retain compatibility with the legacy plain `current` pointer; the next successful rotation writes `current.json`, retains old generations, and becomes the migration boundary.

## Rationale

Portable offline recovery with a clear secret-zero boundary.

## Consequences

Keys exist in process memory while TLS is active; memory compromise remains key compromise.

## Security implications

Modes, core-dump policy, zeroizing wrappers, canary tests, and separate recovery identity are required.

## Reliability implications

Initial import is all-or-nothing and syncs generation and parent directories where the platform supports directory sync. Pointer publication happens only after the complete generation is durable. Old generations remain through renewal/storage failure and neither current nor previous may be garbage-collected.

## Operational implications

Rotation and restore runbooks are mandatory.

## Migration implications

Recipient rotation writes new envelopes and verifies restore before old retirement.

## Alternatives rejected

Raw key files and custom cryptographic envelopes.

## Revisit conditions

KMS/HSM requirement or platform key isolation need.
