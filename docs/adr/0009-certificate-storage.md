# ADR-0009: Encrypted certificate storage

Status: Accepted
Date: 2026-07-16

## Context

BYO and managed private keys must survive restart without raw disk storage.

## Constraints

No plaintext key logging/export; prior valid generation retained.

## Options considered

Age-encrypted files; OS keyring only; plaintext PEM; external vault required.

## Decision

Use age-encrypted generation files with externally supplied decryption identity and atomic `current` pointer.

## Rationale

Portable offline recovery with a clear secret-zero boundary.

## Consequences

Keys exist in process memory while TLS is active; memory compromise remains key compromise.

## Security implications

Modes, core-dump policy, zeroizing wrappers, canary tests, and separate recovery identity are required.

## Reliability implications

Old generation remains through renewal/storage failure.

## Operational implications

Rotation and restore runbooks are mandatory.

## Migration implications

Recipient rotation writes new envelopes and verifies restore before old retirement.

## Alternatives rejected

Raw key files and custom cryptographic envelopes.

## Revisit conditions

KMS/HSM requirement or platform key isolation need.
