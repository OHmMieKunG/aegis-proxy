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

Use age-encrypted generation files with externally supplied decryption identity and atomic `current` pointer. Phase 2 imports activate a new certificate ID by atomically renaming its complete staged directory and reject replacement; later rotation must retain old generations and provide platform-correct pointer replacement.

## Rationale

Portable offline recovery with a clear secret-zero boundary.

## Consequences

Keys exist in process memory while TLS is active; memory compromise remains key compromise.

## Security implications

Modes, core-dump policy, zeroizing wrappers, canary tests, and separate recovery identity are required.

## Reliability implications

Initial import is all-or-nothing. Old generations remain through later renewal/storage failure once rotation is introduced.

## Operational implications

Rotation and restore runbooks are mandatory.

## Migration implications

Recipient rotation writes new envelopes and verifies restore before old retirement.

## Alternatives rejected

Raw key files and custom cryptographic envelopes.

## Revisit conditions

KMS/HSM requirement or platform key isolation need.
