# TLS key recovery runbook

This runbook covers Phase 2 BYO certificate generations. It does not cover ACME, online rotation, or clustered storage.

## Security boundary

The state directory contains public certificate chains and age-encrypted private keys. The age X25519 identity is the recovery secret and must be stored separately. Possession of both the state backup and identity permits private-key recovery; possession of either one alone should not.

Never commit identities, plaintext private keys, production certificates, state archives, or command output containing site paths to Git. Disable core dumps for the proxy process and recovery host.

## Initial identity ceremony

The built-in identity-generation command is deferred. Generate an age X25519 identity with a compatible, reviewed age tool on an offline administration host. For example:

```text
age-keygen -o /secure/aegisproxy-recovery.agekey
age-keygen -y /secure/aegisproxy-recovery.agekey
```

The second command prints the public `age1...` recipient. It is safe to supply that recipient to certificate import. The identity file is not safe to print or copy into configuration.

On Linux, set the identity and plaintext-key source files to mode `0600`, owned by the recovery operator. On Windows, restrict their ACLs to the recovery operator and the dedicated proxy service identity; the application cannot currently prove Windows ACL equivalence.

Keep at least two offline, encrypted copies of the identity under separate access control. Record custodians and test retrieval without exposing the identity in tickets or logs.

## Import

Use absolute `file://` references. Existing certificate IDs are rejected; Phase 2 never overwrites an active generation.

```text
rust-proxy cert import \
  --state-dir /var/lib/aegisproxy \
  --id public-site \
  --host example.com \
  --host www.example.com \
  --certificate-chain file:///secure/fullchain.pem \
  --private-key file:///secure/private-key.pem \
  --recipient age1REPLACE_WITH_PUBLIC_RECIPIENT
```

Import validates the certificate chain, validity period, configured names, key match, input bounds, and recipient before atomically exposing the new ID. It prints safe `certificate_chain` and encrypted `private_key` references for the TOML certificate entry.

Before deleting the plaintext source, perform the offline verification below. Then securely retire the source according to the storage medium and organizational policy; ordinary file deletion is not guaranteed to erase flash or copy-on-write storage.

## Configuration

The runtime decryption identity is an injected secret reference, not the recipient and not inline key text:

```toml
[tls]
identity = "file:///run/secrets/aegisproxy-recovery.agekey"

[[certificates]]
id = "public-site"
hosts = ["example.com", "www.example.com"]
certificate_chain = "file:///var/lib/aegisproxy/certificates/public-site/generations/REPLACE/chain.pem"
private_key = "file:///var/lib/aegisproxy/certificates/public-site/generations/REPLACE/key.age"
```

Use the exact generation references printed by import. Do not hand-edit `current`, generation metadata, the certificate chain, or the encrypted key.

## Backup

Back up the complete `certificates/` directory using a stopped-process or filesystem-consistent snapshot. Back up the age identity separately; never put it in the same archive, volume, or access-control domain as proxy state.

Phase 2 has no built-in backup command, archive authentication, or retention manager. Record backup hashes and storage metadata in the operator system, not inside the archive. Backup/restore tooling and tamper-evident manifests remain later-phase work.

## Offline restore drill

Restore state into an isolated absolute scratch directory on a trusted host. Do not start listeners or overwrite live state during the drill.

```text
rust-proxy cert list --state-dir /restore/aegisproxy
rust-proxy cert inspect --state-dir /restore/aegisproxy public-site
rust-proxy cert inspect \
  --state-dir /restore/aegisproxy \
  --identity file:///secure/aegisproxy-recovery.agekey \
  public-site
```

Success requires `private_key_verified = true`. The command decrypts the envelope in memory, rechecks the key/certificate match, validity, and host coverage, and prints no private material. Compare ID, generation, hosts, issuer, and expiry against the expected inventory.

Repeat for every active certificate. A list or metadata-only inspect is not a recovery proof.

## Failure behavior

- Missing, unreadable, over-permissive (Unix), malformed, or wrong age identities fail verification and startup.
- Corrupted metadata, chain, encrypted key, mismatched key, wrong-domain certificate, expired certificate, or unsupported PEM fails closed.
- Startup preparation completes before public listeners bind; invalid certificate state does not cause plaintext fallback.
- Phase 2 import never replaces an existing ID. A failed import leaves the existing ID untouched.
- Do not delete the last working identity or state backup after a failed drill.

## Rotation limitations

Recipient rotation, atomic replacement of an existing stored ID, generation retention policy, ACME renewal, and online reload are not implemented in Phase 2. Until those phases land, create a new certificate ID and update validated configuration during a controlled maintenance window. Retain the old ID and identity until the new generation passes offline verification and runtime TLS checks.

Escalate identity loss as loss of recoverability. It cannot be bypassed safely; issue a new private key and certificate instead of weakening envelope or TLS validation.
