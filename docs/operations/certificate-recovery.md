# Certificate key recovery

Static and ACME-managed private keys are stored as age-encrypted generations. Decryption identity
is external `env://` or absolute `file:///` material. Loss of every matching identity makes stored
keys unrecoverable.

## Identity ceremony

Generate X25519 identity with approved age tooling. Put only public recipient in configuration;
inject private identity through mode-restricted secret source. Store recovery copy separately from
encrypted proxy state. Never commit or print it.

```toml
[tls]
identity = "file:///run/secrets/aegisproxy-age-identity"
state_encryption_recipients = ["age1REPLACE"]
```

## Static import

Certificate chain and key files must be private and absolute. Import creates a new immutable
certificate ID; it never overwrites existing ID.

```bash
chmod 600 /tmp/aegis-tls/cert.pem /tmp/aegis-tls/key.pem
rust-proxy cert import \
  --state-dir /var/lib/aegisproxy \
  --id public-site \
  --host example.test \
  --certificate-chain file:///tmp/aegis-tls/cert.pem \
  --private-key file:///tmp/aegis-tls/key.pem \
  --recipient age1REPLACE
```

Validation checks key match, validity, and hostname before encryption/publication. Failed import
leaves active state unchanged.

## Offline verification

Stop daemon or use isolated state copy:

```bash
rust-proxy cert inspect \
  --state-dir /var/lib/aegisproxy \
  --identity file:///run/secrets/aegisproxy-age-identity \
  public-site
```

Command decrypts and validates key without printing it.

## Backup and rotation

Use encrypted backup workflow and separately escrowed identity. Static import cannot replace same
ID; rotate through new ID and validated listener change. Managed ACME generations rotate atomically
and retain previous valid generation. Account-key rollover and revocation remain external/new-issuer
procedures described in [ACME operations](acme.md).

Process compromise can expose active keys in memory. Drain node, revoke externally, rotate affected
identities/credentials, restore clean artifact, and preserve evidence. See
[incident response](incident-response.md).
