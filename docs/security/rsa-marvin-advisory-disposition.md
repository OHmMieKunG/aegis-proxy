# RUSTSEC-2023-0071 Disposition

## Advisory

- ID: RUSTSEC-2023-0071
- Affected crate: `rsa`
- Resolved version: none currently available
- Dependency path:
  `rust-proxy -> aegisproxy-admin -> openidconnect -> rsa`

## Relevant private-key paths

AegisProxy handles TLS certificate private keys. Those keys are parsed as
Rustls `PrivateKeyDer` values and used through Rustls' `aws_lc_rs`
cryptographic provider.

The `SectionKind::RsaPrivateKey` occurrence in `proxy-tls/src/store.rs`
identifies a PKCS#1 PEM section. It is not the RustCrypto
`rsa::RsaPrivateKey` type.

No dependency path from `aegisproxy-tls` to RustCrypto `rsa` has been
identified.

## OIDC usage

AegisProxy uses:

- authorization-code flow;
- PKCE;
- client-secret authentication;
- provider metadata and JWKS;
- provider public-key ID-token verification.

AegisProxy does not use:

- `private_key_jwt`;
- RSA client assertions;
- RustCrypto RSA signing;
- RustCrypto RSA decryption;
- any remotely observable RustCrypto RSA private-key operation.

## Reachability decision

The vulnerable crate is present in the production dependency graph through
`openidconnect`, but the affected private-key operation is not reachable
through AegisProxy's current OIDC implementation.

Status: temporarily accepted as non-reachable.

## Invalidating changes

Re-review is mandatory if any change introduces:

- `private_key_jwt`;
- JWT client assertions signed by AegisProxy;
- RSA-encrypted OIDC tokens;
- direct use of `rsa::RsaPrivateKey`;
- direct calls to RustCrypto RSA signing or decryption APIs;
- a change in the TLS cryptographic provider;
- an updated advisory or patched dependency.

Review deadline: 2026-11-05.
