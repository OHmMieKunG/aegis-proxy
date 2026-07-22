# Troubleshooting

## `Address already in use`

Another process owns listener or upstream port. Identify it before retrying:

```bash
ss -ltnp | grep ':9000\|:8080\|:8443'
```

Do not start a second fixture on same port or assume existing service contains test content.

## `502 Bad Gateway`

Route matched, but configured upstream failed. Check upstream listener, scheme, port, CIDR policy,
TLS name/CA, and timeout. A successful HTML response listing repository files means existing Python
server is serving wrong directory; proxy itself may be working.

## Configuration file missing

`could not read configuration: No such file or directory` means exact `--config` path does not
exist. Create file first and validate it; shell snippets do not create files unless they include an
explicit write step.

## Secret file permissions too broad

On Unix, secret files must not be group/world accessible:

```bash
chmod 600 /absolute/path/to/secret
chmod 700 /absolute/path/to/secret-directory
```

Use only files created for this service. Never weaken checks on real shared secret files.

## TLS curl errors

`curl --resolve` still needs a URL:

```bash
curl --cacert /tmp/aegis-tls/cert.pem \
  --resolve example.test:8443:127.0.0.1 \
  https://example.test:8443/
```

## Old Cargo rejects edition 2024

Install and select stable Rust 1.88 or newer. Repository `rust-toolchain.toml` is authoritative.

## Admin socket unavailable

Confirm daemon config/state directory and socket path, parent mode 0700, peer UID policy, and audit
key. Never bridge private socket to unauthenticated/public TCP.
