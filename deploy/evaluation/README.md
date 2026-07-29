# Local browser evaluation

This stack is for disposable evaluation on a Linux Docker Engine host only. It uses host
networking so the proxy can preserve its loopback-only browser boundary. Do not deploy it to a
shared or production host: the imported realm contains fixed, public evaluation credentials.

From the repository root:

```text
docker compose -f compose.evaluation.yaml up --build --wait
docker compose -f compose.evaluation.yaml exec proxy \
  rust-proxy web setup-token --socket /var/lib/aegisproxy/admin/admin.sock
```

Open `http://localhost:9090`, sign in to the evaluation realm as `admin` with password
`aegis-evaluation-only`, then redeem the one-use setup token. The Keycloak management-only
bootstrap account is `evaluation-bootstrap-admin` with password
`aegis-evaluation-bootstrap-only`.

Create an HTTP Proxy Host with:

- domain: `proxy.localhost`
- forward host/IP: `127.0.0.1`
- forward port: `9000`
- protocol: `http`
- automatic HTTPS: off
- access policy: none
- enabled: on

Validate, preview, create, and activate it, then verify:

```text
curl --fail --header 'Host: proxy.localhost' http://127.0.0.1:8080/
```

Normal `rust-proxy run --config ...` startup recompiles durable typed objects over the mounted TOML
base and resumes or creates a bound revision. Restart the proxy container and repeat the `curl`
check to verify the same Host without another mutation. Invalid reconciliation fails startup
instead of silently serving only the TOML routes.

Keycloak is available only at `https://localhost:9443`, browser administration only at
`http://localhost:9090`, proxy traffic only at `127.0.0.1:8080`, and the sample upstream only at
`127.0.0.1:9000`. A generated 30-day CA and certificate live in a named volume; AegisProxy trusts
that CA through its existing OIDC `ca_bundle` secret reference.

Docker Desktop's host networking may keep these loopback listeners inside its Linux VM. The
supported operator workflow remains a native Linux Docker Engine host.

Remove all disposable state and generated secrets with:

```text
docker compose -f compose.evaluation.yaml down --volumes
```
