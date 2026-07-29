import { useState } from "react";
import {
  Form,
  redirect,
  useActionData,
  useLoaderData,
  useNavigate,
  useOutletContext,
} from "react-router-dom";
import {
  activateProxyHost,
  activateRevision,
  auditRecords,
  createBackup,
  createProxyHost,
  createResource,
  deleteResource,
  health,
  listPolicies,
  listProxyHosts,
  listResource,
  loadSession,
  permits,
  previewProxyHost,
  previewRevision,
  providers,
  redeemSetup,
  revisions,
  rollbackRevision,
  status,
  updateResource,
  validateProxyHost,
  validateRestore,
  webStatus,
  type Action,
  type ProxyHost,
  type Resource,
  type Session,
  type Stored,
} from "./api";

async function authorized(action: Action) {
  const session = await loadSession();
  if (!permits(session, action)) throw new Response("Forbidden", { status: 403 });
  return session;
}

function Json({ value }: { value: unknown }) {
  return <pre>{JSON.stringify(value, null, 2)}</pre>;
}

export async function dashboardLoader() {
  await authorized("read_status");
  const [node, history, source] = await Promise.all([status(), revisions(), providers()]);
  return { node, history, source };
}

export function Dashboard() {
  const { node, history, source } = useLoaderData() as Awaited<
    ReturnType<typeof dashboardLoader>
  >;
  return (
    <section>
      <div className="page-heading">
        <div>
          <p className="eyebrow">OVERVIEW</p>
          <h2>Dashboard</h2>
          <p>Live control-plane state, without hidden writes.</p>
        </div>
        <span className={node.administration_ready ? "state good" : "state bad"}>
          {node.administration_ready ? "Ready" : "Attention"}
        </span>
      </div>
      <div className="metrics">
        <article><span>Active revision</span><strong>{node.active_revision}</strong></article>
        <article><span>Uptime</span><strong>{node.uptime_secs}s</strong></article>
        <article><span>Managed certificates</span><strong>{node.managed_certificates}</strong></article>
        <article><span>Provider records</span><strong>{source.length}</strong></article>
      </div>
      <article className="panel">
        <h3>Recent revisions</h3>
        <ul className="plain-list">
          {history.slice(0, 5).map((item) => (
            <li key={item.id}><code>{item.id}</code><span>{item.source}</span></li>
          ))}
        </ul>
      </article>
    </section>
  );
}

export function Setup() {
  const session = useOutletContext<Session>();
  const navigate = useNavigate();
  const [error, setError] = useState("");
  if (session.owner_id !== null) {
    return <section><h2>Setup complete</h2><p>This identity is already bound.</p></section>;
  }
  return (
    <section className="narrow">
      <p className="eyebrow">FIRST RUN</p>
      <h2>Bind this administrator</h2>
      <p>Generate a setup token from the private Unix CLI, then redeem it once here.</p>
      <form
        onSubmit={(event) => {
          event.preventDefault();
          const token = new FormData(event.currentTarget).get("setup_token");
          void redeemSetup(String(token))
            .then(() => navigate("/", { replace: true }))
            .catch((reason: Error) => setError(reason.message));
        }}
      >
        <label>Setup token<input name="setup_token" required minLength={43} maxLength={43} autoComplete="off" /></label>
        <button>Complete setup</button>
      </form>
      {error && <p role="alert" className="error">{error}</p>}
    </section>
  );
}

export async function proxyHostLoader() {
  const session = await authorized("read_proxy_hosts");
  const [hosts, policies, node] = await Promise.all([
    listProxyHosts(),
    listPolicies(),
    status(),
  ]);
  return { session, hosts, policies, revision: node.active_revision };
}

function proxyObject(form: FormData, owner: string): ProxyHost {
  const domain = String(form.get("domain") ?? "").trim().toLowerCase();
  const id = `proxy-${domain.replace(/[^a-z0-9]+/g, "-").replace(/-+$/g, "")}`.slice(0, 63);
  return {
    api_version: "v1",
    metadata: { id, owner_id: owner },
    spec: {
      domain,
      forward_host: String(form.get("forward_host") ?? "").trim(),
      forward_port: Number(form.get("forward_port")),
      forward_protocol: String(form.get("forward_protocol")) as "http" | "https",
      automatic_https: String(form.get("automatic_https")) as "disabled" | "managed",
      access_policy_ref: String(form.get("access_policy_ref") || "") || null,
      enabled: form.get("enabled") === "on",
    },
  };
}

export async function proxyHostAction({ request }: { request: Request }) {
  const session = await authorized("read_proxy_hosts");
  if (!session.owner_id) throw new Response("Setup required", { status: 403 });
  const form = await request.formData();
  const intent = String(form.get("_intent"));
  const revision = String(form.get("revision"));
  if (intent === "activate") {
    await authorized("activate_typed_candidate");
    await activateProxyHost(String(form.get("candidate")), revision);
    return { kind: "activated" };
  }
  const object = proxyObject(form, session.owner_id);
  if (intent === "validate") return { kind: "validation", data: await validateProxyHost(object) };
  if (intent === "preview") return { kind: "preview", data: await previewProxyHost(object) };
  await authorized("create_proxy_host");
  const created = await createProxyHost(object, revision);
  return { kind: "created", data: created, candidate: created.candidate.id };
}

export function ProxyHosts() {
  const { session, hosts, policies, revision } = useLoaderData() as Awaited<
    ReturnType<typeof proxyHostLoader>
  >;
  const result = useActionData() as
    | { kind: string; data?: unknown; candidate?: string }
    | undefined;
  return (
    <section>
      <div className="page-heading"><div><p className="eyebrow">ROUTING</p><h2>Proxy Hosts</h2><p>Seven common fields compile into a safe candidate.</p></div></div>
      <div className="split">
        <article className="panel">
          <h3>New Proxy Host</h3>
          <Form method="post">
            <input type="hidden" name="revision" value={revision} />
            <label>Domain<input name="domain" required maxLength={253} placeholder="app.example.com" /></label>
            <div className="field-row">
              <label>Forward host or IP<input name="forward_host" required maxLength={253} /></label>
              <label>Forward port<input name="forward_port" type="number" min="1" max="65535" defaultValue="8080" required /></label>
            </div>
            <label>Upstream protocol<select name="forward_protocol" defaultValue="http"><option>http</option><option>https</option></select></label>
            <label>HTTPS<select name="automatic_https" defaultValue="disabled"><option value="disabled">Disabled</option><option value="managed">Managed</option></select></label>
            <label>Access policy<select name="access_policy_ref" defaultValue=""><option value="">None</option>{policies.map(({ object }) => <option key={object.metadata.id}>{object.metadata.id}</option>)}</select></label>
            <label className="check"><input name="enabled" type="checkbox" defaultChecked />Enabled</label>
            <details><summary>Advanced controls</summary><p>The API derives listener, route, endpoint, timeout, and recovery defaults.</p></details>
            <div className="actions">
              <button name="_intent" value="validate" className="quiet">Validate</button>
              <button name="_intent" value="preview" className="quiet">Preview &amp; diff</button>
              {permits(session, "create_proxy_host") && <button name="_intent" value="create">Create candidate</button>}
            </div>
          </Form>
          {result?.data !== undefined && <Json value={result.data} />}
          {result?.candidate && permits(session, "activate_typed_candidate") && (
            <Form method="post" onSubmit={(event) => { if (!confirm("Activate this exact candidate?")) event.preventDefault(); }}>
              <input type="hidden" name="revision" value={revision} />
              <input type="hidden" name="candidate" value={result.candidate} />
              <button name="_intent" value="activate">Activate candidate</button>
            </Form>
          )}
        </article>
        <article className="panel">
          <h3>Current desired state</h3>
          <ul className="object-list">
            {hosts.map(({ generation, object }) => (
              <li key={object.metadata.id}><div><strong>{object.spec.domain}</strong><span>{object.spec.forward_protocol}://{object.spec.forward_host}:{object.spec.forward_port}</span></div><span>g{generation}</span></li>
            ))}
          </ul>
        </article>
      </div>
    </section>
  );
}

const readAction: Record<Resource, Action> = {
  "stream-hosts": "read_stream_hosts",
  certificates: "read_certificate_objects",
  "access-policies": "read_access_policies",
  users: "read_users",
};
const createAction: Record<Resource, Action> = {
  "stream-hosts": "create_stream_host",
  certificates: "create_certificate",
  "access-policies": "create_access_policy",
  users: "create_user",
};
const updateAction: Record<Resource, Action> = {
  "stream-hosts": "update_stream_host",
  certificates: "update_certificate",
  "access-policies": "update_access_policy",
  users: "update_user",
};
const deleteAction = {
  "stream-hosts": "delete_stream_host",
  certificates: "delete_certificate",
  "access-policies": "delete_access_policy",
} as const;

export async function resourceLoader(resource: Resource) {
  const session = await authorized(readAction[resource]);
  const [items, node] = await Promise.all([listResource(resource), status()]);
  return { session, items, revision: node.active_revision };
}

export function actionFor(resource: Resource) {
  return async ({ request }: { request: Request }) => {
    const form = await request.formData();
    const intent = String(form.get("_intent"));
    const revision = String(form.get("revision"));
    const object = JSON.parse(String(form.get("object")));
    if (intent === "create") {
      await authorized(createAction[resource]);
      await createResource(resource, object, revision);
    } else if (intent === "update") {
      await authorized(updateAction[resource]);
      await updateResource(resource, String(form.get("id")), object, Number(form.get("generation")), revision);
    } else if (intent === "delete" && resource !== "users") {
      await authorized(deleteAction[resource]);
      await deleteResource(resource, String(form.get("id")), Number(form.get("generation")), revision);
    } else {
      throw new Response("Invalid action", { status: 400 });
    }
    return redirect(`/${resource}`);
  };
}

const templates: Record<Resource, (owner: string) => unknown> = {
  "stream-hosts": (owner) => ({ api_version: "v1", metadata: { id: "stream-example", owner_id: owner }, spec: { listen_port: 8443, protocol: "tcp", forward_host: "127.0.0.1", forward_port: 443, sni_hosts: [], enabled: true } }),
  certificates: (owner) => ({ api_version: "v1", metadata: { id: "certificate-example", owner_id: owner }, spec: { enabled: true, shared_with: [], certificate_ref: "existing-certificate" } }),
  "access-policies": (owner) => ({ api_version: "v1", metadata: { id: "policy-example", owner_id: owner }, spec: { enabled: true, shared_with: [], middlewares: ["existing-middleware"] } }),
  users: () => ({ api_version: "v1", metadata: { id: "user-example", owner_id: "user-example" }, spec: { display_name: "Example user", role: "viewer", enabled: true } }),
};

export function ResourcePage({ resource }: { resource: Resource }) {
  const { session, items, revision } = useLoaderData() as {
    session: Session; items: Array<Stored<unknown>>; revision: string;
  };
  const title = resource.split("-").map((word) => word[0].toUpperCase() + word.slice(1)).join(" ");
  return (
    <section>
      <div className="page-heading"><div><p className="eyebrow">TYPED OBJECTS</p><h2>{title}</h2><p>Every write carries the exact active revision and object generation.</p></div></div>
      {permits(session, createAction[resource]) && (
        <article className="panel narrow">
          <h3>Create</h3>
          <Form method="post">
            <input type="hidden" name="revision" value={revision} />
            <label>Typed API object<textarea name="object" rows={12} defaultValue={JSON.stringify(templates[resource](session.owner_id ?? ""), null, 2)} required /></label>
            <button name="_intent" value="create">Create</button>
          </Form>
        </article>
      )}
      <div className="cards">
        {items.map((item) => {
          const object = item.object as { metadata: { id: string } };
          return (
            <article className="panel" key={object.metadata.id}>
              <h3>{object.metadata.id}</h3><p>Generation {item.generation}</p>
              <Json value={item.object} />
              {permits(session, updateAction[resource]) && (
                <details><summary>Edit exact object</summary>
                  <Form method="post">
                    <input type="hidden" name="revision" value={revision} />
                    <input type="hidden" name="id" value={object.metadata.id} />
                    <input type="hidden" name="generation" value={item.generation} />
                    <label>Typed API object<textarea name="object" rows={12} defaultValue={JSON.stringify(item.object, null, 2)} required /></label>
                    <button name="_intent" value="update">Update</button>
                    {resource !== "users" && permits(session, deleteAction[resource]) && <button name="_intent" value="delete" className="danger" onClick={(event) => { if (!confirm(`Delete ${object.metadata.id}?`)) event.preventDefault(); }}>Delete</button>}
                  </Form>
                </details>
              )}
            </article>
          );
        })}
      </div>
    </section>
  );
}

export async function healthLoader() {
  await authorized("read_status");
  const [details, source] = await Promise.all([health(), providers()]);
  return { details, source };
}

export function HealthPage() {
  const data = useLoaderData() as Awaited<ReturnType<typeof healthLoader>>;
  return <section><div className="page-heading"><div><p className="eyebrow">RUNTIME</p><h2>Health</h2></div><span className={data.details.administration_ready ? "state good" : "state bad"}>{data.details.status}</span></div><div className="split"><article className="panel"><h3>Certificates</h3><Json value={data.details.certificates} /></article><article className="panel"><h3>Providers</h3><Json value={data.source} /></article></div></section>;
}

export async function logsLoader() {
  await authorized("read_audit");
  return auditRecords();
}

export function Logs() {
  const records = useLoaderData() as Awaited<ReturnType<typeof logsLoader>>;
  return <section><div className="page-heading"><div><p className="eyebrow">DURABLE AUDIT</p><h2>Logs</h2><p>Authenticated audit records only; no operational stream is exposed.</p></div></div><div className="table-wrap"><table><thead><tr><th>Sequence</th><th>Actor</th><th>Action</th><th>Resource</th><th>Outcome</th></tr></thead><tbody>{records.map((record) => <tr key={record.sequence}><td>{record.sequence}</td><td>{record.actor_type}:{record.actor_id}</td><td>{record.action}</td><td>{record.resource_id}</td><td>{record.outcome}</td></tr>)}</tbody></table></div></section>;
}

export async function revisionsLoader() {
  await authorized("read_revisions");
  const [items, node] = await Promise.all([revisions(), status()]);
  return { items, revision: node.active_revision, session: await loadSession() };
}

export async function revisionsAction({ request }: { request: Request }) {
  const form = await request.formData();
  const intent = String(form.get("_intent"));
  const id = String(form.get("id"));
  const revision = String(form.get("revision"));
  if (intent === "preview") return { preview: await previewRevision(id) };
  if (intent === "activate") {
    await authorized("activate_typed_candidate");
    await activateRevision(id, revision);
  } else {
    await authorized("rollback_typed_revision");
    await rollbackRevision(id, revision);
  }
  return redirect("/revisions");
}

export function Revisions() {
  const { items, revision, session } = useLoaderData() as Awaited<ReturnType<typeof revisionsLoader>>;
  const result = useActionData() as { preview?: unknown } | undefined;
  return <section><div className="page-heading"><div><p className="eyebrow">IMMUTABLE HISTORY</p><h2>Revisions</h2></div></div>{result?.preview !== undefined && <Json value={result.preview} />}<div className="cards">{items.map((item) => <article className="panel" key={item.id}><h3><code>{item.id}</code></h3><p>{item.source}</p><Form method="post"><input type="hidden" name="id" value={item.id} /><input type="hidden" name="revision" value={revision} /><button className="quiet" name="_intent" value="preview">Preview</button>{permits(session, "activate_typed_candidate") && <button name="_intent" value="activate" onClick={(event) => { if (!confirm("Activate this candidate?")) event.preventDefault(); }}>Activate</button>}{permits(session, "rollback_typed_revision") && <button name="_intent" value="rollback" onClick={(event) => { if (!confirm("Create and activate a forward rollback revision?")) event.preventDefault(); }}>Forward rollback</button>}</Form></article>)}</div></section>;
}

export async function backupsAction({ request }: { request: Request }) {
  const form = await request.formData();
  const node = await status();
  if (form.get("_intent") === "create") {
    await authorized("create_backup");
    await createBackup(String(form.get("output")), node.active_revision);
  } else {
    await authorized("validate_restore");
    await validateRestore(String(form.get("input")), String(form.get("identity")), node.active_revision);
  }
  return { success: true };
}

export function Backups() {
  const session = useOutletContext<Session>();
  const result = useActionData() as { success?: boolean } | undefined;
  return <section><div className="page-heading"><div><p className="eyebrow">RECOVERY</p><h2>Backups</h2><p>Creation and validation only. Restore remains an explicit operator procedure.</p></div></div>{result?.success && <p className="success" role="status">Operation completed.</p>}<div className="split">{permits(session, "create_backup") && <article className="panel"><h3>Create encrypted archive</h3><Form method="post"><label>Absolute output path<input name="output" required /></label><button name="_intent" value="create">Create backup</button></Form></article>}{permits(session, "validate_restore") && <article className="panel"><h3>Validate archive</h3><Form method="post"><label>Absolute archive path<input name="input" required /></label><label>Identity secret reference<input name="identity" required placeholder="env://AEGIS_AGE_IDENTITY" /></label><button name="_intent" value="validate">Validate only</button></Form></article>}</div></section>;
}

export async function settingsLoader() {
  await authorized("read_status");
  const [node, web, session, history] = await Promise.all([status(), webStatus(), loadSession(), revisions()]);
  return { node, web, session, active: history.find((item) => item.id === node.active_revision) };
}

export function Settings() {
  const data = useLoaderData() as Awaited<ReturnType<typeof settingsLoader>>;
  return <section><div className="page-heading"><div><p className="eyebrow">READ ONLY</p><h2>Settings</h2><p>Web, session, active configuration, and process information.</p></div></div><Json value={data} /></section>;
}
