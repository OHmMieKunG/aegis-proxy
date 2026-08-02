import { useState } from "react";
import {
  Form,
  Link,
  redirect,
  useActionData,
  useLoaderData,
  useNavigate,
  useNavigation,
  useOutletContext,
} from "react-router-dom";
import {
  ApiError,
  activateProxyHost,
  activateRevision,
  auditRecords,
  createBackup,
  createProxyHost,
  createProxyHostDraft,
  createResource,
  deleteProxyHost,
  deleteResource,
  discardProxyHostDraft,
  getProxyHost,
  health,
  listPolicies,
  listProxyHostDrafts,
  listProxyHosts,
  listResource,
  loadSession,
  permits,
  previewRevision,
  promoteProxyHostDraft,
  proxyHostApplicationState,
  providers,
  redeemSetup,
  revisions,
  rollbackRevision,
  status,
  updateProxyHost,
  updateProxyHostDraft,
  updateResource,
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

type ProxyHostOperation = "created" | "updated" | "enabled" | "disabled" | "deleted" | "draft-saved" | "draft-discarded";

type ProxyHostActionResult = {
  kind: "error" | "recovery-required" | "saved-not-active" | "status-unavailable" | "audit-unavailable";
  heading: string;
  message: string;
  reload: boolean;
};

function recoveryRequiredResult(): ProxyHostActionResult {
  return {
    kind: "recovery-required",
    heading: "Storage recovery required",
    message:
      "A previous save could not be confirmed. Proxy Host changes are temporarily blocked until AegisProxy restarts and validates the stored state.",
    reload: false,
  };
}

export async function proxyHostLoader({ request }: { request: Request }) {
  const session = await authorized("read_proxy_hosts");
  const [hosts, drafts, node, application] = await Promise.all([
    listProxyHosts(),
    listProxyHostDrafts(),
    status(),
    proxyHostApplicationState(),
  ]);
  const result = new URL(request.url).searchParams.get("result");
  return {
    session,
    hosts,
    drafts,
    application,
    revision: node.active_revision,
    result: ["created", "updated", "enabled", "disabled", "deleted", "draft-saved", "draft-discarded"].includes(result ?? "")
      ? (result as ProxyHostOperation)
      : null,
  };
}

function proxyObject(form: FormData, owner: string, id?: string): ProxyHost {
  const domain = String(form.get("domain") ?? "").trim().toLowerCase();
  const objectId =
    id ??
    `proxy-${domain.replace(/[^a-z0-9]+/g, "-").replace(/-+$/g, "")}`.slice(0, 63);
  return {
    api_version: "v1",
    metadata: { id: objectId, owner_id: owner },
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

function conflictResult(error: unknown, operation?: ProxyHostOperation): ProxyHostActionResult {
  if (error instanceof ApiError) {
    if (error.code === "recovery_required") return recoveryRequiredResult();
    if (error.code === "audit_failed_after_save") {
      return {
        kind: "audit-unavailable",
        heading: "Saved but audit unavailable",
        message: `The Proxy Host was ${operation ?? "changed"} in saved configuration, but the audit result could not be confirmed. The change was not activated and previously active routing remains in service. Further changes are blocked until AegisProxy restarts and validates its audit log.`,
        reload: false,
      };
    }
    if (error.code === "audit_failed") {
      return {
        kind: "audit-unavailable",
        heading: "Audit unavailable",
        message:
          "AegisProxy could not durably record the operation. Reload after the service recovers its audit log before making another change.",
        reload: true,
      };
    }
    if (error.code === "candidate_persistence_failed") {
      return {
        kind: "error",
        heading: "Save failed",
        message: "The compiled change could not be saved. Desired configuration and active routing are unchanged; retry is allowed.",
        reload: false,
      };
    }
    if (error.code === "persistence_failed") {
      return {
        kind: "error",
        heading: "Save failed",
        message: "The Proxy Host was not saved and active routing is unchanged. Retry is allowed.",
        reload: false,
      };
    }
    if (error.status === 409 || error.status === 412) {
      return {
        kind: "error",
        heading: "Conflict detected",
        message: "This Proxy Host changed after you opened it. Reload the current host and try again.",
        reload: true,
      };
    }
    if (error.status === 400 || error.status === 422) {
      return {
        kind: "error",
        heading: "Validation failed",
        message: "The Proxy Host is invalid or conflicts with another route. Review the fields and try again.",
        reload: false,
      };
    }
    if (error.status === 404) {
      return {
        kind: "error",
        heading: "Proxy Host not found",
        message: "The Proxy Host may have been deleted. Reload the host list.",
        reload: true,
      };
    }
    if (error.status === 503) {
      return {
        kind: "error",
        heading: "Save status unavailable",
        message:
          "AegisProxy could not confirm the saved state. Active traffic was not replaced; reload before making another change.",
        reload: true,
      };
    }
  }
  return {
    kind: "error",
    heading: "Save status unavailable",
    message:
      "The browser could not confirm whether the Proxy Host was saved. Activation was not attempted and active routing is unchanged. Reload the stored state before making another change.",
    reload: true,
  };
}

function activationFailure(operation: ProxyHostOperation, error: unknown): ProxyHostActionResult {
  const changed =
    operation === "deleted"
      ? "The Proxy Host was deleted from saved configuration"
      : `The Proxy Host was ${operation} in saved configuration`;
  const conflict = error instanceof ApiError &&
    ["revision_conflict", "object_conflict", "candidate_conflict"].includes(error.code ?? "");
  if (conflict) {
    return {
      kind: "saved-not-active",
      heading: "Conflict detected",
      message: `${changed}, but another change won the activation check. Refresh to determine which configuration is active.`,
      reload: true,
    };
  }
  return {
    kind: "saved-not-active",
    heading: "Activation failed",
    message: `${changed}, but the change is not active. The previously active routing remains in service.`,
    reload: true,
  };
}

function activationStatusUnavailable(operation: ProxyHostOperation): ProxyHostActionResult {
  const changed = operation === "deleted"
    ? "The Proxy Host was deleted from saved configuration."
    : `The Proxy Host was ${operation} in saved configuration.`;
  return {
    kind: "status-unavailable",
    heading: "Activation status unavailable",
    message: `${changed} The browser could not confirm whether activation completed. Refresh to determine which configuration is active.`,
    reload: true,
  };
}

async function saveAndApply(
  mutation: Promise<{ candidate: { id: string } }>,
  revision: string,
  operation: ProxyHostOperation,
) {
  let candidate: string;
  try {
    candidate = (await mutation).candidate.id;
  } catch (error) {
    return conflictResult(error, operation);
  }
  try {
    await activateProxyHost(candidate, revision);
  } catch (error) {
    if (error instanceof ApiError && error.code === "recovery_required") {
      return recoveryRequiredResult();
    }
    if (error instanceof ApiError && error.code === "rollback_failed") {
      return {
        kind: "recovery-required",
        heading: "Rollback failed",
        message:
          "Previously active routing was restored in memory, but durable rollback could not be confirmed. Further changes are blocked until AegisProxy restarts and recovers its activation state.",
        reload: false,
      };
    }
    if (error instanceof ApiError && error.code === "audit_failed_after_activation") {
      return {
        kind: "audit-unavailable",
        heading: "Changes active; audit unavailable",
        message:
          "The intended routing change is active, but its terminal audit record could not be confirmed. Further changes are blocked until AegisProxy restarts and validates its audit log.",
        reload: false,
      };
    }
    return error instanceof ApiError &&
      ["activation_failed", "revision_conflict", "object_conflict", "candidate_conflict"].includes(error.code ?? "")
      ? activationFailure(operation, error)
      : activationStatusUnavailable(operation);
  }
  return redirect(`/proxy-hosts?result=${operation}`);
}

function generation(form: FormData): number {
  const value = Number(form.get("generation"));
  if (!Number.isSafeInteger(value) || value < 1) {
    throw new Response("Invalid object generation", { status: 400 });
  }
  return value;
}

export async function proxyHostAction({ request }: { request: Request }) {
  const session = await authorized("read_proxy_hosts");
  if (!session.owner_id) throw new Response("Setup required", { status: 403 });
  const form = await request.formData();
  const intent = String(form.get("_intent"));
  const revision = String(form.get("revision"));
  const id = String(form.get("id"));
  await authorized("activate_typed_candidate");
  if (intent === "delete") {
    await authorized("delete_proxy_host");
    return saveAndApply(
      deleteProxyHost(id, generation(form), revision),
      revision,
      "deleted",
    );
  }
  if (intent === "enable" || intent === "disable") {
    await authorized("update_proxy_host");
    let stored;
    try {
      stored = await getProxyHost(id);
    } catch (error) {
      return conflictResult(error);
    }
    const object = {
      ...stored.object,
      spec: { ...stored.object.spec, enabled: intent === "enable" },
    };
    return saveAndApply(
      updateProxyHost(id, object, generation(form), revision),
      revision,
      intent === "enable" ? "enabled" : "disabled",
    );
  }
  throw new Response("Invalid action", { status: 400 });
}

const resultMessage: Record<ProxyHostOperation, string> = {
  created: "Proxy Host created. Changes active.",
  updated: "Proxy Host updated. Changes active.",
  enabled: "Proxy Host enabled. Changes active.",
  disabled: "Proxy Host disabled. Changes active.",
  deleted: "Proxy Host deleted. Changes active.",
  "draft-saved": "Draft saved. It is not applied to routing.",
  "draft-discarded": "Draft discarded. Applied and active routing are unchanged.",
};

function ActionResult({ result }: { result: ProxyHostActionResult | undefined }) {
  if (!result) return null;
  return (
    <div className={result.kind === "error" ? "notice error" : "notice warning"} role="alert">
      <strong>{result.heading}</strong>
      <p>{result.message}</p>
      {result.reload && <button type="button" className="quiet" onClick={() => window.location.reload()}>Reload current state</button>}
    </div>
  );
}

export function ProxyHosts() {
  const { session, hosts, drafts, application, revision, result } = useLoaderData() as Awaited<
    ReturnType<typeof proxyHostLoader>
  >;
  const actionResult = useActionData() as ProxyHostActionResult | undefined;
  const navigation = useNavigation();
  const pending = navigation.state !== "idle";
  const recoveryBlocked = application.recovery_required || actionResult?.kind === "recovery-required" || actionResult?.kind === "status-unavailable" || actionResult?.kind === "audit-unavailable";
  const canCreateDraft = permits(session, "create_proxy_host");
  const canUpdateDraft = permits(session, "update_proxy_host");
  const canApply = permits(session, "activate_typed_candidate");
  const canToggle = canUpdateDraft && canApply;
  const canDelete =
    permits(session, "delete_proxy_host") && canApply;
  return (
    <section>
      <div className="page-heading">
        <div><p className="eyebrow">ROUTING</p><h2>Proxy Hosts</h2><p>Manage domains and forwarding targets with safe, versioned changes.</p></div>
        {canCreateDraft && !recoveryBlocked && <Link className="button-link" to="/proxy-hosts/new">New Proxy Host</Link>}
      </div>
      {result && <p className="notice success" role="status">{resultMessage[result]}</p>}
      <ActionResult result={actionResult} />
      <article className="panel">
        <h3>Configured hosts</h3>
        {hosts.length === 0 ? <p className="muted">No Proxy Hosts configured.</p> : (
          <ul className="object-list host-list">
            {hosts.map(({ generation: objectGeneration, object }) => {
              const applied = application.objects.find(({ object_id }) => object_id === object.metadata.id);
              return <li key={object.metadata.id}>
                <div>
                  <strong>{object.spec.domain}</strong>
                  <span>{object.metadata.id}</span>
                  <span>{object.spec.forward_protocol}://{object.spec.forward_host}:{object.spec.forward_port}</span>
                  <span>{!application.active_state_known ? "Active status unavailable" : applied?.desired_matches_active ? "Changes active" : "Saved but not active"}</span>
                </div>
                <div className="host-state">
                  <span className={object.spec.enabled ? "state good" : "state"}>{object.spec.enabled ? "Enabled" : "Disabled"}</span>
                  {(canUpdateDraft || canDelete || canCreateDraft) && (
                    <details className="action-menu">
                      <summary aria-label={`Actions for ${object.spec.domain}`}>Actions</summary>
                      <div className="actions">
                        {canUpdateDraft && !recoveryBlocked && <Link to={`/proxy-hosts/${encodeURIComponent(object.metadata.id)}/edit`}>Edit</Link>}
                        {canCreateDraft && !recoveryBlocked && <Link to={`/proxy-hosts/${encodeURIComponent(object.metadata.id)}/duplicate`}>Duplicate</Link>}
                        {canToggle && (
                          <Form method="post">
                            <input type="hidden" name="revision" value={revision} />
                            <input type="hidden" name="id" value={object.metadata.id} />
                            <input type="hidden" name="generation" value={objectGeneration} />
                            <button disabled={pending || recoveryBlocked} name="_intent" value={object.spec.enabled ? "disable" : "enable"} className="quiet">
                              {object.spec.enabled ? "Disable" : "Enable"}
                            </button>
                          </Form>
                        )}
                        {canDelete && (
                          <Form
                            method="post"
                            onSubmit={(event) => {
                              if (!confirm(`Delete Proxy Host ${object.spec.domain}?`)) event.preventDefault();
                            }}
                          >
                            <input type="hidden" name="revision" value={revision} />
                            <input type="hidden" name="id" value={object.metadata.id} />
                            <input type="hidden" name="generation" value={objectGeneration} />
                            <button disabled={pending || recoveryBlocked} name="_intent" value="delete" className="danger">Delete</button>
                          </Form>
                        )}
                      </div>
                    </details>
                  )}
                </div>
              </li>;
            })}
          </ul>
        )}
      </article>
      <article className="panel">
        <h3>Drafts</h3>
        {drafts.length === 0 ? <p className="muted">No inactive drafts.</p> : (
          <ul className="object-list host-list">
            {drafts.map((draft) => (
              <li key={draft.object.metadata.id}>
                <div>
                  <strong>{draft.object.spec.domain}</strong>
                  <span>{draft.object.metadata.id}</span>
                  <span>Draft not applied</span>
                </div>
                <div className="host-state">
                  <span className="state">Draft</span>
                  {canUpdateDraft && !recoveryBlocked && (
                    <Link to={`/proxy-hosts/${encodeURIComponent(draft.object.metadata.id)}/edit`}>Edit draft</Link>
                  )}
                </div>
              </li>
            ))}
          </ul>
        )}
      </article>
    </section>
  );
}

type ProxyHostEditorMode = "new" | "edit" | "duplicate";

export async function proxyHostEditorLoader({
  request,
  params,
}: {
  request: Request;
  params: { id?: string };
}) {
  const session = await authorized("read_proxy_hosts");
  const path = new URL(request.url).pathname;
  const mode: ProxyHostEditorMode = path.endsWith("/duplicate")
    ? "duplicate"
    : path.endsWith("/edit")
      ? "edit"
      : "new";
  const [policies, node, hosts, drafts, application] = await Promise.all([
    listPolicies(),
    status(),
    listProxyHosts(),
    listProxyHostDrafts(),
    proxyHostApplicationState(),
  ]);
  const host = mode === "new"
    ? null
    : hosts.find(({ object }) => object.metadata.id === params.id) ?? null;
  const draft = mode === "edit"
    ? drafts.find(({ object }) => object.metadata.id === params.id) ?? null
    : null;
  if (mode !== "new" && !host && !draft) throw new Response("Proxy Host not found", { status: 404 });
  const ids = mode === "duplicate"
    ? [...hosts, ...drafts].map(({ object }) => object.metadata.id)
    : [];
  return { session, policies, revision: node.active_revision, mode, host, draft, ids, application };
}

function duplicateId(existing: string[], source: string): string {
  const used = new Set(existing);
  for (let number = 1; number <= used.size + 1; number += 1) {
    const suffix = number === 1 ? "-copy" : `-copy-${number}`;
    const id = `${source.slice(0, 63 - suffix.length)}${suffix}`;
    if (!used.has(id)) return id;
  }
  return "proxy-host-copy";
}

export async function proxyHostEditorAction({
  request,
  params,
}: {
  request: Request;
  params: { id?: string };
}) {
  const session = await authorized("read_proxy_hosts");
  if (!session.owner_id) throw new Response("Setup required", { status: 403 });
  const form = await request.formData();
  const intent = String(form.get("_intent"));
  const revision = String(form.get("revision"));
  const mode = String(form.get("mode")) as ProxyHostEditorMode;
  const id = mode === "edit" ? params.id ?? "" : String(form.get("object_id") || "");
  const object = proxyObject(form, session.owner_id, id || undefined);
  const draftGenerationValue = Number(form.get("draft_generation"));
  const draftGeneration = Number.isSafeInteger(draftGenerationValue) && draftGenerationValue > 0
    ? draftGenerationValue
    : undefined;
  if (intent === "discard-draft") {
    await authorized("update_proxy_host");
    if (!draftGeneration) throw new Response("Invalid draft generation", { status: 400 });
    try {
      await discardProxyHostDraft(id, draftGeneration);
      return redirect("/proxy-hosts?result=draft-discarded");
    } catch (error) {
      return conflictResult(error);
    }
  }
  if (intent === "save-draft") {
    await authorized(mode === "edit" ? "update_proxy_host" : "create_proxy_host");
    try {
      if (draftGeneration) {
        await updateProxyHostDraft(id, object, draftGeneration);
      } else {
        await createProxyHostDraft(object, mode === "edit" ? generation(form) : undefined);
      }
      return redirect("/proxy-hosts?result=draft-saved");
    } catch (error) {
      return conflictResult(error);
    }
  }
  if (intent !== "save-apply") throw new Response("Invalid action", { status: 400 });
  await authorized("activate_typed_candidate");
  if (draftGeneration) {
    await authorized("update_proxy_host");
    let savedDraft;
    try {
      savedDraft = await updateProxyHostDraft(id, object, draftGeneration);
    } catch (error) {
      return conflictResult(error);
    }
    return saveAndApply(
      promoteProxyHostDraft(id, savedDraft.draft.generation, revision),
      revision,
      hostOperation(form),
    );
  }
  if (mode === "edit") {
    await authorized("update_proxy_host");
    return saveAndApply(
      updateProxyHost(
        id,
        object,
        generation(form),
        revision,
      ),
      revision,
      "updated",
    );
  }
  if (mode === "new" || mode === "duplicate") {
    await authorized("create_proxy_host");
    return saveAndApply(
      createProxyHost(object, revision),
      revision,
      "created",
    );
  }
  throw new Response("Invalid action", { status: 400 });
}

function hostOperation(form: FormData): ProxyHostOperation {
  return String(form.get("applied_exists")) === "true" ? "updated" : "created";
}

export function ProxyHostEditor() {
  const { session, policies, revision, mode, host, draft, ids, application } = useLoaderData() as Awaited<
    ReturnType<typeof proxyHostEditorLoader>
  >;
  const result = useActionData() as ProxyHostActionResult | undefined;
  const navigation = useNavigation();
  const pending = navigation.state !== "idle";
  const recoveryBlocked = application.recovery_required || result?.kind === "recovery-required" || result?.kind === "status-unavailable" || result?.kind === "audit-unavailable";
  const source = draft?.object ?? host?.object;
  const objectId = mode === "duplicate" && source
    ? duplicateId(ids, source.metadata.id)
    : source?.metadata.id ?? "";
  const canSave = permits(session, "activate_typed_candidate") &&
    permits(session, mode === "edit" ? "update_proxy_host" : "create_proxy_host");
  const canSaveDraft = permits(session, mode === "edit" ? "update_proxy_host" : "create_proxy_host");
  const title = mode === "edit"
    ? `Edit ${source?.spec.domain ?? "Proxy Host"}`
    : mode === "duplicate"
      ? `Duplicate ${source?.spec.domain ?? "Proxy Host"}`
      : "New Proxy Host";
  return (
    <section className="narrow">
      <div className="page-heading">
        <div><p className="eyebrow">ROUTING</p><h2>{title}</h2><p>Save and apply validates the complete configuration before changing active routing.</p></div>
      </div>
      {mode === "duplicate" && <p className="notice">The copy has a new identity and starts disabled. Change its domain before saving to avoid a route conflict.</p>}
      <ActionResult result={result} />
      {draft && <p className="notice">Draft not applied. Saving it does not change active routing.</p>}
      <article className="panel">
        <Form method="post">
          <input type="hidden" name="revision" value={revision} />
          <input type="hidden" name="generation" value={host?.generation ?? ""} />
          <input type="hidden" name="draft_generation" value={draft?.generation ?? ""} />
          <input type="hidden" name="applied_exists" value={host ? "true" : "false"} />
          <input type="hidden" name="mode" value={mode} />
          <input type="hidden" name="object_id" value={objectId} />
          <label>Domain<input name="domain" required maxLength={253} defaultValue={source?.spec.domain ?? ""} placeholder="app.example.com" /></label>
          <div className="field-row">
            <label>Forward host or IP<input name="forward_host" required maxLength={253} defaultValue={source?.spec.forward_host ?? ""} /></label>
            <label>Forward port<input name="forward_port" type="number" min="1" max="65535" defaultValue={source?.spec.forward_port ?? 8080} required /></label>
          </div>
          <label>Upstream protocol<select name="forward_protocol" defaultValue={source?.spec.forward_protocol ?? "http"}><option>http</option><option>https</option></select></label>
          <label>HTTPS<select name="automatic_https" defaultValue={source?.spec.automatic_https ?? "disabled"}><option value="disabled">Disabled</option><option value="managed">Managed</option></select></label>
          <label>Access policy<select name="access_policy_ref" defaultValue={source?.spec.access_policy_ref ?? ""}><option value="">None</option>{policies.map(({ object }) => <option key={object.metadata.id}>{object.metadata.id}</option>)}</select></label>
          <label className="check"><input name="enabled" type="checkbox" defaultChecked={mode === "duplicate" ? false : source?.spec.enabled ?? true} />Enabled</label>
          <details><summary>Advanced controls</summary><p>AegisProxy derives listener, routing, timeout, and recovery defaults from these typed fields.</p></details>
          <div className="actions">
            {canSaveDraft && <button disabled={pending || recoveryBlocked} name="_intent" value="save-draft" className="quiet">{pending ? "Saving…" : "Save draft"}</button>}
            {canSave && <button disabled={pending || recoveryBlocked} name="_intent" value="save-apply">{pending ? "Applying…" : "Save and apply"}</button>}
            {draft && canSaveDraft && <button disabled={pending || recoveryBlocked} name="_intent" value="discard-draft" className="danger">Discard draft</button>}
            <Link className="button-link quiet" to="/proxy-hosts">Cancel</Link>
          </div>
        </Form>
      </article>
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
