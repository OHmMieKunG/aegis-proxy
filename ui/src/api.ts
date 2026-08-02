import createClient, { type Middleware } from "openapi-fetch";
import type { components, paths } from "./generated/api";

export type Session = components["schemas"]["BrowserSession"];
export type Action = components["schemas"]["TokenScope"];
export type ProxyHost = components["schemas"]["ProxyHostObject"];
export type StoredProxyHost = components["schemas"]["StoredProxyHost"];
export type StoredProxyHostDraft = components["schemas"]["StoredProxyHostDraft"];
export type ProxyHostApplicationState = components["schemas"]["ProxyHostApplicationState"];
export type AccessPolicy = components["schemas"]["AccessPolicyObject"];
export type Certificate = components["schemas"]["CertificateObject"];
export type StreamHost = components["schemas"]["StreamHostObject"];
export type User = components["schemas"]["UserObject"];
export type Stored<T> = { generation: number; object: T };
export type Resource = "stream-hosts" | "certificates" | "access-policies" | "users";

export type Status = {
  version: string;
  uptime_secs: number;
  node_id: string;
  fleet_generation: number;
  active_revision: string;
  active_hash: string;
  administration_ready: boolean;
  audit_ready: boolean;
  draining: boolean;
  managed_certificates: number;
  actor_type: string;
  actor_id: string;
};

export type Health = {
  status: string;
  active_revision: string;
  administration_ready: boolean;
  audit_ready: boolean;
  certificates: Array<{
    id: string;
    not_before_unix_secs: number | null;
    not_after_unix_secs: number | null;
    state: string;
  }>;
};

export type Revision = {
  id: string;
  sequence: number;
  hash: string;
  created_unix_secs: number;
  source: string;
  binding_hash?: string;
};

export type AuditRecord = {
  sequence: number;
  timestamp_unix_secs: number;
  node_id: string;
  actor_type: string;
  actor_id: string;
  action: string;
  resource_id: string;
  outcome: "intent" | "success" | "denied" | "failed";
  error_code: string | null;
};

type Result<T> = {
  data?: T;
  error?: unknown;
  response: Response;
};

export class ApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
    public readonly code?: string,
  ) {
    super(message.slice(0, 240));
  }
}

let csrfToken = "";
let cachedSession: Session | undefined;

const middleware: Middleware = {
  async onRequest({ request }) {
    if (!["GET", "HEAD", "OPTIONS"].includes(request.method) && csrfToken) {
      request.headers.set("x-aegis-csrf-token", csrfToken);
    }
    return request;
  },
};

export const api = createClient<paths>({
  baseUrl: "",
  credentials: "same-origin",
});
api.use(middleware);

function errorCode(error: unknown): string | undefined {
  if (
    error &&
    typeof error === "object" &&
    "error" in error &&
    error.error &&
    typeof error.error === "object" &&
    "code" in error.error
  ) {
    return String(error.error.code);
  }
  return undefined;
}

function unwrap<T>(result: Result<T>): T {
  if (result.response.ok && result.data !== undefined) return result.data;
  const code = errorCode(result.error);
  throw new ApiError(
    result.response.status,
    code ? `${result.response.status}: ${code}` : `${result.response.status}: request failed`,
    code,
  );
}

function unsafeHeaders() {
  return {
    Origin: window.location.origin,
    "Sec-Fetch-Site": "same-origin" as const,
    "X-Aegis-Csrf-Token": csrfToken,
  };
}

const ifMatch = (revision: string) => `"${revision}"`;

export async function loadSession(force = false): Promise<Session> {
  if (cachedSession && !force) return cachedSession;
  const result = await api.GET("/v1/session");
  if (result.response.status === 401) {
    const returnTo = `${window.location.pathname}${window.location.search}`;
    window.location.assign(`/v1/auth/login?return_to=${encodeURIComponent(returnTo)}`);
    return new Promise<Session>(() => undefined);
  }
  cachedSession = unwrap(result);
  csrfToken = cachedSession.csrf_token;
  return cachedSession;
}

export async function logout(): Promise<void> {
  const result = await api.POST("/v1/session/logout", {
    params: { header: unsafeHeaders() },
  });
  if (!result.response.ok) throw new ApiError(result.response.status, "Logout failed");
  cachedSession = undefined;
  csrfToken = "";
  window.location.assign("/v1/auth/login");
}

export async function redeemSetup(setupToken: string): Promise<Session> {
  const result = await api.POST("/v1/session/setup", {
    params: { header: unsafeHeaders() },
    body: { setup_token: setupToken },
  });
  cachedSession = unwrap(result);
  csrfToken = cachedSession.csrf_token;
  return cachedSession;
}

export async function status(): Promise<Status> {
  return unwrap((await api.GET("/v1/status")) as unknown as Result<Status>);
}

export async function health(): Promise<Health> {
  return unwrap((await api.GET("/health/details")) as unknown as Result<Health>);
}

export async function webStatus() {
  return unwrap(await api.GET("/v1/web/status"));
}

export async function revisions(): Promise<Revision[]> {
  const page = unwrap(
    (await api.GET("/v1/config/revisions")) as unknown as Result<{
      items: Revision[];
      next_sequence: number | null;
    }>,
  );
  return page.items;
}

export async function auditRecords(): Promise<AuditRecord[]> {
  const page = unwrap(
    (await api.GET("/v1/audit", {
      params: { query: { limit: 100 } },
    })) as unknown as Result<{ items: AuditRecord[]; next_sequence: number | null }>,
  );
  return page.items;
}

export async function providers(): Promise<unknown[]> {
  return unwrap((await api.GET("/v1/runtime/providers")) as unknown as Result<unknown[]>);
}

export async function listProxyHosts(): Promise<StoredProxyHost[]> {
  return unwrap(await api.GET("/v1/proxy-hosts"));
}

export async function listProxyHostDrafts(): Promise<StoredProxyHostDraft[]> {
  return unwrap(await api.GET("/v1/proxy-host-drafts"));
}

export async function proxyHostApplicationState(): Promise<ProxyHostApplicationState> {
  return unwrap(await api.GET("/v1/proxy-hosts/application-state"));
}

export async function createProxyHostDraft(
  object: ProxyHost,
  appliedGeneration?: number,
) {
  return unwrap(
    await api.POST("/v1/proxy-host-drafts", {
      params: { header: { "X-Aegis-Object-Generation": appliedGeneration } },
      body: object,
    }),
  );
}

export async function updateProxyHostDraft(
  id: string,
  object: ProxyHost,
  draftGeneration: number,
) {
  return unwrap(
    await api.PUT("/v1/proxy-host-drafts/{id}", {
      params: {
        path: { id },
        header: { "X-Aegis-Draft-Generation": draftGeneration },
      },
      body: object,
    }),
  );
}

export async function discardProxyHostDraft(id: string, draftGeneration: number) {
  return unwrap(
    await api.DELETE("/v1/proxy-host-drafts/{id}", {
      params: {
        path: { id },
        header: { "X-Aegis-Draft-Generation": draftGeneration },
      },
    }),
  );
}

export async function promoteProxyHostDraft(
  id: string,
  draftGeneration: number,
  revision: string,
) {
  return unwrap(
    await api.POST("/v1/proxy-host-drafts/{id}/promote", {
      params: {
        path: { id },
        header: {
          "If-Match": ifMatch(revision),
          "X-Aegis-Draft-Generation": draftGeneration,
        },
      },
    }),
  );
}

export async function listPolicies(): Promise<Array<Stored<AccessPolicy>>> {
  return unwrap(await api.GET("/v1/access-policies"));
}

export async function previewProxyHost(object: ProxyHost) {
  return unwrap(await api.POST("/v1/proxy-hosts/preview", { body: object }));
}

export async function validateProxyHost(object: ProxyHost) {
  return unwrap(await api.POST("/v1/proxy-hosts/validate", { body: object }));
}

export async function createProxyHost(object: ProxyHost, revision: string) {
  return unwrap(
    await api.POST("/v1/proxy-hosts", {
      params: { header: { "If-Match": ifMatch(revision) } },
      body: object,
    }),
  );
}

export async function getProxyHost(id: string): Promise<StoredProxyHost> {
  return unwrap(
    await api.GET("/v1/proxy-hosts/{id}", {
      params: { path: { id } },
    }),
  );
}

export async function updateProxyHost(
  id: string,
  object: ProxyHost,
  generation: number,
  revision: string,
) {
  return unwrap(
    await api.PUT("/v1/proxy-hosts/{id}", {
      params: {
        path: { id },
        header: {
          "If-Match": ifMatch(revision),
          "X-Aegis-Object-Generation": generation,
        },
      },
      body: object,
    }),
  );
}

export async function deleteProxyHost(id: string, generation: number, revision: string) {
  return unwrap(
    await api.DELETE("/v1/proxy-hosts/{id}", {
      params: {
        path: { id },
        header: {
          "If-Match": ifMatch(revision),
          "X-Aegis-Object-Generation": generation,
        },
      },
    }),
  );
}

export async function activateProxyHost(candidate: string, revision: string): Promise<void> {
  unwrap(
    await api.POST("/v1/config/typed-candidates/{id}/activate", {
      params: { path: { id: candidate }, header: { "If-Match": ifMatch(revision) } },
    }),
  );
}

export async function listResource(resource: Resource): Promise<Array<Stored<unknown>>> {
  switch (resource) {
    case "stream-hosts":
      return unwrap(
        (await api.GET("/v1/stream-hosts")) as unknown as Result<Array<Stored<StreamHost>>>,
      );
    case "certificates":
      return unwrap(
        (await api.GET("/v1/certificates")) as unknown as Result<Array<Stored<Certificate>>>,
      );
    case "access-policies":
      return unwrap(await api.GET("/v1/access-policies"));
    case "users":
      return unwrap(
        (await api.GET("/v1/users")) as unknown as Result<Array<Stored<User>>>,
      );
  }
}

export async function createResource(
  resource: Resource,
  object: unknown,
  revision: string,
): Promise<void> {
  let result;
  switch (resource) {
    case "stream-hosts":
      result = await api.POST("/v1/stream-hosts", {
        params: { header: { "If-Match": ifMatch(revision) } },
        body: object as StreamHost,
      });
      break;
    case "certificates":
      result = await api.POST("/v1/certificates", {
        params: { header: { "If-Match": ifMatch(revision) } },
        body: object as Certificate,
      });
      break;
    case "access-policies":
      result = await api.POST("/v1/access-policies", {
        params: { header: { "If-Match": ifMatch(revision) } },
        body: object as AccessPolicy,
      });
      break;
    case "users":
      result = await api.POST("/v1/users", {
        params: { header: { "If-Match": ifMatch(revision) } },
        body: object as User,
      });
  }
  if (!result.response.ok) throw new ApiError(result.response.status, `${resource} create failed`);
}

export async function updateResource(
  resource: Resource,
  id: string,
  object: unknown,
  generation: number,
  revision: string,
): Promise<void> {
  const parameters = {
    path: { id },
    header: {
      "If-Match": ifMatch(revision),
      "X-Aegis-Object-Generation": generation,
    },
  };
  let result;
  switch (resource) {
    case "stream-hosts":
      result = await api.PUT("/v1/stream-hosts/{id}", {
        params: parameters,
        body: object as StreamHost,
      });
      break;
    case "certificates":
      result = await api.PUT("/v1/certificates/{id}", {
        params: parameters,
        body: object as Certificate,
      });
      break;
    case "access-policies":
      result = await api.PUT("/v1/access-policies/{id}", {
        params: parameters,
        body: object as AccessPolicy,
      });
      break;
    case "users":
      result = await api.PUT("/v1/users/{id}", {
        params: parameters,
        body: object as User,
      });
  }
  if (!result.response.ok) throw new ApiError(result.response.status, `${resource} update failed`);
}

export async function deleteResource(
  resource: Exclude<Resource, "users">,
  id: string,
  generation: number,
  revision: string,
): Promise<void> {
  const parameters = {
    path: { id },
    header: {
      "If-Match": ifMatch(revision),
      "X-Aegis-Object-Generation": generation,
    },
  };
  const result =
    resource === "stream-hosts"
      ? await api.DELETE("/v1/stream-hosts/{id}", { params: parameters })
      : resource === "certificates"
        ? await api.DELETE("/v1/certificates/{id}", { params: parameters })
        : await api.DELETE("/v1/access-policies/{id}", { params: parameters });
  if (!result.response.ok) throw new ApiError(result.response.status, `${resource} delete failed`);
}

export async function previewRevision(id: string): Promise<unknown> {
  return unwrap(
    (await api.GET("/v1/config/typed-candidates/{id}/preview", {
      params: { path: { id } },
    })) as unknown as Result<unknown>,
  );
}

export async function activateRevision(id: string, revision: string): Promise<void> {
  const result = await api.POST("/v1/config/typed-candidates/{id}/activate", {
    params: { path: { id }, header: { "If-Match": ifMatch(revision) } },
  });
  if (!result.response.ok) throw new ApiError(result.response.status, "Activation failed");
}

export async function rollbackRevision(id: string, revision: string): Promise<void> {
  const result = await api.POST("/v1/config/typed-revisions/{id}/rollback", {
    params: { path: { id }, header: { "If-Match": ifMatch(revision) } },
  });
  if (!result.response.ok) throw new ApiError(result.response.status, "Rollback failed");
}

export async function createBackup(output: string, revision: string): Promise<void> {
  const result = await api.POST("/v1/backups", {
    params: { header: { "If-Match": ifMatch(revision) } },
    body: { output },
  });
  if (!result.response.ok) throw new ApiError(result.response.status, "Backup creation failed");
}

export async function validateRestore(
  input: string,
  identity: string,
  revision: string,
): Promise<void> {
  const result = await api.POST("/v1/restore/validate", {
    params: { header: { "If-Match": ifMatch(revision) } },
    body: { input, identity },
  });
  if (!result.response.ok) throw new ApiError(result.response.status, "Restore validation failed");
}

export function permits(session: Session, action: Action): boolean {
  return session.permitted_actions.includes(action);
}
