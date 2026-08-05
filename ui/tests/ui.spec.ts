import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page, type Route } from "@playwright/test";
import type { Session } from "../src/api";

const adminSession: Session = {
  identity_id: "uid-1000",
  owner_id: "uid-1000",
  role: "admin",
  permitted_actions: [
    "read_status",
    "read_config",
    "read_revisions",
    "read_proxy_hosts",
    "create_proxy_host",
    "update_proxy_host",
    "delete_proxy_host",
    "activate_proxy_host",
    "read_stream_hosts",
    "create_stream_host",
    "update_stream_host",
    "delete_stream_host",
    "read_certificate_objects",
    "create_certificate",
    "update_certificate",
    "delete_certificate",
    "read_access_policies",
    "create_access_policy",
    "update_access_policy",
    "delete_access_policy",
    "read_users",
    "create_user",
    "update_user",
    "read_audit",
    "activate_typed_candidate",
    "rollback_typed_revision",
    "create_backup",
    "validate_restore",
  ],
  csrf_token: "c".repeat(43),
  idle_expires_unix_secs: 2000,
  absolute_expires_unix_secs: 3000,
};

async function json(route: Route, body: unknown, status = 200) {
  await route.fulfill({
    status,
    contentType: "application/json",
    body: JSON.stringify(body),
  });
}

async function mockApi(page: Page, session = adminSession) {
  await page.route("**/v1/**", async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    if (path === "/v1/session") return json(route, session);
    if (path === "/v1/status")
      return json(route, {
        version: "0.1.0",
        uptime_secs: 42,
        node_id: "standalone",
        fleet_generation: 0,
        active_revision: `00000000000000000001-${"a".repeat(64)}`,
        active_hash: "a".repeat(64),
        administration_ready: true,
        audit_ready: true,
        draining: false,
        managed_certificates: 1,
        actor_type: "oidc_session",
        actor_id: session.identity_id,
      });
    if (path === "/v1/config/revisions")
      return json(route, {
        items: [
          {
            id: `00000000000000000001-${"a".repeat(64)}`,
            sequence: 1,
            hash: "a".repeat(64),
            created_unix_secs: 1000,
            source: "test",
          },
        ],
        next_sequence: null,
      });
    if (path === "/v1/runtime/providers") return json(route, []);
    if (path === "/v1/proxy-host-drafts") return json(route, []);
    if (path === "/v1/proxy-hosts/application-state")
      return json(route, {
        active_revision: `00000000000000000001-${"a".repeat(64)}`,
        recovery_required: false,
        active_state_known: true,
        objects: [],
      });
    if (path === "/v1/proxy-hosts") return json(route, []);
    if (path === "/v1/access-policies") return json(route, []);
    if (path === "/v1/audit")
      return json(route, {
        items: [
          {
            sequence: 1,
            timestamp_unix_secs: 1000,
            node_id: "node",
            actor_type: "test",
            actor_id: "<img src=x onerror=alert(1)>",
            action: "read",
            resource_id: "resource",
            outcome: "success",
            error_code: null,
          },
        ],
        next_sequence: null,
      });
    if (path === "/v1/web/status")
      return json(route, {
        web_enabled: true,
        oidc_configured: true,
        oidc_available: true,
        setup_required: false,
        setup_token_active: false,
      });
    return json(route, []);
  });
  await page.route("**/health/details", (route) =>
    json(route, {
      status: "ready",
      active_revision: `00000000000000000001-${"a".repeat(64)}`,
      administration_ready: true,
      audit_ready: true,
      certificates: [],
    }),
  );
}

test("role-aware shell is keyboard accessible and renders payloads as text", async ({ page }) => {
  await mockApi(page);
  await page.goto("/logs");
  await expect(page.getByRole("heading", { name: "Logs" })).toBeVisible();
  await expect(page.getByText("<img src=x onerror=alert(1)>")).toBeVisible();
  expect(await page.locator("img").count()).toBe(0);
  await page.keyboard.press("Tab");
  await expect(page.getByText("Skip to content")).toBeFocused();
  const results = await new AxeBuilder({ page }).analyze();
  expect(results.violations).toEqual([]);
  expect(await page.evaluate(() => Object.keys(localStorage))).toEqual([]);
  expect(await page.evaluate(() => Object.keys(sessionStorage))).toEqual([]);
});

test("Proxy Host browser lifecycle saves, applies, conflicts safely, and retains active routing on failure", async ({ page }) => {
  await mockApi(page);
  const original = {
    api_version: "v1" as const,
    metadata: { id: "proxy-existing", owner_id: "uid-1000" },
    spec: {
      domains: ["existing.example.com"],
      forward_host: "127.0.0.1",
      forward_port: 8080,
      forward_protocol: "http" as const,
      automatic_https: "disabled" as const,
      access_policy_ref: null,
      locations: [] as Array<{
        id: string;
        match_kind: "exact" | "prefix";
        path: string;
        forward_host: string;
        forward_port: number;
        forward_protocol: "http" | "https";
        access_policy_ref: string | null;
        enabled: boolean;
      }>,
      enabled: true,
    },
  };
  let hosts = [{ generation: 1, object: structuredClone(original) }];
  let drafts: Array<{ generation: number; base_generation: number | null; object: typeof original }> = [];
  let activeHosts = structuredClone(hosts);
  let activeRevision = `00000000000000000001-${"a".repeat(64)}`;
  let sequence = 1;
  let failNextActivation = false;
  let conflictNextActivation = false;
  let deleteRequests = 0;
  const pending = new Map<string, typeof hosts>();
  const openActions = async (domain: string) => {
    const summary = page.locator(`summary[aria-label="Actions for ${domain}"]`);
    const open = await summary.evaluate((element) =>
      (element.parentElement as HTMLDetailsElement | null)?.open ?? false
    );
    if (!open) await summary.click();
  };

  await page.route("**/v1/status", (route) =>
    json(route, {
      version: "0.1.0",
      uptime_secs: 42,
      node_id: "standalone",
      fleet_generation: 0,
      active_revision: activeRevision,
      active_hash: "a".repeat(64),
      administration_ready: true,
      audit_ready: true,
      draining: false,
      managed_certificates: 0,
      actor_type: "oidc_session",
      actor_id: "uid-1000",
    }),
  );
  await page.route("**/v1/config/typed-candidates/*/activate", async (route) => {
    expect(route.request().headers()["if-match"]).toBe(`"${activeRevision}"`);
    if (conflictNextActivation) {
      conflictNextActivation = false;
      return json(route, {
        error: { code: "revision_conflict", message: "changed", details: [], request_id: "test" },
      }, 409);
    }
    if (failNextActivation) {
      failNextActivation = false;
      return json(route, {
        error: { code: "activation_failed", message: "failed", details: [], request_id: "test" },
      }, 503);
    }
    const id = new URL(route.request().url()).pathname.split("/").at(-2) ?? "";
    const snapshot = pending.get(id);
    expect(snapshot).toBeDefined();
    const previous = activeRevision;
    activeRevision = id;
    activeHosts = structuredClone(snapshot ?? []);
    return json(route, { active: id, previous });
  });
  await page.route("**/v1/proxy-host-drafts**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    const suffix = path.slice("/v1/proxy-host-drafts".length).replace(/^\//, "");
    const [encodedId, operation] = suffix.split("/");
    const id = encodedId ? decodeURIComponent(encodedId) : null;
    if (request.method() === "GET") {
      if (!id) return json(route, drafts);
      const draft = drafts.find(({ object }) => object.metadata.id === id);
      return draft ? json(route, draft) : json(route, { error: { code: "not_found" } }, 404);
    }
    if (operation === "promote" && request.method() === "POST") {
      expect(request.headers()["if-match"]).toBe(`"${activeRevision}"`);
      const index = drafts.findIndex(({ object }) => object.metadata.id === id);
      if (index < 0 || drafts[index].generation !== Number(request.headers()["x-aegis-draft-generation"])) {
        return json(route, { error: { code: "object_conflict" } }, 409);
      }
      const draft = drafts[index];
      const appliedIndex = hosts.findIndex(({ object }) => object.metadata.id === id);
      const stored = {
        generation: appliedIndex < 0 ? 1 : hosts[appliedIndex].generation + 1,
        object: structuredClone(draft.object),
      };
      hosts = appliedIndex < 0
        ? [...hosts, stored]
        : hosts.map((current, currentIndex) => currentIndex === appliedIndex ? stored : current);
      drafts.splice(index, 1);
      sequence += 1;
      const candidate = `0000000000000000000${sequence}-${String(sequence).repeat(64).slice(0, 64)}`;
      pending.set(candidate, structuredClone(hosts));
      return json(route, {
        object: stored,
        candidate: { id: candidate, hash: String(sequence).repeat(64).slice(0, 64), sequence },
      });
    }
    if (request.method() === "POST") {
      const object = request.postDataJSON() as typeof original;
      const applied = hosts.find(({ object: current }) => current.metadata.id === object.metadata.id);
      const expected = request.headers()["x-aegis-object-generation"];
      if ((applied?.generation ?? null) !== (expected ? Number(expected) : null)) {
        return json(route, { error: { code: "object_conflict" } }, 409);
      }
      const draft = { generation: 1, base_generation: applied?.generation ?? null, object };
      drafts.push(draft);
      return json(route, { draft }, 201);
    }
    const index = drafts.findIndex(({ object }) => object.metadata.id === id);
    if (index < 0 || drafts[index].generation !== Number(request.headers()["x-aegis-draft-generation"])) {
      return json(route, { error: { code: "object_conflict" } }, 409);
    }
    if (request.method() === "PUT") {
      const draft = {
        ...drafts[index],
        generation: drafts[index].generation + 1,
        object: request.postDataJSON() as typeof original,
      };
      drafts[index] = draft;
      return json(route, { draft });
    }
    const [draft] = drafts.splice(index, 1);
    return json(route, { draft });
  });
  await page.route("**/v1/proxy-hosts**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (path === "/v1/proxy-hosts/application-state") {
      const ids = new Set([
        ...hosts.map(({ object }) => object.metadata.id),
        ...drafts.map(({ object }) => object.metadata.id),
        ...activeHosts.map(({ object }) => object.metadata.id),
      ]);
      return json(route, {
        active_revision: activeRevision,
        recovery_required: false,
        active_state_known: true,
        objects: [...ids].map((object_id) => {
          const desired = hosts.find(({ object }) => object.metadata.id === object_id)?.object;
          const active = activeHosts.find(({ object }) => object.metadata.id === object_id)?.object;
          return {
            object_id,
            desired: Boolean(desired),
            draft: drafts.some(({ object }) => object.metadata.id === object_id),
            active: Boolean(active),
            desired_matches_active: JSON.stringify(desired) === JSON.stringify(active),
          };
        }),
      });
    }
    const id = path === "/v1/proxy-hosts"
      ? null
      : decodeURIComponent(path.slice("/v1/proxy-hosts/".length));
    if (request.method() === "GET") {
      if (!id) return json(route, hosts);
      const stored = hosts.find(({ object }) => object.metadata.id === id);
      return stored
        ? json(route, stored)
        : json(route, { error: { code: "not_found" } }, 404);
    }
    expect(request.headers()["if-match"]).toBe(`"${activeRevision}"`);
    if (request.method() === "POST") {
      const object = request.postDataJSON() as typeof original;
      if (hosts.some(({ object: current }) =>
        current.metadata.id === object.metadata.id
          || current.spec.domains.some((domain) => object.spec.domains.includes(domain))
      )) {
        return json(route, {
          error: { code: "invalid_request", message: "conflict", details: [], request_id: "test" },
        }, 400);
      }
      const stored = { generation: 1, object };
      hosts = [...hosts, stored];
      sequence += 1;
      const candidate = `0000000000000000000${sequence}-${String(sequence).repeat(64).slice(0, 64)}`;
      pending.set(candidate, structuredClone(hosts));
      return json(route, {
        object: stored,
        candidate: { id: candidate, hash: String(sequence).repeat(64).slice(0, 64), sequence },
      }, 201);
    }
    const index = hosts.findIndex(({ object }) => object.metadata.id === id);
    if (index < 0) return json(route, { error: { code: "not_found" } }, 404);
    const expectedGeneration = Number(request.headers()["x-aegis-object-generation"]);
    if (hosts[index].generation !== expectedGeneration) {
      return json(route, {
        error: { code: "object_conflict", message: "changed", details: [], request_id: "test" },
      }, 409);
    }
    sequence += 1;
    const candidate = `0000000000000000000${sequence}-${String(sequence).repeat(64).slice(0, 64)}`;
    if (request.method() === "PUT") {
      const stored = {
        generation: hosts[index].generation + 1,
        object: request.postDataJSON() as typeof original,
      };
      hosts = hosts.map((current, currentIndex) => currentIndex === index ? stored : current);
      pending.set(candidate, structuredClone(hosts));
      return json(route, {
        object: stored,
        candidate: { id: candidate, hash: String(sequence).repeat(64).slice(0, 64), sequence },
      });
    }
    deleteRequests += 1;
    const [deleted] = hosts.splice(index, 1);
    pending.set(candidate, structuredClone(hosts));
    return json(route, {
      deleted,
      candidate: { id: candidate, hash: String(sequence).repeat(64).slice(0, 64), sequence },
    });
  });

  await page.goto("/proxy-hosts");
  await expect(page.locator("main")).not.toContainText(/\bcandidate\b|\brevision\b|activation CAS/i);
  await page.getByRole("link", { name: "New Proxy Host" }).click();
  await page.getByRole("textbox", { name: "Domain 1 (primary)" }).fill("app.example.com");
  await page.getByRole("button", { name: "Add domain" }).click();
  await page.getByRole("textbox", { name: "Domain 2", exact: true }).fill("www.app.example.com");
  await page.getByRole("button", { name: "Move www.app.example.com up" }).click();
  await expect(page.getByRole("textbox", { name: "Domain 1 (primary)" })).toHaveValue("www.app.example.com");
  await page.getByRole("button", { name: "Move www.app.example.com down" }).click();
  await page.getByRole("button", { name: "Add domain" }).click();
  await page.getByRole("textbox", { name: "Domain 3", exact: true }).fill("remove.example.com");
  await page.getByRole("button", { name: "Remove remove.example.com" }).click();
  await page.getByLabel("Default forward host or IP").fill("127.0.0.1");
  await page.getByRole("button", { name: "Add location" }).click();
  const apiLocation = page.locator(".location-row").first();
  await apiLocation.getByLabel("Path", { exact: true }).fill("/api");
  await apiLocation.getByLabel("Forward host or IP").fill("api.internal");
  await apiLocation.getByLabel("Forward port").fill("9000");
  await page.getByRole("button", { name: "Add location" }).click();
  const removedLocation = page.locator(".location-row").nth(1);
  await removedLocation.getByLabel("Path", { exact: true }).fill("/remove");
  await removedLocation.getByLabel("Forward host or IP").fill("remove.internal");
  await page.getByRole("button", { name: "Move /remove up" }).click();
  await page.getByRole("button", { name: "Remove /remove" }).click();
  await page.getByRole("button", { name: "Save and apply" }).click();
  await expect(page.getByText("Proxy Host created. Changes active.")).toBeVisible();
  await expect(page.getByText("app.example.com +1 more")).toBeVisible();
  expect(hosts.find(({ object }) => object.spec.domains.includes("app.example.com"))?.object.spec.locations).toMatchObject([
    { path: "/api", forward_host: "api.internal", forward_port: 9000, match_kind: "prefix", enabled: true },
  ]);

  await openActions("app.example.com");
  await page.getByRole("link", { name: "Edit" }).click();
  await page.getByLabel("Default forward port").fill("8181");
  await page.getByRole("button", { name: "Save draft" }).click();
  await expect(page.getByText("Draft saved. It is not applied to routing.")).toBeVisible();
  expect(hosts.find(({ object }) => object.spec.domains.includes("app.example.com"))?.object.spec.forward_port).toBe(8080);
  expect(activeHosts.find(({ object }) => object.spec.domains.includes("app.example.com"))?.object.spec.forward_port).toBe(8080);
  await page.getByRole("link", { name: "Edit draft" }).click();
  await expect(page.getByText("Draft not applied. Saving it does not change active routing.")).toBeVisible();
  await expect(page.getByLabel("Default forward port")).toHaveValue("8181");
  await expect(page.locator(".location-row").getByLabel("Path", { exact: true })).toHaveValue("/api");
  await page.locator(".location-row").getByLabel("Forward port").fill("9100");
  await page.getByLabel("Default forward port").fill("9090");
  await page.getByRole("button", { name: "Save and apply" }).click();
  await expect(page.getByText("Proxy Host updated. Changes active.")).toBeVisible();
  expect(activeHosts.find(({ object }) => object.spec.domains.includes("app.example.com"))?.object.spec.forward_port).toBe(9090);
  expect(drafts).toHaveLength(0);

  await openActions("app.example.com");
  await page.getByRole("link", { name: "Edit" }).click();
  await page.getByLabel("Default forward port").fill("9190");
  await page.getByRole("button", { name: "Save draft" }).click();
  await page.getByRole("link", { name: "Edit draft" }).click();
  await page.getByRole("button", { name: "Discard draft" }).click();
  await expect(page.getByText("Draft discarded. Applied and active routing are unchanged.")).toBeVisible();
  expect(drafts).toHaveLength(0);
  expect(activeHosts.find(({ object }) => object.spec.domains.includes("app.example.com"))?.object.spec.forward_port).toBe(9090);

  await openActions("app.example.com");
  await page.getByRole("link", { name: "Edit" }).click();
  await page.getByLabel("Default forward port").fill("9190");
  await page.getByRole("button", { name: "Save draft" }).click();
  await page.getByRole("link", { name: "Edit draft" }).click();
  failNextActivation = true;
  await page.getByRole("button", { name: "Save and apply" }).click();
  await expect(page.getByText("Activation failed")).toBeVisible();
  expect(drafts).toHaveLength(0);
  expect(hosts.find(({ object }) => object.spec.domains.includes("app.example.com"))?.object.spec.forward_port).toBe(9190);
  expect(activeHosts.find(({ object }) => object.spec.domains.includes("app.example.com"))?.object.spec.forward_port).toBe(9090);
  await page.goto("/proxy-hosts");
  await expect(page.getByText("Saved but not active").first()).toBeVisible();

  await openActions("app.example.com");
  failNextActivation = true;
  await page.getByRole("button", { name: "Disable" }).click();
  await expect(page.getByText("Activation failed")).toBeVisible();
  await expect(page.getByText(/previously active routing remains/)).toBeVisible();
  expect(hosts.find(({ object }) => object.spec.domains.includes("app.example.com"))?.object.spec.enabled).toBe(false);
  expect(activeHosts.find(({ object }) => object.spec.domains.includes("app.example.com"))?.object.spec.enabled).toBe(true);

  await expect(page.getByText("Disabled", { exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Enable" }).click();
  await expect(page.getByText("Proxy Host enabled. Changes active.")).toBeVisible();
  expect(activeHosts.find(({ object }) => object.spec.domains.includes("app.example.com"))?.object.spec.enabled).toBe(true);

  await openActions("app.example.com");
  conflictNextActivation = true;
  await page.getByRole("button", { name: "Disable" }).click();
  await expect(page.getByText("Conflict detected")).toBeVisible();
  await expect(page.getByText(/another change won the activation check/)).toBeVisible();
  await expect(page.getByText(/previously active routing remains/)).toHaveCount(0);
  await page.getByRole("button", { name: "Enable" }).click();
  await expect(page.getByText("Proxy Host enabled. Changes active.")).toBeVisible();

  await openActions("app.example.com");
  await page.getByRole("link", { name: "Duplicate" }).click();
  await expect(page.getByRole("heading", { name: "Duplicate app.example.com" })).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Domain 1 (primary)" })).toHaveValue("app.example.com");
  await expect(page.getByRole("textbox", { name: "Domain 2", exact: true })).toHaveValue("www.app.example.com");
  await expect(page.getByLabel("Default forward port")).toHaveValue("9190");
  await expect(page.getByRole("checkbox", { name: "Enabled" })).not.toBeChecked();
  expect(hosts).toHaveLength(2);
  await page.getByRole("button", { name: "Save and apply" }).click();
  await expect(page.getByText("Validation failed")).toBeVisible();
  expect(hosts).toHaveLength(2);
  await page.getByRole("textbox", { name: "Domain 1 (primary)" }).fill("copy.example.com");
  await page.getByRole("textbox", { name: "Domain 2", exact: true }).fill("www.copy.example.com");
  await page.getByRole("button", { name: "Save and apply" }).click();
  await expect(page.getByText("Proxy Host created. Changes active.")).toBeVisible();
  const copy = hosts.find(({ object }) => object.spec.domains.includes("copy.example.com"));
  const appOriginal = hosts.find(({ object }) => object.spec.domains.includes("app.example.com"));
  expect(copy?.object.metadata.id).not.toBe("proxy-app-example-com");
  expect(copy?.object.spec.enabled).toBe(false);
  expect(copy?.object.spec.locations[0].id).not.toBe(appOriginal?.object.spec.locations[0].id);
  expect(copy?.object.spec.locations[0].path).toBe("/api");

  await openActions("app.example.com");
  await page.getByRole("link", { name: "Edit" }).click();
  await expect(page.getByLabel("Default forward port")).toHaveValue("9190");
  const app = hosts.find(({ object }) => object.spec.domains.includes("app.example.com"));
  if (!app) throw new Error("expected app host");
  app.generation += 1;
  app.object.spec.forward_port = 9191;
  await page.getByLabel("Default forward port").fill("9292");
  await page.getByRole("button", { name: "Save and apply" }).click();
  await expect(page.getByText("Conflict detected")).toBeVisible();
  await expect(page.getByRole("button", { name: "Reload current state" })).toBeVisible();
  expect(app.object.spec.forward_port).toBe(9191);

  await page.goto("/proxy-hosts");
  await openActions("copy.example.com");
  page.once("dialog", (dialog) => dialog.dismiss());
  await page.getByRole("button", { name: "Delete" }).click();
  expect(deleteRequests).toBe(0);
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Delete" }).click();
  await expect(page.getByText("Proxy Host deleted. Changes active.")).toBeVisible();
  expect(deleteRequests).toBe(1);
  expect(hosts.some(({ object }) => object.spec.domains.includes("copy.example.com"))).toBe(false);
});

test("Proxy Host destructive controls require exact permissions", async ({ page }) => {
  await mockApi(page, {
    ...adminSession,
    role: "operator",
    permitted_actions: ["read_proxy_hosts", "update_proxy_host", "activate_typed_candidate"],
  });
  await page.route("**/v1/proxy-hosts", (route) =>
    json(route, [{
      generation: 1,
      object: {
        api_version: "v1",
        metadata: { id: "proxy-example", owner_id: "uid-1000" },
        spec: {
          domains: ["example.test"],
          forward_host: "127.0.0.1",
          forward_port: 8080,
          forward_protocol: "http",
          automatic_https: "disabled",
          access_policy_ref: null,
          enabled: true,
        },
      },
    }]),
  );
  await page.goto("/proxy-hosts");
  await page.locator('summary[aria-label="Actions for example.test"]').click();
  await expect(page.getByRole("button", { name: "Disable" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Delete" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Duplicate" })).toHaveCount(0);
});

test("Proxy Host managed HTTPS rejects an uncovered multi-domain set without activation", async ({ page }) => {
  await mockApi(page);
  let activationAttempted = false;
  await page.route("**/v1/proxy-hosts", async (route) => {
    if (route.request().method() === "GET") return json(route, []);
    const object = route.request().postDataJSON() as { spec: { domains: string[] } };
    expect(object.spec.domains).toEqual(["covered.example.test", "uncovered.example.test"]);
    return json(route, {
      error: { code: "certificate_coverage_failed", message: "certificate coverage", details: [], request_id: "test" },
    }, 422);
  });
  await page.route("**/v1/config/typed-candidates/*/activate", (route) => {
    activationAttempted = true;
    return json(route, {});
  });

  await page.goto("/proxy-hosts/new");
  await page.getByRole("textbox", { name: "Domain 1 (primary)" }).fill("covered.example.test");
  await page.getByRole("button", { name: "Add domain" }).click();
  await page.getByRole("textbox", { name: "Domain 2", exact: true }).fill("uncovered.example.test");
  await page.getByLabel("Default forward host or IP").fill("127.0.0.1");
  await page.locator('select[name="automatic_https"]').selectOption("managed");
  await page.getByRole("button", { name: "Save and apply" }).click();
  await expect(page.getByText("Certificate does not cover every domain")).toBeVisible();
  await expect(page.getByText(/covered\.example\.test, uncovered\.example\.test/)).toBeVisible();
  await expect(page.getByRole("textbox", { name: "Domain 2", exact: true })).toHaveValue("uncovered.example.test");
  expect(activationAttempted).toBeFalsy();
});

test("Proxy Host draft actions remain visible without activation permission", async ({ page }) => {
  await mockApi(page, {
    ...adminSession,
    role: "operator",
    permitted_actions: ["read_proxy_hosts", "create_proxy_host", "update_proxy_host"],
  });
  const stored = {
    generation: 1,
    object: {
      api_version: "v1",
      metadata: { id: "proxy-draft-only", owner_id: "uid-1000" },
      spec: {
        domains: ["draft-only.example.test"],
        forward_host: "127.0.0.1",
        forward_port: 8080,
        forward_protocol: "http",
        automatic_https: "disabled",
        access_policy_ref: null,
        enabled: true,
      },
    },
  };
  await page.route("**/v1/proxy-hosts", (route) => json(route, [stored]));
  await page.route("**/v1/proxy-host-drafts", (route) => json(route, [{
    generation: 1,
    base_generation: 1,
    object: { ...stored.object, spec: { ...stored.object.spec, forward_port: 8181 } },
  }]));

  await page.goto("/proxy-hosts");
  await expect(page.getByRole("link", { name: "New Proxy Host" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Edit draft" })).toBeVisible();
  await page.locator('summary[aria-label="Actions for draft-only.example.test"]').click();
  await expect(page.getByRole("link", { name: "Edit", exact: true })).toBeVisible();
  await expect(page.getByRole("link", { name: "Duplicate" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Disable" })).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Delete" })).toHaveCount(0);
  await page.getByRole("link", { name: "Edit draft" }).click();
  await expect(page.getByRole("button", { name: "Save draft" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Save and apply" })).toHaveCount(0);
});

test("Proxy Host recovery-required response reports uncertainty and blocks mutations", async ({ page }) => {
  await mockApi(page);
  let activationAttempted = false;
  const stored = {
    generation: 4,
    object: {
      api_version: "v1",
      metadata: { id: "proxy-recovery", owner_id: "uid-1000" },
      spec: {
        domains: ["recovery.example.test"],
        forward_host: "127.0.0.1",
        forward_port: 8080,
        forward_protocol: "http",
        automatic_https: "disabled",
        access_policy_ref: null,
        enabled: true,
      },
    },
  };
  await page.route("**/v1/proxy-hosts**", (route) => {
    if (route.request().method() === "GET") {
      const path = new URL(route.request().url()).pathname;
      if (path === "/v1/proxy-hosts/application-state") {
        return json(route, {
          active_revision: `00000000000000000001-${"a".repeat(64)}`,
          recovery_required: false,
          active_state_known: true,
          objects: [{ object_id: stored.object.metadata.id, desired: true, draft: false, active: true, desired_matches_active: true }],
        });
      }
      return json(route, path === "/v1/proxy-hosts" ? [stored] : stored);
    }
    return json(route, {
      error: {
        code: "recovery_required",
        message: "stored state requires recovery",
        details: [],
        request_id: "recovery-test",
      },
    }, 503);
  });
  await page.route("**/v1/revisions/activate", (route) => {
    activationAttempted = true;
    return json(route, {});
  });

  await page.goto("/proxy-hosts");
  await page.locator('summary[aria-label="Actions for recovery.example.test"]').click();
  await page.getByRole("button", { name: "Disable" }).click();
  await expect(page.getByText("Storage recovery required")).toBeVisible();
  await expect(page.getByText(/previous save could not be confirmed/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Disable" })).toBeDisabled();
  await expect(page.getByRole("button", { name: "Delete" })).toBeDisabled();
  await expect(page.getByRole("link", { name: "New Proxy Host" })).toHaveCount(0);
  expect(activationAttempted).toBeFalsy();
});

test("Proxy Host audit failures distinguish saved and active outcomes", async ({ page }) => {
  await mockApi(page);
  const stored = {
    generation: 1,
    object: {
      api_version: "v1",
      metadata: { id: "proxy-audit", owner_id: "uid-1000" },
      spec: {
        domains: ["audit.example.test"],
        forward_host: "127.0.0.1",
        forward_port: 8080,
        forward_protocol: "http",
        automatic_https: "disabled",
        access_policy_ref: null,
        enabled: true,
      },
    },
  };
  let afterActivation = false;
  let activationCode = "audit_failed_after_activation";
  let activationResponseUnavailable = false;
  let mutationResultUnavailable = false;
  let activationAttempts = 0;
  await page.route("**/v1/proxy-hosts**", (route) => {
    if (route.request().method() === "GET") {
      const path = new URL(route.request().url()).pathname;
      if (path === "/v1/proxy-hosts/application-state") {
        return json(route, {
          active_revision: `00000000000000000001-${"a".repeat(64)}`,
          recovery_required: false,
          active_state_known: true,
          objects: [{ object_id: stored.object.metadata.id, desired: true, draft: false, active: true, desired_matches_active: true }],
        });
      }
      return json(route, path === "/v1/proxy-hosts" ? [stored] : stored);
    }
    if (mutationResultUnavailable) return route.abort("failed");
    if (!afterActivation) {
      return json(route, {
        error: { code: "audit_failed_after_save", message: "audit unavailable", details: [], request_id: "audit-save" },
      }, 503);
    }
    return json(route, {
      object: { ...stored, generation: 2 },
      candidate: { id: `00000000000000000002-${"b".repeat(64)}`, hash: "b".repeat(64), sequence: 2 },
    });
  });
  await page.route("**/v1/config/typed-candidates/*/activate", (route) => {
    activationAttempts += 1;
    if (activationResponseUnavailable) return route.abort("failed");
    return json(route, {
      error: { code: activationCode, message: "activation unavailable", details: [], request_id: "audit-active" },
    }, 503);
  });

  await page.goto("/proxy-hosts");
  await page.locator('summary[aria-label="Actions for audit.example.test"]').click();
  await page.getByRole("button", { name: "Disable" }).click();
  await expect(page.getByText("Saved but audit unavailable")).toBeVisible();
  await expect(page.getByText(/change was not activated/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Disable" })).toBeDisabled();

  afterActivation = true;
  await page.goto("/proxy-hosts");
  await page.locator('summary[aria-label="Actions for audit.example.test"]').click();
  await page.getByRole("button", { name: "Disable" }).click();
  await expect(page.getByText("Changes active; audit unavailable")).toBeVisible();
  await expect(page.getByText(/intended routing change is active/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Disable" })).toBeDisabled();

  activationCode = "rollback_failed";
  await page.goto("/proxy-hosts");
  await page.locator('summary[aria-label="Actions for audit.example.test"]').click();
  await page.getByRole("button", { name: "Disable" }).click();
  await expect(page.getByText("Rollback failed")).toBeVisible();
  await expect(page.getByText(/durable rollback could not be confirmed/)).toBeVisible();
  await expect(page.getByRole("button", { name: "Disable" })).toBeDisabled();

  activationResponseUnavailable = true;
  await page.goto("/proxy-hosts");
  await page.locator('summary[aria-label="Actions for audit.example.test"]').click();
  await page.getByRole("button", { name: "Disable" }).click();
  await expect(page.getByText("Activation status unavailable")).toBeVisible();
  await expect(page.getByText(/Refresh to determine which configuration is active/)).toBeVisible();
  await expect(page.getByText(/previously active routing remains/)).toHaveCount(0);
  await expect(page.getByRole("button", { name: "Disable" })).toBeDisabled();
  activationResponseUnavailable = false;

  mutationResultUnavailable = true;
  const previousActivationAttempts = activationAttempts;
  await page.goto("/proxy-hosts");
  await page.locator('summary[aria-label="Actions for audit.example.test"]').click();
  await page.getByRole("button", { name: "Disable" }).click();
  await expect(page.getByText("Save status unavailable")).toBeVisible();
  await expect(page.getByText(/browser could not confirm whether the Proxy Host was saved/)).toBeVisible();
  expect(activationAttempts).toBe(previousActivationAttempts);
});

test("provisional setup redeems without storing the token", async ({ page }) => {
  const provisional = { ...adminSession, owner_id: null, permitted_actions: [] };
  await mockApi(page, provisional);
  await page.route("**/v1/session/setup", (route) =>
    json(route, { ...adminSession, csrf_token: "d".repeat(43) }),
  );
  await page.goto("/setup");
  await page.getByLabel("Setup token").fill("s".repeat(43));
  await page.getByRole("button", { name: "Complete setup" }).click();
  await expect(page).toHaveURL("/");
  expect(await page.evaluate(() => JSON.stringify(localStorage))).not.toContain("s".repeat(43));
});

test("phone layout keeps primary navigation and content usable", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockApi(page);
  await page.goto("/");
  await expect(page.getByRole("navigation", { name: "Primary" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Dashboard" })).toBeVisible();
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth > window.innerWidth);
  expect(overflow).toBeFalsy();
});

test("typed delete controls require their exact permission", async ({ page }) => {
  await mockApi(page, {
    ...adminSession,
    role: "operator",
    permitted_actions: ["read_stream_hosts", "update_stream_host"],
  });
  await page.route("**/v1/stream-hosts", (route) =>
    json(route, [{
      generation: 3,
      object: {
        api_version: "v1",
        metadata: { id: "stream-example", owner_id: "uid-1000" },
        spec: { listen_port: 8443, protocol: "tcp", forward_host: "127.0.0.1", forward_port: 443, sni_hosts: [], enabled: true },
      },
    }]),
  );
  await page.goto("/stream-hosts");
  await page.getByText("Edit exact object").click();
  await expect(page.getByRole("button", { name: "Update" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Delete" })).toHaveCount(0);
});
