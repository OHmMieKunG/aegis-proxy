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

test("proxy host wizard previews, creates, and activates the exact candidate", async ({ page }) => {
  await mockApi(page);
  let activated = false;
  await page.route("**/v1/proxy-hosts/**", async (route) => {
    const path = new URL(route.request().url()).pathname;
    if (path.endsWith("/preview"))
      return json(route, { preview: { summary: { domain: "app.example.com" } }, diff: { changes: [] } });
    if (path.includes("/candidates/")) {
      activated = true;
      return route.fulfill({ status: 200 });
    }
    return route.fallback();
  });
  await page.route("**/v1/proxy-hosts", async (route) => {
    if (route.request().method() === "POST")
      return json(route, {
        object: { generation: 1, object: {} },
        candidate: { id: `00000000000000000002-${"b".repeat(64)}`, hash: "b".repeat(64), sequence: 2 },
      }, 201);
    return json(route, []);
  });
  await page.goto("/proxy-hosts");
  await page.getByLabel("Domain").fill("app.example.com");
  await page.getByLabel("Forward host or IP").fill("127.0.0.1");
  await page.getByRole("button", { name: "Preview & diff" }).click();
  await expect(page.getByText(/app\.example\.com/)).toBeVisible();
  await page.getByRole("button", { name: "Create candidate" }).click();
  page.once("dialog", (dialog) => dialog.accept());
  await page.getByRole("button", { name: "Activate candidate" }).click();
  await expect.poll(() => activated).toBeTruthy();
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
