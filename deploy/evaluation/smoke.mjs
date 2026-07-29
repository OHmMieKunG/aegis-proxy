import assert from "node:assert/strict";
import { chromium } from "../../ui/node_modules/playwright/index.mjs";

const setupToken = process.env.SETUP_TOKEN;
const restartCheck = process.env.CHECK_RESTART === "1";
const proxyDomain = process.env.PROXY_DOMAIN ?? "proxy.localhost";

const browser = await chromium.launch({ headless: true });
const context = await browser.newContext({
  ignoreHTTPSErrors: true,
  ...(restartCheck
    ? { storageState: "/work/ui/test-results/evaluation-state.json" }
    : {}),
});
const page = await context.newPage();
page.on("response", async (response) => {
  if (response.status() >= 400) {
    console.error(`${response.request().method()} ${response.url()}: ${response.status()}`);
  }
});

if (restartCheck) {
  try {
    const traffic = await page.request.get("http://127.0.0.1:8080/", {
      headers: { Host: "proxy.localhost" },
    });
    assert.equal(traffic.status(), 200);
    assert.match(await traffic.text(), /AegisProxy evaluation upstream/);
    await page.goto("http://localhost:9090/");
    await page.waitForURL("https://localhost:9443/**");
    console.log("durable route and post-restart session loss: PASS");
  } finally {
    await browser.close();
  }
  process.exit(0);
}

try {
  const response = await page.goto("http://localhost:9090/");
  assert(response);
  await page.locator("#username").fill("admin");
  await page.locator("#password").fill("aegis-evaluation-only");
  const callbackResponse = page.waitForResponse((candidate) =>
    candidate.url().startsWith("http://localhost:9090/v1/auth/callback"),
  );
  await page.locator("#kc-login").click();
  const callback = await callbackResponse;
  console.log(`OIDC callback: ${callback.status()}`);
  await page.waitForURL("http://localhost:9090/**");

  const provisional = await page.request.get("http://localhost:9090/v1/session");
  assert.equal(provisional.status(), 200);
  const provisionalSession = await provisional.json();
  const provisionalCookie = (await context.cookies()).find(
    ({ name }) => name === "__Host-aegis-session",
  )?.value;
  if (provisionalSession.owner_id === null) {
    assert.equal(setupToken?.length, 43, "SETUP_TOKEN must be the 43-character CLI token");
    await page.goto("http://localhost:9090/setup");
    await page.getByLabel("Setup token").fill(setupToken);
    await page.getByRole("button", { name: "Complete setup" }).click();
    await page.waitForURL("http://localhost:9090/");

    const bound = await page.request.get("http://localhost:9090/v1/session");
    assert.equal(bound.status(), 200);
    const boundSession = await bound.json();
    const boundCookie = (await context.cookies()).find(
      ({ name }) => name === "__Host-aegis-session",
    )?.value;
    assert.equal(boundSession.role, "admin");
    assert.notEqual(boundSession.owner_id, null);
    assert.notEqual(boundSession.csrf_token, provisionalSession.csrf_token);
    assert.notEqual(boundCookie, provisionalCookie);
    const storage = await page.evaluate(() => ({
      local: JSON.stringify(localStorage),
      session: JSON.stringify(sessionStorage),
    }));
    assert(!storage.local.includes(setupToken));
    assert(!storage.session.includes(setupToken));
  }

  await page.goto("http://localhost:9090/proxy-hosts");
  await page.getByLabel("Domain").fill(proxyDomain);
  await page.getByLabel("Forward host or IP").fill("127.0.0.1");
  await page.getByLabel("Forward port").fill("9000");
  await page.getByRole("button", { name: "Validate" }).click();
  await page.locator("pre").waitFor();
  await page.getByRole("button", { name: "Preview & diff" }).click();
  await page.getByText(proxyDomain, { exact: false }).waitFor();
  await page.getByRole("button", { name: "Create candidate" }).click();
  await page.getByRole("button", { name: "Activate candidate" }).waitFor();
  page.once("dialog", (dialog) => dialog.accept());
  const activationResponse = page.waitForResponse(
    (response) =>
      response.request().method() === "POST" &&
      response.url().includes("/v1/config/typed-candidates/"),
  );
  await page.getByRole("button", { name: "Activate candidate" }).click();
  assert.equal((await activationResponse).status(), 200);

  const traffic = await page.request.get("http://127.0.0.1:8080/", {
    headers: { Host: proxyDomain },
  });
  assert.equal(traffic.status(), 200);
  assert.match(await traffic.text(), /AegisProxy evaluation upstream/);

  const documentHeaders = response.headers();
  assert(documentHeaders["content-security-policy"]);
  assert.match(documentHeaders["cache-control"] ?? "", /no-store/);
  assert.match(provisional.headers()["cache-control"] ?? "", /no-store/);

  await context.storageState({ path: "/work/ui/test-results/evaluation-state.json" });
  console.log("OIDC login, setup rotation, UI validate/preview/create/activate, and traffic: PASS");
} catch (error) {
  console.error(`browser URL: ${page.url()}`);
  console.error((await page.locator("body").innerText()).slice(0, 1_000));
  throw error;
} finally {
  await browser.close();
}
