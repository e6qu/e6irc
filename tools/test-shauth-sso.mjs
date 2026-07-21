// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { createRequire } from "node:module";

const require = createRequire(new URL("../web/package.json", import.meta.url));
const { chromium } = require("playwright");

const username = required("SHAUTH_VALIDATOR_USERNAME");
const password = required("SHAUTH_BOOTSTRAP_ADMIN_PASSWORD");
const nonAuthenticCredential = required("E6IRC_NON_AUTHENTIC_CREDENTIAL_SENTINEL");
const releaseRevision = required("E6IRC_TEST_REVISION");
assert.notEqual(nonAuthenticCredential, password);
const primaryPort = requiredPort("E6IRC_SSO_PRIMARY_PORT");
const secondaryPort = requiredPort("E6IRC_SSO_SECONDARY_PORT");
assert.notEqual(primaryPort, secondaryPort);

const primaryOrigin = `http://e6irc-primary.localhost:${primaryPort}`;
const secondaryOrigin = `http://e6irc-secondary.localhost:${secondaryPort}`;
const shauthOrigin = "http://localhost:8080";
const primaryBridge = `${primaryOrigin}/auth/shauth/logout/complete`;
const trackedOrigins = new Set([primaryOrigin, secondaryOrigin, shauthOrigin]);

const browser = await chromium.launch({
  headless: true,
  executablePath: process.env.PLAYWRIGHT_EXECUTABLE_PATH || undefined,
});
const failures = [];
try {
  await assertCredentialBoundary(browser);
  const context = await browser.newContext();
  const page = await context.newPage();
  const credentialBoundary = await installCredentialBoundary(context, page);
  const bridgeRequests = [];
  page.on("console", (message) => {
    if (message.type() === "error") failures.push(message.text());
  });
  page.on("pageerror", (error) => failures.push(error.message));
  page.on("requestfailed", (request) => {
    const coordinate = new URL(request.url());
    if (trackedOrigins.has(coordinate.origin)) {
      failures.push(`${coordinate.origin}${coordinate.pathname}: ${request.failure()?.errorText ?? "request failed"}`);
    }
  });
  page.on("request", (request) => {
    const coordinate = new URL(request.url());
    if (coordinate.origin === primaryOrigin && coordinate.pathname === "/auth/shauth/logout/complete") {
      bridgeRequests.push(coordinate.toString());
    }
    if (!trackedOrigins.has(coordinate.origin)) {
      failures.push(`external runtime dependency: ${coordinate.origin}${coordinate.pathname}`);
    }
  });

  const anonymousValidation = await context.request.get(`${primaryOrigin}/auth/validation`, { maxRedirects: 0 });
  assert.equal(anonymousValidation.status(), 303);
  assert.equal(anonymousValidation.headers().location, "/auth/signed-out");
  assertNoStore(anonymousValidation.headers());

  const localCredentialAttempt = await context.request.post(`${primaryOrigin}/api/v1/auth/app-passwords`, {
    data: { account: username, password: nonAuthenticCredential, label: "validator probe" },
  });
  assert.equal(localCredentialAttempt.status(), 401);

  await page.goto(`${primaryOrigin}/`);
  await page.waitForURL(`${primaryOrigin}/login`);
  const directStarter = page.getByRole("link", { name: "Continue with shauth", exact: true });
  assert.equal(await directStarter.getAttribute("href"), "/api/v1/auth/oidc/shauth/start");
  await directStarter.click();
  await page.waitForURL((url) => url.origin === shauthOrigin && url.pathname === "/login");
  await page.locator("#username").fill(username);
  await page.locator("#password").fill(password);
  await page.getByRole("button", { name: "Sign in with password", exact: true }).click();
  await page.waitForURL(`${primaryOrigin}/`);
  await assertProductIdentity(page, primaryOrigin, "admin@localhost.test", "admin");
  await assertValidationIdentity(page, primaryOrigin, "admin@localhost.test", "admin");

  await page.goto(`${shauthOrigin}/apps`);
  await page.getByRole("link", { name: "Open e6irc secondary", exact: true }).click();
  await page.waitForURL(`${secondaryOrigin}/`);
  assert.equal(await page.locator("#username").count(), 0);
  await assertProductIdentity(page, secondaryOrigin, "admin@localhost.test", "admin");
  await assertValidationIdentity(page, secondaryOrigin, "admin@localhost.test", "admin");

  await page.goto(`${primaryOrigin}/`);
  await page.locator("[data-shauth-user]").waitFor();
  const bridgeCount = bridgeRequests.length;
  await page.locator("[data-shauth-sign-out]").click();
  await page.waitForURL(`${primaryOrigin}/auth/signed-out`);
  assert.deepEqual(bridgeRequests.slice(bridgeCount), [primaryBridge]);
  let recovery = page.getByRole("link", { name: "Sign in with shauth", exact: true });
  assert.equal(await recovery.getAttribute("href"), "/api/v1/auth/oidc/shauth/start");
  await page.reload();
  recovery = page.getByRole("link", { name: "Sign in with shauth", exact: true });
  await recovery.waitFor();
  await waitForRevocation(context, primaryOrigin);
  await waitForRevocation(context, secondaryOrigin);

  const injectedBridge = await context.request.get(
    `${primaryBridge}?next=https%3A%2F%2Fattacker.example&redirect_uri=https%3A%2F%2Fattacker.example&code=secret`,
    { maxRedirects: 0 },
  );
  assert.equal(injectedBridge.status(), 303);
  assert.equal(injectedBridge.headers().location, `${shauthOrigin}/oauth/logout/complete`);
  assertNoStore(injectedBridge.headers());
  const replay = await context.request.get(
    `${shauthOrigin}/oauth/logout/complete?next=https%3A%2F%2Fattacker.example`,
    { maxRedirects: 0 },
  );
  assert.equal(replay.status(), 303);
  assert.equal(new URL(replay.headers().location, shauthOrigin).toString(), `${shauthOrigin}/signed-out`);

  await recovery.click();
  await page.waitForURL((url) => url.origin === shauthOrigin && url.pathname === "/login");
  await page.locator("#username").fill(username);
  await page.locator("#password").fill(password);
  await page.getByRole("button", { name: "Sign in with password", exact: true }).click();
  await page.waitForURL(`${primaryOrigin}/`);
  await assertProductIdentity(page, primaryOrigin, "admin@localhost.test", "admin");

  await page.goto(`${secondaryOrigin}/`);
  await page.waitForURL(`${secondaryOrigin}/`);
  assert.equal(await page.locator("#username").count(), 0);
  await assertProductIdentity(page, secondaryOrigin, "admin@localhost.test", "admin");

  await page.goto(`${shauthOrigin}/logout`);
  await page.getByRole("button", { name: "Sign out of all apps", exact: true }).click();
  await page.waitForURL(`${shauthOrigin}/signed-out`);
  await page.reload();
  await page.getByRole("link", { name: "Sign in to Shauth", exact: true }).waitFor();
  await waitForRevocation(context, primaryOrigin);
  await waitForRevocation(context, secondaryOrigin);
  // After the provider-wide sign-out, entry is fail-closed: the silent probe
  // comes back unauthenticated and the application returns the visitor to its
  // own sign-in page with no authenticated shell, exactly as it does for a
  // first-time visitor above.
  await page.goto(`${primaryOrigin}/`);
  await page.waitForURL(`${primaryOrigin}/login`);
  await page
    .getByRole("link", { name: "Continue with shauth", exact: true })
    .waitFor({ state: "visible" });
  assert.equal(await page.locator("[data-shauth-user]").count(), 0);

  assert.deepEqual(credentialBoundary.handlerErrors, []);
  assert.deepEqual(credentialBoundary.violations, []);
  assert.deepEqual(failures, []);
} finally {
  await browser.close();
}

async function assertProductIdentity(page, origin, email, role) {
  assert.equal(page.url(), `${origin}/`);
  const user = page.locator(`[data-shauth-user="${username}"]`);
  await user.waitFor();
  await page.locator("[data-shauth-sign-out]").waitFor();
  assert.equal(await page.locator("#account-name").getAttribute("title"), email);
  assert.equal((await page.locator("#account-role").textContent())?.trim(), role);
}

async function assertValidationIdentity(page, origin, email, role) {
  await page.goto(`${origin}/auth/validation`);
  assert.equal(page.url(), `${origin}/auth/validation`);
  assert.equal((await page.getByTestId("validation-username").textContent())?.trim(), username);
  assert.equal((await page.getByTestId("validation-email").textContent())?.trim(), email);
  assert.equal((await page.getByTestId("validation-role").textContent())?.trim(), role);
  assert.equal((await page.getByTestId("validation-release").textContent())?.trim(), releaseRevision);
  await page.locator(`[data-shauth-user="${username}"]`).waitFor();
  await page.locator("[data-shauth-sign-out]").waitFor();
}

async function waitForRevocation(context, origin) {
  for (let attempt = 0; attempt < 120; attempt += 1) {
    const response = await context.request.get(`${origin}/auth/validation`, { maxRedirects: 0 });
    if (response.status() === 303 && response.headers().location === "/auth/signed-out") return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  assert.fail(`${origin} remained authenticated after global logout`);
}

function assertNoStore(headers) {
  assert.equal(headers["cache-control"], "no-store");
  assert.equal(headers.pragma, "no-cache");
  assert.equal(headers["referrer-policy"], "no-referrer");
}

async function assertCredentialBoundary(browserInstance) {
  const context = await browserInstance.newContext({
    extraHTTPHeaders: {
      Authorization: `Basic ${Buffer.from(`${username}:${password}`).toString("base64")}`,
    },
  });
  try {
    const page = await context.newPage();
    const boundary = await installCredentialBoundary(context, page);
    await assert.rejects(page.goto(`${primaryOrigin}/api/v1/me`), /ERR_BLOCKED_BY_CLIENT/);
    assert.deepEqual(boundary.handlerErrors, []);
    assert.deepEqual(boundary.violations, [{ method: "GET", url: `${primaryOrigin}/api/v1/me` }]);
  } finally {
    await context.close();
  }
}

async function installCredentialBoundary(context, page) {
  const violations = [];
  const handlerErrors = [];
  const session = await context.newCDPSession(page);
  await session.send("Fetch.enable", { patterns: [{ urlPattern: "*", requestStage: "Request" }] });
  session.on("Fetch.requestPaused", async (event) => {
    try {
      if (!requestContainsCredential(event.request)) {
        await session.send("Fetch.continueRequest", { requestId: event.requestId });
        return;
      }
      const target = new URL(event.request.url);
      const permitted =
        event.request.method === "POST" &&
        target.origin === shauthOrigin &&
        target.pathname === "/login" &&
        target.search === "" &&
        target.hash === "";
      if (permitted) {
        await session.send("Fetch.continueRequest", { requestId: event.requestId });
      } else {
        violations.push({ method: event.request.method, url: event.request.url });
        await session.send("Fetch.failRequest", { requestId: event.requestId, errorReason: "BlockedByClient" });
      }
    } catch (error) {
      handlerErrors.push(error instanceof Error ? error.message : String(error));
    }
  });
  return { violations, handlerErrors };
}

function requestContainsCredential(request) {
  const values = [
    password,
    encodeURIComponent(password),
    Buffer.from(password).toString("base64"),
    Buffer.from(`${username}:${password}`).toString("base64"),
  ];
  const payloads = [request.url, request.postData ?? "", ...Object.entries(request.headers).flat()];
  return payloads.some((payload) => values.some((value) => payload.includes(value)));
}

function required(name) {
  const value = process.env[name];
  assert.ok(value, `${name} is required`);
  return value;
}

function requiredPort(name) {
  const value = Number.parseInt(required(name), 10);
  assert.ok(Number.isSafeInteger(value) && value > 0 && value < 65536, `${name} must be a port`);
  return value;
}
