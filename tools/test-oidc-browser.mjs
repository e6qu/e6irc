// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const require = createRequire(new URL("../web/package.json", import.meta.url));
const { chromium } = require("playwright");

const databaseURL = process.env.E6IRC_TEST_DATABASE_URL;
const issuerURL = process.env.E6IRC_TEST_DEX_URL;
assert.ok(databaseURL, "E6IRC_TEST_DATABASE_URL is required");
assert.ok(issuerURL, "E6IRC_TEST_DEX_URL is required");

const applicationOrigin = "http://127.0.0.1:18083";
const temporaryDirectory = await mkdtemp(join(tmpdir(), "e6irc-oidc-browser-"));
const configPath = join(temporaryDirectory, "e6irc.toml");
const serverOutput = [];
await writeFile(
  configPath,
  `server_name = "irc.browser.example"
network_name = "BrowserNet"

[[listeners]]
addr = "127.0.0.1:0"

[http]
addr = "127.0.0.1:18083"
public_url = "${applicationOrigin}"
secure_cookies = false

[database]
url = ${JSON.stringify(databaseURL)}

[[oidc]]
# dex, not Shauth: this harness proves the generic OpenID Connect relying-party
# path against a real provider. dex advertises no end-session endpoint, which is
# a supported configuration here (logout fails closed), whereas a provider named
# "shauth" must satisfy Shauth's stricter contract. tools/test-shauth-sso.sh
# covers that contract against a real Shauth.
name = "dex"
issuer_url = ${JSON.stringify(issuerURL)}
client_id = "e6irc-test"
client_secret = "e6irc-test-secret"
`,
);

const binary = resolve(repositoryRoot, process.env.E6IRC_TEST_SERVER_BINARY ?? "target/debug/e6ircd");
const server = spawn(binary, ["--config", configPath], { stdio: ["ignore", "pipe", "pipe"] });
for (const stream of [server.stdout, server.stderr]) {
  stream.setEncoding("utf8");
  stream.on("data", (chunk) => serverOutput.push(chunk));
}

let browser;
try {
  await waitForHealthyServer();
  browser = await chromium.launch({ headless: true });
  const context = await browser.newContext();
  const page = await context.newPage();
  const browserErrors = [];
  const navigationTrace = [];
  page.on("request", (request) => {
    if (request.isNavigationRequest()) navigationTrace.push(`request ${request.method()} ${sanitizeURL(request.url())}`);
  });
  page.on("console", (message) => {
    if (message.type() === "error") browserErrors.push(message.text());
  });
  page.on("pageerror", (error) => browserErrors.push(error.message));
  page.on("requestfailed", (request) => browserErrors.push(`${request.url()}: ${request.failure()?.errorText ?? "request failed"}`));

  // The Shauth catalog launches this exact same-origin starter. A real dex
  // authorization-code + PKCE flow provisions the account and returns to the
  // baked e6irc application.
  await page.goto(`${applicationOrigin}/api/v1/auth/oidc/dex/start`);
  await page.waitForURL(`${applicationOrigin}/`);
  await page.locator("#account-name").waitFor();
  assert.notEqual(await page.locator("#account-name").textContent(), "signed in");
  assert.ok(
    navigationTrace.includes(`request GET ${applicationOrigin}/api/v1/auth/oidc/dex/start`),
    `portal flow bypassed the e6irc OpenID Connect starter:\n${navigationTrace.join("\n")}`,
  );

  // Clearing only e6irc's application session leaves the provider SSO cookie
  // intact. Opening the application directly must silently restore access.
  assert.equal((await context.request.post(`${applicationOrigin}/api/v1/auth/logout`)).status(), 204);
  assert.equal((await context.request.get(`${applicationOrigin}/api/v1/me`)).status(), 401);
  const directTraceStart = navigationTrace.length;
  await page.goto(`${applicationOrigin}/`);
  await page.waitForURL(`${applicationOrigin}/`);
  await page.locator("#account-name").waitFor();
  assert.ok(
    navigationTrace.slice(directTraceStart).includes(`request GET ${applicationOrigin}/api/v1/auth/oidc/dex/sso`),
    `direct flow did not use silent single sign-on:\n${navigationTrace.slice(directTraceStart).join("\n")}`,
  );

  // The provider's registered post-logout return is public, persistent, and
  // recoverable through the application's own OIDC starter after a reload.
  assert.equal((await context.request.post(`${applicationOrigin}/api/v1/auth/logout`)).status(), 204);
  await page.goto(`${applicationOrigin}/auth/signed-out`);
  await page.getByRole("heading", { name: "You are signed out" }).waitFor();
  let signIn = page.getByRole("link", { name: "Sign in with dex" });
  assert.equal(await signIn.getAttribute("href"), "/api/v1/auth/oidc/dex/start");
  await page.reload();
  await page.getByRole("heading", { name: "You are signed out" }).waitFor();
  signIn = page.getByRole("link", { name: "Sign in with dex" });
  assert.equal(await signIn.getAttribute("href"), "/api/v1/auth/oidc/dex/start");
  const recoveryTraceStart = navigationTrace.length;
  await signIn.click();
  await page.waitForURL(`${applicationOrigin}/`);
  assert.ok(
    navigationTrace.slice(recoveryTraceStart).includes(`request GET ${applicationOrigin}/api/v1/auth/oidc/dex/start`),
    `signed-out recovery bypassed the e6irc OpenID Connect starter:\n${navigationTrace.slice(recoveryTraceStart).join("\n")}`,
  );
  assert.deepEqual(browserErrors, []);
} finally {
  if (browser) await browser.close();
  server.kill("SIGTERM");
  await Promise.race([
    new Promise((resolveExit) => server.once("exit", resolveExit)),
    new Promise((resolveTimeout) => setTimeout(resolveTimeout, 5_000)),
  ]);
  await rm(temporaryDirectory, { recursive: true, force: true });
}

async function waitForHealthyServer() {
  for (let attempt = 0; attempt < 150; attempt += 1) {
    if (server.exitCode !== null) {
      assert.fail(`e6ircd exited before becoming healthy:\n${serverOutput.join("")}`);
    }
    try {
      const response = await fetch(`${applicationOrigin}/healthz`);
      if (response.ok) return;
    } catch {
      // The real server is still starting.
    }
    await new Promise((resolveDelay) => setTimeout(resolveDelay, 100));
  }
  assert.fail(`e6ircd did not become healthy:\n${serverOutput.join("")}`);
}

function sanitizeURL(value) {
  const parsed = new URL(value);
  return `${parsed.origin}${parsed.pathname}`;
}
