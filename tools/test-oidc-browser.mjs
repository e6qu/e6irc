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

// Hard watchdog: a hung browser, an unresponsive `browser.close()`, or a stuck
// navigation must fail this test in seconds, not sit until the CI job's own
// timeout cancels it (which turned a transient hang into a 13-minute red run).
// Every Playwright action already has a 30s default; this bounds the whole
// script, including teardown, which those defaults do not cover.
const watchdog = setTimeout(() => {
  console.error("test-oidc-browser: watchdog fired after 180s; forcing exit");
  process.exit(1);
}, 180_000);

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
  page.on("requestfailed", (request) => {
    const errorText = request.failure()?.errorText ?? "request failed";
    // A request cancelled in flight when the page is torn down or navigates
    // (e.g. the client's on-load /api/v1/me/networks fetch) reports ERR_ABORTED;
    // that is a teardown artifact, not a page error.
    if (errorText === "net::ERR_ABORTED") return;
    browserErrors.push(`${request.url()}: ${errorText}`);
  });

  // The Shauth catalog launches this exact same-origin starter. A real dex
  // authorization-code + PKCE flow provisions the account and returns to the
  // baked e6irc application.
  await page.goto(`${applicationOrigin}/api/v1/auth/oidc/dex/start`);
  await page.waitForURL(`${applicationOrigin}/`);
  await page.locator("#account-name").waitFor();
  // The client fills #account-name from an async /api/v1/me fetch on boot, so
  // wait for it to be populated rather than racing the placeholder — the
  // element exists in the served HTML immediately, but its identity does not.
  await page.waitForFunction(
    () => document.getElementById("account-name")?.textContent !== "signed in",
  );
  assert.notEqual(await page.locator("#account-name").textContent(), "signed in");
  // The embedded client shell must render an honest, usable zero-network
  // state: account navigation and preferences remain available, the picker
  // distinguishes an empty collection from an API failure, and the composer
  // cannot accept a message with no attached network.
  await page.locator("#network-select").waitFor();
  assert.equal(await page.locator("#network-select").inputValue(), "");
  assert.equal(await page.locator("#message").isDisabled(), true);
  assert.equal(await page.locator("#composer button").isDisabled(), true);
  assert.match(await page.locator("#messages").innerText(), /No networks are configured/);
  assert.equal(await page.getByText("Preferences", { exact: true }).count(), 1);
  assert.equal(await page.getByRole("link", { name: "Manage", exact: true }).getAttribute("href"), "/console/networks");
  // The same authenticated browser owns the server-rendered registered-channel
  // control plane. A new account has an explicit empty state and the complete
  // founder workflow remains discoverable in console navigation.
  await page.goto(`${applicationOrigin}/console/channels`);
  await page.getByRole("heading", { name: "Registered channels", exact: true }).waitFor();
  assert.match(await page.locator("main").innerText(), /No channels registered to this account/);
  await page.getByRole("button", { name: "Register channel", exact: true }).waitFor();
  assert.equal(
    await page.getByRole("link", { name: "Registered channels", exact: true }).getAttribute("class"),
    "active",
  );
  await page.goto(`${applicationOrigin}/`);
  await page.locator("#network-select").waitFor();
  await page.route(`${applicationOrigin}/api/v1/me/networks`, async (route) => {
    await route.fulfill({
      status: 503,
      contentType: "application/problem+json",
      body: JSON.stringify({ status: 503, title: "Database unavailable" }),
    });
  });
  const deliberateFailureErrorStart = browserErrors.length;
  const deliberateFailureResponse = page.waitForResponse(
    (response) =>
      response.url() === `${applicationOrigin}/api/v1/me/networks` &&
      response.status() === 503,
  );
  await page.reload();
  await deliberateFailureResponse;
  await page.locator('[data-alert="networks"]').waitFor();
  assert.match(await page.locator("#messages").innerText(), /API failure, not an empty account/);
  assert.match(await page.locator('[data-alert="networks"]').innerText(), /Database unavailable/);
  assert.equal(
    await page.locator("#network-select option").first().textContent(),
    "Networks unavailable",
  );
  const deliberateFailureErrors = browserErrors.splice(deliberateFailureErrorStart);
  assert.equal(
    deliberateFailureErrors.length,
    1,
    `the deliberate 503 produced unexpected browser errors: ${deliberateFailureErrors.join("; ")}`,
  );
  assert.match(
    deliberateFailureErrors[0],
    /^Failed to load resource: the server responded with a status of 503 \(Service Unavailable\)$/,
  );
  await page.unroute(`${applicationOrigin}/api/v1/me/networks`);
  await page.reload();
  await page.waitForFunction(
    () => document.getElementById("account-name")?.textContent !== "signed in",
  );

  // Exercise the chat shell against a deterministic browser-side network. This
  // covers conversation lifecycle without depending on a live external IRC
  // server: tagged overlap is merged once, a line arriving while history is
  // loading survives, NAMES replaces stale membership, DMs close locally, and
  // a confirmed self-PART removes the channel.
  const networkURL = `${applicationOrigin}/api/v1/me/networks`;
  const historyURL = `${applicationOrigin}/api/v1/me/networks/demo/buffer?limit=1000`;
  await page.route(networkURL, async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        networks: [
          {
            name: "demo",
            kind: "irc",
            nick: "webnick",
            enabled: true,
            connected: false,
            runtime: { state: "reconnect_backoff" },
          },
        ],
      }),
    });
  });
  let mockSocket;
  const clientFrames = [];
  let snapshotSent = false;
  let namesRequestedBeforeSnapshot = false;
  await page.routeWebSocket(/\/ws\/ui\?network=demo$/, (webSocket) => {
    mockSocket = webSocket;
    webSocket.onMessage((frame) => {
      const value = typeof frame === "string" ? frame : frame.toString();
      clientFrames.push(value);
      const command = JSON.parse(value).message;
      if (command === "/raw NAMES #room") {
        if (!snapshotSent) namesRequestedBeforeSnapshot = true;
        webSocket.send(
          JSON.stringify({
            t: "line",
            v: ":irc.example 353 webnick = #room :@webnick +alice bob",
          }),
        );
        webSocket.send(
          JSON.stringify({
            t: "line",
            v: ":irc.example 366 webnick #room :End of /NAMES list",
          }),
        );
      } else if (command === "/part #room") {
        webSocket.send(
          JSON.stringify({
            t: "line",
            v: ":webnick!u@h PART #room :leaving",
          }),
        );
      }
    });
    webSocket.send(JSON.stringify({ t: "status", v: "connected" }));
    webSocket.send(
      JSON.stringify({
        t: "line",
        v: ":irc.example 001 webnick :Welcome",
      }),
    );
    webSocket.send(
      JSON.stringify({
        t: "line",
        v: ":webnick!u@h JOIN #room",
      }),
    );
    webSocket.send(
      JSON.stringify({
        t: "line",
        v: "@time=2026-07-28T20:00:00.000Z;msgid=shared :alice!u@h PRIVMSG #room :initial tagged",
      }),
    );
    // Leave a real scheduling gap: a regression that requests NAMES while
    // replay is still arriving is observable rather than hidden by a
    // synchronous mock burst.
    setTimeout(() => {
      snapshotSent = true;
      webSocket.send(JSON.stringify({ t: "snapshot", v: "complete" }));
    }, 25);
  });
  await page.goto(`${applicationOrigin}/?network=demo`);
  await page.getByText("#room", { exact: true }).first().waitFor();
  await page.waitForFunction(
    () => document.getElementById("nickcount")?.textContent === "3",
  );
  assert.equal(await page.locator("#nickcount").textContent(), "3");
  assert.equal(namesRequestedBeforeSnapshot, false, "NAMES was requested before replay completed");
  assert.match(await page.locator("#network-select").innerText(), /reconnect backoff/);
  const expectedTaggedTime = await page.evaluate(() => {
    const date = new Date("2026-07-28T20:00:00.000Z");
    return `${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`;
  });
  assert.equal(
    await page.getByText("initial tagged", { exact: true }).locator("..").locator(".ts").textContent(),
    expectedTaggedTime,
  );

  let resolveHistoryRoute;
  const historyRouteReached = new Promise((resolve) => {
    resolveHistoryRoute = resolve;
  });
  await page.route(historyURL, (route) => {
    resolveHistoryRoute(route);
  });
  await page.locator("#load-earlier").click();
  await page.getByRole("button", { name: "Loading…" }).waitFor();
  const pendingHistoryRoute = await historyRouteReached;
  mockSocket.send(
    JSON.stringify({
      t: "line",
      v: "@time=2026-07-28T20:00:02.000Z;msgid=live :alice!u@h PRIVMSG #room :arrived while loading",
    }),
  );
  await pendingHistoryRoute.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify({
      lines: [
        "@time=2026-07-28T19:59:00.000Z;msgid=older :alice!u@h PRIVMSG #room :older context",
        "@time=2026-07-28T20:00:00.000Z;msgid=shared :alice!u@h PRIVMSG #room :initial tagged",
      ],
    }),
  });
  await page.locator("#load-earlier").waitFor({ state: "hidden" });
  assert.equal(await page.getByText("initial tagged", { exact: true }).count(), 1);
  assert.equal(await page.getByText("older context", { exact: true }).count(), 1);
  assert.equal(await page.getByText("arrived while loading", { exact: true }).count(), 1);

  // A later NAMES snapshot is authoritative: bob and alice disappear, carol
  // appears, and the list/count cannot retain stale members.
  mockSocket.send(
    JSON.stringify({
      t: "line",
      v: ":irc.example 353 webnick = #room :@webnick carol",
    }),
  );
  mockSocket.send(
    JSON.stringify({
      t: "line",
      v: ":irc.example 366 webnick #room :End of /NAMES list",
    }),
  );
  await page.getByText("carol", { exact: true }).waitFor();
  assert.equal(await page.locator("#nickcount").textContent(), "2");
  assert.equal(await page.getByText("bob", { exact: true }).count(), 0);

  mockSocket.send(
    JSON.stringify({
      t: "line",
      v: "@time=2026-07-28T20:00:03.000Z;msgid=dm :bob!u@h PRIVMSG webnick :private hello",
    }),
  );
  await page.locator(".buf-name").filter({ hasText: /^bob$/ }).click();
  assert.equal(await page.locator("#buffer-action").textContent(), "Close");
  await page.locator("#buffer-action").click();
  assert.equal(await page.locator(".buf-name").filter({ hasText: /^bob$/ }).count(), 0);

  await page.locator(".buf-name").filter({ hasText: /^#room$/ }).click();
  assert.equal(await page.locator("#buffer-action").textContent(), "Leave");
  await page.locator("#buffer-action").click();
  await page.getByText("You left #room (leaving).", { exact: true }).waitFor();
  assert.equal(await page.locator(".buf-name").filter({ hasText: /^#room$/ }).count(), 0);
  assert.ok(
    clientFrames.some((frame) => JSON.parse(frame).message === "/part #room"),
    "Leave did not send PART for the active channel",
  );
  await page.unroute(historyURL);
  await page.unroute(networkURL);

  assert.ok(
    navigationTrace.includes(`request GET ${applicationOrigin}/api/v1/auth/oidc/dex/start`),
    `portal flow bypassed the e6irc OpenID Connect starter:\n${navigationTrace.join("\n")}`,
  );

  // Clearing only e6irc's application session leaves the provider SSO cookie
  // intact. Opening the application directly must use the ordinary
  // authorization starter and restore access without prompting at the
  // provider.
  assert.equal((await context.request.post(`${applicationOrigin}/api/v1/auth/logout`)).status(), 204);
  assert.equal((await context.request.get(`${applicationOrigin}/api/v1/me`)).status(), 401);
  const directTraceStart = navigationTrace.length;
  await page.goto(`${applicationOrigin}/`);
  await page.waitForURL(`${applicationOrigin}/`);
  await page.locator("#account-name").waitFor();
  assert.ok(
    navigationTrace.slice(directTraceStart).includes(`request GET ${applicationOrigin}/api/v1/auth/oidc/dex/start`),
    `direct flow did not use the ordinary OpenID Connect starter:\n${navigationTrace.slice(directTraceStart).join("\n")}`,
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
  clearTimeout(watchdog);
  // `browser.close()` can itself hang on a wedged chromium; bound it so teardown
  // never becomes the thing that hangs the run.
  if (browser) {
    await Promise.race([
      browser.close(),
      new Promise((resolveTimeout) => setTimeout(resolveTimeout, 10_000)),
    ]);
  }
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
