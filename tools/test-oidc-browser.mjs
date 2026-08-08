// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { createRequire } from "node:module";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const repositoryRoot = resolve(fileURLToPath(new URL("..", import.meta.url)));
const require = createRequire(new URL("../web/package.json", import.meta.url));
const playwright = require("playwright");
const AxeBuilder = require("@axe-core/playwright").default;
const browserName = process.env.E6IRC_TEST_BROWSER ?? "chromium";
assert.ok(
  ["chromium", "firefox", "webkit"].includes(browserName),
  `E6IRC_TEST_BROWSER must be chromium, firefox, or webkit; got ${browserName}`,
);
const browserType = playwright[browserName];
const requireNativeNotificationPermission = browserName === "chromium";

async function clickAndWaitForURL(page, locator, expectedURL) {
  const navigation = page.waitForEvent("framenavigated", (frame) =>
    frame === page.mainFrame() && frame.url() === expectedURL
  );
  await Promise.all([navigation, locator.click()]);
  assert.equal(page.url(), expectedURL);
}

async function expectAccessible(page, selector) {
  const results = await new AxeBuilder({ page }).include(selector).analyze();
  assert.deepEqual(
    results.violations,
    [],
    results.violations.map(({ id, help, nodes }) => `${id}: ${help}\n${nodes.map((node) => node.html).join("\n")}`).join("\n\n"),
  );
}

// A configuration form POST navigates to a re-rendered page, but the old
// document — including its previous status banner — stays in the DOM until
// the response arrives. Waiting for any role="status" therefore resolves
// against the stale banner and reads the previous outcome on slower engines
// (webkit). Wait for the banner that carries this action's outcome instead.
async function expectStatus(page, pattern) {
  const banner = page.getByRole("status").filter({ hasText: pattern });
  await banner.waitFor();
  assert.match(await banner.innerText(), pattern);
}

async function waitForConfigurationServerName(page, value) {
  await page.waitForFunction(
    (expected) => document.querySelector('form.settings-form input[name="server_name"]')?.value === expected,
    value,
  );
}

const databaseURL = process.env.E6IRC_TEST_DATABASE_URL;
const issuerURL = process.env.E6IRC_TEST_DEX_URL;
assert.ok(databaseURL, "E6IRC_TEST_DATABASE_URL is required");
assert.ok(issuerURL, "E6IRC_TEST_DEX_URL is required");

const applicationOrigin = "http://127.0.0.1:18083";
const temporaryDirectory = await mkdtemp(join(tmpdir(), "e6irc-oidc-browser-"));
const configPath = join(temporaryDirectory, "e6irc.toml");
const secretKeyPath = join(temporaryDirectory, "master.key");
const serverOutput = [];
const upstream = await startIrcUpstream();
await writeFile(secretKeyPath, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n", {
  mode: 0o600,
});
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
admin_accounts = ["kilgore"]

[database]
url = ${JSON.stringify(databaseURL)}

[secrets]
key_file = ${JSON.stringify(secretKeyPath)}

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
let server = startApplicationServer();

// Hard watchdog: a hung browser, an unresponsive `browser.close()`, or a stuck
// navigation must fail this test in seconds, not sit until the CI job's own
// timeout cancels it (which turned a transient hang into a 13-minute red run).
// Every Playwright action already has a 30s default; this bounds the whole
// script, including teardown, which those defaults do not cover.
const watchdog = setTimeout(() => {
  console.error("test-oidc-browser: watchdog fired after 180s; forcing exit");
  process.exit(1);
}, 180_000);

const artifactDirectory = process.env.E6IRC_BROWSER_ARTIFACTS_DIR;
const applicationErrors = [];
const applicationRequests = [];
const navigationTrace = [];
let browser;
let context;
let page;
let tracing = false;
try {
  await waitForHealthyServer();
  // Playwright's default Chromium headless shell accepts a notification
  // permission grant but can only report it as denied because the shell omits
  // the native notification service. The full Chromium channel uses the same
  // new-headless engine as production Chromium and exposes the permission
  // boundary this journey is meant to prove.
  browser = await browserType.launch({
    headless: true,
    ...(browserName === "chromium" ? { channel: "chromium" } : {}),
  });
  context = await browser.newContext();
  if (artifactDirectory) {
    await mkdir(artifactDirectory, { recursive: true });
    await context.tracing.start({ screenshots: true, snapshots: true, sources: true });
    tracing = true;
  }
  await context.grantPermissions(["notifications"], { origin: applicationOrigin });
  page = await context.newPage();
  page.on("request", (request) => {
    if (isApplicationURL(request.url())) {
      applicationRequests.push(`${request.method()} ${sanitizeURL(request.url())}`);
    }
    if (request.isNavigationRequest()) navigationTrace.push(`request ${request.method()} ${sanitizeURL(request.url())}`);
  });
  page.on("console", (message) => {
    const sourceURL = message.location().url || page.url();
    if (
      message.type() === "error"
      && isApplicationURL(sourceURL)
      && !message.text().startsWith("Failed to load resource:")
    ) {
      applicationErrors.push(message.text());
    }
  });
  page.on("response", (response) => {
    if (response.status() >= 400 && isApplicationURL(response.url())) {
      applicationErrors.push(
        `${response.status()} ${response.request().method()} ${sanitizeURL(response.url())}`,
      );
    }
  });
  page.on("pageerror", (error) => {
    // WebKit reports an intercepted-and-fulfilled fetch as an uncaught
    // "… due to access control checks." rejection in addition to the response
    // diagnostic; the response handler above already records the real status,
    // so this engine artifact is noise, not a page error.
    if (error.message.includes("due to access control checks")) return;
    if (isApplicationURL(page.url())) applicationErrors.push(error.message);
  });
  page.on("requestfailed", (request) => {
    if (!isApplicationURL(request.url())) return;
    const errorText = request.failure()?.errorText ?? "request failed";
    // A request cancelled in flight when the page is torn down or navigates
    // (e.g. the client's on-load /api/v1/me/networks fetch) reports ERR_ABORTED;
    // that is a teardown artifact, not a page error.
    if (
      errorText === "net::ERR_ABORTED"
      || errorText.includes("NS_BINDING_ABORTED")
      || errorText.toLowerCase().includes("cancel")
    ) return;
    applicationErrors.push(`${request.url()}: ${errorText}`);
  });

  // The Shauth catalog launches this exact same-origin starter. A real dex
  // authorization-code + PKCE flow provisions the account and returns to the
  // baked e6irc application.
  await page.goto(`${applicationOrigin}/api/v1/auth/oidc/dex/start`);
  assert.equal(page.url(), `${applicationOrigin}/`);
  await page.locator("#account-name").waitFor();
  // Wait for identity API hydration.
  await page.waitForFunction(
    () => document.getElementById("account-name")?.textContent !== "signed in",
  );
  const accountName = await page.locator("#account-name").textContent();
  assert.ok(accountName && accountName !== "signed in");
  const iconHref = await page.locator('link[rel="icon"]').getAttribute("href");
  assert.match(iconHref, /^\.\/assets\/favicon-[A-Za-z0-9_-]+\.svg$/);
  const iconResponse = await context.request.get(new URL(iconHref, applicationOrigin).href);
  assert.equal(iconResponse.status(), 200);
  assert.match(iconResponse.headers()["content-type"], /^image\/svg\+xml\b/);
  assert.equal(
    iconResponse.headers()["cache-control"],
    "public, max-age=31536000, immutable",
  );
  // The embedded client shell must render an honest, usable zero-network
  // state: account navigation and preferences remain available, the picker
  // distinguishes an empty collection from an API failure, and the composer
  // cannot accept a message with no attached network.
  await page.locator("#network-select").waitFor();
  // The zero-network state is rendered only after the boot-time networks fetch
  // resolves; reading #messages before then races the fetch (and loses on
  // slower runners), so wait for the render itself.
  await page.locator("#messages").getByText("No networks are configured").waitFor();
  await expectAccessible(page, "#app");
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
  await page.getByText("No channels registered to this account", { exact: true }).waitFor();
  await page.getByRole("button", { name: "Register channel", exact: true }).waitFor();
  assert.equal(
    await page.getByRole("link", { name: "Registered channels", exact: true }).getAttribute("class"),
    "active",
  );

  // An OpenID Connect-only account can add a local password through the real
  // self-service form, sign out, and submit the actual local-login page in
  // Chromium. This closes the browser boundary that the HTTP credential tests
  // cannot cross.
  let tokenDirectoryReads = 0;
  const tokenFailureErrorStart = applicationErrors.length;
  await page.route(`${applicationOrigin}/api/v1/me/tokens`, async (route) => {
    tokenDirectoryReads += 1;
    if (tokenDirectoryReads === 1) {
      await route.fulfill({
        status: 503,
        contentType: "application/problem+json",
        body: JSON.stringify({ status: 503, title: "Token storage unavailable" }),
      });
    } else {
      await route.continue();
    }
  });
  await page.goto(`${applicationOrigin}/console/account`);
  await expectAccessible(page, "body");
  const tokenFailure = page.locator("#account-token-rows [role=status]");
  await tokenFailure.waitFor();
  assert.match(await tokenFailure.innerText(), /Token storage unavailable/);
  await page.locator("#account-token-rows").getByRole("button", { name: "Retry", exact: true }).click();
  await page.getByText("No personal access tokens.", { exact: true }).waitFor();
  assert.equal(tokenDirectoryReads, 2, "Retry made exactly one replacement token request");
  assert.deepEqual(
    applicationErrors.splice(tokenFailureErrorStart),
    [`503 GET ${applicationOrigin}/api/v1/me/tokens`],
    "the deliberate token failure was the only browser diagnostic during recovery",
  );
  await page.unroute(`${applicationOrigin}/api/v1/me/tokens`);
  let malformedTokenDirectoryReads = 0;
  const malformedTokenDirectoryErrorStart = applicationErrors.length;
  await page.route(`${applicationOrigin}/api/v1/me/tokens`, async (route) => {
    malformedTokenDirectoryReads += 1;
    if (malformedTokenDirectoryReads === 1) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ tokens: {} }),
      });
    } else {
      await route.continue();
    }
  });
  await page.reload();
  const malformedTokenDirectoryFailure = page.locator("#account-token-rows [role=status]");
  await malformedTokenDirectoryFailure.waitFor();
  assert.match(await malformedTokenDirectoryFailure.innerText(), /token directory response is invalid/i);
  await page.locator("#account-token-rows").getByRole("button", { name: "Retry", exact: true }).click();
  await page.getByText("No personal access tokens.", { exact: true }).waitFor();
  assert.equal(malformedTokenDirectoryReads, 2, "Retry made exactly one replacement malformed-token request");
  assert.deepEqual(
    applicationErrors.splice(malformedTokenDirectoryErrorStart),
    [],
    "a malformed successful token response is an in-document contract failure, not a browser diagnostic",
  );
  await page.unroute(`${applicationOrigin}/api/v1/me/tokens`);
  await page.getByRole("heading", { name: "Add a local password", exact: true }).waitFor();
  // Console and chat deliberately share one typed local preference document.
  // Exercise the console's own control through a persisted choice, a reload,
  // and the system reset; API tests cannot prove these browser-only outcomes.
  const consoleTheme = page.locator("[data-console-theme]");
  await consoleTheme.selectOption("light");
  await page.waitForFunction(() => document.documentElement.dataset.theme === "light");
  assert.deepEqual(
    await page.evaluate(() => JSON.parse(localStorage.getItem("e6irc.settings"))),
    { theme: "light", notifications: false },
  );
  await page.reload();
  await page.getByRole("heading", { name: "Add a local password", exact: true }).waitFor();
  assert.equal(await consoleTheme.inputValue(), "light");
  assert.equal(await page.locator("html").getAttribute("data-theme"), "light");
  await consoleTheme.selectOption("auto");
  await page.waitForFunction(() => !document.documentElement.hasAttribute("data-theme"));
  assert.deepEqual(
    await page.evaluate(() => JSON.parse(localStorage.getItem("e6irc.settings"))),
    { theme: "auto", notifications: false },
  );
  await consoleTheme.selectOption("dark");
  await page.waitForFunction(() => document.documentElement.dataset.theme === "dark");
  // A narrow viewport keeps the console's complete navigation in its own
  // horizontal rail instead of creating a second tall page above the task.
  // The document itself must remain free of horizontal overflow, including
  // the authenticated header and its account identity.
  await page.setViewportSize({ width: 375, height: 800 });
  await page.locator("[data-shauth-user]").evaluate((user) => {
    user.textContent = "an-unbroken-account-identity-that-must-wrap-on-a-narrow-viewport";
  });
  const narrowLayout = await page.evaluate(() => {
    const nav = document.querySelector("nav");
    const layout = document.querySelector(".layout");
    const main = document.querySelector("main");
    return {
      documentWidth: document.documentElement.scrollWidth,
      viewportWidth: document.documentElement.clientWidth,
      layoutWidth: layout.getBoundingClientRect().width,
      mainWidth: main.getBoundingClientRect().width,
      navClientWidth: nav.clientWidth,
      navScrollWidth: nav.scrollWidth,
    };
  });
  assert.equal(
    narrowLayout.documentWidth <= narrowLayout.viewportWidth,
    true,
    JSON.stringify(narrowLayout),
  );
  assert.equal(
    await page.locator("nav").evaluate((nav) => getComputedStyle(nav).overflowX),
    "auto",
  );
  await page.getByRole("link", { name: "Registered channels", exact: true }).click();
  await page.getByRole("heading", { name: "Registered channels", exact: true }).waitFor();
  assert.equal(
    await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    true,
  );
  await page.setViewportSize({ width: 1280, height: 720 });
  await page.goto(`${applicationOrigin}/console/account`);
  await page.getByRole("heading", { name: "Add a local password", exact: true }).waitFor();
  await page.getByLabel("New password", { exact: true }).fill("browser-local-password");
  await page.getByLabel("Confirm new password", { exact: true }).fill("browser-local-password");
  await page.getByRole("button", { name: "Add password", exact: true }).click();
  await expectStatus(page, /Local password added/);
  assert.equal((await context.request.post(`${applicationOrigin}/api/v1/auth/logout`)).status(), 204);
  await page.goto(`${applicationOrigin}/login`);
  await page.getByLabel("Account", { exact: true }).fill(accountName);
  await page.getByLabel("Password", { exact: true }).fill("browser-local-password");
  await clickAndWaitForURL(
    page,
    page.getByRole("button", { name: "Sign in", exact: true }),
    `${applicationOrigin}/`,
  );
  await page.waitForFunction(
    () => document.getElementById("account-name")?.textContent !== "signed in",
  );
  assert.equal(await page.locator("#account-name").textContent(), accountName);

  // Preferences are a real product workflow, not incidental localStorage.
  // Headless engines differ in whether they expose a granted Notification
  // permission after context.grantPermissions. Chromium's full headless
  // channel is a required native boundary; where another engine does not expose
  // that platform surface, provide exactly the granted boundary. The later
  // real-stack DM assertion supplies and inspects the constructor independently.
  await page.getByText("Preferences", { exact: true }).click();
  await page.locator("#theme-select").selectOption("dark");
  assert.equal(await page.locator("html").getAttribute("data-theme"), "dark");
  const notificationPermission = await page.evaluate(
    () => globalThis.Notification?.permission ?? "unsupported",
  );
  if (notificationPermission !== "granted") {
    assert.ok(
      ["default", "denied", "unsupported"].includes(notificationPermission),
      `unexpected Notification permission state: ${notificationPermission}`,
    );
    assert.equal(
      requireNativeNotificationPermission,
      false,
      `the browser did not honor the granted Notification permission: ${notificationPermission}`,
    );
    await page.evaluate(() => {
      Object.defineProperty(globalThis, "Notification", {
        configurable: true,
        value: class {
          static permission = "granted";
          static requestPermission() {
            return Promise.resolve("granted");
          }
        },
      });
    });
  }
  await page.getByRole("button", { name: "Desktop notifications: off" }).click();
  assert.equal(
    await page.getByRole("button", { name: "Desktop notifications: on" }).getAttribute(
      "aria-pressed",
    ),
    "true",
  );
  assert.deepEqual(
    await page.evaluate(() => JSON.parse(localStorage.getItem("e6irc.settings"))),
    { theme: "dark", notifications: true },
  );
  await page.reload();
  assert.equal(await page.locator("html").getAttribute("data-theme"), "dark");
  await page.getByText("Preferences", { exact: true }).click();
  await page.getByRole("button", { name: "Desktop notifications: on" }).waitFor();

  // The administrator manages every scalar configuration section and all
  // credential-bearing collections through the rendered browser controls.
  // Secrets are deliberately conspicuous and must never reappear in the DOM.
  assert.equal(
    accountName,
    "kilgore",
    "dex mock identity drifted from the configured administrator",
  );
  let configurationReads = 0;
  const configurationFailureErrorStart = applicationErrors.length;
  await page.route(`${applicationOrigin}/api/v1/admin/configuration`, async (route) => {
    configurationReads += 1;
    if (configurationReads === 1) {
      await route.fulfill({
        status: 503,
        contentType: "application/problem+json",
        body: JSON.stringify({ status: 503, title: "Configuration inventory unavailable" }),
      });
    } else {
      await route.continue();
    }
  });
  await page.goto(`${applicationOrigin}/console/configuration`);
  await page.getByRole("heading", { name: "Configuration", exact: true }).waitFor();
  const configurationFailure = page.locator("#configuration-api-result");
  await configurationFailure.getByRole("button", { name: "Retry", exact: true }).waitFor();
  assert.match(await configurationFailure.innerText(), /Configuration inventory unavailable/);
  await configurationFailure.getByRole("button", { name: "Retry", exact: true }).click();
  const settingsForm = page.locator("form.settings-form");
  await waitForConfigurationServerName(page, "irc.browser.example");
  assert.equal(configurationReads, 2, "Retry made exactly one replacement configuration request");
  assert.deepEqual(
    applicationErrors.splice(configurationFailureErrorStart),
    [`503 GET ${applicationOrigin}/api/v1/admin/configuration`],
    "the deliberate configuration failure was the only browser diagnostic during recovery",
  );
  await page.unroute(`${applicationOrigin}/api/v1/admin/configuration`);
  await settingsForm.getByLabel("Server hostname").fill("irc.browser-managed.example");
  await settingsForm.getByLabel("Network name").fill("ManagedBrowserNet");
  await settingsForm.getByLabel("Description").fill("Browser-managed server");
  await settingsForm.getByLabel("Message of the day").fill("Managed in Chromium\nSecond line");
  await settingsForm.getByLabel("Accept BNC client connections").check();
  await settingsForm.getByLabel("Listen address").fill("127.0.0.1:0");
  await settingsForm.getByLabel("Listener definitions").fill("127.0.0.1:0 | plain");
  await settingsForm.getByLabel("Public URL").fill(applicationOrigin);
  await settingsForm.getByLabel("Require secure session cookies").uncheck();
  await settingsForm.getByLabel("Administrator accounts").fill("kilgore");
  await settingsForm.getByLabel("Nickname length").fill("24");
  await settingsForm.getByLabel("Send queue").fill("2048");
  await settingsForm.getByLabel("Core queue").fill("32768");
  await settingsForm.getByLabel("Hot channels").fill("4096");
  await settingsForm.getByLabel("Connections per IP").fill("128");
  await settingsForm.getByLabel("Command burst").fill("32");
  await settingsForm.getByLabel("Authentication burst").fill("8");
  await settingsForm.getByLabel("Registration burst").fill("4");
  await settingsForm.getByLabel("Trusted proxies").fill("127.0.0.1/32");
  const storageSettings = settingsForm.locator("section.settings-section").filter({
    has: page.getByRole("heading", { name: "Storage retention", exact: true }),
  });
  await storageSettings.getByLabel("Message history retention").fill("45");
  await storageSettings.getByLabel("Audit retention").fill("400");
  const monitoringSettings = settingsForm.locator("section.settings-section").filter({
    has: page.getByRole("heading", { name: "Monitoring history", exact: true }),
  });
  await monitoringSettings.getByLabel("Store monitoring samples").check();
  await monitoringSettings.getByLabel("Sample interval").fill("5");
  await monitoringSettings.getByLabel("Retention").fill("24");
  await settingsForm
    .getByLabel("Allow registration before connection registration completes")
    .check();
  await settingsForm.getByLabel("Require an email field").check();
  await settingsForm.getByRole("button", { name: "Save configuration" }).click();
  await expectStatus(page, /Configuration saved/);
  await waitForConfigurationServerName(page, "irc.browser-managed.example");
  assert.match(await page.locator("main").innerText(), /Revision 2/);
  assert.match(await page.locator("main").innerText(), /Accepting clients on/);
  assert.equal(
    await settingsForm.getByLabel("Server hostname").inputValue(),
    "irc.browser-managed.example",
  );
  assert.equal(await settingsForm.getByLabel("Require an email field").isChecked(), true);
  assert.equal(await storageSettings.getByLabel("Message history retention").inputValue(), "45");
  assert.equal(await storageSettings.getByLabel("Audit retention").inputValue(), "400");

  const sharedNetworkSecret = "browser-shared-network-secret";
  const serverNetworks = page.locator("section").filter({
    has: page.getByRole("heading", { name: "Server networks", exact: true }),
  });
  await serverNetworks.getByLabel("Network name").fill("shared-browser");
  await serverNetworks.getByLabel("Address").fill(upstream.address);
  await serverNetworks.getByLabel("Nickname / user").fill("sharedbrowser");
  await serverNetworks.getByLabel("Autojoin").fill("#shared");
  await serverNetworks.getByLabel("Use TLS").uncheck();
  await serverNetworks.getByLabel("SASL account").fill("shared-account");
  await serverNetworks.getByLabel("SASL password").fill(sharedNetworkSecret);
  await serverNetworks.getByRole("button", { name: "Add server network" }).click();
  await expectStatus(page, /added server network shared-browser/);
  assert.equal((await page.content()).includes(sharedNetworkSecret), false);

  const operatorSecret = "browser-operator-secret";
  const operators = page.locator("section").filter({
    has: page.getByRole("heading", { name: "IRC operators", exact: true }),
  });
  await operators.getByLabel("Operator name").fill("browserop");
  await operators.getByLabel("New password").fill(operatorSecret);
  await operators.getByRole("button", { name: "Add operator" }).click();
  await expectStatus(page, /added IRC operator browserop/);
  assert.equal((await page.content()).includes(operatorSecret), false);

  const providerSecret = "browser-provider-secret";
  const providers = page.locator("section").filter({
    has: page.getByRole("heading", { name: "OpenID Connect", exact: true }),
  });
  await providers.getByLabel("Provider name").fill("browser-idp");
  await providers.getByLabel("Issuer URL").fill("https://identity.example");
  await providers.getByLabel("Client ID").fill("browser-client");
  await providers.getByLabel("Client secret").fill(providerSecret);
  await providers.getByLabel("Scopes").fill("openid profile");
  await providers.getByLabel("Token authentication").selectOption("client_secret_post");
  await providers.getByLabel("End-session endpoint").fill("https://identity.example/logout");
  await providers.getByRole("button", { name: "Add identity provider" }).click();
  await expectStatus(page, /added OpenID Connect provider browser-idp/);
  assert.equal((await page.content()).includes(providerSecret), false);

  for (const [heading, item, outcome] of [
    ["Server networks", "shared-browser", "removed server network shared-browser"],
    ["IRC operators", "browserop", "removed IRC operator browserop"],
    ["OpenID Connect", "browser-idp", "removed OpenID Connect provider browser-idp"],
  ]) {
    const section = page.locator("section").filter({
      has: page.getByRole("heading", { name: heading, exact: true }),
    });
    const row = section.locator("article, .compact-list > div").filter({ hasText: item });
    await row.getByRole("button", { name: "Remove" }).click();
    await expectStatus(page, new RegExp(outcome));
  }
  // The success banner is rendered before the API-hydrated revision text on
  // slower engines. Wait for the observed configuration revision itself.
  await page.getByText("Revision 8", { exact: true }).waitFor();

  // The operational console is part of the browser acceptance boundary, not
  // merely a collection of HTTP handlers. Visit every administrator directory,
  // prove queue pressure crosses the live JSON/UI boundary, and perform a
  // durable policy mutation through the rendered controls.
  let administratorNetworkReads = 0;
  const administratorNetworkFailureErrorStart = applicationErrors.length;
  await page.route(`${applicationOrigin}/api/v1/admin/networks`, async (route) => {
    administratorNetworkReads += 1;
    if (administratorNetworkReads === 1) {
      await route.fulfill({
        status: 503,
        contentType: "application/problem+json",
        body: JSON.stringify({ status: 503, title: "Fleet inventory unavailable" }),
      });
    } else {
      await route.continue();
    }
  });
  await page.goto(`${applicationOrigin}/console/admin/networks`);
  const administratorNetworkFailure = page.locator("#admin-network-rows [role=status]");
  await administratorNetworkFailure.waitFor();
  assert.match(await administratorNetworkFailure.innerText(), /Fleet inventory unavailable/);
  await page.locator("#admin-network-rows").getByRole("button", { name: "Retry", exact: true }).click();
  await page.getByText("No networks configured by any account.", { exact: true }).waitFor();
  assert.equal(administratorNetworkReads, 2, "Retry made exactly one replacement fleet request");
  assert.deepEqual(
    applicationErrors.splice(administratorNetworkFailureErrorStart),
    [`503 GET ${applicationOrigin}/api/v1/admin/networks`],
    "the deliberate fleet failure was the only browser diagnostic during recovery",
  );
  await page.unroute(`${applicationOrigin}/api/v1/admin/networks`);

  let overviewStatsReads = 0;
  const overviewFailureErrorStart = applicationErrors.length;
  await page.route(`${applicationOrigin}/api/v1/admin/stats`, async (route) => {
    overviewStatsReads += 1;
    if (overviewStatsReads === 1) {
      await route.fulfill({
        status: 503,
        contentType: "application/problem+json",
        body: JSON.stringify({ status: 503, title: "Overview statistics unavailable" }),
      });
    } else {
      await route.continue();
    }
  });
  await page.goto(`${applicationOrigin}/console`);
  const overviewFailure = page.locator("#overview-api-result");
  await overviewFailure.getByRole("button", { name: "Retry", exact: true }).waitFor();
  assert.match(await overviewFailure.innerText(), /Overview statistics unavailable/);
  await overviewFailure.getByRole("button", { name: "Retry", exact: true }).click();
  await page.getByRole("heading", { name: "Newest accounts", exact: false }).waitFor();
  assert.equal(overviewStatsReads, 2, "Retry made exactly one replacement overview request");
  assert.deepEqual(
    applicationErrors.splice(overviewFailureErrorStart),
    [`503 GET ${applicationOrigin}/api/v1/admin/stats`],
    "the deliberate overview failure was the only browser diagnostic during recovery",
  );
  await page.unroute(`${applicationOrigin}/api/v1/admin/stats`);

  for (const [path, heading] of [
    ["/console/accounts", "Account directory"],
    ["/console/admin/channels", "Registered-channel directory"],
    ["/console/admin/networks", "All BNC networks"],
    ["/console/sessions", "Live connections"],
    ["/console/integrations", "Integrations"],
    ["/console/audit", "Audit log"],
  ]) {
    await page.goto(`${applicationOrigin}${path}`);
    await page.getByRole("heading", { name: heading, exact: true }).waitFor();
    await expectAccessible(page, "main");
  }

  await page.goto(`${applicationOrigin}/console`);
  await page.getByRole("heading", { name: "Newest accounts", exact: false }).waitFor();
  assert.match(await page.locator("main").innerText(), /Recent audited actions/);

  // Cross invitation onboarding and permanent self-service deletion through
  // two independent browser contexts. The administrator sees the bearer link
  // once; the recipient chooses its own password, receives its own session,
  // downloads a secret-free export, sees security activity, and deletes the
  // account with explicit confirmation.
  const accountDirectoryResponse = await page.goto(`${applicationOrigin}/console/accounts`);
  assert.equal(
    accountDirectoryResponse?.status(),
    200,
    `account directory navigation failed at ${page.url()}:\n${await page.locator("main").innerText()}`,
  );
  await page.getByRole("heading", { name: "Account directory", exact: true }).waitFor();
  const inviteAccount = page.locator("section").filter({
    has: page.getByRole("heading", { name: "Invite an account", exact: true }),
  });
  await inviteAccount.getByLabel("Account name", { exact: true }).fill("browserguest");
  await inviteAccount.getByLabel("Contact email (optional)", { exact: true }).fill("Guest@Example.COM");
  await inviteAccount.getByLabel("Lifetime", { exact: true }).selectOption("1");
  await inviteAccount.getByRole("button", { name: "Issue invitation", exact: true }).click();
  await expectStatus(page, /Invitation issued/);
  const invitationURL = (await page.locator("#issued-invitation").innerText()).trim();
  assert.match(invitationURL, /^http:\/\/127\.0\.0\.1:18083\/invite\/e6i_/);

  const guestContext = await browser.newContext();
  try {
    const guest = await guestContext.newPage();
    await guest.goto(invitationURL);
    await guest.getByRole("heading", { name: "Create browserguest", exact: true }).waitFor();
    await guest.getByLabel("Password", { exact: true }).fill("browser-guest-password");
    await guest.getByLabel("Confirm password", { exact: true }).fill("browser-guest-password");
    await clickAndWaitForURL(
      guest,
      guest.getByRole("button", { name: "Create account", exact: true }),
      `${applicationOrigin}/console`,
    );

    await guest.goto(`${applicationOrigin}/console/account`);
    await guest.getByRole("heading", { name: "Security activity", exact: true }).waitFor();
    await guest.getByText("ACCOUNT_LOGIN", { exact: true }).waitFor();
    const exportResponse = await guestContext.request.get(`${applicationOrigin}/api/v1/me/export`);
    assert.equal(exportResponse.status(), 200);
    assert.match(exportResponse.headers()["content-disposition"], /e6irc-account-export\.json/);
    const exported = await exportResponse.json();
    assert.equal(exported.account.name, "browserguest");
    assert.equal(exported.account.contact_email, "Guest@example.com");

    const deleteAccount = guest.locator("section").filter({
      has: guest.getByRole("heading", {
        name: "Permanently delete this account",
        exact: true,
      }),
    });
    await deleteAccount.getByLabel("Type browserguest to confirm", { exact: true }).fill("browserguest");
    await deleteAccount.getByRole("button", {
      name: "Delete my account permanently",
      exact: true,
    }).click();
    const confirmation = guest.getByRole("dialog", { name: "Confirm action", exact: true });
    await confirmation.waitFor();
    await expectAccessible(guest, "[data-console-confirm]");
    assert.equal(
      await confirmation.evaluate((dialog) => dialog.contains(document.activeElement)),
      true,
      "confirmation did not move focus into its modal dialog",
    );
    await confirmation.press("Escape");
    await confirmation.waitFor({ state: "hidden" });
    assert.equal(
      await deleteAccount.getByRole("button", {
        name: "Delete my account permanently",
        exact: true,
      }).evaluate((button) => button === document.activeElement),
      true,
      "closing confirmation did not restore focus to its trigger",
    );
    assert.equal(
      await deleteAccount.getByLabel("Type browserguest to confirm", { exact: true }).inputValue(),
      "browserguest",
    );
    await deleteAccount.getByRole("button", {
      name: "Delete my account permanently",
      exact: true,
    }).click();
    await confirmation.waitFor();
    await clickAndWaitForURL(
      guest,
      confirmation.getByRole("button", { name: "Continue", exact: true }),
      `${applicationOrigin}/auth/signed-out`,
    );
    assert.equal((await guestContext.request.get(`${applicationOrigin}/api/v1/me`)).status(), 401);
  } finally {
    await guestContext.close();
  }

  await page.emulateMedia({ reducedMotion: "reduce" });
  assert.equal(
    await page.evaluate(() => matchMedia("(prefers-reduced-motion: reduce)").matches),
    true,
  );
  const monitoringURL = `${applicationOrigin}/api/v1/admin/monitoring?minutes=60`;
  let releaseInitialMonitoring;
  const initialMonitoringReleased = new Promise((resolve) => {
    releaseInitialMonitoring = resolve;
  });
  let initialMonitoringSeen;
  const initialMonitoringRequest = new Promise((resolve) => {
    initialMonitoringSeen = resolve;
  });
  let queuedMonitoringSeen;
  const queuedMonitoringRequest = new Promise((resolve) => {
    queuedMonitoringSeen = resolve;
  });
  let monitoringRequests = 0;
  await page.route(monitoringURL, async (route) => {
    monitoringRequests += 1;
    if (monitoringRequests === 1) {
      initialMonitoringSeen();
      await initialMonitoringReleased;
    } else if (monitoringRequests === 2) {
      queuedMonitoringSeen();
    }
    await route.continue();
  });
  const monitoringRead = page.waitForResponse(
    (response) =>
      response.url() === monitoringURL &&
      response.request().method() === "GET",
  );
  await page.goto(`${applicationOrigin}/console/monitoring`);
  await initialMonitoringRequest;
  const refreshMonitoring = page.getByRole("button", { name: "Refresh", exact: true });
  await refreshMonitoring.click();
  await refreshMonitoring.click();
  releaseInitialMonitoring();
  assert.equal((await monitoringRead).status(), 200);
  await queuedMonitoringRequest;
  assert.equal(monitoringRequests, 2, "overlapping refreshes must coalesce to one queued request");
  await page.getByRole("heading", { name: "Monitoring", exact: true }).waitFor();
  await page.getByRole("heading", { name: "Queue pressure", exact: true }).waitFor();
  await page.getByText("Live data refreshed.", { exact: true }).waitFor();
  assert.equal(
    await page.locator(".pulse").evaluate((pulse) => getComputedStyle(pulse).animationName),
    "none",
    "reduced motion must disable the live-status pulse",
  );
  await page.unroute(monitoringURL);
  const runtimeQueues = page.locator("section").filter({
    has: page.getByRole("heading", { name: "Runtime queues", exact: true }),
  });
  assert.match(await runtimeQueues.innerText(), /IRC core/);
  assert.match(await runtimeQueues.innerText(), /Database worker/);
  assert.match(await runtimeQueues.innerText(), /FIFO/);
  const observability = await context.request.get(
    `${applicationOrigin}/api/v1/admin/observability?minutes=60`,
  );
  assert.equal(observability.status(), 200);
  const observabilityBody = await observability.json();
  assert.equal(observabilityBody.current.schema_version, 3);
  // Queue allocation is restart-required. Telemetry must describe the
  // capacity actually enforcing backpressure now, not the next-start value.
  assert.equal(observabilityBody.current.queues.core.capacity, 65_536);
  assert.equal(observabilityBody.current.queues.db.capacity, 1_024);
  assert.equal(
    applicationRequests.some((url) => url.includes("/console/monitoring/panel")),
    false,
    "monitoring must read its documented JSON endpoint, not an HTML fragment",
  );

  await page.goto(`${applicationOrigin}/console/bans`);
  await page.getByRole("heading", { name: "Server bans", exact: true }).waitFor();
  const addBan = page.locator("section").filter({
    has: page.getByRole("heading", { name: "Add server ban", exact: true }),
  });
  await addBan.getByLabel("Policy kind").selectOption("kline");
  await addBan.getByLabel("Mask").fill("*@browser-policy.example");
  await addBan.getByLabel("Reason").fill("browser journey policy");
  await addBan.getByRole("button", { name: "Add and enforce ban" }).click();
  await page.getByText("*@browser-policy.example", { exact: true }).waitFor();
  const banRow = page.locator("tbody tr").filter({ hasText: "*@browser-policy.example" });
  await banRow.getByRole("button", { name: "Remove", exact: true }).click();
  const banConfirmation = page.getByRole("dialog", { name: "Confirm action", exact: true });
  await banConfirmation.waitFor();
  await banConfirmation.getByRole("button", { name: "Continue", exact: true }).click();
  await page.getByText("*@browser-policy.example", { exact: true }).waitFor({ state: "detached" });

  await page.goto(`${applicationOrigin}/console/audit`);
  await page.getByRole("heading", { name: "Audit log", exact: true }).waitFor();
  await page.getByText("KLINE", { exact: true }).waitFor();
  await page.waitForFunction(async (auditURL) => {
    const response = await fetch(auditURL, {
      cache: "no-store",
      credentials: "same-origin",
      headers: { Accept: "application/json" },
    });
    if (!response.ok) return false;
    const payload = await response.json();
    return Array.isArray(payload.audit) && payload.audit.some((entry) => entry.action === "UNKLINE");
  }, `${applicationOrigin}/api/v1/admin/audit?action=UNKLINE&target=${encodeURIComponent("*@browser-policy.example")}`);
  assert.match(await page.locator("main").innerText(), /browser-policy\.example/);
  assert.match(await page.locator("main").innerText(), /KLINE/);

  // API-backed administrator directories retain their table semantics and
  // offer an in-place retry when a transient read fails. This is browser-only
  // behavior: the ordinary API contract suite already covers the 503 shape.
  let auditDirectoryReads = 0;
  const auditFailureErrorStart = applicationErrors.length;
  await page.route(`${applicationOrigin}/api/v1/admin/audit`, async (route) => {
    auditDirectoryReads += 1;
    if (auditDirectoryReads === 1) {
      await route.fulfill({
        status: 503,
        contentType: "application/problem+json",
        body: JSON.stringify({ status: 503, title: "Audit storage unavailable" }),
      });
    } else {
      await route.continue();
    }
  });
  await page.goto(`${applicationOrigin}/console/audit`);
  const auditFailure = page.locator("#admin-audit-rows [role=status]");
  await auditFailure.waitFor();
  assert.match(await auditFailure.innerText(), /Audit storage unavailable/);
  const retryAuditDirectory = page.locator("#admin-audit-rows").getByRole("button", {
    name: "Retry",
    exact: true,
  });
  await retryAuditDirectory.click();
  await page.getByText("KLINE", { exact: true }).waitFor();
  assert.equal(auditDirectoryReads, 2, "Retry made exactly one replacement API request");
  assert.deepEqual(
    applicationErrors.splice(auditFailureErrorStart),
    [`503 GET ${applicationOrigin}/api/v1/admin/audit`],
    "the deliberate API failure was the only browser diagnostic during recovery",
  );
  await page.unroute(`${applicationOrigin}/api/v1/admin/audit`);

  // Configure a custom IRC upstream entirely through the API-backed console,
  // then use the production web client and its real /ws/ui socket in both
  // directions. The local upstream is a protocol peer, not a browser route
  // replacement: this crosses browser → REST/console → PostgreSQL → registry →
  // IRC driver → TCP peer and back through the multiplexer/WebSocket.
  let ownerNetworkReads = 0;
  const ownerNetworkFailureErrorStart = applicationErrors.length;
  await page.route(`${applicationOrigin}/api/v1/me/networks`, async (route) => {
    ownerNetworkReads += 1;
    if (ownerNetworkReads === 1) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: "{",
      });
    } else {
      await route.continue();
    }
  });
  await page.goto(`${applicationOrigin}/console/networks`);
  const ownerNetworkFailure = page.locator("#network-rows [role=status]");
  await ownerNetworkFailure.waitFor();
  assert.match(await ownerNetworkFailure.innerText(), /API response is invalid/i);
  await page.locator("#network-rows").getByRole("button", { name: "Retry", exact: true }).click();
  await page.getByText("No networks yet. Add one above.", { exact: true }).waitFor();
  assert.equal(ownerNetworkReads, 2, "Retry made exactly one replacement owner-network request");
  assert.deepEqual(
    applicationErrors.splice(ownerNetworkFailureErrorStart),
    [],
    "the malformed successful response stayed an explicit in-document recovery state",
  );
  await page.unroute(`${applicationOrigin}/api/v1/me/networks`);

  const networkReadStart = applicationRequests.length;
  const networkListRead = page.waitForResponse(
    (response) => response.url() === `${applicationOrigin}/api/v1/me/networks` && response.status() === 200,
  );
  await page.goto(`${applicationOrigin}/console/networks`);
  await page.getByRole("heading", { name: "Your networks", exact: true }).waitFor();
  await networkListRead;
  assert.ok(
    !applicationRequests.slice(networkReadStart).includes(`GET ${applicationOrigin}/console/networks/rows`),
    "owner network list used a rendered console fragment instead of its API resource",
  );
  assert.equal(await page.locator('select[name="preset"]').inputValue(), "libera");
  assert.equal(await page.locator('input[name="addr"]').inputValue(), "irc.libera.chat:6697");
  assert.equal(await page.locator('input[name="tls"]').isChecked(), true);
  await page.locator('select[name="preset"]').selectOption("custom");
  await page.locator('input[name="name"]').fill("journey");
  await page.locator('input[name="addr"]').fill(upstream.address);
  await page.locator('input[name="nick"]').fill("webjourney");
  await page.locator('input[name="autojoin"]').fill("#journey");
  await page.locator('input[name="tls"]').uncheck();
  await page.getByRole("button", { name: "Test connection", exact: true }).click();
  await page.getByRole("status").filter({ hasText: /Registered as webjourney/ }).waitFor();
  assert.match(await page.getByRole("status").innerText(), /DNS \d+ms, connection \d+ms, registration \d+ms/);
  assert.match(await page.getByRole("status").innerText(), /No network was created/);
  assert.equal(page.url(), `${applicationOrigin}/console/networks`);
  assert.equal(await page.getByRole("link", { name: "journey", exact: true }).count(), 0);
  assert.equal(await page.locator('input[name="addr"]').inputValue(), upstream.address);
  await clickAndWaitForURL(
    page,
    page.getByRole("button", { name: "Add network", exact: true }),
    `${applicationOrigin}/console/networks`,
  );
  await page.getByRole("link", { name: "journey", exact: true }).waitFor();
  await upstream.waitForJoin("#journey");

  await page.goto(`${applicationOrigin}/?network=journey`);
  await page.locator(".buf-name").filter({ hasText: /^#journey$/ }).waitFor();
  const journeyBuffer = page.getByRole("button", { name: "Open #journey", exact: true });
  assert.equal(await journeyBuffer.evaluate((button) => button.tagName), "BUTTON");
  assert.equal(await journeyBuffer.getAttribute("aria-pressed"), "true");
  const skipToChat = page.getByRole("link", { name: "Skip to chat", exact: true });
  await skipToChat.focus();
  await skipToChat.press("Enter");
  assert.equal(await page.evaluate(() => document.activeElement?.id), "chatpane");
  const peerMember = page.getByRole("button", { name: "peer", exact: true });
  await peerMember.waitFor();
  assert.equal(await peerMember.evaluate((button) => button.tagName), "BUTTON");
  await upstream.sendPeerMessage("#journey", "browser receives through the real stack");
  await page.getByText("browser receives through the real stack", { exact: true }).waitFor();

  // Cross the complete notification path once: real TCP upstream, IRC driver,
  // multiplexer, /ws/ui, web-client DM selection, and Chromium's granted API.
  await page.evaluate(() => {
    globalThis.__e6ircRealNotifications = [];
    Object.defineProperty(document, "hidden", {
      configurable: true,
      value: true,
    });
    Object.defineProperty(globalThis, "Notification", {
      configurable: true,
      value: class {
        static permission = "granted";
        constructor(title, options) {
          globalThis.__e6ircRealNotifications.push({
            title,
            body: options?.body,
            tag: options?.tag,
          });
        }
      },
    });
  });
  await upstream.sendPeerMessage("webjourney", "real upstream direct notification");
  await page.waitForFunction(() => globalThis.__e6ircRealNotifications?.length === 1);
  assert.deepEqual(await page.evaluate(() => globalThis.__e6ircRealNotifications), [
    {
      title: "DM from peer",
      body: "real upstream direct notification",
      tag: "peer",
    },
  ]);

  await page.locator("#message").fill("browser sends through the real stack");
  await page.locator("#composer button[type=submit]").click();
  await upstream.waitForLine(
    (line) => line === "PRIVMSG #journey :browser sends through the real stack",
  );
  const sentMessage = page.getByText("browser sends through the real stack", { exact: true });
  await sentMessage.waitFor();
  assert.equal(
    await sentMessage.count(),
    1,
    "a server-admitted composer send must render exactly one local echo",
  );

  // The owner-facing configuration and diagnostics must reflect that same live
  // exchange through their canonical APIs rather than rendering the stored row.
  let ownerNetworkDetailReads = 0;
  const ownerNetworkDetailFailureErrorStart = applicationErrors.length;
  await page.route(`${applicationOrigin}/api/v1/me/networks/journey`, async (route) => {
    ownerNetworkDetailReads += 1;
    if (ownerNetworkDetailReads === 1) {
      await route.fulfill({
        status: 503,
        contentType: "application/problem+json",
        body: JSON.stringify({ status: 503, title: "Network details unavailable" }),
      });
    } else {
      await route.continue();
    }
  });
  await page.goto(`${applicationOrigin}/console/networks/journey`);
  const ownerNetworkDetailFailure = page.locator("#network-api-result");
  await ownerNetworkDetailFailure.getByRole("button", { name: "Retry", exact: true }).waitFor();
  assert.match(await ownerNetworkDetailFailure.innerText(), /Network details unavailable/);
  await ownerNetworkDetailFailure.getByRole("button", { name: "Retry", exact: true }).click();
  await page.getByRole("heading", { name: "journey", exact: true }).waitFor();
  assert.equal(ownerNetworkDetailReads, 2, "Retry made exactly one replacement owner-network-detail request");
  assert.deepEqual(
    applicationErrors.splice(ownerNetworkDetailFailureErrorStart),
    [`503 GET ${applicationOrigin}/api/v1/me/networks/journey`],
    "the deliberate owner-network-detail failure was the only browser diagnostic during recovery",
  );
  await page.unroute(`${applicationOrigin}/api/v1/me/networks/journey`);

  const detailRead = page.waitForResponse(
    (response) =>
      response.url() === `${applicationOrigin}/api/v1/me/networks/journey` &&
      response.request().method() === "GET",
  );
  const operationsReadStart = applicationRequests.length;
  const operationsRead = page.waitForResponse(
    (response) =>
      response.url() === `${applicationOrigin}/api/v1/me/networks/journey/operations` &&
      response.request().method() === "GET",
  );
  await page.goto(`${applicationOrigin}/console/networks/journey`);
  assert.equal((await detailRead).status(), 200);
  assert.equal((await operationsRead).status(), 200);
  await page.getByRole("heading", { name: "journey", exact: true }).waitFor();
  await page.locator('[data-network-field="addr"]', { hasText: upstream.address }).waitFor();
  await page.getByText("Received from upstream", { exact: true }).waitFor();
  await page.waitForFunction(
    () =>
      document
        .querySelector("#network-operations .health-strip > div:first-child strong")
        ?.textContent?.trim() === "connected",
  );
  // The upstream message arrives over the live WebSocket — wait for it to
  // render into the operations panel before asserting, or the async relay
  // races the read on slower runners.
  await page
    .locator("#network-operations")
    .getByText("browser receives through the real stack")
    .waitFor();
  assert.match(await page.locator("#network-operations").innerText(), /browser receives through the real stack/);
  assert.ok(
    !applicationRequests.slice(operationsReadStart).includes(
      `GET ${applicationOrigin}/console/networks/journey/operations`,
    ),
    "network Operations used a rendered console fragment instead of its API resource",
  );

  let ownerNetworkEditorReads = 0;
  const ownerNetworkEditorFailureErrorStart = applicationErrors.length;
  await page.route(`${applicationOrigin}/api/v1/me/networks/journey`, async (route) => {
    ownerNetworkEditorReads += 1;
    if (ownerNetworkEditorReads === 1) {
      await route.fulfill({
        status: 503,
        contentType: "application/problem+json",
        body: JSON.stringify({ status: 503, title: "Network editor unavailable" }),
      });
    } else {
      await route.continue();
    }
  });
  await page.goto(`${applicationOrigin}/console/networks/journey/edit`);
  const ownerNetworkEditorFailure = page.locator("#network-api-result");
  await ownerNetworkEditorFailure.getByRole("button", { name: "Retry", exact: true }).waitFor();
  assert.match(await ownerNetworkEditorFailure.innerText(), /Network editor unavailable/);
  await ownerNetworkEditorFailure.getByRole("button", { name: "Retry", exact: true }).click();
  await page.locator('input[name="addr"]').waitFor({ state: "visible" });
  assert.equal(ownerNetworkEditorReads, 2, "Retry made exactly one replacement owner-network-editor request");
  assert.deepEqual(
    applicationErrors.splice(ownerNetworkEditorFailureErrorStart),
    [`503 GET ${applicationOrigin}/api/v1/me/networks/journey`],
    "the deliberate owner-network-editor failure was the only browser diagnostic during recovery",
  );
  await page.unroute(`${applicationOrigin}/api/v1/me/networks/journey`);

  const editorRead = page.waitForResponse(
    (response) =>
      response.url() === `${applicationOrigin}/api/v1/me/networks/journey` &&
      response.request().method() === "GET",
  );
  await page.goto(`${applicationOrigin}/console/networks/journey/edit`);
  assert.equal((await editorRead).status(), 200);
  await page.locator('input[name="addr"]').waitFor({ state: "visible" });
  assert.equal(await page.locator('input[name="addr"]').inputValue(), upstream.address);
  assert.equal(await page.locator('input[name="nick"]').inputValue(), "webjourney");

  // Exercise the daemon's actual signal handler and startup preload while the
  // same browser context, account session, network definition, upstream, and
  // backlog all exist. Component restart tests cannot prove that these durable
  // domains are wired together in the shipped process.
  await page.goto("about:blank");
  await stopApplicationServer({ requireGraceful: true });
  server = startApplicationServer();
  await waitForHealthyServer();
  await page.goto(`${applicationOrigin}/console/networks/journey`);
  await page.getByRole("heading", { name: "journey", exact: true }).waitFor();
  await page.getByText("Received from upstream", { exact: true }).waitFor();
  await page
    .locator(".backlog code")
    .filter({ hasText: "browser receives through the real stack" })
    .waitFor();
  await page.waitForFunction(
    () =>
      document
        .querySelector("#network-operations .health-strip > div:first-child strong")
        ?.textContent?.trim() === "connected",
  );
  const restartedObservability = await context.request.get(
    `${applicationOrigin}/api/v1/admin/observability?minutes=60`,
  );
  assert.equal(restartedObservability.status(), 200);
  assert.equal((await restartedObservability.json()).current.queues.core.capacity, 32_768);

  await page.goto(`${applicationOrigin}/`);
  await page.locator("#network-select").waitFor();
  let deliberateFailureRequests = 0;
  await page.route(`${applicationOrigin}/api/v1/me/networks`, async (route) => {
    deliberateFailureRequests += 1;
    await route.fulfill({
      status: 503,
      contentType: "application/problem+json",
      body: JSON.stringify({ status: 503, title: "Database unavailable" }),
    });
  });
  const deliberateFailureErrorStart = applicationErrors.length;
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
  const deliberateFailureErrors = applicationErrors.splice(deliberateFailureErrorStart);
  // Every engine records the handled fetch 503 through the first-party
  // response diagnostic as method, status, and URL; the application contract
  // above is identical, and the output is still bounded by intercepted
  // requests rather than broadly ignored.
  assert.ok(
    deliberateFailureRequests >= 1 && deliberateFailureRequests <= 2,
    `the deliberate 503 route saw ${deliberateFailureRequests} requests`,
  );
  assert.ok(
    deliberateFailureErrors.length <= deliberateFailureRequests,
    `the deliberate 503 produced unexpected browser errors: ${deliberateFailureErrors.join("; ")}`,
  );
  for (const error of deliberateFailureErrors) {
    assert.equal(error, `503 GET ${applicationOrigin}/api/v1/me/networks`);
  }
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
  let rejectedSendAttempts = 0;
  let socketConnections = 0;
  let resolveManualReconnect;
  const manualReconnect = new Promise((resolve) => {
    resolveManualReconnect = resolve;
  });
  let snapshotSent = false;
  let namesRequestedBeforeSnapshot = false;
  await page.routeWebSocket(/\/ws\/ui\?network=demo$/, (webSocket) => {
    mockSocket = webSocket;
    socketConnections += 1;
    if (socketConnections === 2) resolveManualReconnect();
    webSocket.onMessage((frame) => {
      const value = typeof frame === "string" ? frame : frame.toString();
      clientFrames.push(value);
      const request = JSON.parse(value);
      const command = request.message;
      if (request.id && command === "accepted only after acknowledgement") {
        setTimeout(() => {
          webSocket.send(JSON.stringify({ t: "sent", v: request.id }));
        }, 75);
      } else if (request.id && command === "rejected without a false echo") {
        rejectedSendAttempts += 1;
        webSocket.send(JSON.stringify(
          rejectedSendAttempts === 1
            ? {
                t: "send-error",
                v: request.id,
                message: "synthetic upstream refusal; nothing was sent",
              }
            : { t: "sent", v: request.id },
        ));
      }
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
    if (socketConnections === 1) {
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
    } else {
      webSocket.send(JSON.stringify({ t: "snapshot", v: "complete" }));
    }
  });
  await page.goto(`${applicationOrigin}/?network=demo`);
  await page.getByText("#room", { exact: true }).first().waitFor();
  await page.waitForFunction(
    () => document.getElementById("nickcount")?.textContent === "3",
  );
  assert.equal(await page.locator("#nickcount").textContent(), "3");
  assert.equal(namesRequestedBeforeSnapshot, false, "NAMES was requested before replay completed");
  assert.match(
    await page.locator("#network-select option:checked").textContent(),
    /reconnect backoff/,
  );
  const expectedTaggedTime = await page.evaluate(() => {
    const date = new Date("2026-07-28T20:00:00.000Z");
    return `${String(date.getHours()).padStart(2, "0")}:${String(date.getMinutes()).padStart(2, "0")}`;
  });
  assert.equal(
    await page.getByText("initial tagged", { exact: true }).locator("..").locator(".ts").textContent(),
    expectedTaggedTime,
  );

  // Reading older content must not make new live traffic disappear below the
  // viewport. The explicit control stays keyboard-accessible and returns to
  // the newest line without changing conversations.
  await page.evaluate(() => {
    const messages = document.getElementById("messages");
    messages.style.flex = "none";
    messages.style.height = "5rem";
  });
  for (let index = 0; index < 12; index += 1) {
    mockSocket.send(
      JSON.stringify({
        t: "line",
        v: `:alice!u@h PRIVMSG #room :scrollback filler ${index}`,
      }),
    );
  }
  await page.getByText("scrollback filler 11", { exact: true }).waitFor();
  await page.locator("#messages").evaluate((node) => { node.scrollTop = 0; });
  mockSocket.send(
    JSON.stringify({
      t: "line",
      v: ":alice!u@h PRIVMSG #room :new while reading",
    }),
  );
  const jumpLatest = page.getByRole("button", {
    name: "1 new message. Jump to latest messages.",
  });
  await jumpLatest.waitFor();
  assert.equal(await jumpLatest.textContent(), "1 new message — jump to latest");
  await jumpLatest.click();
  await page.waitForFunction(() => {
    const messages = document.getElementById("messages");
    return messages.scrollHeight - messages.scrollTop - messages.clientHeight < 1;
  });
  await page.locator("#jump-latest").waitFor({ state: "hidden" });

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
  assert.equal(
    await page.locator("#messages").evaluate((node) => node.scrollTop),
    0,
    "loading earlier history returned the reader to the live edge",
  );

  // Local echoes are request-correlated: socket admission alone is not
  // success. The accepted message appears only after the server's `sent`
  // event, while a `send-error` remains visibly refused without a false echo.
  await page.locator("#message").fill("accepted only after acknowledgement");
  await page.locator("#composer button[type=submit]").click();
  assert.equal(
    await page.getByText("accepted only after acknowledgement", { exact: true }).count(),
    0,
  );
  await page.getByText("accepted only after acknowledgement", { exact: true }).waitFor();
  await page.locator("#message").fill("rejected without a false echo");
  await page.locator("#composer button[type=submit]").click();
  await page.getByText("synthetic upstream refusal; nothing was sent", { exact: true }).waitFor();
  assert.equal(await page.getByText("rejected without a false echo", { exact: true }).count(), 0);
  // A refusal never auto-retries (which could duplicate a message if a
  // transport verdict arrived late). It exposes the exact text for deliberate
  // review and resend instead.
  await page.getByRole("button", { name: "Restore message" }).click();
  assert.equal(await page.locator("#message").inputValue(), "rejected without a false echo");
  await page.locator("#composer button[type=submit]").click();
  await page.getByText("rejected without a false echo", { exact: true }).waitFor();
  assert.equal(await page.getByText("rejected without a false echo", { exact: true }).count(), 1);
  assert.equal(rejectedSendAttempts, 2, "the message was resent only after the explicit action");

  // A user can skip the reconnect countdown after a transient browser-socket
  // loss. One click creates one fresh attachment; terminal network failures
  // use their separate configuration-recovery path.
  mockSocket.close({ code: 1011, reason: "synthetic interruption" });
  await page.getByRole("button", { name: "Retry now" }).waitFor();
  await page.getByRole("button", { name: "Retry now" }).click();
  await manualReconnect;
  await page.getByText("demo: upstream connected", { exact: true }).waitFor();
  assert.equal(socketConnections, 2, "manual retry created exactly one replacement socket");

  // Inactive conversations distinguish ordinary unread traffic from messages
  // that name us. Opening that conversation clears both indicators without
  // affecting any other buffer.
  mockSocket.send(
    JSON.stringify({
      t: "line",
      v: ":alice!u@h PRIVMSG #mentions :webnick: please review this",
    }),
  );
  const mentionsBuffer = page.getByRole("button", {
    name: "Open #mentions, 1 unread message, 1 mention",
  });
  await mentionsBuffer.waitFor();
  assert.equal(await mentionsBuffer.locator(".mention-badge").textContent(), "@1");
  await mentionsBuffer.click();
  await page.getByRole("button", { name: "Open #mentions" }).waitFor();
  assert.equal(await page.locator(".mention-badge").count(), 0);
  // The following authoritative NAMES snapshot updates #room's member list,
  // so return to its rendered conversation after proving the mention reset.
  await page.getByRole("button", { name: "Open #room" }).click();

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

  // Chromium owns the operating-system notification surface, but the
  // application still has a testable contract: while backgrounded, a DM or
  // mention must call the granted Notification API with bounded text. Record
  // that boundary without replacing any e6irc transport or rendering code.
  await page.evaluate(() => {
    globalThis.__e6ircNotifications = [];
    Object.defineProperty(document, "hidden", {
      configurable: true,
      value: true,
    });
    Object.defineProperty(globalThis, "Notification", {
      configurable: true,
      value: class {
        static permission = "granted";
        static async requestPermission() {
          return "granted";
        }
        constructor(title, options) {
          globalThis.__e6ircNotifications.push({
            title,
            body: options?.body,
            tag: options?.tag,
          });
        }
      },
    });
  });
  mockSocket.send(
    JSON.stringify({
      t: "line",
      v: "@time=2026-07-28T20:00:03.000Z;msgid=dm :bob!u@h PRIVMSG webnick :private hello",
    }),
  );
  await page.waitForFunction(() => globalThis.__e6ircNotifications?.length === 1);
  assert.deepEqual(await page.evaluate(() => globalThis.__e6ircNotifications), [
    { title: "DM from bob", body: "private hello", tag: "bob" },
  ]);

  // A platform notification failure must disable the preference visibly,
  // rather than throwing out of the message handler and leaving a broken
  // opt-in active.
  await page.evaluate(() => {
    Object.defineProperty(globalThis, "Notification", {
      configurable: true,
      value: class {
        static permission = "granted";
        constructor() {
          throw new Error("synthetic notification failure");
        }
      },
    });
  });
  mockSocket.send(
    JSON.stringify({
      t: "line",
      v: "@time=2026-07-28T20:00:04.000Z;msgid=dm-failure :bob!u@h PRIVMSG webnick :second private message",
    }),
  );
  await page
    .getByText(/Could not show a desktop notification.*synthetic notification failure/)
    .waitFor();
  assert.deepEqual(
    await page.evaluate(() => JSON.parse(localStorage.getItem("e6irc.settings"))),
    { theme: "dark", notifications: false },
  );
  assert.equal(
    await page.locator("#notify-toggle").getAttribute("aria-pressed"),
    "false",
  );

  // Permission denial and an absent browser API are explicit, recoverable
  // opt-in failures and cannot silently flip the persisted setting.
  await page.evaluate(() => {
    Object.defineProperty(globalThis, "Notification", {
      configurable: true,
      value: class {
        static permission = "default";
        static async requestPermission() {
          return "denied";
        }
      },
    });
  });
  await page.getByText("Preferences", { exact: true }).click();
  await page.getByRole("button", { name: "Desktop notifications: off" }).click();
  await page.locator(".buf-name").filter({ hasText: /^server$/ }).click();
  await page.getByText("Notification permission was not granted.", { exact: true }).waitFor();
  assert.deepEqual(
    await page.evaluate(() => JSON.parse(localStorage.getItem("e6irc.settings"))),
    { theme: "dark", notifications: false },
  );
  await page.evaluate(() => {
    delete globalThis.Notification;
  });
  await page.getByRole("button", { name: "Desktop notifications: off" }).click();
  await page
    .getByText("This browser does not support desktop notifications.", { exact: true })
    .waitFor();
  assert.deepEqual(
    await page.evaluate(() => JSON.parse(localStorage.getItem("e6irc.settings"))),
    { theme: "dark", notifications: false },
  );

  // Restoring a working browser API lets the user opt in again and then turn
  // notifications off deliberately; both transitions are persisted.
  await page.evaluate(() => {
    Object.defineProperty(globalThis, "Notification", {
      configurable: true,
      value: class {
        static permission = "granted";
        static async requestPermission() {
          return "granted";
        }
        constructor() {}
      },
    });
  });
  await page.getByRole("button", { name: "Desktop notifications: off" }).click();
  await page.getByRole("button", { name: "Desktop notifications: on" }).click();
  assert.deepEqual(
    await page.evaluate(() => JSON.parse(localStorage.getItem("e6irc.settings"))),
    { theme: "dark", notifications: false },
  );

  // On a narrow screen, the conversation rail is a focused, dismissible
  // destination instead of a permanently hidden list. Escape returns to the
  // trigger; choosing a conversation closes the rail and restores the
  // composer as the next chat action.
  await page.setViewportSize({ width: 400, height: 700 });
  const conversations = page.getByRole("button", { name: "Conversations" });
  await conversations.click();
  assert.equal(await conversations.getAttribute("aria-expanded"), "true");
  assert.equal(
    await page.evaluate(() => document.activeElement?.classList.contains("buf")),
    true,
    "opening Conversations did not focus a buffer",
  );
  await page.keyboard.press("Escape");
  assert.equal(await conversations.getAttribute("aria-expanded"), "false");
  assert.equal(await page.evaluate(() => document.activeElement?.id), "sidebar-toggle");
  await conversations.click();
  await page.locator(".buf-name").filter({ hasText: /^#room$/ }).click();
  assert.equal(await conversations.getAttribute("aria-expanded"), "false");
  assert.equal(await page.evaluate(() => document.activeElement?.id), "message");
  await page.setViewportSize({ width: 1280, height: 720 });

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
  // intact. Opening the application entry goes to the login page; clicking
  // the provider link restores access without prompting at the provider
  // (the IdP session is still valid).
  assert.equal((await context.request.post(`${applicationOrigin}/api/v1/auth/logout`)).status(), 204);
  assert.equal((await context.request.get(`${applicationOrigin}/api/v1/me`)).status(), 401);
  await page.goto(`${applicationOrigin}/`);
  assert.equal(page.url(), `${applicationOrigin}/login`);
  const directTraceStart = navigationTrace.length;
  const directSignIn = page.getByRole("link", { name: "Sign in with dex" });
  await clickAndWaitForURL(page, directSignIn, `${applicationOrigin}/`);
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
  await clickAndWaitForURL(page, signIn, `${applicationOrigin}/`);
  assert.ok(
    navigationTrace.slice(recoveryTraceStart).includes(`request GET ${applicationOrigin}/api/v1/auth/oidc/dex/start`),
    `signed-out recovery bypassed the e6irc OpenID Connect starter:\n${navigationTrace.slice(recoveryTraceStart).join("\n")}`,
  );
  // A document navigation can race the final explicit logout in Firefox: the
  // old document's owner-network read then correctly completes as unauthorized.
  // Keep that expected post-logout response separate from application failures.
  const expectedSignedOutNetworkRead = `401 GET ${applicationOrigin}/api/v1/me/networks`;
  assert.deepEqual(
    applicationErrors.filter((error) => error !== expectedSignedOutNetworkRead),
    [],
  );
} catch (error) {
  if (artifactDirectory && context) {
    const results = await Promise.allSettled([
      page?.screenshot({ path: join(artifactDirectory, `${browserName}-failure.png`), fullPage: true }),
      tracing
        ? context.tracing.stop({ path: join(artifactDirectory, `${browserName}-trace.zip`) })
        : Promise.resolve(),
      writeFile(
        join(artifactDirectory, `${browserName}-diagnostics.json`),
        JSON.stringify({ applicationErrors, applicationRequests, navigationTrace, serverOutput }, null, 2),
      ),
    ]);
    tracing = false;
    for (const result of results) {
      if (result.status === "rejected") console.error(`failed to write browser artifact: ${result.reason}`);
    }
  }
  throw error;
} finally {
  clearTimeout(watchdog);
  if (tracing && context) await context.tracing.stop();
  // `browser.close()` can itself hang on a wedged engine; bound it so teardown
  // never becomes the thing that hangs the run.
  if (browser) {
    await Promise.race([
      browser.close(),
      new Promise((resolveTimeout) => setTimeout(resolveTimeout, 10_000)),
    ]);
  }
  await stopApplicationServer({ requireGraceful: false });
  await upstream.close();
  await rm(temporaryDirectory, { recursive: true, force: true });
}

function startApplicationServer() {
  const child = spawn(binary, ["--config", configPath], {
    stdio: ["ignore", "pipe", "pipe"],
  });
  for (const stream of [child.stdout, child.stderr]) {
    stream.setEncoding("utf8");
    stream.on("data", (chunk) => serverOutput.push(chunk));
  }
  return child;
}

async function stopApplicationServer({ requireGraceful }) {
  if (server.exitCode !== null || server.signalCode !== null) return;
  const exit = new Promise((resolveExit) => {
    server.once("exit", (code, signal) => resolveExit({ code, signal }));
  });
  assert.equal(server.kill("SIGTERM"), true, "failed to signal e6ircd");
  const result = await Promise.race([
    exit,
    new Promise((_, rejectTimeout) =>
      setTimeout(() => rejectTimeout(new Error("e6ircd did not stop within 5 seconds")), 5_000),
    ),
  ]);
  if (requireGraceful) {
    assert.deepEqual(
      result,
      { code: 0, signal: null },
      `e6ircd did not complete graceful shutdown:\n${serverOutput.join("")}`,
    );
  }
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

function isApplicationURL(value) {
  return new URL(value).origin === applicationOrigin;
}

async function startIrcUpstream() {
  const sockets = new Set();
  const lines = [];
  const lineWaiters = [];
  let outboundSequence = 0;
  let joined;
  let resolveJoined;
  const joinedPromise = new Promise((resolve) => {
    resolveJoined = resolve;
  });

  const publishLine = (line) => {
    lines.push(line);
    for (let index = lineWaiters.length - 1; index >= 0; index -= 1) {
      const waiter = lineWaiters[index];
      if (waiter.predicate(line)) {
        lineWaiters.splice(index, 1);
        clearTimeout(waiter.timeout);
        waiter.resolve(line);
      }
    }
  };

  const server = createServer((socket) => {
    sockets.add(socket);
    socket.setEncoding("utf8");
    let buffered = "";
    let nick = "webjourney";
    let sawUser = false;
    let capEnded = false;
    let welcomed = false;
    const send = (line) => socket.write(`${line}\r\n`);
    const welcome = () => {
      if (welcomed || !sawUser || !capEnded) return;
      welcomed = true;
      send(`:journey.example 001 ${nick} :Welcome to the journey upstream`);
      send(`:journey.example 005 ${nick} CHANTYPES=# PREFIX=(ov)@+ :supported`);
    };
    const names = (channel) => {
      send(`:journey.example 353 ${nick} = ${channel} :@${nick} peer`);
      send(`:journey.example 366 ${nick} ${channel} :End of /NAMES list`);
    };
    const onLine = (line) => {
      publishLine(line);
      const [commandRaw, ...params] = line.split(" ");
      const command = commandRaw.toUpperCase();
      if (command === "CAP" && params[0] === "LS") {
        send(":journey.example CAP * LS :server-time message-tags account-tag");
      } else if (command === "CAP" && params[0] === "REQ") {
        send(`:journey.example CAP * ACK :${params.slice(1).join(" ").replace(/^:/, "")}`);
      } else if (command === "CAP" && params[0] === "END") {
        capEnded = true;
        welcome();
      } else if (command === "NICK" && params[0]) {
        nick = params[0];
      } else if (command === "USER") {
        sawUser = true;
        welcome();
      } else if (command === "JOIN" && params[0]) {
        const channel = params[0];
        send(`:${nick}!web@journey JOIN ${channel}`);
        names(channel);
        if (!joined) {
          joined = { socket, nick, channel };
          resolveJoined(joined);
        }
      } else if (command === "NAMES" && params[0]) {
        names(params[0]);
      } else if (command === "PING") {
        send(`PONG ${params.join(" ")}`);
      }
    };
    socket.on("data", (chunk) => {
      buffered += chunk;
      while (buffered.includes("\n")) {
        const newline = buffered.indexOf("\n");
        const line = buffered.slice(0, newline).replace(/\r$/, "");
        buffered = buffered.slice(newline + 1);
        if (line) onLine(line);
      }
    });
    socket.on("close", () => sockets.delete(socket));
  });

  await new Promise((resolveListen, rejectListen) => {
    server.once("error", rejectListen);
    server.listen(0, "127.0.0.1", resolveListen);
  });
  const address = server.address();
  assert.ok(address && typeof address === "object");

  return {
    address: `127.0.0.1:${address.port}`,
    async waitForJoin(channel) {
      const connection = await Promise.race([
        joinedPromise,
        new Promise((_, reject) =>
          setTimeout(() => reject(new Error(`upstream did not observe JOIN ${channel}`)), 10_000),
        ),
      ]);
      assert.equal(connection.channel, channel);
    },
    async sendPeerMessage(target, text) {
      const connection = await joinedPromise;
      outboundSequence += 1;
      connection.socket.write(
        `@time=2026-07-30T02:00:00.000Z;msgid=browser-receive-${outboundSequence} :peer!user@journey PRIVMSG ${target} :${text}\r\n`,
      );
    },
    async waitForLine(predicate) {
      const existing = lines.find(predicate);
      if (existing) return existing;
      return new Promise((resolveLine, rejectLine) => {
        const waiter = {
          predicate,
          resolve: resolveLine,
          timeout: setTimeout(() => {
            const index = lineWaiters.indexOf(waiter);
            if (index >= 0) lineWaiters.splice(index, 1);
            rejectLine(new Error(`upstream line not observed; received:\n${lines.join("\n")}`));
          }, 10_000),
        };
        lineWaiters.push(waiter);
      });
    },
    async close() {
      for (const socket of sockets) socket.destroy();
      await new Promise((resolveClose) => server.close(resolveClose));
    },
  };
}
