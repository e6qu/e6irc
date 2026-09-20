import playwrightTest from "playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { readFile } from "node:fs/promises";

const { expect, test } = playwrightTest;

const identity = { account: "visual-test", email: "visual@example.test", role: "operator", csrf_token: "session-bound-token" };
const presets = [
  { id: "libera", label: "Libera Chat", name: "libera", addr: "irc.libera.chat:6697", tls: true },
  { id: "oftc", label: "OFTC", name: "oftc", addr: "irc.oftc.net:6697", tls: true },
];
const response = (schema) => ({ content: { "application/json": { schema } } });
const apiContract = {
  paths: {
    "/api/v1/me": {
      get: { responses: { 200: response({
        type: "object", additionalProperties: false, required: ["account"], properties: {
          account: { type: "string", minLength: 1 }, email: { type: ["string", "null"] },
          role: { type: ["string", "null"] }, logout_url: { type: "string" },
          csrf_token: { type: "string" },
        },
      }) } },
    },
    "/api/v1/network-presets": {
      get: { responses: { 200: response({
        type: "object", additionalProperties: false, required: ["presets"], properties: {
          presets: { type: "array", items: {
            type: "object", additionalProperties: false, required: ["id", "label", "name", "addr", "tls"],
            properties: {
              id: { type: "string" }, label: { type: "string" }, name: { type: "string" },
              addr: { type: "string" }, tls: { type: "boolean" },
            },
          } },
        },
      }) } },
    },
    "/api/v1/me/networks": {
      get: { responses: { 200: response({
        type: "object", additionalProperties: false, required: ["networks"], properties: {
          networks: { type: "array", items: {
            type: "object", additionalProperties: false,
            required: ["name", "kind", "nick", "enabled", "connected", "runtime"],
            properties: {
              name: { type: "string", minLength: 1 }, kind: { type: "string" }, nick: { type: "string" },
              enabled: { type: "boolean" }, connected: { type: ["boolean", "null"] }, runtime: { oneOf: [
                { type: "null" },
                { type: "object", additionalProperties: false, required: ["state"], properties: {
                  state: { type: "string" },
                  last_error: { oneOf: [
                    { type: "null" },
                    { type: "object", additionalProperties: false, required: ["code"], properties: {
                      code: { type: "string" }, diagnostic: { type: "string" },
                    } },
                  ] },
                } },
              ] },
            },
          } },
        },
      }) } },
      post: {
        requestBody: { required: true, content: { "application/json": { schema: {
          type: "object", additionalProperties: false,
          required: ["kind", "name", "addr", "tls", "nick", "realname", "autojoin"],
          properties: {
            kind: { const: "irc" }, name: { type: "string" }, addr: { type: "string" }, tls: { type: "boolean" },
            nick: { type: "string" }, realname: { type: "string" },
            autojoin: { type: "array", items: { type: "string" } },
            sasl_account: { type: "string" }, sasl_password: { type: "string" },
          },
        } } } },
        responses: { 201: response({
          type: "object", additionalProperties: false, required: ["name", "attach"],
          properties: { name: { type: "string" }, attach: { type: "string" } },
        }) },
      },
    },
  },
};

async function expectAccessible(page) {
  const results = await new AxeBuilder({ page }).include("#app").analyze();
  expect(results.violations, results.violations.map(({ id, help }) => `${id}: ${help}`).join("\n")).toEqual([]);
}

async function mockApiContract(page) {
  await page.route("/api/v1/openapi.json", (route) => route.fulfill({
    contentType: "application/json", body: JSON.stringify(apiContract),
  }));
}

async function mockSession(page, networks, failureStatus = 503, identityPayload = identity) {
  await mockApiContract(page);
  await page.route(/\/api\/v1\/me$/, (route) =>
    route.fulfill({
      contentType: "application/json",
      body: typeof identityPayload === "string" ? identityPayload : JSON.stringify(identityPayload),
    }),
  );
  await page.route(/\/api\/v1\/network-presets$/, (route) =>
    route.fulfill({ contentType: "application/json", body: JSON.stringify({ presets }) }),
  );
  await page.route(/\/api\/v1\/me\/networks$/, (route) => {
    if (route.request().method() !== "GET") return route.fallback();
    if (networks instanceof Error) {
      return route.fulfill({
        status: failureStatus,
        contentType: "application/problem+json",
        body: JSON.stringify({ title: networks.message }),
      });
    }
    return route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ networks }),
    });
  });
}

async function setStyledFixture(page, fixture, styles) {
  const html = await readFile(new URL(`fixtures/${fixture}`, import.meta.url), "utf8");
  await page.setContent(html.replace("/* TEST_STYLES */", styles));
}

// Renders the part of a console template a browser test needs: every
// conditional takes its "absent" branch, and named values fill the rest.
async function consoleTemplate(name, values = {}) {
  const source = await readFile(new URL(`../../crates/e6ircd/templates/${name}`, import.meta.url), "utf8");
  let html = source.match(/\{% block main %\}([\s\S]*)\{% endblock %\}/)?.[1];
  expect(html).toBeTruthy();
  const conditional = /\{% if [^%]*%\}(?:(?!\{% if )[\s\S])*?\{% endif %\}/g;
  while (conditional.test(html)) html = html.replace(conditional, "");
  return html
    .replace(/\{%[^%]*%\}/g, "")
    .replace(/\{\{\s*([\w.]+)\s*\}\}/g, (_, key) => values[key] ?? "");
}

async function consoleStyles() {
  const template = await readFile(new URL("../../crates/e6ircd/templates/console_base.html", import.meta.url), "utf8");
  return template.match(/<style>([\s\S]+)<\/style>/)[1];
}

async function mountConsoleRuntime(page, body, styles = "", apiResponses = {}) {
  const runtime = await readFile(new URL("../../crates/e6ircd/assets/console.js", import.meta.url), "utf8");
  await page.route("**/console.js", (route) => route.fulfill({
    contentType: "text/javascript",
    body: runtime,
  }));
  await page.route("**/console-contract.js", (route) => route.fulfill({
    contentType: "text/javascript",
    body: `const responses = ${JSON.stringify(apiResponses)};
      export const apiContractLoader = () => async () => ({});
      export const getOperationJson = async (_fetch, _contract, method, url, options) => {
        window.consoleApiRequests ??= [];
        window.consoleApiRequests.push(url);
        window.consoleApiMutations ??= [];
        if (method !== "GET") window.consoleApiMutations.push({ method, url, json: options?.json });
        if (window.consoleApiGate) await window.consoleApiGate;
        const match = Object.entries(responses).find(([prefix]) => url.startsWith(prefix));
        return match ? match[1] : {};
      };`,
  }));
  await page.route("**/console-settings.js", (route) => route.fulfill({
    contentType: "text/javascript",
    body: "export const loadSettings = () => ({ settings: { theme: 'auto' }, warning: null }); export const saveSettings = () => null;",
  }));
  await page.route("**/console-runtime-test", (route) => route.fulfill({
    contentType: "text/html",
    body: `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><style>${styles}</style></head><body><div id="app">${body}</div><script type="module" src="/console.js"></script></body></html>`,
  }));
  await page.goto("/console-runtime-test");
}

test("identity entry uses the shared relay-desk system", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "light", reducedMotion: "reduce" });
  await page.setViewportSize({ width: 1280, height: 800 });
  const styles = await readFile(new URL("../../crates/e6ircd/assets/auth.css", import.meta.url), "utf8");
  await setStyledFixture(page, "identity-entry.html", styles);

  await expectAccessible(page);
  await expect(page).toHaveScreenshot("identity-entry-light.png", { animations: "disabled", fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
  await expectAccessible(page);
  await page.emulateMedia({ forcedColors: "active" });
  await expectAccessible(page);
});

test("console shell keeps operations dense and legible", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "light", reducedMotion: "reduce" });
  await page.setViewportSize({ width: 1280, height: 800 });
  const template = await readFile(new URL("../../crates/e6ircd/templates/console_base.html", import.meta.url), "utf8");
  const styles = template.match(/<style>([\s\S]+)<\/style>/)?.[1];
  expect(styles).toBeTruthy();
  await setStyledFixture(page, "console-overview.html", styles);

  await expectAccessible(page);
  await expect(page).toHaveScreenshot("console-overview-light.png", { animations: "disabled", fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 });
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
  await expectAccessible(page);
  await page.emulateMedia({ forcedColors: "active" });
  await expectAccessible(page);
});

test("console confirmations preserve the named action and cancel safely", async ({ page }) => {
  await mountConsoleRuntime(page, `
    <main>
      <form data-confirm="Delete the route permanently?">
        <button class="danger" name="operation" value="delete">Delete route</button>
      </form>
      <form data-confirm="Restart the route now?">
        <button name="operation" value="restart">Restart route</button>
      </form>
    </main>
    <dialog data-console-confirm aria-labelledby="confirm-title" aria-describedby="confirm-message">
      <form method="dialog">
        <h2 id="confirm-title">Confirm action</h2>
        <p id="confirm-message" data-console-confirm-message></p>
        <button type="submit" value="cancel">Cancel</button>
        <button class="danger" type="submit" value="confirm" data-console-confirm-action>Continue</button>
      </form>
    </dialog>
    <script>
      window.confirmedOperations = [];
      document.addEventListener("submit", (event) => {
        if (!event.target.matches("form[data-confirm]")) return;
        event.preventDefault();
        window.confirmedOperations.push(event.submitter?.value ?? null);
      });
    </script>
  `);

  const dialog = page.getByRole("dialog", { name: "Confirm action" });
  const deleteRoute = page.getByRole("button", { name: "Delete route" });
  await deleteRoute.click();
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole("button", { name: "Delete route" })).toHaveClass("danger");
  await expectAccessible(page);
  await dialog.getByRole("button", { name: "Delete route" }).click();
  await expect(dialog).toBeHidden();
  await expect.poll(() => page.evaluate(() => window.confirmedOperations)).toEqual(["delete"]);

  const restartRoute = page.getByRole("button", { name: "Restart route" });
  await restartRoute.click();
  await expect(dialog.getByRole("button", { name: "Restart route" })).toHaveClass("primary");
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(restartRoute).toBeFocused();
  await expect.poll(() => page.evaluate(() => window.confirmedOperations)).toEqual(["delete"]);
});

test("console mutations expose progress and reject duplicate submissions", async ({ page }) => {
  await mountConsoleRuntime(page, `
    <main>
      <p id="ban-api-result" role="status" aria-live="polite"></p>
      <form action="/api/v1/admin/bans" data-api-ban-create>
        <input type="hidden" name="csrf" value="test-csrf">
        <label>Policy kind <input name="kind" value="kline"></label>
        <label>Mask <input name="mask" value="*@bad.example"></label>
        <label>Reason <input name="reason" value="abuse"></label>
        <button type="submit">Add ban</button>
        <button type="submit">Add and enforce ban</button>
      </form>
      <span id="admin-ban-count"></span>
      <div id="admin-ban-pager"></div>
      <table><tbody data-api-admin-ban-list data-csrf="test-csrf"></tbody></table>
    </main>
  `, "button[data-submitting='true']::after { content: '\u2026'; }", {
    "/api/v1/admin/bans": { bans: [] },
  });
  await expect.poll(() => page.evaluate(() => window.consoleApiRequests.length)).toBe(1);
  await page.evaluate(() => {
    window.consoleApiRequests = [];
    window.consoleApiGate = new Promise((resolve) => { window.releaseConsoleApi = resolve; });
  });

  const form = page.locator("form[data-api-ban-create]");
  const firstAction = form.getByRole("button", { name: "Add ban" });
  const chosenAction = form.getByRole("button", { name: "Add and enforce ban" });
  await chosenAction.click();

  await expect(form).toHaveAttribute("aria-busy", "true");
  await expect(firstAction).toBeDisabled();
  await expect(chosenAction).toBeDisabled();
  await expect(chosenAction).toHaveAttribute("data-submitting", "true");
  await expect(chosenAction).toHaveAttribute("aria-label", "Add and enforce ban — in progress");
  await expect.poll(() => page.evaluate(() => window.consoleApiRequests.length)).toBe(1);
  await form.evaluate((node) => {
    node.dispatchEvent(new SubmitEvent("submit", { bubbles: true, cancelable: true }));
  });
  await expect.poll(() => page.evaluate(() => window.consoleApiRequests.length)).toBe(1);
  await expectAccessible(page);

  await page.evaluate(() => window.releaseConsoleApi());
  await expect(form).not.toHaveAttribute("aria-busy");
  await expect(firstAction).toBeEnabled();
  await expect(chosenAction).toBeEnabled();
  await expect(chosenAction).not.toHaveAttribute("data-submitting");
  await expect(chosenAction).not.toHaveAttribute("aria-label");
  await expect(page.getByRole("status")).toHaveText("Updated.");
  await expect.poll(() => page.evaluate(() => window.consoleApiRequests.length)).toBe(2);
});

test("console phone navigation reveals the active destination", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const links = Array.from({ length: 11 }, (_, index) => `<a href="/console/route-${index}">Route ${index}</a>`).join("");
  await mountConsoleRuntime(page, `
    <nav aria-label="Console">${links}<a href="/console/account" aria-current="page">Account &amp; access</a></nav>
    <main>Account</main>
  `, `
    * { box-sizing: border-box; }
    body { margin: 0; }
    nav { display: flex; gap: 8px; width: 100%; overflow-x: auto; padding: 8px; }
    nav a { flex: 0 0 132px; }
  `);

  const navigation = page.getByRole("navigation", { name: "Console" });
  const active = navigation.getByRole("link", { name: "Account & access" });
  await expect.poll(() => navigation.evaluate((node) => node.scrollLeft)).toBeGreaterThan(0);
  await expect.poll(async () => {
    const navigationBox = await navigation.boundingBox();
    const activeBox = await active.boundingBox();
    return Boolean(
      navigationBox
      && activeBox
      && activeBox.x >= navigationBox.x
      && activeBox.x + activeBox.width <= navigationBox.x + navigationBox.width,
    );
  }).toBe(true);
  await expectAccessible(page);
});

test("console adds a known network from a nickname alone, with no forced test", async ({ page }) => {
  const form = await consoleTemplate("console_networks.html", {
    "shell.csrf": "test-csrf", "preset.id": "libera", "preset.name": "libera", "preset.label": "Libera Chat",
    "preset.addr": "irc.libera.chat:6697", "form.name": "libera", "form.addr": "irc.libera.chat:6697", "form.nick": "alice",
  });
  await mountConsoleRuntime(page, `<main>${form}</main>`, await consoleStyles(), { "/api/v1/me/networks": { networks: [] } });

  const add = page.getByRole("button", { name: "Add network", exact: true });
  const advanced = page.locator("[data-network-advanced]");
  await expect(add).toBeEnabled();
  await expect(advanced).not.toHaveAttribute("open");
  expect(await page.locator("form[data-api-owner-network-create] label > span:first-of-type").allTextContents()).toEqual([
    "IRC network", "Nickname", "NickServ account optional", "NickServ password optional", "Channels to join optional",
    "Name", "Server", "Use TLSRecommended for public IRC networks.", "Real name optional",
  ]);
  await expectAccessible(page);

  await add.click();
  await expect.poll(() => page.evaluate(() => window.consoleApiMutations)).toEqual([{
    method: "POST", url: "/api/v1/me/networks", json: {
      kind: "irc", name: "libera", addr: "irc.libera.chat:6697", tls: false, nick: "alice", realname: "alice",
      autojoin: [], sasl_account: null, sasl_password: null,
    },
  }]);

  // A custom server is the one case that needs the advanced fields, and a
  // missing one must never refuse the submission from inside closed details.
  await page.locator('select[name="preset"]').selectOption("custom");
  await expect(advanced).toHaveAttribute("open");
  const name = page.locator('input[name="name"]');
  await name.fill("");
  await advanced.evaluate((node) => { node.open = false; });
  await add.click();
  await expect(advanced).toHaveAttribute("open");
  await expect(name).toBeFocused();
  expect(await page.evaluate(() => window.consoleApiMutations.length)).toBe(1);

  // Testing stays available, needs no name, and sends what Add would.
  await page.getByLabel("Real name").fill("Alice Example");
  await page.getByRole("button", { name: "Test connection", exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.consoleApiMutations.at(-1))).toEqual({
    method: "POST", url: "/api/v1/me/networks/preflight", json: {
      addr: "irc.libera.chat:6697", tls: false, nick: "alice", realname: "Alice Example",
      autojoin: [], sasl_account: null, sasl_password: null,
    },
  });
});

test("console network editor sends the nickname for a blank real name and restores the password field", async ({ page }) => {
  const editor = await consoleTemplate("console_network_edit.html", { name: "libera", "shell.csrf": "test-csrf" });
  const network = {
    kind: "irc", name: "libera", addr: "irc.libera.chat:6697", tls: true, nick: "alice", realname: null,
    autojoin: ["#e6irc"], sasl_account: "alice", has_sasl_account: true, has_sasl_password: true, enabled: true,
  };
  await mountConsoleRuntime(page, `<main>${editor}</main>`, await consoleStyles(), { "/api/v1/me/networks/libera": network });

  await expect(page.getByLabel("Nickname", { exact: true })).toHaveValue("alice");
  await expect(page.locator("[data-network-advanced]")).not.toHaveAttribute("open");
  await expectAccessible(page);
  const remove = page.getByLabel("Remove the stored account and password");
  const password = page.getByLabel("New NickServ password");
  await remove.check();
  await expect(password).toBeDisabled();
  await remove.uncheck();
  await expect(password).toBeEnabled();
  await expect(page.getByLabel("NickServ account")).toHaveValue("alice");

  await page.getByRole("button", { name: "Save changes", exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.consoleApiMutations)).toEqual([{
    method: "PUT", url: "/api/v1/me/networks/libera", json: {
      addr: "irc.libera.chat:6697", tls: true, nick: "alice", realname: "alice", autojoin: ["#e6irc"],
      credentials: { action: "set", account: "alice", password: null },
    },
  }]);
});

test("console network page shows the NickServ account first and registration on request", async ({ page }) => {
  const detail = await consoleTemplate("console_network_detail.html", { name: "libera", "shell.csrf": "test-csrf" });
  const network = {
    kind: "irc", name: "libera", addr: "irc.libera.chat:6697", tls: true, nick: "alice", realname: null,
    autojoin: [], sasl_account: null, has_sasl_account: false, has_sasl_password: false, enabled: true,
  };
  const operations = { enabled: true, runtime: null, storage: { lines: 0, oldest_at: null, newest_at: null }, recent_lines: [] };
  await mountConsoleRuntime(page, `<main>${detail}</main>`, await consoleStyles(), {
    "/api/v1/me/networks/libera/operations": operations,
    "/api/v1/me/networks/libera": network,
  });

  const save = page.locator("[data-api-network-account-save]");
  await expect(save.getByLabel("NickServ account")).toHaveValue("alice");
  await expect(save.getByLabel("NickServ password")).toBeVisible();
  const register = page.locator("[data-api-network-account-register]");
  await expect(register).toBeHidden();
  await page.getByText("Register a new NickServ account", { exact: true }).click();
  await expect(register.getByLabel("Email address")).toBeVisible();
  await expectAccessible(page);

  await register.getByLabel("Email address").fill("alice@example.test");
  await register.getByLabel("New NickServ password").fill("new-secret");
  await register.getByRole("button", { name: "Request verification email" }).click();
  await expect(save.getByLabel("NickServ password")).toHaveValue("new-secret");
  await save.getByRole("button", { name: "Save and reconnect", exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.consoleApiMutations.map(({ method, url }) => `${method} ${url}`))).toEqual([
    "POST /api/v1/me/networks/libera/account-registration",
    "PUT /api/v1/me/networks/libera",
  ]);
});

test("dynamic console tables retain distinct named scroll regions", async ({ page }) => {
  await mountConsoleRuntime(page, `
    <main data-api-admin-accounts-page data-csrf="test-csrf">
      <section data-api-admin-invitations>Loading invitations…</section>
      <section data-api-admin-accounts>Loading accounts…</section>
    </main>
  `, "", {
    "/api/v1/admin/accounts": {
      accounts: [{
        id: 7,
        name: "operator",
        created_at: "2026-08-19T12:00:00Z",
        current: true,
        suspended: false,
        administrator: true,
        administrator_sources: { durable: true, configuration: false },
        authentication: {
          local_password: true,
          oidc_identities: 0,
          app_passwords: 0,
          browser_sessions: 1,
          api_tokens: 0,
        },
        resources: { networks: 2, founded_channels: 1 },
      }],
      next_before_id: null,
    },
    "/api/v1/admin/invitations": {
      invitations: [{
        id: 9,
        account: "guest",
        contact_email: null,
        administrator: false,
        created_by: "operator",
        expires_at: "2026-08-26T12:00:00Z",
      }],
      next_before_id: null,
    },
  });

  const invitations = page.getByRole("region", { name: "Pending account invitations" });
  const accounts = page.getByRole("region", { name: "Account directory" });
  await expect(invitations).toHaveAttribute("tabindex", "0");
  await expect(accounts).toHaveAttribute("tabindex", "0");
  await expect(invitations.getByRole("table", { name: "Pending account invitations" })).toBeVisible();
  await expect(accounts.getByRole("table", { name: "Account directory" })).toBeVisible();
  await expectAccessible(page);
});

test("network picker renders the empty account state", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "light", reducedMotion: "reduce" });
  await page.setViewportSize({ width: 1280, height: 800 });
  await mockSession(page, []);
  await page.goto("/");

  await expect(page.getByText("No networks are configured for this account.")).toBeVisible();
  await expect(page.locator("ol#messages[aria-live=polite]")).toBeVisible();
  await expect(page.getByRole("list", { name: "Messages" })).toHaveAttribute("tabindex", "0");
  await expect(page.getByRole("button", { name: "Join channel" })).toBeDisabled();
  await expectAccessible(page);
  await expect(page).toHaveScreenshot("network-picker-empty-light.png", {
    animations: "disabled",
    fullPage: true,
  });
});

test("chat preferences are keyboard-dismissible and retain their trigger focus", async ({ page }) => {
  await mockSession(page, []);
  await page.goto("/");

  const preferences = page.getByText("Preferences", { exact: true });
  await preferences.focus();
  await preferences.press("Enter");
  await expect(page.getByLabel("Chat preferences")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(page.getByLabel("Chat preferences")).toBeHidden();
  await expect(preferences).toBeFocused();
});

test("the selected conversation exposes current navigation state", async ({ page }) => {
  await mockSession(page, []);
  await page.goto("/");

  const server = page.getByRole("button", { name: "Open server" });
  await expect(server).toHaveAttribute("aria-current", "true");
  await expect(server).not.toHaveAttribute("aria-pressed");
  await expectAccessible(page);
});

test("chat stays non-interactive while the network catalog loads", async ({ page }) => {
  let releaseRequest;
  const release = new Promise((resolve) => {
    releaseRequest = resolve;
  });
  let markRequested;
  const requested = new Promise((resolve) => {
    markRequested = resolve;
  });
  await mockApiContract(page);
  await page.route(/\/api\/v1\/me$/, (route) =>
    route.fulfill({ contentType: "application/json", body: JSON.stringify(identity) }),
  );
  await page.route(/\/api\/v1\/me\/networks$/, async (route) => {
    markRequested();
    await release;
    await route.fulfill({ contentType: "application/json", body: JSON.stringify({ networks: [] }) });
  });
  await page.goto("/");
  await requested;

  await expect(page.locator("#status")).toHaveText("starting…");
  await expect(page.locator("#message")).toBeDisabled();
  await expect(page.locator("#composer button")).toBeDisabled();
  await expect(page.getByLabel("Join a channel")).toBeDisabled();
  await expectAccessible(page);

  releaseRequest();
  await expect(page.getByText("No networks are configured for this account.")).toBeVisible();
});

// A live socket the test controls: the chat opens a network by itself now, so a
// page with a runnable network attaches, and the snapshot needs that to settle.
async function mockLiveSocket(page) {
  await page.routeWebSocket(/\/ws\/ui/, (socket) => {
    socket.send(JSON.stringify({ t: "status", v: "disconnected", reason: "registration_rejected" }));
    socket.send(JSON.stringify({ t: "snapshot", v: "complete" }));
  });
}

test("the one network list shows typed states and opens a runnable network by itself", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "light", reducedMotion: "reduce" });
  await page.setViewportSize({ width: 768, height: 1024 });
  await mockLiveSocket(page);
  await mockSession(page, [
    { name: "Archive", kind: "irc", nick: "viewer", enabled: false, connected: null, runtime: null },
    {
      name: "Libera",
      kind: "irc",
      nick: "viewer",
      enabled: true,
      connected: false,
      runtime: {
        state: "reconnecting",
        last_error: { code: "registration_rejected", diagnostic: "Closing Link: (SASL access only)" },
      },
    },
  ]);
  await page.goto("/");

  // Opening the only runnable network is not a choice, so it is not asked:
  // the disabled one cannot run, and the address bar says what was opened.
  await expect(page).toHaveURL(/\?network=Libera$/);
  const networks = page.getByRole("list", { name: "Networks" });
  await expect(networks.getByRole("link")).toHaveCount(2);
  await expect(networks.getByRole("link", { name: "Open Libera, reconnecting" })).toHaveAttribute("data-state", "reconnecting");
  await expect(networks.getByRole("link", { name: "Open Archive, disabled" })).toBeVisible();
  // The network's own words sit beside the control that repairs it.
  await expect(networks.getByText(/The network said: “Closing Link: \(SASL access only\)”/)).toBeVisible();
  await expect(networks.getByRole("button", { name: "Settings for Libera" })).toBeVisible();
  // One list: no second picker in the header or the message area.
  await expect(page.getByRole("combobox", { name: "Active network" })).toHaveCount(0);
  await expect(page.getByLabel("Messages").getByRole("link")).toHaveCount(0);
  await expectAccessible(page);
  await expect(page).toHaveScreenshot("network-picker-tablet.png", {
    animations: "disabled",
    fullPage: true,
    mask: [page.locator("#messages .ts")],
  });
});

test("with several runnable networks the person chooses; the client does not pick one", async ({ page }) => {
  let sockets = 0;
  await page.routeWebSocket(/\/ws\/ui/, () => { sockets += 1; });
  const runnable = (name, connected) => ({
    name, kind: "irc", nick: "viewer", enabled: true, connected,
    runtime: { state: connected ? "connected" : "reconnecting", last_error: null },
  });
  await mockSession(page, [runnable("Libera", false), runnable("OFTC", true)]);
  await page.goto("/");

  await expect(page.getByText("Choose a network from your list to open it.")).toBeVisible();
  await expect(page).toHaveURL(/\/$/);
  expect(sockets).toBe(0);
  const networks = page.getByRole("list", { name: "Networks" });
  await networks.getByRole("link", { name: "Open OFTC, connected" }).click();
  await expect(page).toHaveURL(/\?network=OFTC$/);
  await expectAccessible(page);
});

test("on a phone the choice says how to reach the list instead of opening it unasked", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  const runnable = (name) => ({
    name, kind: "irc", nick: "viewer", enabled: true, connected: true,
    runtime: { state: "connected", last_error: null },
  });
  await mockSession(page, [runnable("Libera"), runnable("OFTC")]);
  await page.goto("/");

  const networks = page.getByRole("list", { name: "Networks" });
  await expect(networks).toBeHidden();
  await page.getByRole("button", { name: "Show my networks" }).click();
  await expect(networks.getByRole("link", { name: "Open Libera, connected" })).toBeVisible();
  await expectAccessible(page);
});

test("the network list follows the server instead of the first answer it got", async ({ page }) => {
  await mockLiveSocket(page);
  await mockSession(page, []);
  let reads = 0;
  await page.route(/\/api\/v1\/me\/networks$/, (route) => {
    reads += 1;
    const parked = reads > 1;
    return route.fulfill({ contentType: "application/json", body: JSON.stringify({ networks: [{
      name: "Libera",
      kind: "irc",
      nick: "viewer",
      enabled: true,
      connected: !parked,
      runtime: parked
        ? { state: "authentication_failed", last_error: { code: "authentication_rejected" } }
        : { state: "connected", last_error: null },
    }] }) });
  });
  await page.goto("/");

  const networks = page.getByRole("list", { name: "Networks" });
  await expect(networks.getByRole("link", { name: "Open Libera, connected" })).toBeVisible();
  await expect(networks.getByRole("link", { name: "Open Libera, authentication failed" })).toBeVisible({ timeout: 15_000 });
  await expect(networks.getByText(/rejected the NickServ account or password/)).toBeVisible();
});

test("adding a network asks only what a known network cannot supply, and carries the session token", async ({ page }) => {
  await mockSession(page, []);
  let created;
  await page.route(/\/api\/v1\/me\/networks$/, async (route) => {
    if (route.request().method() !== "POST") return route.fallback();
    created = { csrf: await route.request().headerValue("x-e6irc-csrf"), body: route.request().postDataJSON() };
    return route.fulfill({
      status: 201,
      contentType: "application/json",
      body: JSON.stringify({ name: "libera", attach: "visual-test/libera" }),
    });
  });
  await page.goto("/");

  // The empty account's one action opens the dialog here, not another application.
  await page.getByRole("button", { name: "Add a network", exact: true }).last().click();
  const dialog = page.getByRole("dialog", { name: "Add a network" });
  await expect(dialog.locator("#nf-preset")).toHaveValue("libera");
  await expect(dialog.locator("#nf-nick")).toHaveValue("visual-test");
  await expect(dialog.locator("#nf-nick")).toBeFocused();
  // Nothing is stored yet, so there is nothing to offer to remove.
  await expect(dialog.getByText("Remove the stored account and password")).toBeHidden();
  // What Libera already determines is filled in and out of the way.
  await expect(dialog.locator("#nf-addr")).toBeHidden();
  await expect(dialog.locator("#nf-addr")).toHaveValue("irc.libera.chat:6697");
  await expectAccessible(page);

  // Another network hands the name and server to the person, in view.
  await dialog.locator("#nf-preset").selectOption("custom");
  await expect(dialog.locator("#nf-addr")).toBeVisible();
  await expect(dialog.locator("#nf-name")).toBeFocused();
  await dialog.locator("#nf-preset").selectOption("libera");

  await dialog.locator("#nf-sasl-account").fill("visual-account");
  await dialog.locator("#nf-sasl-password").fill("correct horse");
  await dialog.getByRole("button", { name: "Save" }).click();

  await expect(page).toHaveURL(/\?network=libera$/);
  expect(created).toEqual({
    csrf: "session-bound-token",
    body: {
      kind: "irc",
      name: "libera",
      addr: "irc.libera.chat:6697",
      tls: true,
      nick: "visual-test",
      realname: "visual-test",
      autojoin: [],
      sasl_account: "visual-account",
      sasl_password: "correct horse",
    },
  });
});

test("chat reflows at a 200 percent equivalent layout width", async ({ page }) => {
  await page.setViewportSize({ width: 640, height: 800 });
  await mockSession(page, [
    {
      name: "Libera",
      kind: "irc",
      nick: "viewer",
      enabled: true,
      connected: false,
      runtime: { state: "reconnecting" },
    },
  ]);
  await mockLiveSocket(page);
  await page.goto("/");

  await expect(page).toHaveURL(/\?network=Libera$/);
  await expect(page.locator("#status")).toContainText("Libera");
  await expect
    .poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth))
    .toBe(true);
  await expectAccessible(page);
});

test("network picker distinguishes an unavailable API on narrow dark screens", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "dark", reducedMotion: "reduce" });
  await page.setViewportSize({ width: 390, height: 844 });
  await mockSession(page, new Error("Network service unavailable"));
  await page.goto("/");

  await expect(page.getByRole("alert")).toContainText("Network service unavailable");
  await expect(page.getByRole("link", { name: "Retry" })).toBeVisible();
  await expectAccessible(page);
  await expect(page).toHaveScreenshot("network-picker-unavailable-dark-narrow.png", {
    animations: "disabled",
    fullPage: true,
  });
});

test("parked Libera registration gives the recovery beside its settings control", async ({ page }) => {
  await mockLiveSocket(page);
  await mockSession(page, [{
    name: "Libera",
    kind: "irc",
    nick: "viewer",
    enabled: true,
    connected: false,
    runtime: {
      state: "registration_failed",
      last_error: { code: "registration_rejected" },
    },
  }]);
  await page.goto("/");

  const networks = page.getByRole("list", { name: "Networks" });
  await expect(networks.getByText(/verified SASL is required/)).toBeVisible();
  await expect(networks.getByRole("button", { name: "Settings for Libera" })).toBeVisible();
  await expectAccessible(page);
});

test("network picker directs an expired session to sign in", async ({ page }) => {
  await mockSession(page, new Error("Unauthorized"), 401);
  await page.goto("/");

  await expect(page.getByRole("alert")).toContainText("Your session expired while trying to load your networks");
  await expect(page.getByRole("link", { name: "Sign in" })).toHaveAttribute("href", "/login");
  await expect(page.getByRole("link", { name: "Retry" })).toHaveCount(0);
  await expectAccessible(page);
});

test("malformed identity response stays an explicit recovery state", async ({ page }) => {
  await mockSession(page, [], 503, { account: 1 });
  await page.goto("/");

  await expect(page.getByRole("alert")).toContainText("Could not load your signed-in identity");
  await expect(page.locator("#account-name")).toHaveText("identity unavailable");
  await expectAccessible(page);
});

test("oversized identity response stays an explicit recovery state", async ({ page }) => {
  await mockSession(page, [], 503, `"${"€".repeat(524289)}"`);
  await page.goto("/");

  await expect(page.getByRole("alert")).toContainText("Could not load your signed-in identity");
  await expect(page.locator("#account-name")).toHaveText("identity unavailable");
  await expectAccessible(page);
});

test("network picker keeps recovery controls usable in forced colors", async ({ page }) => {
  await page.emulateMedia({ forcedColors: "active" });
  await mockSession(page, new Error("Network service unavailable"));
  await page.goto("/");

  const retry = page.getByRole("link", { name: "Retry" });
  await expect(retry).toBeVisible();
  await retry.focus();
  await expect(retry).toBeFocused();
  await expectAccessible(page);
});

test("phone conversation rail returns focus after Escape", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await mockSession(page, []);
  await page.goto("/");

  const conversations = page.getByRole("button", { name: "Conversations" });
  await conversations.click();
  const server = page.getByRole("button", { name: "Open server" });
  await expect(server).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(conversations).toBeFocused();
  await expect
    .poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth))
    .toBe(true);
  await expectAccessible(page);
});
