import playwrightTest from "playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { readFile } from "node:fs/promises";

const { expect, test } = playwrightTest;

const identity = {
  account: "visual-test", email: "visual@example.test", role: "operator", csrf_token: "session-bound-token",
  logout_url: "/api/v1/auth/logout?csrf=session-bound-token",
};
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
          required: ["kind", "name", "addr", "tls", "nick", "username", "realname", "autojoin"],
          properties: {
            kind: { const: "irc" }, name: { type: "string" }, addr: { type: "string" }, tls: { type: "boolean" },
            nick: { type: "string" }, username: { type: "string", pattern: "^[A-Za-z0-9][A-Za-z0-9_-]{0,9}$" },
            realname: { type: "string" },
            autojoin: { type: "array", items: { type: "string" } },
            sasl_account: { type: "string" }, sasl_password: { type: "string" },
            server_password: { type: ["string", "null"], minLength: 1, maxLength: 504, writeOnly: true },
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

// The console's one stylesheet (served at /console.css; the pages allow no
// inline style).
async function consoleStyles() {
  return readFile(new URL("../../crates/e6ircd/assets/console.css", import.meta.url), "utf8");
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
    body: "export const loadSettings = () => ({ settings: { theme: 'auto' }, warning: null }); export const saveSetting = () => null;",
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
  const styles = await consoleStyles();
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
    "Name", "Server", "Use TLSRecommended for public IRC networks.", "Username optional", "Real name optional",
    "Server password optional",
  ]);
  await expect(page.locator('input[name="server_password"]')).toHaveAttribute("autocomplete", "new-password");
  await expectAccessible(page);

  await add.click();
  await expect.poll(() => page.evaluate(() => window.consoleApiMutations)).toEqual([{
    method: "POST", url: "/api/v1/me/networks", json: {
      kind: "irc", name: "libera", addr: "irc.libera.chat:6697", tls: false, nick: "alice", username: "alice", realname: "alice",
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
    method: "POST", url: "/api/v1/me/network-preflight", json: {
      addr: "irc.libera.chat:6697", tls: false, nick: "alice", username: "alice", realname: "Alice Example",
      autojoin: [], sasl_account: null, sasl_password: null,
    },
  });
});

test("console network editor sends the nickname for a blank real name and restores the password field", async ({ page }) => {
  const editor = await consoleTemplate("console_network_edit.html", { name: "libera", "shell.csrf": "test-csrf" });
  const network = {
    kind: "irc", name: "libera", addr: "irc.libera.chat:6697", tls: true, nick: "alice", username: "alice", realname: null,
    autojoin: ["#e6irc"], sasl_account: "alice", has_sasl_account: true, has_sasl_password: true, has_server_password: true, enabled: true,
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
      addr: "irc.libera.chat:6697", tls: true, nick: "alice", username: "alice", realname: "alice", autojoin: ["#e6irc"],
      // The contract declares every credential field a string: a blank
      // password is omitted (the sealed one is kept), never sent as null.
      credentials: { action: "set", account: "alice" },
      server_password: { action: "keep" },
    },
  }]);

  // Emptying the stored account without ticking Remove is refused at the box:
  // the box says "no account" and the body would have said "keep it".
  await page.getByLabel("NickServ account").fill("");
  await page.getByRole("button", { name: "Save changes", exact: true }).click();
  await expect(page.getByRole("status")).toContainText("alice is still stored");
  await expect(page.getByLabel("NickServ account")).toBeFocused();
  expect(await page.evaluate(() => window.consoleApiMutations.length)).toBe(1);
  await page.getByLabel("NickServ account").fill("alice");

  // The server password: typed is a set, Remove clears and disables the box
  // and is a remove.
  await page.getByText("Advanced").click();
  const serverPassword = page.getByLabel("New server password");
  await serverPassword.fill("rotated");
  await page.getByRole("button", { name: "Save changes", exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.consoleApiMutations.at(-1).json.server_password)).toEqual({ action: "set", password: "rotated" });
  await serverPassword.fill("typed");
  await page.getByLabel("Remove the stored server password").check();
  await expect(serverPassword).toBeDisabled();
  await expect(serverPassword).toHaveValue("");
  await expectAccessible(page);
  await page.getByRole("button", { name: "Save changes", exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.consoleApiMutations.at(-1).json.server_password)).toEqual({ action: "remove" });
});

test("console bridge editor sends only the fields the contract declares for a bridge", async ({ page }) => {
  const editor = await consoleTemplate("console_bridge_edit.html", { name: "team", "shell.csrf": "test-csrf" });
  const network = {
    kind: "slack", name: "team", addr: "https://slack.com/api", tls: true, nick: "", username: null, realname: null,
    autojoin: ["C123"], sasl_account: null, has_sasl_account: true, has_sasl_password: true, has_server_password: false, enabled: true,
  };
  await mountConsoleRuntime(page, `<main>${editor}</main>`, await consoleStyles(), { "/api/v1/me/networks/team": network });
  await expect(page.getByRole("button", { name: "Save bridge", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Save bridge", exact: true }).click();
  // No realname (the contract declares it a string and a bridge has none), and
  // blank credentials mean keep -- nothing is null.
  await expect.poll(() => page.evaluate(() => window.consoleApiMutations)).toEqual([{
    method: "PUT", url: "/api/v1/me/networks/team", json: {
      addr: "https://slack.com/api", tls: true, nick: "", autojoin: ["C123"], credentials: { action: "keep" },
      server_password: { action: "keep" },
    },
  }]);
  await page.locator('[name="sasl_password"]').fill("xapp-new");
  await page.getByRole("button", { name: "Save bridge", exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.consoleApiMutations.at(-1).json.credentials)).toEqual({ action: "set", password: "xapp-new" });
});

test("the console network page's save control says when it also enables the network", async ({ page }) => {
  const detail = await consoleTemplate("console_network_detail.html", { name: "libera", "shell.csrf": "test-csrf" });
  const network = {
    kind: "irc", name: "libera", addr: "irc.libera.chat:6697", tls: true, nick: "alice", username: "alice", realname: null,
    autojoin: [], sasl_account: null, has_sasl_account: false, has_sasl_password: false, has_server_password: false, enabled: false,
  };
  const operations = { enabled: false, runtime: null, storage: { lines: 0, oldest_at: null, newest_at: null }, recent_lines: [] };
  await mountConsoleRuntime(page, `<main>${detail}</main>`, await consoleStyles(), {
    "/api/v1/me/networks/libera/operations": operations,
    "/api/v1/me/networks/libera": network,
  });
  const save = page.locator("[data-api-network-account-save]");
  const button = save.getByRole("button", { name: "Save credentials and enable", exact: true });
  await expect(button).toBeVisible();
  await expect(save.getByText("This network is disabled. Saving enables it")).toBeVisible();
  await expect(page.locator("[data-network-account-save-name]")).toHaveText("Save credentials and enable");
  await expectAccessible(page);
  await save.getByLabel("NickServ password").fill("secret");
  await button.click();
  await expect.poll(() => page.evaluate(() => window.consoleApiMutations.map(({ method, url, json }) => `${method} ${url} ${JSON.stringify(json)}`))).toEqual([
    'PUT /api/v1/me/networks/libera {"addr":"irc.libera.chat:6697","tls":true,"nick":"alice","username":"alice","realname":null,"autojoin":[],"credentials":{"action":"set","account":"alice","password":"secret"},"server_password":{"action":"keep"}}',
    'PATCH /api/v1/me/networks/libera {"enabled":true}',
  ]);
  await expect(page.getByRole("status")).toContainText("saved and the network enabled");
});

test("every console disconnect reason box names its connection", async ({ page }) => {
  const body = await consoleTemplate("console_sessions.html", { "shell.csrf": "test-csrf", own: "true" });
  await mountConsoleRuntime(page, `<main>${body}</main>`, await consoleStyles(), {
    "/api/v1/me/sessions": { sessions: [] },
    "/api/v1/me/connections": { connections: [
      { id: "7", nick: "alice", user: "alice", host: "h", oper: false, account: "alice", transport: "tls", connected_at: "2026-09-21T10:00:00Z", idle_seconds: 4, channels: ["#e6irc"] },
      { id: "8", nick: "bob", user: "bob", host: "h", oper: false, account: null, transport: "ws", connected_at: "2026-09-21T10:00:00Z", idle_seconds: 9, channels: [] },
    ], next_before_id: null },
  });
  await expect(page.getByLabel("Disconnect reason for connection 7 (alice)")).toBeVisible();
  await expect(page.getByLabel("Disconnect reason for connection 8 (bob)")).toBeVisible();
  await expectAccessible(page);
});

test("console network page shows the NickServ account first and registration on request", async ({ page }) => {
  const detail = await consoleTemplate("console_network_detail.html", { name: "libera", "shell.csrf": "test-csrf" });
  const network = {
    kind: "irc", name: "libera", addr: "irc.libera.chat:6697", tls: true, nick: "alice", username: "alice", realname: null,
    autojoin: [], sasl_account: null, has_sasl_account: false, has_sasl_password: false, has_server_password: false, enabled: true,
  };
  const operations = { enabled: true, runtime: null, storage: { lines: 0, oldest_at: null, newest_at: null }, recent_lines: [] };
  await mountConsoleRuntime(page, `<main>${detail}</main>`, await consoleStyles(), {
    "/api/v1/me/networks/libera/operations": operations,
    "/api/v1/me/networks/libera": network,
  });

  await expect(page.locator('[data-network-field="server-password"]')).toHaveText("Not set");
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

test("console log pages refresh on request and keep the reader's place", async ({ page }) => {
  const body = await consoleTemplate("console_network_logs.html", { name: "libera" });
  const lines = Array.from({ length: 400 }, (_, index) => `line ${index}`);
  await mountConsoleRuntime(page, `<main>${body}</main>`, await consoleStyles(), {
    "/api/v1/me/networks/libera/buffer": { lines },
    "/api/v1/me/networks/libera": { name: "libera" },
  });
  const log = page.getByRole("log", { name: "Network log" });
  await expect(log.locator("code")).toHaveCount(400);
  // A log opens at its newest line, which is where its reader wants to be.
  expect(await log.evaluate((node) => node.scrollHeight - node.scrollTop - node.clientHeight)).toBeLessThan(8);

  // The Refresh button names the panel; it used to find no refresher and do nothing.
  await log.evaluate((node) => { node.scrollTop = 120; });
  const before = await page.evaluate(() => window.consoleApiRequests.length);
  await page.getByRole("button", { name: "Refresh", exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.consoleApiRequests.length)).toBeGreaterThan(before);
  await expect(page.getByText("Live log refreshed.", { exact: true })).toBeVisible();
  // Same node, same place: nothing was torn down under the reader.
  expect(await log.evaluate((node) => node.scrollTop)).toBe(120);
  // The panel itself is no longer a live region re-announcing a thousand lines.
  await expect(page.locator("#network-log-panel")).not.toHaveAttribute("aria-live");
  await expectAccessible(page);
});

test("a background refresh never pulls the rows out from under a pending confirmation", async ({ page }) => {
  const form = (await consoleTemplate("console_networks.html", {
    "shell.csrf": "test-csrf", "preset.id": "libera", "preset.name": "libera", "preset.label": "Libera Chat",
    "preset.addr": "irc.libera.chat:6697", "form.name": "libera", "form.addr": "irc.libera.chat:6697", "form.nick": "alice",
  })).replace(/data-refresh-seconds="\d+"/, 'data-refresh-seconds="5"');
  // The shell's own confirmation dialog, so the test cannot drift from it.
  const shell = await readFile(new URL("../../crates/e6ircd/templates/console_base.html", import.meta.url), "utf8");
  const confirmDialog = shell.match(/<dialog class="confirm-dialog"[\s\S]*?<\/dialog>/)[0];
  await mountConsoleRuntime(page, `<main>${form}</main>${confirmDialog}`, await consoleStyles(), {
    "/api/v1/me/networks": { networks: [{
      name: "libera", kind: "irc", addr: "irc.libera.chat:6697", tls: true, nick: "alice", username: "alice", realname: "Alice", autojoin: [],
      sasl_account: null, has_sasl_account: false, has_sasl_password: false, has_server_password: false, enabled: true, connected: true,
      runtime: { state: "connected", attached_clients: 0, errors: 0, last_error: null },
    }] },
  });
  await page.getByRole("button", { name: "Remove", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Confirm action" });
  await expect(dialog).toBeVisible();
  const reads = () => page.evaluate(() => window.consoleApiRequests.filter((url) => url === "/api/v1/me/networks").length);
  const before = await reads();
  // Longer than the refresh interval: replacing the rows now would detach the
  // form this dialog is about to submit, and confirming would then do nothing.
  await page.waitForTimeout(6_500);
  expect(await reads()).toBe(before);
  await dialog.getByRole("button", { name: "Remove", exact: true }).click();
  await expect.poll(() => page.evaluate(() => window.consoleApiMutations)).toEqual([
    { method: "DELETE", url: "/api/v1/me/networks/libera", json: undefined },
  ]);
});

test("console server-network form masks a token and forgets credentials when the type changes", async ({ page }) => {
  const body = await consoleTemplate("console_configuration.html", { "shell.csrf": "test-csrf" });
  await mountConsoleRuntime(page, `<main>${body}</main>`, await consoleStyles());
  const form = page.locator("form[data-api-network-create]");
  const kind = form.locator('select[name="kind"]');
  // The type list is filled from the configuration read; this test is about
  // what choosing a type does, so it supplies the two types itself.
  await kind.evaluate((select) => {
    for (const value of ["irc", "slack"]) select.add(new Option(value.toUpperCase(), value));
    select.value = "irc";
    select.dispatchEvent(new Event("change", { bubbles: true }));
  });
  await kind.selectOption("slack");
  const token = form.locator('[name="sasl_account"]');
  await expect(token).toHaveAttribute("type", "password");
  await expect(token).toHaveAttribute("autocomplete", "new-password");
  await token.fill("xoxb-bot-token");
  await form.locator('[name="sasl_password"]').fill("xapp-app-token");

  // Back to IRC: the same inputs now mean a NickServ account and password, so
  // a Slack token must not still be sitting in them.
  await kind.selectOption("irc");
  await expect(token).toHaveAttribute("type", "text");
  await expect(token).toHaveValue("");
  await expect(form.locator('[name="sasl_password"]')).toHaveValue("");

  // A server password is IRC's alone: offered, masked, and forgotten when the
  // type changes to one that sends no PASS.
  const serverPassword = form.locator('[name="server_password"]');
  await expect(serverPassword).toBeVisible();
  await expect(serverPassword).toHaveAttribute("type", "password");
  await expect(serverPassword).toHaveAttribute("autocomplete", "new-password");
  await serverPassword.fill("open sesame");
  await kind.selectOption("slack");
  await expect(serverPassword).toBeHidden();
  await expect(serverPassword).toBeDisabled();
  await kind.selectOption("irc");
  await expect(serverPassword).toHaveValue("");
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
    socket.send(snapshotEvent(0));
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

const ircNetwork = (name, extra = {}) => ({
  name, kind: "irc", nick: "viewer", enabled: true, connected: true,
  runtime: { state: "connected", last_error: null }, ...extra,
});
const networkDetail = (name, addr) => ({
  name, kind: "irc", addr, tls: true, nick: `${name}-nick`, username: "viewer", realname: "Viewer", autojoin: ["#kept"],
  sasl_account: null, has_sasl_account: false, has_sasl_password: false, has_server_password: false, enabled: true,
});
const detailContract = {
  get: { responses: { 200: response({
    type: "object", additionalProperties: false,
    required: ["name", "kind", "addr", "tls", "nick", "username", "realname", "autojoin", "sasl_account", "has_sasl_account", "has_sasl_password", "has_server_password", "enabled"],
    properties: {
      name: { type: "string" }, kind: { type: "string" }, addr: { type: "string" }, tls: { type: "boolean" },
      nick: { type: "string" }, username: { type: ["string", "null"] }, realname: { type: ["string", "null"] },
      autojoin: { type: "array", items: { type: "string" } }, sasl_account: { type: ["string", "null"] },
      has_sasl_account: { type: "boolean" }, has_sasl_password: { type: "boolean" },
      has_server_password: { type: "boolean" }, enabled: { type: "boolean" },
    },
  }) } },
};

// The replace request as the server documents it: both write-only secrets are
// changed only by an explicit action.
const secretAction = (set) => ({ oneOf: [
  { type: "object", additionalProperties: false, required: ["action"], properties: { action: { const: "keep" } } },
  { type: "object", additionalProperties: false, required: ["action"], properties: { action: { const: "remove" } } },
  { type: "object", additionalProperties: false, required: ["action", ...set.required], properties: { action: { const: "set" }, ...set.properties } },
] });
const replaceContract = {
  requestBody: { required: true, content: { "application/json": { schema: {
    type: "object", additionalProperties: false, required: ["addr", "tls", "nick", "credentials", "server_password"],
    properties: {
      addr: { type: "string" }, tls: { type: "boolean" }, nick: { type: "string" },
      username: { type: "string" }, realname: { type: "string" }, autojoin: { type: "array", items: { type: "string" } },
      credentials: secretAction({ required: [], properties: { account: { type: "string" }, password: { type: "string" } } }),
      server_password: secretAction({ required: ["password"], properties: { password: { type: "string", minLength: 1, maxLength: 504 } } }),
    },
  } } } },
  responses: { 204: { description: "updated" } },
};

async function mockNetworkDetails(page, respond) {
  await page.route("/api/v1/openapi.json", (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({ paths: { ...apiContract.paths, "/api/v1/me/networks/{name}": {
      get: {
        ...detailContract.get,
        parameters: [{ name: "name", in: "path", required: true, schema: { type: "string" } }],
      },
      put: {
        ...replaceContract,
        parameters: [{ name: "name", in: "path", required: true, schema: { type: "string" } }],
      },
    } } }),
  }));
  await page.route(/\/api\/v1\/me\/networks\/[^/]+$/, respond);
}

test("a refresh that changes nothing leaves keyboard focus where it was", async ({ page }) => {
  await mockLiveSocket(page);
  await mockSession(page, [ircNetwork("Libera"), ircNetwork("OFTC")]);
  let reads = 0;
  page.on("request", (request) => { if (/\/api\/v1\/me\/networks$/.test(request.url())) reads += 1; });
  await page.goto("/?network=Libera");
  const cog = page.getByRole("button", { name: "Settings for OFTC" });
  await cog.focus();
  const before = reads;
  await expect.poll(() => reads, { timeout: 15_000 }).toBeGreaterThan(before);
  await expect(cog).toBeFocused();
});

test("two quick settings clicks cannot put one network's values under another's name", async ({ page }) => {
  await mockLiveSocket(page);
  await mockSession(page, [ircNetwork("Libera"), ircNetwork("OFTC")]);
  let releaseLibera;
  const liberaHeld = new Promise((resolve) => { releaseLibera = resolve; });
  await mockNetworkDetails(page, async (route) => {
    const name = decodeURIComponent(new URL(route.request().url()).pathname.split("/").pop());
    if (name === "Libera") await liberaHeld;
    return route.fulfill({ contentType: "application/json", body: JSON.stringify(networkDetail(name, `irc.${name.toLowerCase()}.example:6697`)) });
  });
  await page.goto("/?network=Libera");

  // Libera's answer is slow; OFTC is clicked meanwhile and answers first. The
  // dialog is modal, so the second click is made the way a script or a fast
  // double-tap lands it: directly on the control.
  await page.getByRole("button", { name: "Settings for Libera" }).click();
  await page.getByRole("button", { name: "Settings for OFTC" }).dispatchEvent("click");
  const dialog = page.getByRole("dialog", { name: "Settings — OFTC" });
  await expect(dialog.locator("#nf-nick")).toHaveValue("OFTC-nick");
  releaseLibera();
  await page.waitForTimeout(300);
  await expect(dialog.locator("#nf-nick")).toHaveValue("OFTC-nick");
  await expect(dialog.locator("#nf-addr")).toHaveValue("irc.oftc.example:6697");
  await expect(dialog.getByRole("button", { name: "Save" })).toBeEnabled();
});

test("settings that failed to load cannot be saved over the stored ones", async ({ page }) => {
  await mockLiveSocket(page);
  await mockSession(page, [ircNetwork("Libera")]);
  await mockNetworkDetails(page, (route) => route.fulfill({
    status: 503, contentType: "application/problem+json", body: JSON.stringify({ status: 503, title: "Database unavailable" }),
  }));
  await page.goto("/?network=Libera");
  await page.getByRole("button", { name: "Settings for Libera" }).click();
  const dialog = page.getByRole("dialog", { name: "Settings — Libera" });
  await expect(dialog.getByRole("alert")).toContainText("Database unavailable");
  await expect(dialog.getByRole("button", { name: "Save" })).toBeDisabled();
});

test("a revealed password is hidden again and gone when the dialog is reopened", async ({ page }) => {
  await mockSession(page, []);
  await page.goto("/");
  await page.getByRole("button", { name: "Add a network", exact: true }).last().click();
  const dialog = page.getByRole("dialog", { name: "Add a network" });
  await dialog.locator("#nf-sasl-password").fill("typed secret");
  await dialog.getByRole("button", { name: "Show password" }).click();
  await expect(dialog.locator("#nf-sasl-password")).toHaveAttribute("type", "text");
  await dialog.getByRole("button", { name: "Cancel" }).click();
  await expect(page.locator("#nf-sasl-password")).toHaveValue("");

  await page.getByRole("button", { name: "Add a network", exact: true }).last().click();
  await expect(dialog.locator("#nf-sasl-password")).toHaveAttribute("type", "password");
  await expect(dialog.getByRole("button", { name: "Show password" })).toHaveAttribute("aria-pressed", "false");
});

test("a bridge network's settings open its own form, not the IRC dialog", async ({ page }) => {
  await mockLiveSocket(page);
  await mockSession(page, [ircNetwork("Libera"), ircNetwork("Team", { kind: "slack", nick: "" })]);
  await page.goto("/?network=Libera");
  await expect(page.getByRole("link", { name: "Settings for Team" })).toHaveAttribute("href", "/console/networks/Team");
  await expect(page.getByRole("button", { name: "Settings for Libera" })).toBeVisible();
});

test("only a join asked for here moves the view", async ({ page }) => {
  let upstream;
  await page.routeWebSocket(/\/ws\/ui/, (socket) => {
    upstream = socket;
    socket.send(JSON.stringify({ t: "status", v: "connected" }));
    socket.send(JSON.stringify({ t: "session", nick: "viewer", channels: [] }));
    socket.send(snapshotEvent(0));
    socket.onMessage((frame) => {
      const request = JSON.parse(frame);
      if (request.message === "/join #asked") socket.send(lineEvent(":viewer!u@h JOIN #asked", 2));
    });
  });
  await mockSession(page, [ircNetwork("Libera")]);
  await page.goto("/?network=Libera");
  await expect(page.getByLabel("Join a channel")).toBeEnabled();

  // The bouncer rejoining after a reconnect, or another attached client.
  upstream.send(lineEvent(":viewer!u@h JOIN #rejoined", 1));
  await expect(page.getByRole("button", { name: /^Open #rejoined/ })).toBeVisible();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("server");

  await page.getByLabel("Join a channel").fill("#asked");
  await page.getByRole("button", { name: "Join channel" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("#asked");
});

test("a connection the server refuses by policy is said once and not hammered", async ({ page }) => {
  let attempts = 0;
  await page.routeWebSocket(/\/ws\/ui/, (socket) => {
    attempts += 1;
    // What the server does to the 33rd live socket of one account.
    socket.close({ code: 1008, reason: "This account has 32 live chat connections open, the most allowed. Close another tab and retry." });
  });
  await mockSession(page, [ircNetwork("Libera")]);
  await page.goto("/?network=Libera");

  const alert = page.getByRole("alert").filter({ hasText: "32 live chat connections" });
  await expect(alert).toBeVisible();
  await expect(alert).toContainText("e6irc is not retrying");
  // Longer than the first reconnect delay: a refusal is not a dropped link.
  await page.waitForTimeout(2500);
  expect(attempts).toBe(1);

  // The person decides when the condition has changed.
  await alert.getByRole("button", { name: "Retry now" }).click();
  await expect.poll(() => attempts).toBe(2);
});

test("opening a network returns to the conversation that was open, never to whatever replay mentioned last", async ({ page }) => {
  const attach = (channels) => page.routeWebSocket(/\/ws\/ui/, (socket) => {
    socket.send(JSON.stringify({ t: "status", v: "connected" }));
    channels.forEach((channel, index) => socket.send(lineEvent(`:viewer!u@h JOIN ${channel}`, index + 1)));
    socket.send(JSON.stringify({ t: "session", nick: "viewer", channels }));
    socket.send(snapshotEvent(channels.length));
  });
  await mockSession(page, [ircNetwork("Libera")]);
  const heading = page.getByRole("heading", { level: 1 });

  // Several conversations and nothing remembered: the person picks.
  await attach(["#alpha", "#beta"]);
  await page.goto("/?network=Libera");
  await expect(page.getByRole("button", { name: /^Open #beta/ })).toBeVisible();
  await expect(heading).toHaveText("server");

  // What they pick is where the network opens next time.
  await page.getByRole("button", { name: /^Open #alpha/ }).click();
  await expect(heading).toHaveText("#alpha");
  await page.reload();
  await expect(heading).toHaveText("#alpha");
});

test("a network's only conversation opens by itself", async ({ page }) => {
  await page.routeWebSocket(/\/ws\/ui/, (socket) => {
    socket.send(JSON.stringify({ t: "status", v: "connected" }));
    socket.send(lineEvent(":viewer!u@h JOIN #only", 1));
    socket.send(JSON.stringify({ t: "session", nick: "viewer", channels: ["#only"] }));
    socket.send(snapshotEvent(1));
  });
  await mockSession(page, [ircNetwork("Libera")]);
  await page.goto("/?network=Libera");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("#only");
});

test("an expired session during a refresh offers sign-in once and stops asking", async ({ page }) => {
  await mockLiveSocket(page);
  await mockSession(page, [ircNetwork("Libera")]);
  let reads = 0;
  await page.route(/\/api\/v1\/me\/networks$/, (route) => {
    reads += 1;
    if (reads === 1) return route.fallback();
    return route.fulfill({ status: 401, contentType: "application/problem+json", body: JSON.stringify({ status: 401, title: "Unauthorized" }) });
  });
  await page.goto("/?network=Libera");
  const alert = page.locator('[data-alert="networks"]');
  await expect(alert).toBeVisible({ timeout: 15_000 });
  await expect(alert.getByRole("link", { name: "Sign in" })).toHaveAttribute("href", "/login");
  const after = reads;
  await page.waitForTimeout(11_000);
  expect(reads).toBe(after);
});

test("stored settings cannot be typed over before they have arrived", async ({ page }) => {
  await mockLiveSocket(page);
  await mockSession(page, [ircNetwork("Libera")]);
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  await mockNetworkDetails(page, async (route) => {
    await held;
    return route.fulfill({ contentType: "application/json", body: JSON.stringify(networkDetail("Libera", "irc.libera.example:6697")) });
  });
  await page.goto("/?network=Libera");
  await page.getByRole("button", { name: "Settings for Libera" }).click();
  const dialog = page.getByRole("dialog", { name: "Settings — Libera" });
  // Every box is about to be filled from the server; one typed into now would
  // silently lose what was typed.
  await expect(dialog.locator("#nf-nick")).toBeDisabled();
  await expect(dialog.locator("#nf-autojoin")).toBeDisabled();
  await expect(dialog.getByRole("button", { name: "Cancel" })).toBeEnabled();
  release();
  await expect(dialog.locator("#nf-nick")).toBeEnabled();
  await expect(dialog.locator("#nf-nick")).toHaveValue("Libera-nick");
  await expect(dialog.locator("#nf-name")).toBeDisabled();
});

test("a nickname typed while the known networks load is not overwritten by the suggestion", async ({ page }) => {
  await mockSession(page, []);
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  await page.route(/\/api\/v1\/network-presets$/, async (route) => {
    await held;
    return route.fallback();
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Add a network", exact: true }).last().click();
  const dialog = page.getByRole("dialog", { name: "Add a network" });
  // The suggestion needs nothing from the server, so it is there at once...
  await expect(dialog.locator("#nf-nick")).toHaveValue("visual-test");
  await expect(dialog.getByRole("button", { name: "Save" })).toBeDisabled();
  // ...and what the person types over it survives the catalog arriving.
  await dialog.locator("#nf-nick").fill("ada");
  release();
  await expect(dialog.getByRole("button", { name: "Save" })).toBeEnabled();
  await expect(dialog.locator("#nf-nick")).toHaveValue("ada");
});

test("a refused network field is marked, revealed, and focused", async ({ page }) => {
  await mockSession(page, []);
  await page.route(/\/api\/v1\/me\/networks$/, (route) => {
    if (route.request().method() !== "POST") return route.fallback();
    return route.fulfill({
      status: 400,
      contentType: "application/problem+json",
      body: JSON.stringify({ status: 400, title: "Invalid upstream address", detail: "addr must be host:port", field: "addr" }),
    });
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Add a network", exact: true }).last().click();
  const dialog = page.getByRole("dialog", { name: "Add a network" });
  await expect(dialog.locator("#nf-addr")).toBeHidden();
  // The session's nickname is too long to double as a username; one that can
  // leaves the server's refusal as the only thing in the way. The dialog fills
  // the nickname in once its presets have loaded, so wait for that: typing
  // first would be overwritten by it.
  await expect(dialog.locator("#nf-nick")).toHaveValue("visual-test");
  await expect(dialog.getByRole("button", { name: "Save" })).toBeEnabled();
  await dialog.locator("#nf-nick").fill("visual");
  await dialog.getByRole("button", { name: "Save" }).click();

  // The server is under Advanced, so the refusal has to open it to point there.
  await expect(dialog.getByRole("alert")).toContainText("addr must be host:port");
  await expect(dialog.locator("#nf-addr")).toBeVisible();
  await expect(dialog.locator("#nf-addr")).toBeFocused();
  await expect(dialog.locator("#nf-addr")).toHaveAttribute("aria-invalid", "true");
  await expect(dialog.locator("#nf-nick")).not.toHaveAttribute("aria-invalid");
  await expectAccessible(page);
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

  // A blank username means the nickname, but "visual-test" is a character too
  // long to be one. It is not shortened to fit: the form asks, at the box.
  await expect(dialog.getByRole("alert")).toContainText("Enter a username");
  await expect(dialog.locator("#nf-username")).toBeFocused();
  await expect(dialog.locator("#nf-username")).toHaveAttribute("aria-invalid", "true");
  expect(created).toBeUndefined();
  await dialog.locator("#nf-username").fill("visual");
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
      username: "visual",
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

// ---- live socket: replay, refusals, and session expiry ----------------------

// The server names a ring position on every line and on the replay boundary;
// the client hands the last one back on its next attach. Positions here count
// from `first` so a mock can continue a ring across attaches.
const cursorAt = (position) => `9:${position}`;
const lineEvent = (line, position) => JSON.stringify({ t: "line", v: line, cursor: cursorAt(position) });
const snapshotEvent = (position) => JSON.stringify({ t: "snapshot", v: "complete", cursor: cursorAt(position) });
const attachReplay = (socket, lines, channels, first = 1) => {
  socket.send(JSON.stringify({ t: "status", v: "connected" }));
  lines.forEach((line, index) => socket.send(lineEvent(line, first + index)));
  socket.send(JSON.stringify({ t: "session", nick: "viewer", channels }));
  socket.send(snapshotEvent(first + lines.length - 1));
};

test("a reconnect resumes from the last cursor, so every line shows once", async ({ page }) => {
  const ring = [
    ":viewer!u@h JOIN #only",
    ":bob!u@h JOIN #only",
    ":bob!u@h PRIVMSG #only :same words",
    ":bob!u@h PRIVMSG #only :same words",
  ];
  const attachUrls = [];
  await page.routeWebSocket(/\/ws\/ui/, (socket) => {
    attachUrls.push(socket.url());
    if (attachUrls.length === 1) {
      attachReplay(socket, ring, ["#only"]);
      socket.onMessage((frame) => {
        const request = JSON.parse(frame);
        if (request.message.startsWith("/raw NAMES")) return;
        // The bouncer acknowledges the send and buffers its own echo at ring
        // position 5, which this socket is never sent; the live reply takes 6.
        socket.send(JSON.stringify({ t: "sent", v: request.id }));
        socket.send(lineEvent(":bob!u@h PRIVMSG #only :live reply", 6));
        // Then the link drops.
        setTimeout(() => socket.close(), 50);
      });
      return;
    }
    // The client returns with the last cursor it saw; only what came after it
    // is replayed.
    attachReplay(socket, [":bob!u@h PRIVMSG #only :after the drop"], ["#only"], 7);
  });
  await mockSession(page, [ircNetwork("Libera")]);
  await page.goto("/?network=Libera");

  const messages = page.getByLabel("Messages");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("#only");
  await expect(messages.locator(".line-msg")).toHaveCount(2);
  await page.getByRole("textbox", { name: "Message" }).fill("hello from here");
  await page.getByRole("textbox", { name: "Message" }).press("Enter");
  await expect(messages.locator(".line-msg")).toHaveCount(4);
  await expect(page.locator("#status")).toContainText("Libera: connected", { timeout: 15_000 });
  await expect.poll(() => attachUrls.length).toBe(2);
  expect(attachUrls[0]).not.toContain("after=");
  expect(attachUrls[1]).toContain(`after=${encodeURIComponent(cursorAt(6))}`);

  // Two identical bodies, our own send, the live reply, and the new line: each once.
  await expect(messages.locator(".line-msg")).toHaveCount(5);
  await expect(messages.locator(".line-msg", { hasText: "same words" })).toHaveCount(2);
  await expect(messages.locator(".line-msg", { hasText: "hello from here" })).toHaveCount(1);
  await expect(messages.locator(".line-msg", { hasText: "live reply" })).toHaveCount(1);
  await expect(messages.locator(".line-msg", { hasText: "after the drop" })).toHaveCount(1);
  await expect(messages.locator(".line-event", { hasText: "bob joined" })).toHaveCount(1);
  await expect(page.locator("#buffers").getByRole("button", { name: /^Open server/ })).toBeVisible();
  await page.locator("#buffers").getByRole("button", { name: /^Open server/ }).click();
  await expect(messages.getByText("history reloaded")).toHaveCount(0);
});

test("a cursor the server cannot honour reloads the transcript once", async ({ page }) => {
  const ring = [
    ":viewer!u@h JOIN #only",
    ":bob!u@h PRIVMSG #only :same words",
    ":bob!u@h PRIVMSG #only :same words",
  ];
  let attaches = 0;
  await page.routeWebSocket(/\/ws\/ui/, (socket) => {
    attaches += 1;
    if (attaches === 1) {
      attachReplay(socket, ring, ["#only"]);
      setTimeout(() => socket.close(), 200);
      return;
    }
    // The server restarted: the cursor names a ring that no longer exists, so
    // it says the replay is the whole ring and the page starts over.
    socket.send(JSON.stringify({ t: "status", v: "connected" }));
    socket.send(JSON.stringify({ t: "replay", v: "full" }));
    ring.forEach((line, index) => socket.send(JSON.stringify({ t: "line", v: line, cursor: `10:${index + 1}` })));
    socket.send(JSON.stringify({ t: "session", nick: "viewer", channels: ["#only"] }));
    socket.send(JSON.stringify({ t: "snapshot", v: "complete", cursor: `10:${ring.length}` }));
  });
  await mockSession(page, [ircNetwork("Libera")]);
  await page.goto("/?network=Libera");

  const messages = page.getByLabel("Messages");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("#only");
  await expect(messages.locator(".line-msg")).toHaveCount(2);
  await expect.poll(() => attaches, { timeout: 15_000 }).toBe(2);
  await expect(page.locator("#status")).toContainText("Libera: connected", { timeout: 15_000 });
  // The ring was replayed twice; it shows once.
  await expect(messages.locator(".line-msg", { hasText: "same words" })).toHaveCount(2);
  await page.locator("#buffers").getByRole("button", { name: /^Open server/ }).click();
  await expect(messages.getByText(/history reloaded/)).toHaveCount(1);
});

test("a second refused send restores the second message, not the first", async ({ page }) => {
  await page.routeWebSocket(/\/ws\/ui/, (socket) => {
    attachReplay(socket, [":viewer!u@h JOIN #only"], ["#only"]);
    socket.onMessage((frame) => {
      const request = JSON.parse(frame);
      socket.send(JSON.stringify({ t: "send-error", v: request.id, message: "upstream busy" }));
    });
  });
  await mockSession(page, [ircNetwork("Libera")]);
  await page.goto("/?network=Libera");
  const composer = page.getByRole("textbox", { name: "Message" });
  await composer.fill("hello");
  await composer.press("Enter");
  const alert = page.locator('[data-alert="send"]');
  await expect(alert).toContainText("upstream busy");
  await composer.fill("world");
  await composer.press("Enter");
  await expect(alert).toContainText("upstream busy");
  await alert.getByRole("button", { name: "Restore message" }).click();
  await expect(composer).toHaveValue("world");
});

test("plain text into a past channel is refused and points at joining", async ({ page }) => {
  const requests = [];
  await page.routeWebSocket(/\/ws\/ui/, (socket) => {
    // The channel was joined once; the authoritative session no longer holds it.
    attachReplay(socket, [":viewer!u@h JOIN #old", ":bob!u@h PRIVMSG #old :earlier"], []);
    socket.onMessage((frame) => {
      const request = JSON.parse(frame);
      requests.push(request.message);
      if (request.message === "/join #old") socket.send(lineEvent(":viewer!u@h JOIN #old", 2));
      else socket.send(JSON.stringify({ t: "sent", v: request.id }));
    });
  });
  await mockSession(page, [ircNetwork("Libera")]);
  await page.goto("/?network=Libera");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("#old");
  await expect(page.getByRole("button", { name: /^Open #old, past channel/ })).toBeVisible();

  const composer = page.getByRole("textbox", { name: "Message" });
  await composer.fill("anyone there?");
  await composer.press("Enter");
  const alert = page.locator('[data-alert="send"]');
  await expect(alert).toContainText("not in #old");
  await expect(alert).toContainText("Join box");
  expect(requests).toEqual([]);
  await expect(composer).toHaveValue("anyone there?");
  await expect(page.getByLabel("Messages").locator(".line-msg", { hasText: "anyone there?" })).toHaveCount(0);

  // A slash command still goes through: it is how the channel is rejoined.
  await alert.getByRole("button", { name: "Join #old" }).click();
  await expect.poll(() => requests).toEqual(["/join #old"]);
  await expect(page.getByRole("button", { name: /^Open #old, past channel/ })).toHaveCount(0);
  await composer.press("Enter");
  await expect.poll(() => requests).toEqual(["/join #old", "anyone there?"]);
});

test("an expired session stops the socket retry loop and offers sign-in once", async ({ page }) => {
  let attempts = 0;
  await page.routeWebSocket(/\/ws\/ui/, (socket) => {
    attempts += 1;
    // What a refused upgrade looks like from the page: no frames, then closed.
    socket.close();
  });
  await mockSession(page, [ircNetwork("Libera")]);
  let identityReads = 0;
  await page.route(/\/api\/v1\/me$/, (route) => {
    identityReads += 1;
    if (identityReads === 1) return route.fallback();
    return route.fulfill({ status: 401, contentType: "application/problem+json", body: JSON.stringify({ status: 401, title: "Unauthorized" }) });
  });
  await page.goto("/?network=Libera");

  await expect(page.locator("#status")).toHaveText("signed out", { timeout: 10_000 });
  const alert = page.locator('[data-alert="session"]');
  await expect(alert).toContainText("Your session expired while trying to reconnect");
  await expect(alert.getByRole("link", { name: "Sign in" })).toHaveAttribute("href", "/login");
  await expect(page.locator('[data-alert="socket"]')).toHaveCount(0);
  const after = attempts;
  await page.waitForTimeout(3_000);
  expect(attempts).toBe(after);
  expect(after).toBe(1);
  await expectAccessible(page);
});

test("the sign-out link exists only once its CSRF-bearing URL is known", async ({ page }) => {
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  await mockSession(page, []);
  await page.route(/\/api\/v1\/me$/, async (route) => {
    await held;
    return route.fallback();
  });
  await page.goto("/");
  const signOut = page.locator("#logout-link");
  await expect(signOut).toBeHidden();
  await expect(signOut).not.toHaveAttribute("href");
  release();
  await expect(signOut).toBeVisible();
  await expect(signOut).toHaveAttribute("href", "/api/v1/auth/logout?csrf=session-bound-token");
});

test("the add-network dialog's catalog does not type over what was typed while it loaded", async ({ page }) => {
  await mockSession(page, []);
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  await page.route(/\/api\/v1\/network-presets$/, async (route) => {
    await held;
    return route.fallback();
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Add a network", exact: true }).last().click();
  const dialog = page.getByRole("dialog", { name: "Add a network" });
  await expect(dialog.locator("#nf-nick")).toBeFocused();
  await dialog.locator("#nf-advanced summary").click();
  await dialog.locator("#nf-addr").fill("irc.example.org:6667");
  await dialog.locator("#nf-tls").uncheck();
  await dialog.locator("#nf-sasl-password").focus();
  release();
  await expect(dialog.getByRole("button", { name: "Save" })).toBeEnabled();
  // The untouched name takes the preset; the typed server and TLS choice stay;
  // focus stays where the person put it.
  await expect(dialog.locator("#nf-name")).toHaveValue("libera");
  await expect(dialog.locator("#nf-addr")).toHaveValue("irc.example.org:6667");
  await expect(dialog.locator("#nf-tls")).not.toBeChecked();
  await expect(dialog.locator("#nf-sasl-password")).toBeFocused();
});

test("Remove clears and disables the credential boxes in the settings dialog", async ({ page }) => {
  await mockLiveSocket(page);
  await mockSession(page, [ircNetwork("Libera")]);
  await mockNetworkDetails(page, (route) => route.fulfill({
    contentType: "application/json",
    body: JSON.stringify({ ...networkDetail("Libera", "irc.libera.example:6697"), sasl_account: "ada", has_sasl_account: true, has_sasl_password: true }),
  }));
  await page.goto("/?network=Libera");
  await page.getByRole("button", { name: "Settings for Libera" }).click();
  const dialog = page.getByRole("dialog", { name: "Settings — Libera" });
  await expect(dialog.locator("#nf-sasl-account")).toHaveValue("ada");
  await dialog.locator("#nf-sasl-password").fill("typed");
  await dialog.locator("#nf-clear").check();
  await expect(dialog.locator("#nf-sasl-account")).toBeDisabled();
  await expect(dialog.locator("#nf-sasl-account")).toHaveValue("");
  await expect(dialog.locator("#nf-sasl-password")).toBeDisabled();
  await expect(dialog.locator("#nf-sasl-password")).toHaveValue("");
  await dialog.locator("#nf-clear").uncheck();
  await expect(dialog.locator("#nf-sasl-account")).toBeEnabled();
  await expect(dialog.locator("#nf-sasl-account")).toHaveValue("ada");

  // Emptying the stored account without Remove is refused at the box.
  await dialog.locator("#nf-sasl-account").fill("");
  await dialog.getByRole("button", { name: "Save" }).click();
  await expect(dialog.getByRole("alert")).toContainText("ada is still stored");
  await expect(dialog.locator("#nf-sasl-account")).toBeFocused();
  await expect(dialog.locator("#nf-sasl-account")).toHaveAttribute("aria-invalid", "true");
});

test("the server password sits under Advanced, is revealed on request, and is omitted on create when blank", async ({ page }) => {
  await mockSession(page, []);
  const bodies = [];
  await page.route(/\/api\/v1\/me\/networks$/, async (route) => {
    if (route.request().method() !== "POST") return route.fallback();
    bodies.push(route.request().postDataJSON());
    return route.fulfill({ status: 201, contentType: "application/json", body: JSON.stringify({ name: "libera", attach: "visual-test/libera" }) });
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Add a network", exact: true }).last().click();
  const dialog = page.getByRole("dialog", { name: "Add a network" });
  // Addressed by id: the label also carries its reveal button's text.
  const box = dialog.locator("#nf-server-password");
  await expect(box).toBeHidden();
  await dialog.getByText("Advanced").click();
  await expect(box).toBeVisible();
  await expect(box).toHaveAttribute("autocomplete", "new-password");
  await expect(dialog.getByText("Only for private servers that require one.")).toBeVisible();
  await expect(dialog.getByText("Remove the stored server password")).toBeHidden();
  await box.fill("open sesame");
  await dialog.getByRole("button", { name: "Show server password" }).click();
  await expect(box).toHaveAttribute("type", "text");
  await expect(dialog.getByRole("button", { name: "Hide server password" })).toHaveAttribute("aria-pressed", "true");
  await expectAccessible(page);
  await box.fill("");
  await dialog.locator("#nf-username").fill("visual");
  await dialog.getByRole("button", { name: "Save" }).click();
  await expect(page).toHaveURL(/\?network=libera$/);
  expect(bodies).toHaveLength(1);
  expect("server_password" in bodies[0]).toBe(false);
});

test("the settings dialog keeps, sets, or removes the server password only as asked", async ({ page }) => {
  await mockLiveSocket(page);
  await mockSession(page, [ircNetwork("Libera")]);
  const replaced = [];
  await mockNetworkDetails(page, (route) => {
    if (route.request().method() === "PUT") {
      replaced.push(route.request().postDataJSON().server_password);
      return route.fulfill({ status: 204 });
    }
    return route.fulfill({
      contentType: "application/json",
      body: JSON.stringify({ ...networkDetail("Libera", "irc.libera.example:6697"), has_server_password: true }),
    });
  });
  await page.goto("/?network=Libera");
  const open = async () => {
    await page.getByRole("button", { name: "Settings for Libera" }).click();
    const dialog = page.getByRole("dialog", { name: "Settings — Libera" });
    await expect(dialog.locator("#nf-nick")).toHaveValue("Libera-nick");
    await dialog.getByText("Advanced").click();
    return dialog;
  };
  const save = async (dialog, count) => {
    await dialog.getByRole("button", { name: "Save" }).click();
    await expect.poll(() => replaced.length).toBe(count);
    await expect(dialog).toBeHidden();
  };

  let dialog = await open();
  await expect(dialog.getByText("Leave blank to keep the stored one", { exact: false })).toBeVisible();
  await save(dialog, 1);
  expect(replaced[0]).toEqual({ action: "keep" });

  dialog = await open();
  await dialog.locator("#nf-server-password").fill("rotated");
  await save(dialog, 2);
  expect(replaced[1]).toEqual({ action: "set", password: "rotated" });

  dialog = await open();
  await dialog.locator("#nf-server-password").fill("typed");
  await dialog.getByText("Remove the stored server password").click();
  await expect(dialog.locator("#nf-server-password")).toBeDisabled();
  await expect(dialog.locator("#nf-server-password")).toHaveValue("");
  await expectAccessible(page);
  await save(dialog, 3);
  expect(replaced[2]).toEqual({ action: "remove" });
});

test("on a phone the member list opens from the buffer header", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.routeWebSocket(/\/ws\/ui/, (socket) => {
    attachReplay(socket, [":viewer!u@h JOIN #only"], ["#only"]);
    socket.onMessage((frame) => {
      const request = JSON.parse(frame);
      if (request.message !== "/raw NAMES #only") return;
      socket.send(lineEvent(":irc.example 353 viewer = #only :@carol viewer bob", 2));
      socket.send(lineEvent(":irc.example 366 viewer #only :End of /NAMES list", 3));
    });
  });
  await mockSession(page, [ircNetwork("Libera")]);
  await page.goto("/?network=Libera");
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("#only");

  const members = page.getByRole("button", { name: "Members (3)" });
  await expect(members).toBeVisible();
  await expect(members).toHaveAttribute("aria-expanded", "false");
  await expect(members).toHaveAttribute("aria-controls", "nicklist");
  const list = page.getByRole("complementary", { name: "Members" });
  await expect(list).toBeHidden();
  await members.click();
  await expect(members).toHaveAttribute("aria-expanded", "true");
  await expect(list).toBeVisible();
  await expect(list.getByRole("button", { name: "Open conversation with carol" })).toBeFocused();
  await expect.poll(() => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth)).toBe(true);
  await expectAccessible(page);
  await page.keyboard.press("Escape");
  await expect(list).toBeHidden();
  await expect(members).toBeFocused();

  // Opening a conversation from the list closes the panel, as the rail does.
  await members.click();
  await list.getByRole("button", { name: "Open conversation with bob" }).click();
  await expect(page.getByRole("heading", { level: 1 })).toHaveText("bob");
  await expect(members).toBeHidden();
  await expect(list).toBeHidden();
});
