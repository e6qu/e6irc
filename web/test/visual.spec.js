import playwrightTest from "playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { readFile } from "node:fs/promises";

const { expect, test } = playwrightTest;

const identity = { account: "visual-test", email: "visual@example.test", role: "operator" };
const response = (schema) => ({ content: { "application/json": { schema } } });
const apiContract = {
  paths: {
    "/api/v1/me": {
      get: { responses: { 200: response({
        type: "object", additionalProperties: false, required: ["account"], properties: {
          account: { type: "string", minLength: 1 }, email: { type: ["string", "null"] },
          role: { type: ["string", "null"] }, logout_url: { type: "string" },
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
                      code: { type: "string" },
                    } },
                  ] },
                } },
              ] },
            },
          } },
        },
      }) } },
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
  await page.route(/\/api\/v1\/me\/networks$/, (route) => {
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
      export const getOperationJson = async (_fetch, _contract, _method, url) => {
        window.consoleApiRequests ??= [];
        window.consoleApiRequests.push(url);
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

test("network picker renders typed network states on tablets", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "light", reducedMotion: "reduce" });
  await page.setViewportSize({ width: 768, height: 1024 });
  await mockSession(page, [
    {
      name: "Libera",
      kind: "irc",
      nick: "viewer",
      enabled: true,
      connected: false,
      runtime: { state: "reconnecting" },
    },
    { name: "Archive", kind: "irc", nick: "viewer", enabled: false, connected: null, runtime: null },
  ]);
  await page.goto("/");

  // Networks now appear twice on purpose -- the picker in the message area and
  // the sidebar list that carries each network's settings control -- so these
  // assertions name which one they mean rather than matching whichever comes
  // first.
  const picker = page.getByLabel("Messages");
  await expect(picker.getByRole("link", { name: /Libera.*reconnecting/ })).toHaveAttribute("data-state", "reconnecting");
  await expect(picker.getByText("Archive", { exact: true })).toBeVisible();
  await expect(picker.getByRole("link", { name: /Archive.*disabled/ })).toHaveCount(0);
  // A disabled network is reachable in neither list.
  await expect(page.getByRole("link", { name: "Open Archive" })).toHaveCount(1);
  await expect(page.getByRole("button", { name: "Settings for Libera" })).toBeVisible();
  await expect(page.getByLabel("Active network").locator('option[value="Archive"]')).toHaveAttribute("disabled", "");
  await expectAccessible(page);
  await expect(page).toHaveScreenshot("network-picker-tablet.png", {
    animations: "disabled",
    fullPage: true,
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
  await page.goto("/");

  await expect(page.getByRole("link", { name: /Libera.*reconnecting/ })).toBeVisible();
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
