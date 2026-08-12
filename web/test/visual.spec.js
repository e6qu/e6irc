import playwrightTest from "playwright/test";
import AxeBuilder from "@axe-core/playwright";

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
                { type: "object", additionalProperties: false, required: ["state"], properties: { state: { type: "string" } } },
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

test("network picker renders the empty account state", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "light", reducedMotion: "reduce" });
  await page.setViewportSize({ width: 1280, height: 800 });
  await mockSession(page, []);
  await page.goto("/");

  await expect(page.getByText("No networks are configured for this account.")).toBeVisible();
  await expect(page.locator("ol#messages[aria-live=polite]")).toBeVisible();
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

  await expect(page.getByRole("link", { name: /Libera.*reconnecting/ })).toBeVisible();
  await expect(page.getByRole("link", { name: /Archive.*disabled/ })).toBeVisible();
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
