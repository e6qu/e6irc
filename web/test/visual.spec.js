import playwrightTest from "playwright/test";
import AxeBuilder from "@axe-core/playwright";

const { expect, test } = playwrightTest;

const identity = { account: "visual-test", email: "visual@example.test", role: "operator" };

async function expectAccessible(page) {
  const results = await new AxeBuilder({ page }).include("#app").analyze();
  expect(results.violations, results.violations.map(({ id, help }) => `${id}: ${help}`).join("\n")).toEqual([]);
}

async function mockSession(page, networks, failureStatus = 503, identityPayload = identity) {
  await page.route(/\/api\/v1\/me$/, (route) =>
    route.fulfill({ contentType: "application/json", body: JSON.stringify(identityPayload) }),
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
  await expectAccessible(page);
  await expect(page).toHaveScreenshot("network-picker-empty-light.png", {
    animations: "disabled",
    fullPage: true,
  });
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
      enabled: true,
      connected: false,
      runtime: { state: "reconnecting" },
    },
    { name: "Archive", enabled: false, connected: null, runtime: null },
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

  await expect(page.getByRole("alert")).toContainText("Could not load your networks");
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

  await expect(page.getByRole("alert")).toContainText("Could not load your networks");
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
