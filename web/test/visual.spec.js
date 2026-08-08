import playwrightTest from "playwright/test";

const { expect, test } = playwrightTest;

const identity = { account: "visual-test", email: "visual@example.test", role: "operator" };

async function mockSession(page, networks, failureStatus = 503) {
  await page.route(/\/api\/v1\/me$/, (route) =>
    route.fulfill({ contentType: "application/json", body: JSON.stringify(identity) }),
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
  await expect(page).toHaveScreenshot("network-picker-empty-light.png", {
    animations: "disabled",
    fullPage: true,
  });
});

test("network picker distinguishes an unavailable API on narrow dark screens", async ({ page }) => {
  await page.emulateMedia({ colorScheme: "dark", reducedMotion: "reduce" });
  await page.setViewportSize({ width: 390, height: 844 });
  await mockSession(page, new Error("Network service unavailable"));
  await page.goto("/");

  await expect(page.getByRole("alert")).toContainText("Could not load your networks");
  await expect(page.getByRole("link", { name: "Retry" })).toBeVisible();
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
});
