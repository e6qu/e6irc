import playwrightTest from "playwright/test";

const { defineConfig, devices } = playwrightTest;

// The committed baselines are macOS renders (CI's visual-regression job runs
// on macos-15), and font rasterization differs by platform. Elsewhere the
// screenshots live under a platform directory of their own (ignored by git):
// a Linux run compares against Linux renders, and `--update-snapshots` there
// can never overwrite the baselines CI holds.
const snapshots =
  process.platform === "darwin"
    ? "{testDir}/__snapshots__/{testFilePath}/{arg}{ext}"
    : "{testDir}/__snapshots__/{testFilePath}/{platform}/{arg}{ext}";

export default defineConfig({
  testDir: "./test",
  testMatch: "visual.spec.js",
  reporter: "list",
  snapshotPathTemplate: snapshots,
  use: {
    ...devices["Desktop Chrome"],
    baseURL: "http://127.0.0.1:4173",
    trace: "retain-on-failure",
    video: "retain-on-failure",
  },
  webServer: {
    command: "pnpm exec vite --host 127.0.0.1 --port 4173",
    port: 4173,
    reuseExistingServer: !process.env.CI,
  },
});
