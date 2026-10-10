import { existsSync } from "node:fs";
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

// A platform's first run has no renders of its own to compare with, and
// Playwright fails every screenshot test whose baseline is missing even while
// it writes one ("A snapshot doesn't exist … writing actual") — so a fresh
// checkout's first run failed each screenshot test once and the next passed,
// which read as flaky tests. When this platform's directory does not exist
// yet, the run records it and says so; from then on a missing or different
// render fails as it should. macOS always compares with the committed
// baselines.
const platformBaselines = new URL(
  `./test/__snapshots__/visual.spec.js/${process.platform}/`,
  import.meta.url,
);
const recordPlatformBaselines = process.platform !== "darwin" && !existsSync(platformBaselines);
if (recordPlatformBaselines) {
  console.log(
    `visual suite: no ${process.platform} screenshots yet; this run records them in ` +
      `${platformBaselines.pathname} and compares nothing. Run it again to compare.`,
  );
}

// The suite starts its own Vite server for this checkout, on a port nothing
// else holds (`--strictPort` refuses a busy one rather than moving). Reusing
// whatever already answered on the port tested another checkout's pages when
// two worktrees ran the suite at once, and passed or failed on code that was
// not the code under test. E6IRC_VISUAL_PORT picks another port.
const port = Number(process.env.E6IRC_VISUAL_PORT ?? 4173);

export default defineConfig({
  testDir: "./test",
  testMatch: "visual.spec.js",
  reporter: "list",
  snapshotPathTemplate: snapshots,
  updateSnapshots: recordPlatformBaselines ? "all" : "missing",
  use: {
    ...devices["Desktop Chrome"],
    baseURL: `http://127.0.0.1:${port}`,
    trace: "retain-on-failure",
    video: "retain-on-failure",
  },
  webServer: {
    command: `pnpm exec vite --host 127.0.0.1 --port ${port} --strictPort`,
    port,
    reuseExistingServer: false,
  },
});
