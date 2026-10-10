import playwrightTest from "playwright/test";
import { baselineDirectory, recordingBaselines } from "./test/visual-baselines.js";

const { defineConfig, devices } = playwrightTest;

// The committed baselines are macOS renders; elsewhere the screenshots live
// in a platform directory of their own, ignored by git, so `--update-snapshots`
// there can never overwrite the baselines CI holds (test/visual-baselines.js).
const snapshots =
  process.platform === "darwin"
    ? "{testDir}/__snapshots__/{testFilePath}/{arg}{ext}"
    : "{testDir}/__snapshots__/{testFilePath}/{platform}/{arg}{ext}";

// A normal run compares and never writes: Playwright's default would write a
// missing baseline (and fail that once), so the next run passed against a
// render nobody looked at. Only the explicit record step writes.
const recording = recordingBaselines();
if (recording) {
  console.log(
    `visual suite: RECORDING ${process.platform} baselines into web/${baselineDirectory()}: ` +
      "this run compares nothing. Run `pnpm -C web test:visual` to compare against them.",
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
  updateSnapshots: recording ? "all" : "none",
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
