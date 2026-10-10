// Where the visual suite's screenshot baselines come from, and the one way a
// platform's baselines are recorded. Read by the Playwright configuration and
// by the suite, so the two cannot disagree.
//
// The committed baselines are macOS renders (CI's visual-regression job runs
// on macos-15), and font rasterization differs by platform. Elsewhere the
// screenshots live in a platform directory of their own, ignored by git. A
// normal run never records: a missing baseline fails, naming the directory and
// the command below, because a run that records instead of comparing passes
// without testing anything — and every fresh checkout would be one.

export const RECORD_VARIABLE = "E6IRC_VISUAL_RECORD";
export const RECORD_COMMAND = "pnpm -C web test:visual:record";

/// Whether this run records the platform's baselines instead of comparing.
/// Refused in CI, where a recording run would pass whatever it rendered, and
/// on macOS, whose baselines are the committed ones (`--update-snapshots`
/// changes those, deliberately and reviewed).
export function recordingBaselines(environment = process.env, platform = process.platform) {
  if (environment[RECORD_VARIABLE] !== "1") return false;
  if (environment.CI) {
    throw new Error(
      `visual suite: ${RECORD_VARIABLE}=1 is refused in CI: a run that records baselines ` +
        "compares nothing and would pass whatever it rendered",
    );
  }
  if (platform === "darwin") {
    throw new Error(
      `visual suite: ${RECORD_VARIABLE}=1 is refused on macOS, whose baselines are the ` +
        "committed ones; change those with --update-snapshots and review the diff",
    );
  }
  return true;
}

/// Where a platform's baselines are, relative to the test directory.
export function baselineDirectory(platform = process.platform) {
  return platform === "darwin"
    ? "test/__snapshots__/visual.spec.js/"
    : `test/__snapshots__/visual.spec.js/${platform}/`;
}
