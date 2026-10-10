import assert from "node:assert/strict";
import test from "node:test";

import { RECORD_VARIABLE, baselineDirectory, recordingBaselines } from "./visual-baselines.js";

test("a visual run records only when asked, and never in CI or on macOS", () => {
  assert.equal(recordingBaselines({}, "linux"), false, "a normal run compares");
  assert.equal(recordingBaselines({ [RECORD_VARIABLE]: "yes" }, "linux"), false, "only 1 asks");
  assert.equal(recordingBaselines({ [RECORD_VARIABLE]: "1" }, "linux"), true);
  assert.throws(
    () => recordingBaselines({ [RECORD_VARIABLE]: "1", CI: "true" }, "linux"),
    /refused in CI/,
  );
  assert.throws(() => recordingBaselines({ [RECORD_VARIABLE]: "1" }, "darwin"), /refused on macOS/);
  assert.equal(recordingBaselines({ CI: "true" }, "darwin"), false, "CI compares on macOS");
});

test("macOS compares with the committed baselines; every other platform with its own", () => {
  assert.equal(baselineDirectory("darwin"), "test/__snapshots__/visual.spec.js/");
  assert.equal(baselineDirectory("linux"), "test/__snapshots__/visual.spec.js/linux/");
});
