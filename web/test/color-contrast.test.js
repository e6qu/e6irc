// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

function luminance(hex) {
  const channels = hex.match(/[\da-f]{2}/gi).map((value) => Number.parseInt(value, 16) / 255);
  const linear = channels.map((value) => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
  return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
}

function ratio(a, b) {
  const [light, dark] = [luminance(a), luminance(b)].sort((left, right) => right - left);
  return (light + 0.05) / (dark + 0.05);
}

test("shared signal-room palette keeps text and actions above WCAG AA contrast", async () => {
  const [chat, console, identity] = await Promise.all([
    readFile(new URL("../src/style.css", import.meta.url), "utf8"),
    readFile(new URL("../../crates/e6ircd/templates/console_base.html", import.meta.url), "utf8"),
    readFile(new URL("../../crates/e6ircd/assets/auth.css", import.meta.url), "utf8"),
  ]);
  for (const stylesheet of [chat, console, identity]) {
    assert.match(stylesheet, /#075985/);
    assert.match(stylesheet, /#17212b/);
  }
  for (const [foreground, background] of [
    ["#17212b", "#ffffff"],
    ["#475569", "#ffffff"],
    ["#ffffff", "#075985"],
    ["#eef6fa", "#111d26"],
    ["#b7c6d2", "#111d26"],
    ["#082f49", "#7dd3fc"],
  ]) {
    assert.ok(ratio(foreground, background) >= 4.5, `${foreground} on ${background} is below 4.5:1`);
  }
});
