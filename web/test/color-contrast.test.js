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

test("shared relay-desk palette keeps text and actions above WCAG AA contrast", async () => {
  const [chat, console, identity] = await Promise.all([
    readFile(new URL("../src/style.css", import.meta.url), "utf8"),
    readFile(new URL("../../crates/e6ircd/templates/console_base.html", import.meta.url), "utf8"),
    readFile(new URL("../../crates/e6ircd/assets/auth.css", import.meta.url), "utf8"),
  ]);
  for (const stylesheet of [chat, console, identity]) {
    assert.match(stylesheet, /#006b70/);
    assert.match(stylesheet, /#182326/);
  }
  assert.doesNotMatch(identity, /rgb\(113 39 232/);
  for (const [foreground, background] of [
    ["#182326", "#fbfcfa"],
    ["#516266", "#fbfcfa"],
    ["#516266", "#e1e9e8"],
    ["#ffffff", "#006b70"],
    ["#995100", "#fbfcfa"],
    ["#f0f5f3", "#152125"],
    ["#b3c0c1", "#152125"],
    ["#082f32", "#73d7d0"],
    ["#ffffff", "#a45d00"],
    ["#2b1b00", "#f2b84b"],
  ]) {
    assert.ok(ratio(foreground, background) >= 4.5, `${foreground} on ${background} is below 4.5:1`);
  }
});
