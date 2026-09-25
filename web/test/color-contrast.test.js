// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

function luminance(hex) {
  const channels = expand(hex).match(/[\da-f]{2}/gi).map((value) => Number.parseInt(value, 16) / 255);
  const linear = channels.map((value) => value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4);
  return 0.2126 * linear[0] + 0.7152 * linear[1] + 0.0722 * linear[2];
}

// `#fff` is `#ffffff`.
function expand(hex) {
  return hex.length === 4 ? `#${[...hex.slice(1)].map((digit) => digit + digit).join("")}` : hex;
}

function ratio(a, b) {
  const [light, dark] = [luminance(a), luminance(b)].sort((left, right) => right - left);
  return (light + 0.05) / (dark + 0.05);
}

// The `--name: #hex` tokens declared directly in the block that opens at
// `start` (the index of its `{`).
function tokens(stylesheet, start) {
  let depth = 0;
  let end = start;
  for (; end < stylesheet.length; end += 1) {
    if (stylesheet[end] === "{") depth += 1;
    if (stylesheet[end] === "}" && (depth -= 1) === 0) break;
  }
  const block = stylesheet.slice(start + 1, end);
  return Object.fromEntries(
    [...block.matchAll(/--([a-z-]+):\s*(#[\da-f]{6}|#[\da-f]{3})\b/gi)].map(([, name, hex]) => [name, hex.toLowerCase()]),
  );
}

// The palette a stylesheet declares: its light `:root` tokens, and the dark
// scheme those become under `prefers-color-scheme: dark`. A stylesheet with
// an explicit `[data-theme="dark"]` block must declare the same dark tokens
// there, or the theme switch and the system setting show different colours.
function palette(stylesheet, name) {
  const light = tokens(stylesheet, stylesheet.indexOf("{", stylesheet.search(/^:root\s*\{/m)));
  const media = stylesheet.search(/@media \(prefers-color-scheme: dark\)/);
  assert.ok(media >= 0, `${name} has no dark scheme`);
  const mediaRoot = stylesheet.indexOf(":root", media);
  const dark = { ...light, ...tokens(stylesheet, stylesheet.indexOf("{", mediaRoot)) };
  const explicit = stylesheet.search(/:root\[data-theme="dark"\]\s*\{/);
  if (explicit >= 0) {
    assert.deepEqual(
      { ...light, ...tokens(stylesheet, stylesheet.indexOf("{", explicit)) },
      dark,
      `${name}: [data-theme="dark"] and prefers-color-scheme: dark disagree`,
    );
  }
  return { light, dark };
}

// Foreground token on background token, wherever a stylesheet declares both.
const TEXT_PAIRS = [
  ["fg", "bg"], ["fg", "panel"], ["fg", "panel-subtle"],
  ["muted", "bg"], ["muted", "panel"], ["muted", "panel-subtle"],
  ["accent", "panel"], ["accent-text", "accent"], ["warn-text", "warn"],
  ["route", "panel"], ["ok", "panel"], ["off", "panel"], ["info", "panel"], ["violet", "panel"],
  ["chrome-fg", "chrome"], ["chrome-fg", "chrome-raised"], ["chrome-muted", "chrome"],
  ["chrome-danger", "chrome"], ["chrome-ok", "chrome"],
  ["text", "page"], ["text", "surface"], ["muted", "surface"],
  ["accent", "surface"], ["signal", "surface"], ["route", "surface"],
];

test("every stylesheet's text and action tokens keep WCAG AA contrast in both schemes", async () => {
  const sheets = {
    "web/src/style.css": await readFile(new URL("../src/style.css", import.meta.url), "utf8"),
    "assets/console.css": await readFile(new URL("../../crates/e6ircd/assets/console.css", import.meta.url), "utf8"),
    "assets/auth.css": await readFile(new URL("../../crates/e6ircd/assets/auth.css", import.meta.url), "utf8"),
  };
  let checked = 0;
  for (const [name, stylesheet] of Object.entries(sheets)) {
    for (const [scheme, colours] of Object.entries(palette(stylesheet, name))) {
      for (const [foreground, background] of TEXT_PAIRS) {
        if (!(foreground in colours && background in colours)) continue;
        const contrast = ratio(colours[foreground], colours[background]);
        assert.ok(
          contrast >= 4.5,
          `${name} ${scheme}: --${foreground} ${colours[foreground]} on --${background} ${colours[background]} is ${contrast.toFixed(2)}:1, below 4.5:1`,
        );
        checked += 1;
      }
    }
  }
  // Every stylesheet was read: a token renamed out from under the pairs
  // would otherwise check nothing and pass.
  assert.ok(checked >= 60, `only ${checked} pairs were checked`);
});

test("the three surfaces share one relay-desk palette", async () => {
  const [chat, console, identity] = await Promise.all([
    readFile(new URL("../src/style.css", import.meta.url), "utf8"),
    readFile(new URL("../../crates/e6ircd/assets/console.css", import.meta.url), "utf8"),
    readFile(new URL("../../crates/e6ircd/assets/auth.css", import.meta.url), "utf8"),
  ]);
  const chatPalette = palette(chat, "chat");
  const consolePalette = palette(console, "console");
  const identityPalette = palette(identity, "identity");
  for (const scheme of ["light", "dark"]) {
    for (const token of ["muted", "accent", "route", "chrome"]) {
      assert.equal(consolePalette[scheme][token], chatPalette[scheme][token], `${scheme} --${token}`);
      assert.equal(identityPalette[scheme][token], chatPalette[scheme][token], `${scheme} --${token}`);
    }
    assert.equal(identityPalette[scheme].text, chatPalette[scheme].fg, `${scheme} text`);
    assert.equal(identityPalette[scheme].surface, chatPalette[scheme].panel, `${scheme} surface`);
  }
  assert.doesNotMatch(identity, /rgb\(113 39 232/);
});
