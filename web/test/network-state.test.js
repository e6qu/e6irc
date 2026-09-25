// SPDX-License-Identifier: AGPL-3.0-or-later
//
// main.js keeps the open network's state in module-level bindings. Opening
// another network, or leaving one, must start from none of it: a replay cursor
// carried across is sent to a network it never came from, and buffers, mode
// tables and pending joins carried across show the old network inside the new
// one. Both paths go through one resetNetworkState(); this test holds every
// piece of mutable page state to either being reset there or being named here
// as belonging to the page rather than to a network -- so a binding added later
// cannot be forgotten silently.

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

const source = await readFile(new URL("../src/main.js", import.meta.url), "utf8");

// Mutable state that outlives a network, and why.
const PAGE_STATE = new Map([
  ["network", "the caller sets it to the network being opened, or null"],
  ["reportedAlerts", "alerts are the page's; each network path clears its own"],
  ["socket", "closed by stopLiveConnection, which the reset runs"],
  ["reconnectTimer", "cleared by stopLiveConnection, which the reset runs"],
  ["terminalSocket", "set by stopLiveConnection, cleared by connect()"],
  ["nextSendId", "request ids only need to be unique for the page"],
  ["pendingSends", "rejected into input history by the reset"],
  ["sentHistory", "input history is the person's, and how a rejected send is retried"],
  ["historyIdx", "position in the person's input history"],
  ["historyDraft", "the person's unsent line"],
  ["networkPresets", "the add-network dialog's presets"],
  ["dialogOpening", "the add-network dialog's own sequencing"],
  ["networkListTimer", "the network list is the page's, not one network's"],
  ["renderedNetworks", "the network list is the page's, not one network's"],
]);

function functionBody(name) {
  const start = source.indexOf(`function ${name}(`);
  assert.notEqual(start, -1, `main.js defines ${name}`);
  const open = source.indexOf("{", start);
  let depth = 0;
  for (let index = open; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") depth -= 1;
    if (depth === 0) return source.slice(open, index + 1);
  }
  throw new Error(`${name} is not closed`);
}

function topLevelState() {
  const names = [];
  for (const match of source.matchAll(/^(let|const) (\w+) = (.*)$/gm)) {
    const [, keyword, name, value] = match;
    if (keyword === "let" || /^(new (Map|Set)\(|\[\])/.test(value)) names.push(name);
  }
  return names;
}

test("every piece of network state is reset, or named as the page's", () => {
  const reset = functionBody("resetNetworkState");
  const state = topLevelState();
  assert.ok(state.includes("replayCursor") && state.includes("buffers"), state.join(", "));
  for (const name of state) {
    // Reset means assigned or cleared, not merely mentioned.
    const resetHere = new RegExp(`(^|[^.\\w])${name}(\\s*=[^=]|\\.clear\\(\\))`, "m").test(reset);
    assert.ok(
      resetHere !== PAGE_STATE.has(name),
      resetHere
        ? `${name} is reset by resetNetworkState and also listed as page state`
        : `${name} is neither reset by resetNetworkState nor listed as page state`,
    );
  }
  for (const name of PAGE_STATE.keys()) {
    assert.ok(state.includes(name), `${name} is listed as page state but main.js no longer has it`);
  }
  assert.match(reset, /stopLiveConnection\(\)/);
  assert.match(reset, /rejectAllPendingSends\(/);
});

test("adding a network and leaving one both reset the network state", () => {
  assert.match(functionBody("leaveOpenNetwork"), /resetNetworkState\(\);[\s\S]*network = null/);
  const added = source.slice(source.indexOf("if (!editing) {"));
  assert.match(
    added.slice(0, added.indexOf("openChosenNetwork(")),
    /resetNetworkState\(\);\s*network = name;/,
    "the add path resets before it names the new network",
  );
});

test("topic and NAMES replies never open a conversation", () => {
  for (const name of ["setTopic", "addNick"]) {
    assert.doesNotMatch(functionBody(name), /ensureBuffer\(/, name);
  }
  const names = source.slice(source.indexOf('case "353": {'), source.indexOf('case "366": {'));
  assert.doesNotMatch(names, /ensureBuffer\(/);
  assert.match(names, /existingChannelBuffer\(buffers, chan, ircNames\)/);
});

test("the network's CASEMAPPING and CHANTYPES are adopted from the session and from 005", () => {
  const session = source.slice(source.indexOf("function applySessionSnapshot("), source.indexOf("function adoptNames("));
  assert.match(session, /adoptNames\(namesFromIsupport\(isupport\)/);
  const isupport = source.slice(source.indexOf('case "005": {'), source.indexOf('case "MODE": {'));
  assert.match(isupport, /adoptNames\(namesFrom\(m\.params, ircNames\)\)/);
  // Every IRC name is keyed under the open network's rules; only e6irc's own
  // network names compare under the fixed default.
  assert.match(source, /^const fold = \(name\) => foldUnder\(name, ircNames\);$/m);
  assert.doesNotMatch(source, /[^.\w]fold\(network\)|fold\(item\.name\)/);
});
