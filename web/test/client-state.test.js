// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import test from "node:test";

import {
  ApiError,
  DEFAULT_SETTINGS,
  SETTINGS_KEY,
  backlogFrom,
  errorMessage,
  identityFrom,
  loadSettings,
  networkStateHelp,
  networkStateIsFailure,
  networksFrom,
  networkStateLabel,
  saveSettings,
} from "../src/client-state.js";
import { loadSettings as loadSharedSettings, saveSettings as saveSharedSettings } from "../src/settings.js";

function storage(value, failure = null) {
  return {
    getItem(key) {
      assert.equal(key, SETTINGS_KEY);
      if (failure === "read") throw new Error("denied");
      return value;
    },
    setItem(key, next) {
      assert.equal(key, SETTINGS_KEY);
      if (failure === "write") throw new Error("quota");
      value = next;
    },
  };
}

test("settings use typed defaults and preserve valid preferences", () => {
  assert.deepEqual(loadSettings(storage(null)), {
    settings: DEFAULT_SETTINGS,
    warning: null,
  });
  assert.deepEqual(loadSettings(storage('{"theme":"dark","notifications":true,"rawOutput":true}')), {
    settings: { theme: "dark", notifications: true, rawOutput: true },
    warning: null,
  });
});

test("settings corruption and unsupported values are surfaced and repaired", () => {
  const corrupt = loadSettings(storage("{"));
  assert.deepEqual(corrupt.settings, DEFAULT_SETTINGS);
  assert.match(corrupt.warning, /unreadable/);

  const unsupported = loadSettings(storage('{"theme":"neon","notifications":"yes"}'));
  assert.deepEqual(unsupported.settings, DEFAULT_SETTINGS);
  assert.match(unsupported.warning, /unsupported/);

  const unknown = loadSettings(storage('{"theme":"light","surprise":true}'));
  assert.deepEqual(unknown.settings, { theme: "light", notifications: false, rawOutput: false });
  assert.match(unknown.warning, /unsupported/);
});

test("console and chat share the same preference boundary", () => {
  const malformed = storage('{"theme":"neon"}');
  assert.deepEqual(loadSharedSettings(malformed), loadSettings(malformed));

  let stored = null;
  const sharedStorage = {
    getItem() { return stored; },
    setItem(_key, value) { stored = value; },
  };
  assert.equal(saveSharedSettings(sharedStorage, { theme: "dark", notifications: true, rawOutput: true }), null);
  assert.deepEqual(loadSettings(sharedStorage), {
    settings: { theme: "dark", notifications: true, rawOutput: true },
    warning: null,
  });
});

test("storage denial is explicit on read and write", () => {
  const denied = loadSettings(storage(null, "read"));
  assert.deepEqual(denied.settings, DEFAULT_SETTINGS);
  assert.match(denied.warning, /unavailable/);
  assert.match(
    loadSettings(() => {
      throw new Error("storage getter denied");
    }).warning,
    /unavailable/,
  );

  assert.match(
    saveSettings(storage(null, "write"), { theme: "light", notifications: true }),
    /rejected/,
  );
});

test("network projection preserves the closed API state", () => {
  assert.deepEqual(networksFrom({ networks: [] }), []);
  const offline = { name: "Libera", kind: "irc", nick: "alice", enabled: true, connected: null, runtime: null };
  assert.deepEqual(networksFrom({ networks: [offline] }), [
    { name: "Libera", kind: "irc", nick: "alice", enabled: true, connected: null, state: null, failureCode: null, runtime: null },
  ]);
  assert.deepEqual(
    networksFrom({ networks: [{ ...offline, connected: false, runtime: {
      state: "registration_failed",
      last_error: { code: "registration_rejected" },
    } }] }),
    [{
      name: "Libera",
      kind: "irc",
      nick: "alice",
      enabled: true,
      connected: false,
      state: "registration_failed",
      failureCode: "registration_rejected",
      runtime: { state: "registration_failed", failureCode: "registration_rejected" },
    }],
  );
});

test("backlog projection preserves contract lines", () => {
  assert.deepEqual(backlogFrom({ lines: [":a PRIVMSG #chat :hello"] }), [":a PRIVMSG #chat :hello"]);
});

test("identity projection keeps browser-visible fields", () => {
  assert.deepEqual(identityFrom({ account: "alice", email: "a@example.test", role: "operator", logout_url: "/logout" }), {
    account: "alice",
    email: "a@example.test",
    role: "operator",
    logoutURL: "/logout",
  });
});

test("network labels use the API's typed runtime state", () => {
  assert.equal(networkStateLabel({ enabled: false }), "disabled");
  assert.equal(networkStateLabel({ enabled: true, connected: true }), "connected");
  assert.equal(
    networkStateLabel({
      enabled: true,
      connected: false,
      state: "reconnecting",
    }),
    "reconnecting",
  );
  assert.equal(networkStateLabel({ enabled: true, connected: null, state: null }), "starting");
});

test("API error messages distinguish expired sessions", () => {
  assert.equal(
    errorMessage("load your networks", new ApiError(401, "Unauthorized")),
    "Your session expired while trying to load your networks. Sign in again.",
  );
  assert.equal(
    errorMessage("load your networks", new Error("offline")),
    "Could not load your networks. offline.",
  );
});

// A parked driver stops re-dialling on purpose, so whatever the sidebar says is
// what the person sees indefinitely. The lifecycle says it stopped; the latest
// typed error says why. Both are required to choose the useful repair.
test("rejected credentials explain the repair from the real lifecycle and error pairing", () => {
  const help = networkStateHelp({
    state: "authentication_failed",
    failureCode: "authentication_rejected",
  });
  assert.match(help, /NickServ account or password/);
  assert.match(help, /settings/);
  assert.equal(networkStateIsFailure({ state: "authentication_failed" }), true);
});

test("a refused registration directs verified-account failures to log and settings", () => {
  const help = networkStateHelp({
    state: "registration_failed",
    failureCode: "registration_rejected",
  });
  assert.match(help, /Server log/);
  assert.match(help, /verified SASL/);
  assert.equal(networkStateIsFailure({ state: "registration_failed" }), true);
});

test("parked lifecycle states remain actionable without a last-error detail", () => {
  assert.match(
    networkStateHelp({ state: "authentication_failed", failureCode: null }),
    /replace or remove/,
  );
  assert.match(
    networkStateHelp({ state: "registration_failed", failureCode: null }),
    /upstream reason/,
  );
});

test("states that are merely progress carry no advice and are not failures", () => {
  for (const state of ["connecting", "registering", null, undefined]) {
    assert.equal(networkStateHelp({ state }), null, `${state} should not advise`);
    assert.equal(networkStateIsFailure({ state }), false, `${state} is not a failure`);
  }
});

test("a disabled network says so rather than reporting a driver state", () => {
  assert.equal(networkStateHelp({ enabled: false, state: "authentication_failed" }), "This network is turned off.");
});
