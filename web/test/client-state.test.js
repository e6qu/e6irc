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
  saveSetting,
} from "../src/client-state.js";
import { loadSettings as loadSharedSettings, saveSetting as saveSharedSetting } from "../src/settings.js";

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
  assert.deepEqual(loadSettings(storage('{"theme":"dark","notifications":true}')), {
    settings: { theme: "dark", notifications: true },
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
  assert.deepEqual(unknown.settings, { theme: "light", notifications: false });
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
  // The chat turns notifications on; an already-open console tab, whose own
  // snapshot predates that, then changes the theme. Each writes only what it
  // changed, so neither undoes the other.
  assert.equal(saveSharedSetting(sharedStorage, "notifications", true), null);
  assert.equal(saveSetting(sharedStorage, "theme", "dark"), null);
  assert.deepEqual(loadSettings(sharedStorage), {
    settings: { theme: "dark", notifications: true },
    warning: null,
  });
  assert.throws(() => saveSetting(sharedStorage, "colour", "red"), TypeError);
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
    saveSetting(storage(null, "write"), "theme", "light"),
    /rejected/,
  );
});

test("network projection preserves the closed API state", () => {
  assert.deepEqual(networksFrom({ networks: [] }), []);
  const offline = { name: "Libera", kind: "irc", nick: "alice", enabled: true, connected: null, runtime: null };
  assert.deepEqual(networksFrom({ networks: [offline] }), [
    { name: "Libera", kind: "irc", nick: "alice", enabled: true, connected: null, state: null, failureCode: null, failureDetail: null, runtime: null },
  ]);
  assert.deepEqual(
    networksFrom({ networks: [{ ...offline, connected: false, runtime: {
      state: "registration_failed",
      last_error: { code: "registration_rejected", diagnostic: "Closing Link: (SASL access only)" },
    } }] }),
    [{
      name: "Libera",
      kind: "irc",
      nick: "alice",
      enabled: true,
      connected: false,
      state: "registration_failed",
      failureCode: "registration_rejected",
      failureDetail: "Closing Link: (SASL access only)",
      runtime: { state: "registration_failed", failureCode: "registration_rejected" },
    }],
  );
});

test("backlog projection preserves contract lines", () => {
  assert.deepEqual(backlogFrom({ lines: [":a PRIVMSG #chat :hello"] }), [":a PRIVMSG #chat :hello"]);
});

test("identity projection keeps browser-visible fields", () => {
  assert.deepEqual(identityFrom({ account: "alice", email: "a@example.test", role: "operator", logout_url: "/logout", csrf_token: "session-bound" }), {
    account: "alice",
    email: "a@example.test",
    role: "operator",
    logoutURL: "/logout",
    csrfToken: "session-bound",
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
    /Open Server log for its reason/,
  );
});

test("states that are merely progress carry no advice and are not failures", () => {
  for (const state of ["connecting", "registering", null, undefined]) {
    assert.equal(networkStateHelp({ state }), null, `${state} should not advise`);
    assert.equal(networkStateIsFailure({ state }), false, `${state} is not a failure`);
  }
});

test("a disabled network says so rather than reporting a driver state", () => {
  assert.equal(networkStateHelp({ enabled: false, state: "authentication_failed" }), "This network is disabled.");
});

// The upstream's own sentence is the most useful thing the row can show: it is
// the difference between "registration rejected" and "SASL access only".
test("a refusal quotes the network's own reason, while retrying as well as once parked", () => {
  for (const state of ["reconnecting", "registration_failed"]) {
    assert.match(
      networkStateHelp({
        state,
        failureCode: "registration_rejected",
        failureDetail: "Closing Link: (SASL access only)",
      }),
      /verified SASL.*The network said: “Closing Link: \(SASL access only\)”$/,
    );
  }
  assert.match(
    networkStateHelp({ state: "reconnecting", failureCode: "nickname_in_use", failureDetail: null }),
    /nickname is in use/,
  );
});

// A 464 is a setting to change, and which one depends on whether a server
// password was configured at all.
test("a missing or rejected server password points at the setting that repairs it", () => {
  assert.match(
    networkStateHelp({ state: "reconnecting", failureCode: "server_password_required", failureDetail: "Password required" }),
    /requires a server password.*Server password under Advanced.*The network said: “Password required”$/,
  );
  assert.match(
    networkStateHelp({ state: "registration_failed", failureCode: "server_password_rejected", failureDetail: null }),
    /rejected the server password.*Server password under Advanced/,
  );
});

test("a refusal with no specific repair still quotes the network", () => {
  assert.equal(
    networkStateHelp({ state: "reconnecting", failureCode: "network_banned", failureDetail: "Trying to reconnect too fast." }),
    "The network said: “Trying to reconnect too fast.”",
  );
  assert.equal(networkStateHelp({ state: "reconnecting", failureCode: "connection_lost", failureDetail: null }), null);
});

test("a network with no driver on this server is not reported as starting", () => {
  assert.equal(networkStateLabel({ enabled: true, connected: null, runtime: null, state: null }), "not running");
  assert.equal(networkStateLabel({ enabled: true, connected: false, runtime: { state: null }, state: null }), "starting");
});

test("a connected network carries no advice from an earlier failure", () => {
  assert.equal(
    networkStateHelp({ connected: true, state: "connected", failureCode: "registration_rejected" }),
    null,
  );
});

test("an error that already ends its sentence is not given a second full stop", () => {
  assert.equal(errorMessage("load Libera", new Error("The API path schema is invalid.")), "Could not load Libera. The API path schema is invalid.");
  assert.equal(errorMessage("load Libera", new Error("Database unavailable")), "Could not load Libera. Database unavailable.");
  assert.equal(errorMessage("load Libera", new Error("")), "Could not load Libera.");
});
