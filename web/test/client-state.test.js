// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import test from "node:test";

import {
  ApiError,
  DEFAULT_SETTINGS,
  SETTINGS_KEY,
  backlogFrom,
  errorMessage,
  getJson,
  identityFrom,
  loadSettings,
  networksFrom,
  networkStateLabel,
  saveSettings,
} from "../src/client-state.js";

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

test("JSON requests preserve problem details and reject malformed success bodies", async () => {
  await assert.rejects(
    getJson(
      async () => ({
        ok: false,
        status: 503,
        json: async () => ({ title: "Database unavailable" }),
      }),
      "/api/v1/me/networks",
    ),
    (error) =>
      error instanceof ApiError &&
      error.status === 503 &&
      error.message === "Database unavailable",
  );

  await assert.rejects(
    getJson(
      async () => ({
        ok: true,
        status: 200,
        json: async () => {
          throw new SyntaxError("bad json");
        },
      }),
      "/api/v1/me",
    ),
    /invalid JSON/,
  );
});

test("network collection validation separates an empty list from a broken contract", () => {
  assert.deepEqual(networksFrom({ networks: [] }), []);
  assert.deepEqual(networksFrom({ networks: [{ name: "Libera", enabled: true, connected: null, runtime: null }] }), [
    { name: "Libera", enabled: true, connected: null, state: null },
  ]);
  assert.throws(() => networksFrom({ networks: [{ enabled: true }] }), /invalid network list/);
  assert.throws(
    () => networksFrom({ networks: [{ name: "Libera", enabled: true, connected: true, runtime: null }] }),
    /invalid network list/,
  );
  assert.throws(
    () => networksFrom({ networks: [{ name: "Libera", enabled: true, connected: false, runtime: { state: "connected" } }] }),
    /invalid network list/,
  );
  assert.throws(() => networksFrom({ networks: [], next: "not part of this response" }), /invalid network list/);
});

test("backlog parsing accepts only the closed lines response", () => {
  assert.deepEqual(backlogFrom({ lines: [":a PRIVMSG #chat :hello"] }), [":a PRIVMSG #chat :hello"]);
  assert.throws(() => backlogFrom({ lines: ["ok"], cursor: "unexpected" }), /invalid backlog/);
  assert.throws(() => backlogFrom({ lines: [1] }), /invalid backlog/);
});

test("identity parsing keeps only a safe, complete projection", () => {
  assert.deepEqual(identityFrom({ account: "alice", email: "a@example.test", role: "operator", logout_url: "/logout" }), {
    account: "alice",
    email: "a@example.test",
    role: "operator",
    logoutURL: "/logout",
  });
  assert.deepEqual(identityFrom({ account: "token-user" }), {
    account: "token-user",
    email: null,
    role: null,
    logoutURL: null,
  });
  assert.throws(() => identityFrom({ account: "", email: null }), /invalid identity/);
  assert.throws(() => identityFrom({ account: "alice", role: 1 }), /invalid identity/);
  assert.throws(() => identityFrom({ account: "alice", logout_url: "//other.test/logout" }), /invalid identity/);
  assert.throws(() => identityFrom({ account: "alice", csrf_token: 1 }), /invalid identity/);
  assert.throws(() => identityFrom({ account: "alice", unexpected: true }), /invalid identity/);
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
