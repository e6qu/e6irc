// SPDX-License-Identifier: AGPL-3.0-or-later
import assert from "node:assert/strict";
import test from "node:test";

import {
  NetworkRequestError,
  autojoinList,
  createNetworkBody,
  credentialAction,
  updateNetworkBody,
} from "../src/network-request.js";

// The two endpoints take different credential shapes on purpose, and the first
// version of the settings dialog sent the replace shape to both. These pin the
// difference, because nothing else in the client will.

test("creating a network carries flat credentials, not an action", () => {
  const body = createNetworkBody({
    name: "libera",
    addr: "irc.libera.chat:6697",
    tls: true,
    nick: "ada",
    account: "ada",
    password: "hunter2",
  });
  assert.equal(body.kind, "irc");
  assert.equal(body.sasl_account, "ada");
  assert.equal(body.sasl_password, "hunter2");
  assert.ok(!("credentials" in body), "create must not send the replace shape");
});

test("creating a network without a real name sends the nickname, which the contract requires", () => {
  const body = createNetworkBody({ name: "libera", addr: "irc.libera.chat:6697", tls: true, nick: "ada" });
  assert.equal(body.realname, "ada");
  assert.ok(!("sasl_account" in body), "no account was given, so none is sent");
  assert.ok(!("sasl_password" in body), "no password was given, so none is sent");
});

test("replacing a network carries a tagged action, not flat credentials", () => {
  const body = updateNetworkBody({
    addr: "irc.libera.chat:6697",
    tls: true,
    nick: "ada",
    account: "ada",
    password: "hunter2",
  });
  assert.deepEqual(body.credentials, { action: "set", account: "ada", password: "hunter2" });
  assert.ok(!("sasl_account" in body), "replace must not send the create shape");
  assert.ok(!("sasl_password" in body), "replace must not send the create shape");
});

// An omitted password has to mean something unambiguous, and the API models
// that as an explicit action rather than an absent field.
test("an empty credential box on replace keeps the sealed password", () => {
  assert.deepEqual(credentialAction({}), { action: "keep" });
});

test("an account with no password sets the identity and keeps the sealed password", () => {
  assert.deepEqual(credentialAction({ account: "ada" }), { action: "set", account: "ada" });
});

test("clearing wins over anything typed, so removal is never ambiguous", () => {
  assert.deepEqual(
    credentialAction({ clearing: true, account: "ada", password: "hunter2" }),
    { action: "remove" },
  );
});

// A password with nothing to authenticate as is refused where the field is,
// rather than travelling to the server to come back as a rejected request.
test("a password with no account is refused on both endpoints", () => {
  assert.throws(() => credentialAction({ password: "hunter2" }), NetworkRequestError);
  assert.throws(
    () => createNetworkBody({ name: "libera", addr: "irc.libera.chat:6697", tls: true, nick: "ada", password: "hunter2" }),
    NetworkRequestError,
  );
});

test("replace treats an empty real name as none rather than unchanged", () => {
  const body = updateNetworkBody({ addr: "irc.libera.chat:6697", tls: true, nick: "ada", realname: "  " });
  assert.equal(body.realname, null);
});

test("the connection fields are required before anything is sent", () => {
  assert.throws(() => updateNetworkBody({ addr: "", tls: true, nick: "ada" }), NetworkRequestError);
  assert.throws(() => updateNetworkBody({ addr: "irc.libera.chat:6697", tls: true, nick: " " }), NetworkRequestError);
});

test("auto-join accepts commas, spaces, or both, and drops the gaps", () => {
  assert.deepEqual(autojoinList("#e6qu, #rust  #irc"), ["#e6qu", "#rust", "#irc"]);
  assert.deepEqual(autojoinList(""), []);
  assert.deepEqual(autojoinList(undefined), []);
});
