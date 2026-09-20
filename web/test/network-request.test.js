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

test("replace sends the nickname for an empty real name, as create does", () => {
  const body = updateNetworkBody({ addr: "irc.libera.chat:6697", tls: true, nick: "ada", realname: "  " });
  // The API refuses a null real name for an IRC network, so a blank box must
  // not produce one: it means the nickname, as the form says and as on create.
  assert.equal(body.realname, "ada");
});

// The username is the `USER` parameter an upstream shows as the ident. The API
// requires it and never derives one, so the form has to: a blank box means the
// nickname, as the form says -- but only when the nickname is a legal username.
// Anything else is refused at the box rather than quietly rewritten.
test("a blank username sends the nickname on create and on replace", () => {
  const create = createNetworkBody({ name: "libera", addr: "irc.libera.chat:6697", tls: true, nick: "ada" });
  assert.equal(create.username, "ada");
  const replace = updateNetworkBody({ addr: "irc.libera.chat:6697", tls: true, nick: "ada", username: "  " });
  assert.equal(replace.username, "ada");
});

test("a typed username is sent as typed", () => {
  const body = createNetworkBody({
    name: "libera",
    addr: "irc.libera.chat:6697",
    tls: true,
    nick: "ada|away",
    username: "ada_l",
  });
  assert.equal(body.username, "ada_l");
});

test("a nickname that is not a legal username is never rewritten into one", () => {
  for (const nick of ["ada|away", "[ada]", "_ada", "adalovelace1815"]) {
    assert.throws(
      () => createNetworkBody({ name: "libera", addr: "irc.libera.chat:6697", tls: true, nick }),
      (error) => error instanceof NetworkRequestError && error.field === "username",
      nick,
    );
  }
});

test("an illegal typed username is refused at its own box", () => {
  for (const username of ["ada.l", "-ada", "ada l", "adalovelace1", "ädä"]) {
    assert.throws(
      () => updateNetworkBody({ addr: "irc.libera.chat:6697", tls: true, nick: "ada", username }),
      (error) => error instanceof NetworkRequestError && error.field === "username",
      username,
    );
  }
});

test("every refusal names the box it belongs to", () => {
  const at = (field, build) =>
    assert.throws(build, (error) => error instanceof NetworkRequestError && error.field === field, field);
  at("addr", () => updateNetworkBody({ addr: "", tls: true, nick: "ada" }));
  at("nick", () => updateNetworkBody({ addr: "irc.libera.chat:6697", tls: true, nick: " " }));
  at("name", () => createNetworkBody({ name: " ", addr: "irc.libera.chat:6697", tls: true, nick: "ada" }));
  at("sasl_account", () =>
    createNetworkBody({ name: "libera", addr: "irc.libera.chat:6697", tls: true, nick: "ada", password: "x" }));
  at("sasl_account", () => credentialAction({ password: "x" }));
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
