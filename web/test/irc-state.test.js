// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import test from "node:test";

import {
  asMessage,
  fold,
  mergeTimeline,
  messageIdentity,
  nickPrefix,
  parseIrc,
  splitSigil,
  tagValue,
} from "../src/irc-state.js";

test("IRC parsing preserves tags, prefix, trailing text, and RFC1459 identity", () => {
  const parsed = parseIrc(
    "@time=2026-07-28T20:00:00.000Z;msgid=m1 :Alice!u@h PRIVMSG #Chat :hello there",
  );
  assert.deepEqual(parsed, {
    tags: "time=2026-07-28T20:00:00.000Z;msgid=m1",
    nick: "Alice",
    command: "PRIVMSG",
    params: ["#Chat", "hello there"],
  });
  assert.equal(fold("[Alice]~"), "{alice}^");
});

test("IRC tag values use the protocol escape rules", () => {
  const tags = String.raw`example=one\:two\sthree\\four;empty;msgid=stable`;
  assert.equal(tagValue(tags, "example"), "one;two three\\four");
  assert.equal(tagValue(tags, "empty"), "");
  assert.equal(tagValue(tags, "missing"), null);
  assert.equal(messageIdentity(tags), "stable");
  assert.equal(messageIdentity("msgid="), null);
});

test("membership sigils retain every mode and render the highest rank", () => {
  const member = splitSigil("@+Alice");
  assert.equal(member.name, "Alice");
  assert.deepEqual(member.modes, new Set(["o", "v"]));
  assert.equal(nickPrefix(member.modes), "@");
});

test("CTCP ACTION is rendered as an event", () => {
  assert.deepEqual(asMessage("msg", "alice", "\x01ACTION waves\x01"), {
    kind: "event",
    from: null,
    text: "* alice waves",
  });
  assert.deepEqual(asMessage("notice", "alice", "plain"), {
    kind: "notice",
    from: "alice",
    text: "plain",
  });
});

test("history merge never replaces live or unidentified lines", () => {
  const history = [
    { identity: "old", text: "old" },
    { identity: "shared", text: "persisted shared" },
    { identity: null, text: "first identical body" },
    { identity: null, text: "first identical body" },
  ];
  const live = [
    { identity: "shared", text: "live shared" },
    { identity: null, text: "arrived while loading" },
    { identity: null, text: "local echo not persisted" },
  ];
  assert.deepEqual(mergeTimeline(history, live, 20), [
    { identity: "old", text: "old" },
    { identity: null, text: "first identical body" },
    { identity: null, text: "first identical body" },
    { identity: "shared", text: "live shared" },
    { identity: null, text: "arrived while loading" },
    { identity: null, text: "local echo not persisted" },
  ]);
});

test("history merge deduplicates duplicate stable ids and applies the cap last", () => {
  const history = [
    { identity: "one", text: "oldest" },
    { identity: "two", text: "first copy" },
    { identity: "two", text: "newest copy" },
  ];
  const live = [{ identity: "three", text: "live" }];
  assert.deepEqual(mergeTimeline(history, live, 2), [
    { identity: "two", text: "newest copy" },
    { identity: "three", text: "live" },
  ]);
});
