// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import test from "node:test";

import {
  asMessage,
  chatMessageRoute,
  fold,
  kickPairs,
  membershipTargets,
  mergeTimeline,
  messageIdentity,
  nickPrefix,
  parseIrc,
  reconcileChannelSnapshot,
  splitSigil,
  tagValue,
  topicReply,
} from "../src/irc-state.js";

test("IRC parsing preserves tags, prefix, trailing text, and RFC1459 identity", () => {
  const parsed = parseIrc(
    "@time=2026-07-28T20:00:00.000Z;msgid=m1 :Alice!u@h PRIVMSG #Chat :hello there",
  );
  assert.deepEqual(parsed, {
    tags: "time=2026-07-28T20:00:00.000Z;msgid=m1",
    nick: "Alice",
    sourceIsUser: true,
    command: "PRIVMSG",
    params: ["#Chat", "hello there"],
  });
  assert.equal(fold("[Alice]~"), "{alice}^");
});

test("IRC parsing distinguishes server and user notice sources", () => {
  assert.equal(parseIrc(":irc.example NOTICE alice :maintenance").sourceIsUser, false);
  assert.equal(parseIrc(":NickServ!service@irc.example NOTICE alice :identified").sourceIsUser, true);
});

test("live and history chat routing understands STATUSMSG and server notices", () => {
  const route = (line) => chatMessageRoute(parseIrc(line), "Alice");
  assert.deepEqual(route(":bob!u@h PRIVMSG @#Ops :operators only"), {
    kind: "channel",
    target: "#Ops",
  });
  assert.deepEqual(route(":bob!u@h NOTICE +#Ops :voiced users"), {
    kind: "channel",
    target: "#Ops",
  });
  assert.deepEqual(route(":bob!u@h PRIVMSG #room :hello"), {
    kind: "channel",
    target: "#room",
  });
  assert.deepEqual(route(":Alice!u@h PRIVMSG Bob :outgoing"), {
    kind: "dm",
    target: "Bob",
  });
  assert.deepEqual(route(":Bob!u@h PRIVMSG Alice :incoming"), {
    kind: "dm",
    target: "Bob",
  });
  assert.deepEqual(route(":irc.example NOTICE Alice :maintenance"), {
    kind: "server",
    target: null,
  });
  assert.equal(route(":bob!u@h PRIVMSG #room"), null);
});

test("IRC tag values use the protocol escape rules", () => {
  const tags = String.raw`example=one\:two\sthree\\four;empty;msgid=stable`;
  assert.equal(tagValue(tags, "example"), "one;two three\\four");
  assert.equal(tagValue(tags, "empty"), "");
  assert.equal(tagValue(tags, "missing"), null);
  assert.equal(messageIdentity(tags), "stable");
  assert.equal(messageIdentity("msgid="), null);
});

test("duplicate IRC tags use the final value like e6irc-proto", () => {
  assert.equal(tagValue("time=old;time=new", "time"), "new");
  assert.equal(messageIdentity("msgid=stale;msgid=current"), "current");
  assert.equal(tagValue(String.raw`example=old;example=new\svalue`, "example"), "new value");
});

test("membership target lists use the BNC session tracker's pairing rules", () => {
  assert.deepEqual(membershipTargets("#one,#two"), ["#one", "#two"]);
  assert.deepEqual(kickPairs("#one,#two", "alice,bob"), [
    ["#one", "alice"],
    ["#two", "bob"],
  ]);
  assert.deepEqual(kickPairs("#one", "alice,bob"), [
    ["#one", "alice"],
    ["#one", "bob"],
  ]);
  assert.deepEqual(kickPairs("#one,#two", "alice"), []);
});

test("topic numerics require a channel before mutating browser state", () => {
  assert.deepEqual(topicReply(["me", "#room", "hello"]), {
    channel: "#room",
    topic: "hello",
  });
  assert.equal(topicReply(["me"]), null);
  assert.equal(topicReply(["me", "#room"]), null);
  assert.equal(topicReply(null), null);
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

test("history merge removes only an ordered unidentified wire overlap", () => {
  const first = { identity: null, text: "same body", wire: ":n PRIVMSG #c :same body" };
  const second = { identity: null, text: "same body", wire: ":n PRIVMSG #c :same body" };
  const boundary = { identity: null, text: "boundary", wire: ":n PRIVMSG #c :boundary" };
  const liveOnly = { identity: null, text: "live", wire: ":n PRIVMSG #c :live" };

  assert.deepEqual(
    mergeTimeline([first, second, boundary], [second, boundary, liveOnly], 20),
    [first, second, boundary, liveOnly],
    "the largest suffix/prefix overlap is removed while an earlier identical message remains",
  );
});

test("history merge retains requested context in front of a full live window", () => {
  const older = { identity: "old", text: "older" };
  const live = [
    { identity: "live-1", text: "live one" },
    { identity: "live-2", text: "live two" },
  ];

  assert.deepEqual(
    mergeTimeline([older], live, 3),
    [older, ...live],
    "the expanded explicit-history bound must not discard the row just loaded",
  );
});

test("authoritative session channels replace stale replay membership by casefold", () => {
  assert.deepEqual(
    reconcileChannelSnapshot(["#Keep", "#stale"], ["#keep", "#New", "#new"]),
    {
      removed: ["#stale"],
      added: ["#New"],
      joined: ["#keep", "#New"],
    },
  );
});
