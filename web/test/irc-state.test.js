// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import test from "node:test";

import {
  DEFAULT_CHANNEL_MODES,
  asMessage,
  bufferAction,
  channelModesFrom,
  chatMessageRoute,
  clearTranscript,
  existingChannelBuffer,
  fold,
  isPrefixMode,
  kickPairs,
  memberRank,
  membershipTargets,
  mergeTimeline,
  messageIdentity,
  modeChanges,
  modeTakesParameter,
  nickPrefix,
  parseIrc,
  reconcileChannelSnapshot,
  seededNick,
  splitSigil,
  stripFormatting,
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

test("formatting codes are removed rather than shown as digits and control bytes", () => {
  assert.equal(stripFormatting("\x0304,01red on black\x03 plain"), "red on black plain");
  assert.equal(stripFormatting("\x02bold\x02 \x1ditalic\x1d \x1funder\x1f \x1estrike\x1e \x11mono\x11 \x16rev\x16\x0f"), "bold italic under strike mono rev");
  assert.equal(stripFormatting("\x04ff0000,00ff00hex\x04"), "hex");
  // A bare ^C resets colour; digits that are not a colour stay text.
  assert.equal(stripFormatting("price\x03 42"), "price 42");
  assert.equal(stripFormatting("\x033three"), "three");
  assert.equal(stripFormatting(undefined), "");
  assert.deepEqual(asMessage("msg", "bot", "\x0303ok\x03"), { kind: "msg", from: "bot", text: "ok" });
});

test("a CTCP other than ACTION is named, not shown as raw control bytes", () => {
  assert.deepEqual(asMessage("msg", "alice", "\x01VERSION\x01"), {
    kind: "event", from: null, text: "alice sent a CTCP VERSION request",
  });
  assert.deepEqual(asMessage("msg", "alice", "\x01PING 12345\x01"), {
    kind: "event", from: null, text: "alice sent a CTCP PING request: 12345",
  });
});

// ---- ISUPPORT-driven channel modes (item: MODE argument alignment) --------
//
// Libera declares PREFIX=(ov)@+ and CHANMODES=eIbq,k,flj,...: +q is a quiet
// list, not owner, and +f takes a parameter when set. Read with the RFC-style
// defaults, `+fo #overflow alice` hands #overflow to `o` and drops alice.

test("the pre-005 default table is the current one", () => {
  assert.equal(modeTakesParameter(DEFAULT_CHANNEL_MODES, "o", true), true);
  assert.equal(modeTakesParameter(DEFAULT_CHANNEL_MODES, "b", false), true);
  assert.equal(modeTakesParameter(DEFAULT_CHANNEL_MODES, "k", false), true);
  assert.equal(modeTakesParameter(DEFAULT_CHANNEL_MODES, "l", true), true);
  assert.equal(modeTakesParameter(DEFAULT_CHANNEL_MODES, "l", false), false);
  assert.equal(modeTakesParameter(DEFAULT_CHANNEL_MODES, "f", true), false);
  assert.equal(isPrefixMode(DEFAULT_CHANNEL_MODES, "q"), true);
  assert.equal(nickPrefix(new Set(["q", "v"]), DEFAULT_CHANNEL_MODES), "~");
});

test("005 CHANMODES and PREFIX drive parameters and sigils for that network", () => {
  const first = channelModesFrom(
    parseIrc(":irc.libera.chat 005 me CHANMODES=eIbq,k,flj,CFLMPQRSTcgimnprstuz :are supported by this server").params,
  );
  assert.deepEqual(first.malformed, []);
  const second = channelModesFrom(
    parseIrc(":irc.libera.chat 005 me PREFIX=(ov)@+ STATUSMSG=@+ :are supported by this server").params,
    first.modes,
  );
  const libera = second.modes;
  assert.equal(modeTakesParameter(libera, "f", true), true, "+f takes its limit when set");
  assert.equal(modeTakesParameter(libera, "f", false), false, "-f takes nothing");
  assert.equal(modeTakesParameter(libera, "q", true), true, "+q is a quiet mask, a list mode");
  assert.equal(isPrefixMode(libera, "q"), false, "+q is not owner on Libera");
  assert.equal(isPrefixMode(libera, "o"), true);
  assert.deepEqual(splitSigil("@+alice", libera), { name: "alice", modes: new Set(["o", "v"]) });
  // A sigil the network does not declare is part of the nick, not a rank.
  assert.equal(splitSigil("~tilde", libera).name, "~tilde");
  assert.equal(nickPrefix(new Set(["o", "v"]), libera), "@");
  assert.equal(memberRank(new Set(["v"]), libera), 1);
  assert.equal(memberRank(new Set(), libera), 2);
});

test("MODE arguments are assigned by the network's table", () => {
  const libera = channelModesFrom(
    parseIrc(":s 005 me CHANMODES=eIbq,k,flj,CFLMPQRSTcgimnprstuz PREFIX=(ov)@+ :are supported by this server").params,
  ).modes;
  assert.deepEqual(modeChanges(libera, "+fo", ["#overflow", "alice"]), [
    { mode: "f", adding: true, argument: "#overflow" },
    { mode: "o", adding: true, argument: "alice" },
  ]);
  assert.deepEqual(modeChanges(libera, "+q-l", ["*!*@spam"]), [
    { mode: "q", adding: true, argument: "*!*@spam" },
    { mode: "l", adding: false, argument: undefined },
  ]);
  // Before 005 the default table reads the same line the way it used to.
  assert.deepEqual(modeChanges(DEFAULT_CHANNEL_MODES, "+o-l", ["alice"]), [
    { mode: "o", adding: true, argument: "alice" },
    { mode: "l", adding: false, argument: undefined },
  ]);
});

test("a malformed ISUPPORT token is reported and leaves the table alone", () => {
  const result = channelModesFrom(parseIrc(":s 005 me PREFIX=(ov)@ CHANMODES=a,b :are supported").params);
  assert.deepEqual(result.malformed, ["PREFIX=(ov)@", "CHANMODES=a,b"]);
  assert.deepEqual(result.modes, DEFAULT_CHANNEL_MODES);
  // An empty PREFIX is a network with no ranks at all, which is well-formed.
  assert.deepEqual(channelModesFrom(parseIrc(":s 005 me PREFIX= :are supported").params).modes.prefix, []);
});



test("a topic or NAMES reply finds an open channel buffer and never makes one", () => {
  const channel = { key: "#chat", kind: "channel" };
  const buffers = new Map([["#chat", channel], ["alice", { key: "alice", kind: "dm" }]]);
  assert.equal(existingChannelBuffer(buffers, "#CHAT"), channel);
  assert.equal(existingChannelBuffer(buffers, "#elsewhere"), null);
  assert.equal(existingChannelBuffer(buffers, "*"), null);
  assert.equal(existingChannelBuffer(buffers, "alice"), null);
  assert.equal(existingChannelBuffer(buffers, undefined), null);
  assert.equal(buffers.size, 2);
});

test("a replay clears a transcript and offers its earlier history again", () => {
  const buffer = {
    lines: [{ text: "old" }],
    unread: 3,
    mentions: 1,
    pendingVisibleMessages: 2,
    historyLoaded: true,
  };
  clearTranscript(buffer);
  assert.deepEqual(buffer, {
    lines: [],
    unread: 0,
    mentions: 0,
    pendingVisibleMessages: 0,
    historyLoaded: false,
  });
});

test("a joined bridge channel has nothing to leave; its past and conversations still close", () => {
  const channel = (joined) => ({ kind: "channel", joined });
  // An IRC network: a joined channel is left, a past one closed.
  assert.equal(bufferAction(channel(true), true), "leave");
  assert.equal(bufferAction(channel(false), true), "close");
  assert.equal(bufferAction({ kind: "dm", joined: null }, true), "close");
  // A bridge: the provider account is in its channels, not the person.
  assert.equal(bufferAction(channel(true), false), null);
  assert.equal(bufferAction(channel(false), false), "close");
  assert.equal(bufferAction({ kind: "dm", joined: null }, false), "close");
  // The console has no action anywhere.
  assert.equal(bufferAction({ kind: "server", joined: null }, true), null);
  assert.equal(bufferAction(undefined, true), null);
});

test("a bridge's session snapshot joins its channels under the provider account's nick", () => {
  // A bridge stores no nick; the session names it.
  assert.equal(seededNick(""), null);
  assert.equal(seededNick(undefined), null);
  assert.equal(seededNick("alice"), "alice");
  // Buffers opened by relayed messages before the session are archived until
  // the snapshot names them; then they are joined, and none is removed.
  const reconciliation = reconcileChannelSnapshot(["#general"], ["#General", "#random"]);
  assert.deepEqual(reconciliation.removed, []);
  assert.deepEqual(reconciliation.added, ["#random"]);
  assert.deepEqual(reconciliation.joined, ["#General", "#random"]);
});
