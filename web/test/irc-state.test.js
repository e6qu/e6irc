// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import test from "node:test";

import {
  DEFAULT_CHANNEL_MODES,
  DEFAULT_NAMES,
  SERVER_KEY,
  asMessage,
  bufferAction,
  channelModesFrom,
  channelModesFromIsupport,
  chatMessageRoute,
  clearTranscript,
  composerRequests,
  existingChannelBuffer,
  fold,
  isChannel,
  isPrefixMode,
  kickPairs,
  memberRank,
  membershipTargets,
  mergeTimeline,
  messageIdentity,
  modeChanges,
  modeTakesParameter,
  namesDiffer,
  namesFrom,
  namesFromIsupport,
  nickPrefix,
  oldestRingFloor,
  outgoingChat,
  parseIrc,
  prependHistory,
  reasonSuffix,
  reconcileChannelSnapshot,
  rekeyBuffers,
  seededNick,
  splitSigil,
  splitUtf8,
  stripBidiControls,
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

test("names follow the network's CASEMAPPING and CHANTYPES", () => {
  // Until a 005 says otherwise: rfc1459 and #&.
  assert.equal(fold("#A[]\\~"), "#a{}|^");
  assert.ok(isChannel("#a") && isChannel("&a") && !isChannel("!a") && !isChannel(""));

  // An ascii network: #a[ and #a{ are two channels.
  const ascii = namesFrom(["me", "CASEMAPPING=ascii", "CHANTYPES=#!", "are supported"]);
  assert.equal(ascii.casemapping, "ascii");
  assert.equal(fold("#A[", ascii), "#a[");
  assert.notEqual(fold("#a[", ascii), fold("#a{", ascii));
  assert.ok(isChannel("!x", ascii) && !isChannel("&x", ascii));
  assert.deepEqual(
    chatMessageRoute(parseIrc(":bob!u@h PRIVMSG !chan :hi"), "me", () => false, ascii),
    { kind: "channel", target: "!chan" },
  );
  assert.deepEqual(
    chatMessageRoute(parseIrc(":bob!u@h PRIVMSG &x :hi"), "me", () => false, ascii),
    { kind: "dm", target: "bob" },
  );

  // rfc1459-strict, in either spelling: brackets fold, ~ and ^ stay apart.
  for (const spelling of ["rfc1459-strict", "strict-rfc1459"]) {
    const strict = namesFromIsupport([`CASEMAPPING=${spelling}`]);
    assert.equal(strict.casemapping, "rfc1459-strict");
    assert.equal(fold("#A[~", strict), "#a{~");
  }

  // An unknown mapping compares as ascii and is named; retraction restores.
  const unknown = namesFromIsupport(["CASEMAPPING=rfc7613"]);
  assert.equal(unknown.casemapping, "ascii");
  assert.equal(unknown.unrecognised, "rfc7613");
  const retracted = namesFrom(["me", "-CASEMAPPING", "-CHANTYPES", "x"], ascii);
  assert.ok(!namesDiffer(retracted, DEFAULT_NAMES));
  assert.equal(namesFromIsupport(["CHANTYPES="]).chantypes, "", "a network without channels");

  // Snapshots reconcile under the network's mapping.
  assert.deepEqual(
    reconcileChannelSnapshot(["#a["], ["#a{"], ascii),
    { removed: ["#a["], added: ["#a{"], joined: ["#a{"] },
  );
});

test("buffers are re-keyed when the naming rules change, merging what becomes one name", () => {
  const buffer = (display, extra = {}) => ({
    key: fold(display),
    display,
    kind: "channel",
    lines: [],
    nicks: new Map(),
    unread: 0,
    mentions: 0,
    ...extra,
  });
  const ascii = namesFromIsupport(["CASEMAPPING=ascii"]);
  const server = { ...buffer(SERVER_KEY), kind: "server" };
  const brackets = buffer("#A[", { lines: ["b"], unread: 1 });
  brackets.nicks.set(fold("Al[ex]"), { name: "Al[ex]", modes: new Set() });
  const initial = new Map([[SERVER_KEY, server], [brackets.key, brackets]]);
  const narrowed = rekeyBuffers(initial, ascii);
  assert.deepEqual([...narrowed.buffers.keys()], [SERVER_KEY, "#a["]);
  assert.deepEqual([...brackets.nicks.keys()], ["al[ex]"]);
  assert.deepEqual(narrowed.merged, []);

  const braces = { ...buffer("#a{", { lines: ["c"], unread: 2 }), key: fold("#a{", ascii) };
  narrowed.buffers.set(braces.key, braces);
  const widened = rekeyBuffers(narrowed.buffers, DEFAULT_NAMES);
  assert.deepEqual([...widened.buffers.keys()], [SERVER_KEY, "#a{"]);
  assert.deepEqual(widened.buffers.get("#a{").lines, ["b", "c"]);
  assert.equal(widened.buffers.get("#a{").unread, 3);
  assert.deepEqual(widened.merged, [["#A[", "#a{"]]);
});

test("IRC parsing distinguishes server and user notice sources", () => {
  assert.equal(parseIrc(":irc.example NOTICE alice :maintenance").sourceIsUser, false);
  assert.equal(parseIrc(":NickServ!service@irc.example NOTICE alice :identified").sourceIsUser, true);
});

test("live and history chat routing understands STATUSMSG and server notices", () => {
  const libera = namesFromIsupport(["STATUSMSG=@+"]);
  const route = (line) => chatMessageRoute(parseIrc(line), "Alice", () => false, libera);
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

// The server's bnc_statusmsg_lines_belong_to_their_channel and NetworkNames'
// statusmsg_sigils_come_from_the_network, read by the browser.
test("STATUSMSG sigils are the network's own, never a hard-coded @+", () => {
  const route = (line, names, known = () => false) => chatMessageRoute(parseIrc(line), "alice", known, names);
  const ergo = namesFromIsupport(["STATUSMSG=~&@%+", "CHANTYPES=#&!"]);
  for (const [addressed, channel] of [
    ["@#Room", "#Room"],
    ["+#Room", "#Room"],
    ["@&local", "&local"],
    ["%#dev", "#dev"],
    ["@%#dev", "#dev"],
    ["&#dev", "#dev"],
    ["!ABCDEchan", "!ABCDEchan"],
  ]) {
    assert.deepEqual(route(`:Bob!u@h PRIVMSG ${addressed} :ops only`, ergo), { kind: "channel", target: channel }, addressed);
  }
  assert.deepEqual(route(":alice!u@h NOTICE @#Room :from us", ergo), { kind: "channel", target: "#Room" });
  assert.deepEqual(
    route(":Bob!u@h PRIVMSG +alice :a nick, not a STATUSMSG", namesFromIsupport(["STATUSMSG=~&@%+"])),
    { kind: "dm", target: "Bob" },
  );

  // Under the default CHANTYPES `#&`, `&#dev` is still #dev's STATUSMSG when
  // `&` is a status sigil, not a phantom `&#dev` channel.
  const ampersand = namesFromIsupport(["STATUSMSG=&@"]);
  assert.deepEqual(route(":Bob!u@h PRIVMSG &#dev :hi", ampersand), { kind: "channel", target: "#dev" });
  assert.deepEqual(route(":Bob!u@h PRIVMSG &local :hi", ampersand), { kind: "channel", target: "&local" });

  // A sigil the network does not advertise stays part of the target.
  assert.deepEqual(route(":Bob!u@h PRIVMSG %#dev :hi", namesFromIsupport(["STATUSMSG=@+"])), { kind: "dm", target: "Bob" });
  assert.deepEqual(route(":Bob!u@h PRIVMSG @#dev :hi", DEFAULT_NAMES), { kind: "dm", target: "Bob" }, "no STATUSMSG yet");
  const retracted = namesFrom(["me", "-STATUSMSG", "x"], ergo);
  assert.equal(retracted.statusmsg, "");
  assert.deepEqual(route(":Bob!u@h PRIVMSG %#dev :hi", retracted), { kind: "dm", target: "Bob" });
  // A buffer the page already holds as a channel counts, as before.
  assert.deepEqual(route(":Bob!u@h PRIVMSG @odd :hi", ergo, (name) => name === "odd"), { kind: "channel", target: "odd" });
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

test("CTCP ACTION is rendered as an event that keeps its actor", () => {
  // The actor is kept as the sender: an action naming you is a mention.
  assert.deepEqual(asMessage("msg", "alice", "\x01ACTION waves\x01"), {
    kind: "event",
    from: null,
    sender: "alice",
    text: "* alice waves",
  });
  assert.deepEqual(asMessage("notice", "alice", "plain"), {
    kind: "notice",
    from: "alice",
    sender: "alice",
    text: "plain",
  });
});

test("bidirectional override and isolate controls are removed from displayed text", () => {
  // RLO would show `https://evil.example/\u202Egpj.exe` as ending in "exe.jpg".
  assert.equal(
    stripBidiControls("see https://evil.example/\u202Emoc.elgoog//:sptth"),
    "see https://evil.example/moc.elgoog//:sptth",
  );
  for (const control of ["\u202A", "\u202B", "\u202C", "\u202D", "\u202E", "\u2066", "\u2067", "\u2068", "\u2069"]) {
    assert.equal(stripBidiControls(`a${control}b`), "ab", JSON.stringify(control));
  }
  // Right-to-left text itself is left alone.
  assert.equal(stripBidiControls("שלום world"), "שלום world");
  assert.equal(stripBidiControls(undefined), "");
});

// A channel named `#a‮b` drew reversed in the sidebar, the header and
// the member list, which showed buffer and member names unfiltered.
test("channel and nick names are drawn without bidi controls, in isolation", async () => {
  const source = await readFile(new URL("../src/main.js", import.meta.url), "utf8");
  const drawn = source.split("\n").filter((line) =>
    /textContent\s*=|\.title\s*=|setAttribute\("aria-label"|const (label|action) = /.test(line));
  for (const line of drawn) {
    assert.doesNotMatch(line, /\b(b|buffer)\.display\b|\bm\.name\b/, `drawn unfiltered: ${line.trim()}`);
  }
  assert.match(source, /function bufferLabel\(b\) \{\n\s*return [^\n]*stripBidiControls\(b\.display\);/);
  assert.match(source, /const shown = stripBidiControls\(m\.name\);/);
  // Alerts name channels too: their text is filtered once, where it is shown.
  assert.match(source, /function showAlert\(key, unsafeText[^\n]*\n(?:\s*\/\/[^\n]*\n)*\s*const text = stripBidiControls\(unsafeText\);/);

  const styles = await readFile(new URL("../src/style.css", import.meta.url), "utf8");
  for (const selector of [".buf-name", "#bufname", ".nick"]) {
    const escaped = selector.replace(/[.#]/g, "\\$&");
    const rule = styles.match(new RegExp(`^${escaped} \\{([^}]*)\\}`, "m"));
    assert.ok(rule, selector);
    assert.match(rule[1], /unicode-bidi: isolate;/, selector);
  }
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

test("PART, KICK and QUIT reasons are rendered without formatting codes", async () => {
  assert.equal(reasonSuffix("\x0304,01flood\x03 limit"), " (flood limit)");
  assert.equal(reasonSuffix("plain"), " (plain)");
  assert.equal(reasonSuffix("\x02\x02"), "", "only formatting is no reason");
  assert.equal(reasonSuffix(undefined), "");
  // Each membership event renders its reason through the one helper, never a
  // hand-built ` (${m.params[n]})`, which is how all three forgot the codes.
  const source = await readFile(new URL("../src/main.js", import.meta.url), "utf8");
  assert.doesNotMatch(source, /` \(\$\{m\.params/);
  for (const command of ["PART", "KICK", "QUIT"]) {
    const start = source.indexOf(`case "${command}":`);
    assert.ok(start !== -1, command);
    const body = source.slice(start, source.indexOf("case ", start + 6));
    assert.match(body, /reasonSuffix\(m\.params\[\d\]\)/, command);
  }
});

test("formatting codes are removed rather than shown as digits and control bytes", () => {
  assert.equal(stripFormatting("\x0304,01red on black\x03 plain"), "red on black plain");
  assert.equal(stripFormatting("\x02bold\x02 \x1ditalic\x1d \x1funder\x1f \x1estrike\x1e \x11mono\x11 \x16rev\x16\x0f"), "bold italic under strike mono rev");
  assert.equal(stripFormatting("\x04ff0000,00ff00hex\x04"), "hex");
  // A bare ^C resets colour; digits that are not a colour stay text.
  assert.equal(stripFormatting("price\x03 42"), "price 42");
  assert.equal(stripFormatting("\x033three"), "three");
  assert.equal(stripFormatting(undefined), "");
  assert.deepEqual(asMessage("msg", "bot", "\x0303ok\x03"), { kind: "msg", from: "bot", sender: "bot", text: "ok" });
});

test("a CTCP other than ACTION is named, not shown as raw control bytes", () => {
  assert.deepEqual(asMessage("msg", "alice", "\x01VERSION\x01"), {
    kind: "event", from: null, sender: null, text: "alice sent a CTCP VERSION request",
  });
  assert.deepEqual(asMessage("msg", "alice", "\x01PING 12345\x01"), {
    kind: "event", from: null, sender: null, text: "alice sent a CTCP PING request: 12345",
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

// ---- history merge around rows the history has no counterpart for ---------

test("history merge on a network without msgids matches past join notices and local echoes", () => {
  // No msgid anywhere. The live buffer opens with a join notice, which history
  // has no counterpart for, and holds a local echo of our own message, which
  // history holds as the ring's copy of the line.
  const wire = (text, nick = "bob") => ({
    identity: null, kind: "msg", sender: nick, text, wire: `:${nick}!u@h PRIVMSG #c :${text}`,
  });
  const older = wire("older");
  const first = wire("first");
  const second = wire("second");
  const joined = { identity: null, kind: "event", sender: null, text: "carol joined", wire: null };
  const echo = { identity: null, kind: "msg", sender: "me", text: "mine", wire: null };
  const live = [joined, first, echo, second];
  const isMine = (nick) => nick === "me";

  assert.deepEqual(
    mergeTimeline([older, first, wire("mine", "me"), second], live, 20, isMine),
    [older, joined, first, echo, second],
    "the overlap is matched past rows history cannot hold, so it is not prepended again",
  );
  // Our own older line is still prepended when it precedes the overlap.
  assert.deepEqual(
    mergeTimeline([wire("earlier", "me"), first, wire("mine", "me"), second], live, 20, isMine),
    [wire("earlier", "me"), joined, first, echo, second],
  );
});

test("history bounded by ring position is prepended whole, with msgids still unique", () => {
  const history = [
    { identity: null, text: "same", wire: ":b!u@h PRIVMSG #c :same" },
    { identity: "m1", text: "identified", wire: ":b!u@h PRIVMSG #c :identified" },
  ];
  const live = [
    { identity: null, text: "same", wire: ":b!u@h PRIVMSG #c :same" },
    { identity: "m1", text: "identified", wire: ":b!u@h PRIVMSG #c :identified" },
  ];
  // Equal wire text is not identity: bounded history is older by position, so
  // its unidentified row stays; the shared msgid appears once.
  assert.deepEqual(prependHistory(history, live, 20), [history[0], ...live]);
});

test("a buffer's ring floor is its oldest row's cursor-before", () => {
  assert.equal(oldestRingFloor([]), undefined);
  assert.equal(oldestRingFloor([{ ringFloor: null }, { ringFloor: "9:4" }]), null);
  assert.equal(oldestRingFloor([{ ringFloor: "9:3" }, { ringFloor: "9:4" }]), "9:3");
});

// ---- outgoing chat: local echo and line splitting -------------------------

test("every composer request that sends chat names its command, targets and body", () => {
  assert.deepEqual(outgoingChat("hello", "#c"), { command: "PRIVMSG", targets: ["#c"], body: "hello" });
  assert.equal(outgoingChat("hello", ""), null, "the console sends no chat without a command");
  // /me in any letter case, as the server lowercases the command.
  for (const me of ["/me waves", "/ME waves", "/Me   waves"]) {
    assert.deepEqual(outgoingChat(me, "bob"), { command: "PRIVMSG", targets: ["bob"], body: "\x01ACTION waves\x01" }, me);
  }
  assert.equal(outgoingChat("/me waves", ""), null);
  assert.deepEqual(outgoingChat("/msg NickServ identify pw", "#c"), {
    command: "PRIVMSG", targets: ["NickServ"], body: "identify pw",
  });
  assert.deepEqual(outgoingChat("/MSG a,#b  hi", ""), { command: "PRIVMSG", targets: ["a", "#b"], body: "hi" });
  assert.deepEqual(outgoingChat("/notice bob heads up", "#c"), { command: "NOTICE", targets: ["bob"], body: "heads up" });
  assert.equal(outgoingChat("/msg bob", "#c"), null);
  // Typed raw, into the console or with /raw and /quote.
  assert.deepEqual(outgoingChat("/raw PRIVMSG NickServ :IDENTIFY pw", ""), {
    command: "PRIVMSG", targets: ["NickServ"], body: "IDENTIFY pw",
  });
  assert.deepEqual(outgoingChat("/quote notice #c :hi there", ""), { command: "NOTICE", targets: ["#c"], body: "hi there" });
  for (const other of ["/join #c", "/nick bob", "/raw WHOIS bob", "/part"]) {
    assert.equal(outgoingChat(other, "#c"), null, other);
  }
});

test("UTF-8 splitting never breaks a code point and keeps words whole where it can", () => {
  const bytes = (text) => new TextEncoder().encode(text).length;
  const emoji = "😀".repeat(10); // 40 bytes
  const pieces = splitUtf8(emoji, 10);
  assert.deepEqual(pieces, ["😀😀", "😀😀", "😀😀", "😀😀", "😀😀"]);
  assert.deepEqual(splitUtf8("aé😀", 3), ["aé", "😀"]);
  assert.deepEqual(splitUtf8("hello world again", 12), ["hello world ", "again"]);
  assert.deepEqual(splitUtf8("abcdefghij", 4), ["abcd", "efgh", "ij"]);
  for (const piece of splitUtf8("x y ".repeat(200) + "é".repeat(300), 50)) assert.ok(bytes(piece) <= 50, piece);
  assert.equal(splitUtf8("x y ".repeat(200), 50).join(""), "x y ".repeat(200));
});

test("a message longer than one relayed IRC line is sent as several requests", () => {
  const bytes = (text) => new TextEncoder().encode(text).length;
  // What the upstream relays: `:nick!user@host PRIVMSG #chan :body`, 510 bytes
  // at most, with the user and host given their usual room.
  const relayed = (nick, line) => bytes(`:${nick}!~abcdefghij@${"h".repeat(63)} ${line}`);
  const short = "hello";
  assert.deepEqual(composerRequests(short, "#chan", "alice"), [short]);

  const long = "word ".repeat(300).trim();
  const plain = composerRequests(long, "#chan", "alice");
  assert.ok(plain.length > 1);
  assert.equal(plain.join(""), long);
  for (const piece of plain) assert.ok(relayed("alice", `PRIVMSG #chan :${piece}`) <= 510, piece.length);

  const action = composerRequests(`/ME ${"ü".repeat(400)}`, "#chan", "alice");
  assert.ok(action.length > 1);
  for (const request of action) {
    assert.match(request, /^\/me /);
    assert.ok(relayed("alice", `PRIVMSG #chan :\x01ACTION ${request.slice(4)}\x01`) <= 510);
  }
  assert.equal(action.map((request) => request.slice(4)).join(""), "ü".repeat(400));

  const direct = composerRequests(`/msg bob ${"z".repeat(900)}`, "", "alice");
  assert.ok(direct.length > 1);
  for (const request of direct) {
    assert.match(request, /^\/msg bob z+$/);
    assert.ok(relayed("alice", `PRIVMSG bob :${request.slice(9)}`) <= 510);
  }
  // A raw line is sent exactly as typed; the server bounds it.
  const raw = `/raw PRIVMSG bob :${"z".repeat(900)}`;
  assert.deepEqual(composerRequests(raw, "", "alice"), [raw]);
  // A nick not yet known is given room for a long one.
  for (const piece of composerRequests(long, "#chan", null)) {
    assert.ok(relayed("n".repeat(30), `PRIVMSG #chan :${piece}`) <= 510);
  }
});

test("an ISUPPORT token list builds the network's table from the defaults", () => {
  const { modes, malformed } = channelModesFromIsupport(["CHANTYPES=#", "PREFIX=(ov)@+", "CHANMODES=eIbq,k,flj,CFLMPQScgimnprstuz"]);
  assert.deepEqual(malformed, []);
  assert.deepEqual(modes.prefix, [["o", "@"], ["v", "+"]]);
  assert.equal(modeTakesParameter(modes, "q", false), true, "+q is a list mode on this network");
  assert.equal(modeTakesParameter(modes, "f", true), true);
  assert.deepEqual(channelModesFromIsupport([]).modes, DEFAULT_CHANNEL_MODES);
  assert.deepEqual(channelModesFromIsupport(["PREFIX=(ov)@"]).malformed, ["PREFIX=(ov)@"]);
});
