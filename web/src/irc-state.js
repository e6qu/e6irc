// SPDX-License-Identifier: AGPL-3.0-or-later

// Pure IRC parsing and timeline helpers shared by the browser client and its
// Node tests. Keeping protocol-shaped state out of main.js makes the ordering
// and identity rules testable without a DOM.

// ---- network naming ------------------------------------------------------
//
// Which targets are channels (CHANTYPES), which sigils narrow a channel
// message to its ranks (STATUSMSG) and when two names are the same
// (CASEMAPPING) are properties of the network, declared in its 005, exactly as
// e6irc-client's NetworkNames reads them. Until they arrive -- and after a 005
// retracts one (`-CASEMAPPING`, `-CHANTYPES`, `-STATUSMSG`) -- RFC 1459 holds:
// `rfc1459` and `#&`, and no STATUSMSG sigils, since a network that advertises
// none cannot be sent a message addressed through one. The mappings known are the server's own (e6irc-proto CaseMapping):
// `rfc1459`, `rfc1459-strict` (also spelled `strict-rfc1459` by older
// servers) and `ascii`. Any other (`rfc7613`, `rfc3454`, ...) is compared as
// `ascii` -- the letters every mapping folds and nothing else -- and kept as
// `unrecognised` so the page can say so rather than guess silently.
export const DEFAULT_NAMES = Object.freeze({
  casemapping: "rfc1459",
  chantypes: "#&",
  statusmsg: "",
  unrecognised: null,
});

const KNOWN_CASEMAPPINGS = new Map([
  ["rfc1459", "rfc1459"],
  ["rfc1459-strict", "rfc1459-strict"],
  ["strict-rfc1459", "rfc1459-strict"],
  ["ascii", "ascii"],
]);

// `value` in the network's canonical case, for keying buffers and nicks.
// Without `names`, RFC 1459 (matching the server's CaseMapping::Rfc1459).
export function fold(value, names = DEFAULT_NAMES) {
  const mapping = names.casemapping;
  const specials = mapping !== "ascii";
  let out = "";
  for (const ch of value) {
    const code = ch.charCodeAt(0);
    if (code >= 65 && code <= 90) out += String.fromCharCode(code + 32);
    else if (specials && ch === "[") out += "{";
    else if (specials && ch === "]") out += "}";
    else if (specials && ch === "\\") out += "|";
    else if (mapping === "rfc1459" && ch === "~") out += "^";
    else out += ch;
  }
  return out;
}

export function isChannel(target, names = DEFAULT_NAMES) {
  return typeof target === "string" && target.length > 0 && names.chantypes.includes(target[0]);
}

// Fold the CASEMAPPING, CHANTYPES and STATUSMSG tokens of one 005 line into
// `current`.
export function namesFrom(params, current = DEFAULT_NAMES) {
  let names = current;
  // <me> TOKEN... :are supported by this server -- tokens never contain spaces.
  for (const token of params.slice(1).filter((param) => !param.includes(" "))) {
    const equals = token.indexOf("=");
    const key = equals === -1 ? token : token.slice(0, equals);
    const value = equals === -1 ? "" : token.slice(equals + 1);
    if (key === "-CASEMAPPING") {
      names = { ...names, casemapping: DEFAULT_NAMES.casemapping, unrecognised: null };
    } else if (key === "CASEMAPPING") {
      const known = KNOWN_CASEMAPPINGS.get(value);
      names = known
        ? { ...names, casemapping: known, unrecognised: null }
        : { ...names, casemapping: "ascii", unrecognised: value };
    } else if (key === "-CHANTYPES") {
      names = { ...names, chantypes: DEFAULT_NAMES.chantypes };
    } else if (key === "CHANTYPES") {
      // `CHANTYPES=` (or a bare `CHANTYPES`): the network has no channels.
      names = { ...names, chantypes: value };
    } else if (key === "-STATUSMSG") {
      names = { ...names, statusmsg: DEFAULT_NAMES.statusmsg };
    } else if (key === "STATUSMSG") {
      names = { ...names, statusmsg: value };
    }
  }
  return Object.freeze(names);
}

// The rules an authoritative session event's ISUPPORT tokens describe: the
// defaults, overridden by the network's own CASEMAPPING, CHANTYPES and
// STATUSMSG.
export function namesFromIsupport(tokens) {
  return namesFrom(["", ...tokens], DEFAULT_NAMES);
}

// Whether two naming rules key names differently, so buffers keyed under one
// must be re-keyed under the other. STATUSMSG decides which buffer a message
// files under, never a buffer's key, so it is not compared.
export function namesDiffer(a, b) {
  return a.casemapping !== b.casemapping || a.chantypes !== b.chantypes;
}

// Re-key a Map of buffers (keyed by fold) under `names`. Two buffers that the
// new rules make one name are merged into the first: its lines, then the
// other's, with their unread counts added. Returns the new map and each
// merged pair, so the page can say what it merged.
export function rekeyBuffers(buffers, names) {
  const rekeyed = new Map();
  const merged = [];
  for (const buffer of buffers.values()) {
    const key = buffer.key === SERVER_KEY ? SERVER_KEY : fold(buffer.display, names);
    const existing = rekeyed.get(key);
    if (existing) {
      existing.lines.push(...buffer.lines);
      existing.unread += buffer.unread;
      existing.mentions += buffer.mentions;
      for (const [, member] of buffer.nicks) existing.nicks.set(fold(member.name, names), member);
      merged.push([existing.display, buffer.display]);
      continue;
    }
    buffer.key = key;
    const nicks = new Map();
    for (const [, member] of buffer.nicks) nicks.set(fold(member.name, names), member);
    buffer.nicks = nicks;
    rekeyed.set(key, buffer);
  }
  return { buffers: rekeyed, merged };
}

// The server buffer's key: not a legal channel or nick, so no fold changes it.
export const SERVER_KEY = "*server*";

// The conversation a message target belongs to, as e6irc-client's
// NetworkNames::conversation decides it: a STATUSMSG target (`@#ops`, `%#dev`
// where the network advertises those sigils) is its channel's conversation
// with a narrower audience, so its sigils come off; anything else is already
// the conversation, and sigils in front of what is not a channel are part of a
// nickname. A sigil can also be a channel type (`&` on Ergo and InspIRCd), so
// the fewest sigils that leave a channel are taken off: `@&local` is
// `&local`'s, `&#dev` is `#dev`'s.
function conversationTarget(target, names = DEFAULT_NAMES, isKnownChannel = () => false) {
  let rest = target;
  while (rest.length > 0 && names.statusmsg.includes(rest[0])) {
    rest = rest.slice(1);
    if (isChannel(rest, names) || isKnownChannel(rest)) return rest;
  }
  return target;
}

// Route chat-bearing commands through one policy for both live delivery and
// persisted history. A STATUSMSG target belongs in its channel's buffer.
export function chatMessageRoute(message, ownNick, isKnownChannel = () => false, names = DEFAULT_NAMES) {
  if (
    (message.command !== "PRIVMSG" && message.command !== "NOTICE")
    || typeof message.params?.[0] !== "string"
    || typeof message.params?.[1] !== "string"
  ) return null;

  const wireTarget = message.params[0];
  const target = conversationTarget(wireTarget, names, isKnownChannel);

  if (isChannel(target, names) || isKnownChannel(target)) return { kind: "channel", target };
  if (
    wireTarget === "*"
    || wireTarget === ""
    || (message.command === "NOTICE" && !message.sourceIsUser)
  ) return { kind: "server", target: null };

  const sentByUs = Boolean(
    message.nick && ownNick && fold(message.nick, names) === fold(ownNick, names),
  );
  return { kind: "dm", target: sentByUs ? wireTarget : (message.nick || wireTarget) };
}

// ---- channel modes -------------------------------------------------------
//
// Which modes rank a member, which sigil each shows, and which modes consume a
// MODE parameter are properties of the network, declared in its 005 PREFIX and
// CHANMODES. Until they arrive this RFC/Charybdis-style table applies. Reading
// every network with it misassigns arguments: on Libera (`PREFIX=(ov)@+`,
// `CHANMODES=eIbq,k,flj,...`) `+fo #overflow alice` would hand #overflow to
// `o`, and `+q mask` -- a quiet list entry -- would be taken for an owner.
export const DEFAULT_CHANNEL_MODES = Object.freeze({
  // [mode, sigil], highest rank first, as PREFIX orders them.
  prefix: Object.freeze([["q", "~"], ["a", "&"], ["o", "@"], ["h", "%"], ["v", "+"]].map(Object.freeze)),
  list: "beI", // type A: a parameter whether set or unset
  alwaysParameter: "k", // type B: likewise
  setParameter: "l", // type C: a parameter only when set
});

// Fold the CHANMODES and PREFIX tokens of one 005 line into `current`. A token
// that cannot be read leaves the table alone and is returned, so the caller can
// say so instead of quietly reading the network with the wrong table.
export function channelModesFrom(params, current = DEFAULT_CHANNEL_MODES) {
  let modes = current;
  const malformed = [];
  // <me> TOKEN... :are supported by this server -- tokens never contain spaces.
  for (const token of params.slice(1).filter((param) => !param.includes(" "))) {
    const equals = token.indexOf("=");
    const key = equals === -1 ? token : token.slice(0, equals);
    const value = equals === -1 ? "" : token.slice(equals + 1);
    if (key === "CHANMODES") {
      const classes = value.split(",");
      if (classes.length < 4) {
        malformed.push(token);
        continue;
      }
      modes = { ...modes, list: classes[0], alwaysParameter: classes[1], setParameter: classes[2] };
    } else if (key === "PREFIX") {
      if (value === "") {
        modes = { ...modes, prefix: [] };
        continue;
      }
      const match = value.match(/^\(([A-Za-z]*)\)(.*)$/);
      if (!match || match[1].length !== match[2].length) {
        malformed.push(token);
        continue;
      }
      modes = { ...modes, prefix: [...match[1]].map((mode, index) => [mode, match[2][index]]) };
    }
  }
  return { modes, malformed };
}

// The table an authoritative session event's ISUPPORT tokens describe: the
// defaults, overridden by the network's own PREFIX and CHANMODES. Built from
// the defaults rather than folded into the current table, because the session
// states the whole of what the network advertises now.
export function channelModesFromIsupport(tokens) {
  return channelModesFrom(["", ...tokens], DEFAULT_CHANNEL_MODES);
}

export function isPrefixMode(modes, mode) {
  return modes.prefix.some(([prefixMode]) => prefixMode === mode);
}

export function modeTakesParameter(modes, mode, adding) {
  return isPrefixMode(modes, mode)
    || modes.list.includes(mode)
    || modes.alwaysParameter.includes(mode)
    || (adding && modes.setParameter.includes(mode));
}

// Pair each mode letter of a MODE line with its argument, consuming arguments
// only for the modes the table says take one, so a mixed line like `+o-l nick`
// maps the nick to `o`, not `l`.
export function modeChanges(modes, modestr, args) {
  const changes = [];
  let adding = true;
  let next = 0;
  for (const mode of modestr) {
    if (mode === "+") adding = true;
    else if (mode === "-") adding = false;
    else {
      const argument = modeTakesParameter(modes, mode, adding) ? args[next++] : undefined;
      changes.push({ mode, adding, argument });
    }
  }
  return changes;
}

export function splitSigil(nick, modes = DEFAULT_CHANNEL_MODES) {
  const value = nick || "";
  const modeOfSigil = new Map(modes.prefix.map(([mode, sigil]) => [sigil, mode]));
  let index = 0;
  while (index < value.length && modeOfSigil.has(value[index])) index += 1;
  const memberModes = new Set();
  for (const sigil of value.slice(0, index)) memberModes.add(modeOfSigil.get(sigil));
  return { name: value.slice(index), modes: memberModes };
}

export function stripSigil(nick, modes = DEFAULT_CHANNEL_MODES) {
  return splitSigil(nick, modes).name;
}

export function nickPrefix(memberModes, modes = DEFAULT_CHANNEL_MODES) {
  for (const [mode, sigil] of modes.prefix) {
    if (memberModes.has(mode)) return sigil;
  }
  return "";
}

// A member's position in the rank order: 0 for the highest declared rank,
// `prefix.length` for no rank at all.
export function memberRank(memberModes, modes = DEFAULT_CHANNEL_MODES) {
  const index = modes.prefix.findIndex(([mode]) => memberModes.has(mode));
  return index === -1 ? modes.prefix.length : index;
}

export function parseIrc(line) {
  let rest = line;
  let tags = null;
  if (rest.startsWith("@")) {
    const space = rest.indexOf(" ");
    tags = rest.slice(1, space === -1 ? undefined : space);
    rest = space === -1 ? "" : rest.slice(space + 1);
  }
  let prefix = null;
  if (rest.startsWith(":")) {
    const space = rest.indexOf(" ");
    prefix = rest.slice(1, space === -1 ? undefined : space);
    rest = space === -1 ? "" : rest.slice(space + 1);
  }
  let trailing = null;
  if (rest.startsWith(":")) {
    trailing = rest.slice(1);
    rest = "";
  } else {
    const trailingIndex = rest.indexOf(" :");
    if (trailingIndex >= 0) {
      trailing = rest.slice(trailingIndex + 2);
      rest = rest.slice(0, trailingIndex);
    }
  }
  const params = rest.split(" ").filter((part) => part.length);
  const command = (params.shift() || "").toUpperCase();
  if (trailing !== null) params.push(trailing);
  const nick = prefix ? prefix.split(/[!@]/, 1)[0] : null;
  const sourceIsUser = prefix != null && (prefix.includes("!") || prefix.includes("@"));
  return { tags, nick, sourceIsUser, command, params };
}

function unescapeTagValue(value) {
  let out = "";
  for (let index = 0; index < value.length; index += 1) {
    if (value[index] !== "\\") {
      out += value[index];
      continue;
    }
    index += 1;
    if (index >= value.length) break;
    const escaped = value[index];
    if (escaped === ":") out += ";";
    else if (escaped === "s") out += " ";
    else if (escaped === "r") out += "\r";
    else if (escaped === "n") out += "\n";
    else out += escaped;
  }
  return out;
}

export function tagValue(tags, name) {
  if (!tags) return null;
  const entries = tags.split(";");
  // Match e6irc-proto's duplicate-tag rule: the last occurrence wins.
  for (let index = entries.length - 1; index >= 0; index -= 1) {
    const tag = entries[index];
    const equals = tag.indexOf("=");
    const key = equals === -1 ? tag : tag.slice(0, equals);
    if (key !== name) continue;
    return equals === -1 ? "" : unescapeTagValue(tag.slice(equals + 1));
  }
  return null;
}

// Only a non-empty upstream msgid is a stable identity. Content equality is
// deliberately not used: two distinct IRC messages may have identical source,
// body, and timestamp, and merging them would silently erase one.
export function messageIdentity(tags) {
  return tagValue(tags, "msgid") || null;
}

// IRC permits a comma-separated target list in membership commands. Parse it
// once here so replayed/live JOIN, PART, and KICK update browser state with the
// same semantics as the BNC's authoritative session tracker.
export function membershipTargets(value) {
  if (typeof value !== "string") return [];
  return value.split(",").filter((target) => target.length > 0);
}

export function kickPairs(channelsValue, targetsValue) {
  const channels = membershipTargets(channelsValue);
  const targets = membershipTargets(targetsValue);
  if (channels.length === targets.length) {
    return channels.map((channel, index) => [channel, targets[index]]);
  }
  if (channels.length === 1) {
    return targets.map((target) => [channels[0], target]);
  }
  return [];
}

// The channel buffer already open for `name`, or null. A topic or NAMES reply
// describes a channel; it is not a reason to open one. `/topic #elsewhere`,
// `/names #elsewhere` and the `*` of a NAMES reply for no channel would
// otherwise each leave a conversation in the list the person never joined.
// (The line itself is still shown: every line reaches the console.)
export function existingChannelBuffer(buffers, name, names = DEFAULT_NAMES) {
  if (typeof name !== "string") return null;
  const buffer = buffers.get(fold(name, names));
  return buffer?.kind === "channel" ? buffer : null;
}

// Empty a buffer's transcript so the server's full replay can refill it. The
// persisted history loaded into it went with the lines, so "Load earlier" is
// offered again rather than hidden for the rest of the page's life.
export function clearTranscript(buffer) {
  buffer.lines.length = 0;
  buffer.unread = 0;
  buffer.mentions = 0;
  buffer.pendingVisibleMessages = 0;
  buffer.historyLoaded = false;
}

export function topicReply(params) {
  if (
    !Array.isArray(params)
    || typeof params[1] !== "string"
    || !params[1]
    || typeof params[2] !== "string"
  ) return null;
  return { channel: params[1], topic: params[2] };
}

// mIRC-style formatting: bold, italic, underline, strikethrough, monospace,
// reverse and reset are single control bytes; colour is ^C with up to two
// decimal pairs, and hex colour is ^D with up to two six-digit values. This
// client renders plain text, so they are removed -- otherwise coloured bot
// output and topics read as `04,01text`.
const FORMATTING = /\x03(?:\d{1,2}(?:,\d{1,2})?)?|\x04(?:[0-9a-fA-F]{6}(?:,[0-9a-fA-F]{6})?)?|[\x02\x0f\x11\x16\x1d\x1e\x1f]/g;

export function stripFormatting(text) {
  return String(text ?? "").replace(FORMATTING, "");
}

// The reason a PART, KICK or QUIT carries, as the ` (reason)` its event line
// ends with, or nothing. Every membership event renders its reason through
// here, so none can show a bot's colour codes as `04,01text`; a reason that
// is only formatting is no reason.
export function reasonSuffix(reason) {
  const text = stripFormatting(reason);
  return text ? ` (${text})` : "";
}

// Bidirectional embedding, override and isolate controls (LRE, RLE, PDF, LRO,
// RLO, LRI, RLI, FSI, PDI). In another person's text they reorder what follows
// them, so a link can read as a different address than the one it opens, or a
// line can appear to say something it does not. Right-to-left text needs none
// of them: the rendered text is isolated and laid out by the bidi algorithm on
// its own characters.
const BIDI_CONTROLS = /[\u202A-\u202E\u2066-\u2069]/g;

export function stripBidiControls(text) {
  return String(text ?? "").replace(BIDI_CONTROLS, "");
}

// A CTCP ACTION (`\x01ACTION text\x01`) renders as "* nick text". Any other
// CTCP is named rather than shown as raw \x01 bytes. `sender` is who said it,
// for highlighting: an action is something a person says, and one naming you
// is a mention; a CTCP request is a client asking another client something.
export function asMessage(kind, from, text) {
  const action = text.match(/^\x01ACTION (.*?)\x01?$/s);
  if (action) return { kind: "event", from: null, sender: from, text: `* ${from} ${stripFormatting(action[1])}` };
  const ctcp = text.match(/^\x01([^\x01 ]+)(?: (.*?))?\x01?$/s);
  if (ctcp) {
    const detail = ctcp[2] ? `: ${stripFormatting(ctcp[2])}` : "";
    return { kind: "event", from: null, sender: null, text: `${from} sent a CTCP ${ctcp[1]} request${detail}` };
  }
  return { kind, from, sender: from, text: stripFormatting(text) };
}

// ---- outgoing chat -------------------------------------------------------
//
// What a composer request sends as conversation, mirroring the server's
// `slash_to_irc`: plain text to the open conversation, `/me`, `/msg`,
// `/notice`, and a PRIVMSG or NOTICE typed raw (`/raw`, `/quote`, or into the
// console). The server does not echo a line back to the socket that sent it,
// so this is what the page shows once the send is accepted, in the buffer the
// line is addressed to. `compose` rebuilds the request for a piece of the body
// (null when the request is sent exactly as typed and cannot be split).
function composerForm(text, target) {
  const form = (command, to, body, compose, wrap = ["", ""]) => ({ command, to, body, compose, wrap });
  if (!text.startsWith("/")) {
    return target && text ? form("PRIVMSG", target, text, (piece) => piece) : null;
  }
  const slash = text.slice(1);
  const space = slash.indexOf(" ");
  const command = (space === -1 ? slash : slash.slice(0, space)).toLowerCase();
  const rest = (space === -1 ? "" : slash.slice(space + 1)).trimStart();
  if (command === "me") {
    return target && rest
      ? form("PRIVMSG", target, rest, (piece) => `/me ${piece}`, ["\x01ACTION ", "\x01"])
      : null;
  }
  if (command === "msg" || command === "notice") {
    const gap = rest.search(/\s/);
    if (gap <= 0) return null;
    const to = rest.slice(0, gap);
    const body = rest.slice(gap + 1).trimStart();
    if (!body) return null;
    return form(command === "msg" ? "PRIVMSG" : "NOTICE", to, body, (piece) => `/${command} ${to} ${piece}`);
  }
  if (command === "raw" || command === "quote") {
    const line = parseIrc(rest);
    if ((line.command !== "PRIVMSG" && line.command !== "NOTICE") || line.params.length < 2) return null;
    return form(line.command, line.params[0], line.params[1], null);
  }
  return null;
}

// The chat a composer request sends, one entry per addressed target, or null
// for a request that is not conversation (`/join`, `/nick`, a raw command…).
export function outgoingChat(text, target) {
  const form = composerForm(text, target);
  if (!form) return null;
  const body = `${form.wrap[0]}${form.body}${form.wrap[1]}`;
  const targets = membershipTargets(form.to);
  return targets.length ? { command: form.command, targets, body } : null;
}

// An IRC line is 512 bytes with its CRLF (e6irc-proto MAX_LINE_LEN), and the
// upstream relays ours to everyone else behind our full source,
// `:nick!user@host `. The nick is known; the user and host are the network's to
// choose, so their room is reserved at the usual limits (a `~`-prefixed
// 10-byte USERLEN, a 63-byte HOSTLEN). A nick not yet known is given NICKLEN's
// customary 30 bytes.
const IRC_LINE_BYTES = 510;
const SOURCE_ROOM_BYTES = ":".length + "!".length + 11 + "@".length + 63 + " ".length;
const UNKNOWN_NICK_BYTES = 30;

const utf8 = new TextEncoder();
const utf8Length = (text) => utf8.encode(text).length;

// Split `text` into pieces of at most `budget` UTF-8 bytes, never inside a
// code point. A piece ends after its last space when that space is in the
// piece's second half, so words stay whole where they can; the space stays
// with the piece before it, so joining the pieces gives back `text`.
export function splitUtf8(text, budget) {
  const pieces = [];
  let piece = "";
  let bytes = 0;
  for (const point of text) {
    const size = utf8Length(point);
    if (bytes + size > budget && piece) {
      const space = piece.lastIndexOf(" ");
      const cut = space >= piece.length / 2 ? space + 1 : piece.length;
      pieces.push(piece.slice(0, cut));
      piece = piece.slice(cut);
      bytes = utf8Length(piece);
    }
    piece += point;
    bytes += size;
  }
  if (piece) pieces.push(piece);
  return pieces;
}

// The composer requests that send `text`: the request itself when it fits one
// IRC line as relayed (or is sent exactly as typed, which the server bounds),
// else one request per piece. The server refuses an over-long line whole
// rather than truncating it, so a long message is split here.
export function composerRequests(text, target, nick) {
  const form = composerForm(text, target);
  if (!form?.compose) return [text];
  const source = SOURCE_ROOM_BYTES + (nick ? utf8Length(nick) : UNKNOWN_NICK_BYTES);
  const frame = utf8Length(`${form.command} ${form.to} :${form.wrap[0]}${form.wrap[1]}`);
  const budget = IRC_LINE_BYTES - source - frame;
  if (budget < 1 || utf8Length(form.body) <= budget) return [text];
  return splitUtf8(form.body, budget).map(form.compose);
}

// Prepend older history to the live buffer. Stable msgids suppress a line
// present on both sides; unidentified rows remain distinct, because content
// equality is not identity. The cap applies last, to the oldest rows.
export function prependHistory(history, live, limit) {
  const seen = new Set();
  for (const line of live) {
    if (line.identity) seen.add(line.identity);
  }
  const prependReversed = [];
  for (let index = history.length - 1; index >= 0; index -= 1) {
    const line = history[index];
    if (line.identity && seen.has(line.identity)) continue;
    if (line.identity) seen.add(line.identity);
    prependReversed.push(line);
  }
  prependReversed.reverse();
  return [...prependReversed, ...live].slice(-limit);
}

// What a row is matched by at the seam between history and the live buffer:
// its exact wire line; for a line of our own, what it said, since this page
// shows its own sends as local echoes that have no wire line; nothing for a
// join or part notice, which history has no counterpart for.
function seamKey(line, isMine) {
  if (line.sender != null && isMine(line.sender)) return `mine\n${line.kind}\n${line.text}`;
  return typeof line.wire === "string" && line.wire.length > 0 ? line.wire : null;
}

// Merge history that may overlap the live buffer, for when the server could
// not bound it by ring position (see `oldestRingFloor`). The API page and the
// socket replay can share an ordered suffix / prefix even when an upstream
// supplies no msgid; remove only that exact ordered sequence, never arbitrary
// equal bodies elsewhere. Live rows without a seam key take no part: letting
// a join notice stop the match would prepend the whole overlap again.
export function mergeTimeline(history, live, limit, isMine = () => false) {
  const keyed = live.map((line) => seamKey(line, isMine)).filter((key) => key !== null);
  let overlap = 0;
  const maximum = Math.min(history.length, keyed.length);
  for (let size = 1; size <= maximum; size += 1) {
    const historyStart = history.length - size;
    let matches = true;
    for (let index = 0; index < size; index += 1) {
      const older = seamKey(history[historyStart + index], isMine);
      if (older === null || older !== keyed[index]) {
        matches = false;
        break;
      }
    }
    if (matches) overlap = size;
  }
  return prependHistory(history.slice(0, history.length - overlap), live, limit);
}

// Every row a buffer holds records `ringFloor`: the socket's replay cursor
// before the line that made it (for a local echo, before the echo's own ring
// line, which this socket is never sent). Rows arrive in ring order, so the
// oldest row's floor bounds the buffer: every later ring line addressed here is
// already a row. History read `through` it therefore holds nothing twice.
// `undefined` when the buffer has no rows (all of its history is new to it),
// `null` when its oldest row came first in a full replay (the page holds the
// buffer from the ring's start).
export function oldestRingFloor(lines) {
  return lines.length ? lines[0].ringFloor ?? null : undefined;
}

// What a buffer's action button does: "leave" a joined channel, "close" a
// past channel or a conversation, or nothing (null) for the console. A
// bridge's channels are its configuration -- the provider account, not the
// person, is in them (`membershipIsIrc` false) -- so a joined bridge channel
// has nothing to leave, and a PART would only be refused.
export function bufferAction(buffer, membershipIsIrc) {
  if (!buffer || buffer.kind === "server") return null;
  if (buffer.kind === "channel" && buffer.joined) return membershipIsIrc ? "leave" : null;
  return "close";
}

// The nick a network's stored configuration gives before the server names
// one. A bridge stores none (an empty string); an empty nick is no nick, or
// every line with a leading or trailing non-nick character would read as a
// mention of it.
export function seededNick(configured) {
  return typeof configured === "string" && configured.length > 0 ? configured : null;
}

// Reconcile channel buffers against an authoritative BNC session snapshot.
// Detached replay is bounded history and cannot answer current membership.
export function reconcileChannelSnapshot(current, joined, names = DEFAULT_NAMES) {
  const key = (channel) => fold(channel, names);
  const joinedByKey = new Map();
  for (const channel of joined) {
    if (!joinedByKey.has(key(channel))) joinedByKey.set(key(channel), channel);
  }
  const currentKeys = new Set(current.map(key));
  return Object.freeze({
    removed: Object.freeze(current.filter((channel) => !joinedByKey.has(key(channel)))),
    added: Object.freeze(
      [...joinedByKey.values()].filter((channel) => !currentKeys.has(key(channel))),
    ),
    joined: Object.freeze([...joinedByKey.values()]),
  });
}
