// SPDX-License-Identifier: AGPL-3.0-or-later

// Pure IRC parsing and timeline helpers shared by the browser client and its
// Node tests. Keeping protocol-shaped state out of main.js makes the ordering
// and identity rules testable without a DOM.

// RFC1459 casefold, matching the server's CaseMapping::Rfc1459.
export function fold(value) {
  let out = "";
  for (const ch of value) {
    const code = ch.charCodeAt(0);
    if (code >= 65 && code <= 90) out += String.fromCharCode(code + 32);
    else if (ch === "[") out += "{";
    else if (ch === "]") out += "}";
    else if (ch === "\\") out += "|";
    else if (ch === "~") out += "^";
    else out += ch;
  }
  return out;
}

export function isChannel(target) {
  return target.startsWith("#") || target.startsWith("&");
}

// Route chat-bearing commands through one policy for both live delivery and
// persisted history. IRC STATUSMSG prefixes such as `@#ops` address a subset
// of a channel but still belong in that channel's buffer.
export function chatMessageRoute(message, ownNick, isKnownChannel = () => false) {
  if (
    (message.command !== "PRIVMSG" && message.command !== "NOTICE")
    || typeof message.params?.[0] !== "string"
    || typeof message.params?.[1] !== "string"
  ) return null;

  const wireTarget = message.params[0];
  let target = wireTarget;
  let statusLength = 0;
  while (statusLength < target.length && "@+".includes(target[statusLength])) {
    statusLength += 1;
  }
  if (statusLength > 0) {
    const candidate = target.slice(statusLength);
    if (isChannel(candidate) || isKnownChannel(candidate)) target = candidate;
  }

  if (isChannel(target) || isKnownChannel(target)) return { kind: "channel", target };
  if (
    wireTarget === "*"
    || wireTarget === ""
    || (message.command === "NOTICE" && !message.sourceIsUser)
  ) return { kind: "server", target: null };

  const sentByUs = Boolean(
    message.nick && ownNick && fold(message.nick) === fold(ownNick),
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

// A CTCP ACTION (`\x01ACTION text\x01`) renders as "* nick text". Any other
// CTCP is named rather than shown as raw \x01 bytes.
export function asMessage(kind, from, text) {
  const action = text.match(/^\x01ACTION (.*?)\x01?$/s);
  if (action) return { kind: "event", from: null, text: `* ${from} ${stripFormatting(action[1])}` };
  const ctcp = text.match(/^\x01([^\x01 ]+)(?: (.*?))?\x01?$/s);
  if (ctcp) {
    const detail = ctcp[2] ? `: ${stripFormatting(ctcp[2])}` : "";
    return { kind: "event", from: null, text: `${from} sent a CTCP ${ctcp[1]} request${detail}` };
  }
  return { kind, from, text: stripFormatting(text) };
}

// Prepend persisted history without replacing lines already present in the
// live buffer. The API page and socket replay can share an ordered suffix /
// prefix even when an upstream supplies no msgid; remove only that exact wire
// sequence, never arbitrary equal bodies. Stable msgids cover non-contiguous
// overlap. Unidentified rows outside the ordered overlap remain distinct.
export function mergeTimeline(history, live, limit) {
  let overlap = 0;
  const maximum = Math.min(history.length, live.length);
  for (let size = 1; size <= maximum; size += 1) {
    const historyStart = history.length - size;
    let matches = true;
    for (let index = 0; index < size; index += 1) {
      const olderWire = history[historyStart + index].wire;
      const liveWire = live[index].wire;
      if (typeof olderWire !== "string" || olderWire.length === 0 || olderWire !== liveWire) {
        matches = false;
        break;
      }
    }
    if (matches) overlap = size;
  }

  const seen = new Set();
  for (const line of live) {
    if (line.identity) seen.add(line.identity);
  }
  const prependReversed = [];
  for (let index = history.length - overlap - 1; index >= 0; index -= 1) {
    const line = history[index];
    if (line.identity && seen.has(line.identity)) continue;
    if (line.identity) seen.add(line.identity);
    prependReversed.push(line);
  }
  prependReversed.reverse();
  return [...prependReversed, ...live].slice(-limit);
}

// Reconcile channel buffers against an authoritative BNC session snapshot.
// Detached replay is bounded history and cannot answer current membership.
export function reconcileChannelSnapshot(current, joined) {
  const joinedByKey = new Map();
  for (const channel of joined) {
    const key = fold(channel);
    if (!joinedByKey.has(key)) joinedByKey.set(key, channel);
  }
  const currentKeys = new Set(current.map(fold));
  return Object.freeze({
    removed: Object.freeze(current.filter((channel) => !joinedByKey.has(fold(channel)))),
    added: Object.freeze(
      [...joinedByKey.values()].filter((channel) => !currentKeys.has(fold(channel))),
    ),
    joined: Object.freeze([...joinedByKey.values()]),
  });
}
