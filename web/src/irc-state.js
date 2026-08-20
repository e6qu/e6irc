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

// Channel membership sigils and their underlying modes, highest rank first.
export const MEMBER_RANKS = [
  ["q", "~"],
  ["a", "&"],
  ["o", "@"],
  ["h", "%"],
  ["v", "+"],
];

const SIGIL_MODE = { "~": "q", "&": "a", "@": "o", "%": "h", "+": "v" };

export function splitSigil(nick) {
  const value = nick || "";
  let index = 0;
  while (index < value.length && SIGIL_MODE[value[index]] !== undefined) index += 1;
  const modes = new Set();
  for (const sigil of value.slice(0, index)) modes.add(SIGIL_MODE[sigil]);
  return { name: value.slice(index), modes };
}

export function stripSigil(nick) {
  return splitSigil(nick).name;
}

export function nickPrefix(modes) {
  for (const [mode, sigil] of MEMBER_RANKS) {
    if (modes.has(mode)) return sigil;
  }
  return "";
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

// A CTCP ACTION (`\x01ACTION text\x01`) renders as "* nick text".
export function asMessage(kind, from, text) {
  const action = text.match(/^\x01ACTION (.*?)\x01?$/s);
  if (action) return { kind: "event", from: null, text: `* ${from} ${action[1]}` };
  return { kind, from, text };
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
