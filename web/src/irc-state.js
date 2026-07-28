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
  const nick = prefix ? prefix.split("!")[0] : null;
  return { tags, nick, command, params };
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
  for (const tag of tags.split(";")) {
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

// A CTCP ACTION (`\x01ACTION text\x01`) renders as "* nick text".
export function asMessage(kind, from, text) {
  const action = text.match(/^\x01ACTION (.*?)\x01?$/s);
  if (action) return { kind: "event", from: null, text: `* ${from} ${action[1]}` };
  return { kind, from, text };
}

// Prepend persisted history without replacing lines already present in the
// live buffer. Rows sharing a stable msgid are included once; rows without an
// identity are all retained because content-based deduplication loses valid
// repeated messages.
export function mergeTimeline(history, live, limit) {
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
