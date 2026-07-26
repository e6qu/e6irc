// e6irc web client: a small in-browser IRC client over the /ws/ui socket.
//
// The socket streams JSON events ({t:"line",v:"<raw IRC line>"} and
// {t:"status",v:"connected"}). This module parses each IRC line, routes it to
// the right buffer (a channel, a direct message, or the server buffer), keeps a
// per-channel member list, and renders the active buffer. All rendering uses
// textContent / DOM APIs — never innerHTML with server text — so a hostile
// upstream line cannot inject markup.
//
// Query parameters:
//   network — the BNC network to attach to (required)

import "./style.css";

const params = new URLSearchParams(window.location.search);
const network = params.get("network");

const el = (id) => document.getElementById(id);
const statusEl = el("status");
const buffersEl = el("buffers");
const messagesEl = el("messages");
const bufnameEl = el("bufname");
const buftopicEl = el("buftopic");
const nicklistEl = el("nicklist");
const nicksEl = el("nicks");
const nickcountEl = el("nickcount");
const composer = el("composer");
const messageInput = el("message");

const MAX_LINES = 500;
// Bounds against a hostile upstream that streams distinct channels/senders or a
// giant NAMES list: buffers and per-channel members can't grow without limit.
const MAX_BUFFERS = 200;
const MAX_NICKS = 5000;
const SERVER = "*server*";

// RFC1459 casefold, matching the server's CaseMapping::Rfc1459, so a nick or
// channel is deduplicated case-insensitively (`Alice`/`alice`, `#Chan`/`#chan`).
function fold(s) {
  let out = "";
  for (const ch of s) {
    const c = ch.charCodeAt(0);
    if (c >= 65 && c <= 90) out += String.fromCharCode(c + 32);
    else if (ch === "[") out += "{";
    else if (ch === "]") out += "}";
    else if (ch === "\\") out += "|";
    else if (ch === "~") out += "^";
    else out += ch;
  }
  return out;
}

// name -> { name, kind: "server"|"channel"|"dm", lines: [], nicks: Map, topic, unread }
const buffers = new Map();
let active = null;
let myNick = null;
let socket = null;

function setStatus(text, cls) {
  statusEl.textContent = text;
  statusEl.className = `status status-${cls}`;
}

// Buffers and nicks are keyed by their casefold; the original casing is kept in
// `.display` (buffers) / the nick map's value for rendering.
function ensureBuffer(name, kind) {
  const key = fold(name);
  let b = buffers.get(key);
  if (b) return b;
  // At the cap, a *new* buffer overflows into the server buffer rather than
  // growing the map without bound — the content is still shown, never dropped.
  if (buffers.size >= MAX_BUFFERS) return buffers.get(SERVER);
  b = { key, display: name, kind, lines: [], nicks: new Map(), topic: "", unread: 0 };
  buffers.set(key, b);
  renderBufferList();
  return b;
}

function isChannel(target) {
  return target.startsWith("#") || target.startsWith("&");
}

function stripSigil(nick) {
  return (nick || "").replace(/^[~&@%+]+/, "");
}

// ---- rendering ----------------------------------------------------------

function renderBufferList() {
  buffersEl.replaceChildren();
  const order = [...buffers.values()].sort((a, b) => {
    if (a.key === SERVER) return -1;
    if (b.key === SERVER) return 1;
    return a.display.localeCompare(b.display);
  });
  for (const b of order) {
    const li = document.createElement("li");
    li.className = "buf" + (b.key === active ? " active" : "");
    const label = document.createElement("span");
    label.className = "buf-name";
    label.textContent = b.key === SERVER ? "server" : b.display;
    li.appendChild(label);
    if (b.unread > 0 && b.key !== active) {
      const badge = document.createElement("span");
      badge.className = "badge";
      badge.textContent = String(b.unread);
      li.appendChild(badge);
    }
    li.addEventListener("click", () => setActive(b.key));
    buffersEl.appendChild(li);
  }
}

function messageRow(line) {
  const row = document.createElement("li");
  row.className = "line line-" + line.kind;
  const time = document.createElement("span");
  time.className = "ts";
  time.textContent = line.time;
  const from = document.createElement("span");
  from.className = "from";
  from.textContent = line.from ? line.from : "";
  const text = document.createElement("span");
  text.className = "text";
  text.textContent = line.text;
  row.append(time, from, text);
  return row;
}

function renderActive() {
  const b = buffers.get(active);
  bufnameEl.textContent = !b || b.key === SERVER ? "server" : b.display;
  buftopicEl.textContent = b ? b.topic : "";
  messagesEl.replaceChildren();
  if (b) for (const line of b.lines) messagesEl.appendChild(messageRow(line));
  messagesEl.scrollTop = messagesEl.scrollHeight;
  renderNickList();
}

function renderNickList() {
  const b = buffers.get(active);
  if (!b || b.kind !== "channel") {
    nicklistEl.hidden = true;
    return;
  }
  nicklistEl.hidden = false;
  const names = [...b.nicks.values()].sort((a, c) => a.localeCompare(c));
  nickcountEl.textContent = String(names.length);
  nicksEl.replaceChildren();
  for (const n of names) {
    const li = document.createElement("li");
    li.textContent = n;
    nicksEl.appendChild(li);
  }
}

function setActive(name) {
  active = fold(name);
  const b = buffers.get(active);
  if (b) b.unread = 0;
  renderBufferList();
  renderActive();
  messageInput.focus();
}

// ---- buffer mutation ----------------------------------------------------

function nowHm() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}`;
}

function addLine(bufName, kind, bufKind, from, text) {
  const b = ensureBuffer(bufName, bufKind);
  const line = { time: nowHm(), from, text, kind };
  b.lines.push(line);
  if (b.lines.length > MAX_LINES) b.lines.shift();
  if (b.key === active) {
    const nearBottom =
      messagesEl.scrollHeight - messagesEl.scrollTop - messagesEl.clientHeight < 40;
    messagesEl.appendChild(messageRow(line));
    // Trim on the actual DOM node count — the model was already clamped above,
    // so a guard on `b.lines.length` would never fire and the DOM would grow
    // without bound while pinned to one channel.
    while (messagesEl.children.length > MAX_LINES && messagesEl.firstChild) {
      messagesEl.removeChild(messagesEl.firstChild);
    }
    if (nearBottom) messagesEl.scrollTop = messagesEl.scrollHeight;
  } else {
    b.unread += 1;
    renderBufferList();
  }
}

const addServer = (text) => addLine(SERVER, "server", "server", null, text);
const addEvent = (chan, text) => addLine(chan, "event", "channel", null, text);

function addNick(chan, nick) {
  const display = stripSigil(nick);
  if (!display) return;
  const b = ensureBuffer(chan, "channel");
  if (b.nicks.size >= MAX_NICKS && !b.nicks.has(fold(display))) return;
  b.nicks.set(fold(display), display);
  if (b.key === active) renderNickList();
}

function removeNick(chan, nick) {
  const b = buffers.get(fold(chan));
  if (b && b.nicks.delete(fold(stripSigil(nick))) && b.key === active) renderNickList();
}

function removeNickEverywhere(nick, text) {
  const key = fold(stripSigil(nick));
  if (!key) return;
  for (const b of buffers.values()) {
    if (b.kind === "channel" && b.nicks.delete(key)) addEvent(b.display, text);
  }
  if (active) renderNickList();
}

function renameNick(from, to) {
  const fromKey = fold(stripSigil(from));
  const toDisplay = stripSigil(to);
  if (!fromKey || !toDisplay) return;
  for (const b of buffers.values()) {
    if (b.kind === "channel" && b.nicks.delete(fromKey)) {
      b.nicks.set(fold(toDisplay), toDisplay);
      addEvent(b.display, `${from} is now ${to}`);
    }
  }
  if (active) renderNickList();
}

function setTopic(chan, topic) {
  const b = ensureBuffer(chan, "channel");
  b.topic = topic || "";
  if (b.key === active) buftopicEl.textContent = b.topic;
}

// ---- IRC line parsing + routing ----------------------------------------

function parseIrc(line) {
  let rest = line;
  let prefix = null;
  if (rest.startsWith(":")) {
    const sp = rest.indexOf(" ");
    prefix = rest.slice(1, sp === -1 ? undefined : sp);
    rest = sp === -1 ? "" : rest.slice(sp + 1);
  }
  let trailing = null;
  if (rest.startsWith(":")) {
    trailing = rest.slice(1);
    rest = "";
  } else {
    const ti = rest.indexOf(" :");
    if (ti >= 0) {
      trailing = rest.slice(ti + 2);
      rest = rest.slice(0, ti);
    }
  }
  const parts = rest.split(" ").filter((s) => s.length);
  const command = (parts.shift() || "").toUpperCase();
  if (trailing !== null) parts.push(trailing);
  const nick = prefix ? prefix.split("!")[0] : null;
  return { nick, command, params: parts };
}

// Is this our own nick? Compared under the casefold, since the upstream may
// echo a different casing than our configured nick.
function isMe(nick) {
  return nick != null && myNick != null && fold(nick) === fold(myNick);
}

// A CTCP ACTION (`\x01ACTION text\x01`) renders as "* nick text"; a plain
// message is unchanged. Returns { kind, from, text } for addLine.
function asMessage(kind, from, text) {
  const action = text.match(/^ACTION (.*?)?$/s);
  if (action) return { kind: "event", from: null, text: `* ${from} ${action[1]}` };
  return { kind, from, text };
}

function handleLine(raw) {
  const m = parseIrc(raw);
  switch (m.command) {
    case "001":
      if (m.params[0]) myNick = m.params[0];
      addServer(`connected as ${myNick}`);
      break;
    case "PRIVMSG":
    case "NOTICE": {
      const target = m.params[0] || "";
      const text = m.params[1] ?? "";
      const kind = m.command === "NOTICE" ? "notice" : "msg";
      const r = asMessage(kind, m.nick, text);
      if (isChannel(target)) {
        addLine(target, r.kind, "channel", r.from, r.text);
      } else {
        // A direct message: key the buffer by the other party — the sender,
        // unless the sender is us (a message we sent to `target`).
        const buf = isMe(m.nick) ? target : m.nick || target;
        addLine(buf, r.kind, "dm", r.from, r.text);
      }
      break;
    }
    case "JOIN": {
      const chan = m.params[0];
      if (!chan) break;
      if (isMe(m.nick)) {
        ensureBuffer(chan, "channel");
        setActive(chan);
      } else if (m.nick) {
        addNick(chan, m.nick);
        addEvent(chan, `${m.nick} joined`);
      }
      break;
    }
    case "PART":
      if (m.params[0]) {
        removeNick(m.params[0], m.nick);
        addEvent(m.params[0], `${m.nick || "?"} left`);
      }
      break;
    case "KICK":
      if (m.params[0] && m.params[1]) {
        removeNick(m.params[0], m.params[1]);
        addEvent(m.params[0], `${m.params[1]} was kicked`);
      }
      break;
    case "QUIT":
      if (m.nick) removeNickEverywhere(m.nick, `${m.nick} quit`);
      break;
    case "NICK":
      if (m.nick && m.params[0]) {
        renameNick(m.nick, m.params[0]);
        if (isMe(m.nick)) myNick = m.params[0];
      }
      break;
    case "TOPIC":
      if (m.params[0]) {
        setTopic(m.params[0], m.params[1]);
        addEvent(m.params[0], `${m.nick || "?"} set the topic`);
      }
      break;
    case "332": // RPL_TOPIC: <me> <chan> :topic
      setTopic(m.params[1], m.params[2]);
      break;
    case "353": {
      // RPL_NAMREPLY: <me> <sym> <chan> :n1 n2 ...
      const chan = m.params[2];
      for (const n of (m.params[3] || "").split(" ").filter(Boolean)) addNick(chan, n);
      break;
    }
    case "366": // end of NAMES
      break;
    default:
      // Numerics and everything else land in the server buffer. Show the human
      // part (the trailing) when there is one, else the whole line.
      addServer(m.params.length ? m.params[m.params.length - 1] : raw);
  }
}

// ---- socket + composer --------------------------------------------------

function connect() {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  const url = `${proto}://${window.location.host}/ws/ui?network=${encodeURIComponent(network)}`;
  socket = new WebSocket(url);
  socket.addEventListener("open", () => setStatus(`attached to ${network}`, "ok"));
  socket.addEventListener("close", () => setStatus("disconnected", "error"));
  socket.addEventListener("message", (ev) => {
    let event;
    try {
      event = JSON.parse(ev.data);
    } catch {
      return;
    }
    if (event.t === "line" && typeof event.v === "string") handleLine(event.v);
    else if (event.t === "status") setStatus(`${network}: ${event.v}`, event.v === "connected" ? "ok" : "error");
  });
}

composer.addEventListener("submit", (e) => {
  e.preventDefault();
  const text = messageInput.value;
  if (!text || !socket || socket.readyState !== WebSocket.OPEN) return;
  // The server maps {target, message} (with slash-commands) to an IRC line.
  const b = active !== SERVER ? buffers.get(active) : null;
  const target = b ? b.display : "";
  socket.send(JSON.stringify({ target, message: text }));
  // Echo our own message locally (the upstream doesn't reflect it back). A
  // plain message and a `/me` action both echo; other slash-commands don't.
  if (b) {
    if (text.startsWith("/me ")) addLine(b.display, "event", b.kind, null, `* ${myNick} ${text.slice(4)}`);
    else if (!text.startsWith("/")) addLine(b.display, "msg", b.kind, myNick, text);
  }
  messageInput.value = "";
  messageInput.focus();
});

// ---- boot ---------------------------------------------------------------

async function boot() {
  ensureBuffer(SERVER, "server");
  setActive(SERVER);

  try {
    const me = await (await fetch("/api/v1/me", { headers: { Accept: "application/json" } })).json();
    if (typeof me.account === "string") {
      el("account-name").textContent = me.account;
      el("account-link").dataset.shauthUser = me.account;
    }
    // The email rides the account name's title attribute (the SSO validator
    // reads it there); role and the coordinated-logout coordinate likewise.
    el("account-name").title = typeof me.email === "string" ? me.email : "";
    if (typeof me.role === "string") el("account-role").textContent = me.role;
    // Only accept a same-origin relative path, so a hostile value can't turn the
    // sign-out control into a `javascript:` / cross-origin link. Reject a
    // protocol-relative `//host` (which starts with "/" but is cross-origin).
    if (
      typeof me.logout_url === "string" &&
      me.logout_url.startsWith("/") &&
      !me.logout_url.startsWith("//")
    ) {
      el("logout-link").href = me.logout_url;
    }
  } catch {
    /* identity is best-effort chrome; the chat still works without it */
  }

  if (!network) {
    setStatus("add ?network=<name> to the URL to connect", "error");
    addServer("No network selected. Append ?network=<name> to the URL.");
    return;
  }

  // Seed our nick from the network's configured nick (overridden by 001/NICK).
  try {
    const list = await (await fetch("/api/v1/me/networks", { headers: { Accept: "application/json" } })).json();
    const net = (list.networks || []).find((n) => n.name === network);
    if (net && typeof net.nick === "string") myNick = net.nick;
  } catch {
    /* fall back to learning the nick from 001 */
  }

  connect();
}

boot();
