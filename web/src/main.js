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
const SERVER = "*server*";

// name -> { name, kind: "server"|"channel"|"dm", lines: [], nicks: Map, topic, unread }
const buffers = new Map();
let active = null;
let myNick = null;
let socket = null;

function setStatus(text, cls) {
  statusEl.textContent = text;
  statusEl.className = `status status-${cls}`;
}

function ensureBuffer(name, kind) {
  let b = buffers.get(name);
  if (!b) {
    b = { name, kind, lines: [], nicks: new Map(), topic: "", unread: 0 };
    buffers.set(name, b);
    renderBufferList();
  }
  return b;
}

function isChannel(target) {
  return target.startsWith("#") || target.startsWith("&");
}

function stripSigil(nick) {
  return nick.replace(/^[~&@%+]+/, "");
}

// ---- rendering ----------------------------------------------------------

function renderBufferList() {
  buffersEl.replaceChildren();
  const order = [...buffers.values()].sort((a, b) => {
    if (a.name === SERVER) return -1;
    if (b.name === SERVER) return 1;
    return a.name.localeCompare(b.name);
  });
  for (const b of order) {
    const li = document.createElement("li");
    li.className = "buf" + (b.name === active ? " active" : "");
    const label = document.createElement("span");
    label.className = "buf-name";
    label.textContent = b.name === SERVER ? "server" : b.name;
    li.appendChild(label);
    if (b.unread > 0 && b.name !== active) {
      const badge = document.createElement("span");
      badge.className = "badge";
      badge.textContent = String(b.unread);
      li.appendChild(badge);
    }
    li.addEventListener("click", () => setActive(b.name));
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
  bufnameEl.textContent = !b || b.name === SERVER ? "server" : b.name;
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
  const names = [...b.nicks.keys()].sort((a, c) => a.localeCompare(c));
  nickcountEl.textContent = String(names.length);
  nicksEl.replaceChildren();
  for (const n of names) {
    const li = document.createElement("li");
    li.textContent = n;
    nicksEl.appendChild(li);
  }
}

function setActive(name) {
  active = name;
  const b = buffers.get(name);
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
  if (b.name === active) {
    const nearBottom =
      messagesEl.scrollHeight - messagesEl.scrollTop - messagesEl.clientHeight < 40;
    messagesEl.appendChild(messageRow(line));
    if (b.lines.length > MAX_LINES && messagesEl.firstChild) {
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
  const b = ensureBuffer(chan, "channel");
  b.nicks.set(stripSigil(nick), true);
  if (b.name === active) renderNickList();
}

function removeNick(chan, nick) {
  const b = buffers.get(chan);
  if (b) {
    b.nicks.delete(stripSigil(nick));
    if (b.name === active) renderNickList();
  }
}

function removeNickEverywhere(nick, text) {
  for (const b of buffers.values()) {
    if (b.kind === "channel" && b.nicks.delete(stripSigil(nick))) {
      addEvent(b.name, text);
    }
  }
  if (active) renderNickList();
}

function renameNick(from, to) {
  for (const b of buffers.values()) {
    if (b.kind === "channel" && b.nicks.delete(stripSigil(from))) {
      b.nicks.set(stripSigil(to), true);
      addEvent(b.name, `${from} is now ${to}`);
    }
  }
  if (active) renderNickList();
}

function setTopic(chan, topic) {
  const b = ensureBuffer(chan, "channel");
  b.topic = topic || "";
  if (b.name === active) buftopicEl.textContent = b.topic;
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
      if (isChannel(target)) {
        addLine(target, kind, "channel", m.nick, text);
      } else {
        // A direct message: key the buffer by the other party (the sender).
        const buf = m.nick || target;
        addLine(buf, kind, "dm", m.nick, text);
      }
      break;
    }
    case "JOIN": {
      const chan = m.params[0];
      if (m.nick === myNick) {
        ensureBuffer(chan, "channel");
        setActive(chan);
      } else {
        addNick(chan, m.nick);
        addEvent(chan, `${m.nick} joined`);
      }
      break;
    }
    case "PART":
      removeNick(m.params[0], m.nick);
      addEvent(m.params[0], `${m.nick} left`);
      break;
    case "KICK":
      removeNick(m.params[0], m.params[1]);
      addEvent(m.params[0], `${m.params[1]} was kicked`);
      break;
    case "QUIT":
      removeNickEverywhere(m.nick, `${m.nick} quit`);
      break;
    case "NICK":
      renameNick(m.nick, m.params[0]);
      if (m.nick === myNick) myNick = m.params[0];
      break;
    case "TOPIC":
      setTopic(m.params[0], m.params[1]);
      addEvent(m.params[0], `${m.nick} set the topic`);
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
  const target = active && active !== SERVER ? active : "";
  socket.send(JSON.stringify({ target, message: text }));
  // Echo our own message locally (the upstream doesn't reflect it back).
  if (target && !text.startsWith("/")) addLine(target, "msg", buffers.get(target)?.kind || "channel", myNick, text);
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
    if (typeof me.logout_url === "string") el("logout-link").href = me.logout_url;
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
