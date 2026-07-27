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

// Channel membership sigils and their underlying modes, highest rank first.
// `~`=owner(+q), `&`=admin(+a), `@`=op(+o), `%`=halfop(+h), `+`=voice(+v).
const RANKS = [
  ["q", "~"],
  ["a", "&"],
  ["o", "@"],
  ["h", "%"],
  ["v", "+"],
];
const SIGIL_MODE = { "~": "q", "&": "a", "@": "o", "%": "h", "+": "v" };
// Membership modes (each consumes a nick argument in a MODE line).
const SIGIL_MODE_CHARS = "qaohv";
// Modes that consume a parameter whether set or unset (membership + list +
// key), vs. only when set (limit). Used to keep MODE argument alignment so a
// mixed line like `+o-l nick` maps the nick to `o`, not `l`.
const MODE_ALWAYS_ARG = new Set(["q", "a", "o", "h", "v", "b", "e", "I", "k"]);
const MODE_SET_ARG = new Set(["l"]);

// Split a NAMES/prefix nick into its leading sigils and the bare nick, and seed
// the mode set the sigils imply.
function splitSigil(nick) {
  const s = nick || "";
  let i = 0;
  while (i < s.length && SIGIL_MODE[s[i]] !== undefined) i += 1;
  const modes = new Set();
  for (const c of s.slice(0, i)) modes.add(SIGIL_MODE[c]);
  return { name: s.slice(i), modes };
}

function stripSigil(nick) {
  return splitSigil(nick).name;
}

// The single highest-rank sigil for a set of membership modes ("" if none).
function nickPrefix(modes) {
  for (const [mode, sigil] of RANKS) if (modes.has(mode)) return sigil;
  return "";
}

// ---- rendering ----------------------------------------------------------

// Reflect total unread in the tab title so a background tab shows activity.
function updateTitle() {
  let unread = 0;
  for (const b of buffers.values()) if (b.key !== active) unread += b.unread;
  document.title = unread > 0 ? `(${unread}) e6irc` : "e6irc";
}

function renderBufferList() {
  updateTitle();
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
    li.tabIndex = 0;
    li.setAttribute("role", "button");
    li.addEventListener("click", () => setActive(b.key));
    li.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        setActive(b.key);
      }
    });
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
  // Sort by rank (owner/op/… first) then name, and show the sigil.
  const rankOf = (m) => {
    const p = nickPrefix(m);
    const i = RANKS.findIndex(([, s]) => s === p);
    return i === -1 ? RANKS.length : i;
  };
  const members = [...b.nicks.values()].sort(
    (a, c) => rankOf(a.modes) - rankOf(c.modes) || a.name.localeCompare(c.name),
  );
  nickcountEl.textContent = String(members.length);
  nicksEl.replaceChildren();
  for (const m of members) {
    const li = document.createElement("li");
    li.className = "nick";
    li.tabIndex = 0;
    li.setAttribute("role", "button");
    li.title = `Message ${m.name}`;
    li.textContent = nickPrefix(m.modes) + m.name;
    // Click / Enter opens a query buffer with this nick.
    const open = () => setActive(ensureBuffer(m.name, "dm").display);
    li.addEventListener("click", open);
    li.addEventListener("keydown", (e) => {
      if (e.key === "Enter" || e.key === " ") {
        e.preventDefault();
        open();
      }
    });
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
  const { name, modes } = splitSigil(nick);
  if (!name) return;
  const b = ensureBuffer(chan, "channel");
  const key = fold(name);
  if (b.nicks.size >= MAX_NICKS && !b.nicks.has(key)) return;
  const existing = b.nicks.get(key);
  if (existing) {
    existing.name = name;
    for (const mo of modes) existing.modes.add(mo);
  } else {
    b.nicks.set(key, { name, modes });
  }
  if (b.key === active) renderNickList();
}

// Apply a membership mode change from a channel MODE line: `add` (true for `+`)
// the mode `mode` (o/h/v/a/q) to `nick` in `chan`, updating its sigil.
function setNickMode(chan, nick, mode, add) {
  const b = buffers.get(fold(chan));
  if (!b) return;
  const entry = b.nicks.get(fold(stripSigil(nick)));
  if (!entry) return;
  if (add) entry.modes.add(mode);
  else entry.modes.delete(mode);
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
  const toName = stripSigil(to);
  if (!fromKey || !toName) return;
  for (const b of buffers.values()) {
    if (b.kind !== "channel") continue;
    const entry = b.nicks.get(fromKey);
    if (entry) {
      b.nicks.delete(fromKey);
      entry.name = toName;
      b.nicks.set(fold(toName), entry);
      addEvent(b.display, `${stripSigil(from)} is now ${toName}`);
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
      } else if (target === "*" || target === "") {
        // A server / global notice (e.g. the bouncer's *bnc* control messages):
        // show it in the server buffer, not a phantom DM keyed on the sender.
        addLine(SERVER, r.kind, "server", r.from, r.text);
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
        const reason = m.params[1] ? ` (${m.params[1]})` : "";
        removeNick(m.params[0], m.nick);
        addEvent(m.params[0], `${m.nick || "?"} left${reason}`);
      }
      break;
    case "KICK":
      if (m.params[0] && m.params[1]) {
        const reason = m.params[2] ? ` (${m.params[2]})` : "";
        const by = m.nick ? ` by ${m.nick}` : "";
        removeNick(m.params[0], m.params[1]);
        addEvent(m.params[0], `${m.params[1]} was kicked${by}${reason}`);
      }
      break;
    case "QUIT":
      if (m.nick) {
        const reason = m.params[0] ? ` (${m.params[0]})` : "";
        removeNickEverywhere(m.nick, `${stripSigil(m.nick)} quit${reason}`);
      }
      break;
    case "MODE": {
      // Channel MODE: track membership sigil changes for the member list.
      const chan = m.params[0];
      if (chan && isChannel(chan)) {
        const modestr = m.params[1] || "";
        const args = m.params.slice(2);
        let adding = true;
        let ai = 0;
        for (const ch of modestr) {
          if (ch === "+") adding = true;
          else if (ch === "-") adding = false;
          else {
            const takesArg = MODE_ALWAYS_ARG.has(ch) || (adding && MODE_SET_ARG.has(ch));
            const arg = takesArg ? args[ai++] : undefined;
            if (arg && SIGIL_MODE_CHARS.includes(ch)) setNickMode(chan, arg, ch, adding);
          }
        }
      } else {
        addServer(m.params.length ? m.params[m.params.length - 1] : raw);
      }
      break;
    }
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

// Reconnect with exponential backoff + jitter: a transient drop (server
// restart, laptop sleep, network blip) must not leave a dead socket that the
// user has to reload past. Backoff resets on a successful open.
let reconnectDelay = 0;
let reconnectTimer = null;
const RECONNECT_MIN = 1000;
const RECONNECT_MAX = 30000;

function scheduleReconnect() {
  if (reconnectTimer) return; // one pending attempt at a time
  reconnectDelay = reconnectDelay ? Math.min(reconnectDelay * 2, RECONNECT_MAX) : RECONNECT_MIN;
  const jitter = Math.floor(reconnectDelay * 0.25 * Math.random());
  const wait = reconnectDelay + jitter;
  setStatus(`reconnecting in ${Math.round(wait / 1000)}s…`, "error");
  reconnectTimer = window.setTimeout(() => {
    reconnectTimer = null;
    connect();
  }, wait);
}

function connect() {
  // Drop any previous socket so overlapping connections can't both feed events.
  if (socket) {
    socket.onclose = null;
    try {
      socket.close();
    } catch {
      /* already closed */
    }
  }
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  const url = `${proto}://${window.location.host}/ws/ui?network=${encodeURIComponent(network)}`;
  socket = new WebSocket(url);
  socket.addEventListener("open", () => {
    reconnectDelay = 0; // healthy connection: reset backoff
    setStatus(`attached to ${network}`, "ok");
  });
  socket.addEventListener("close", () => {
    setStatus("disconnected — reconnecting…", "error");
    scheduleReconnect();
  });
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
  // In the server buffer there is no target, so plain text would be sent as a
  // raw IRC line and bounce back as "421 Unknown command". Require a /command
  // (e.g. /join #chan) there instead of emitting a bogus line.
  if (!b && !text.startsWith("/")) {
    addServer("No active channel/query — use a /command here (e.g. /join #chan) or pick a buffer.");
    messageInput.value = "";
    return;
  }
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

// Sidebar "join #channel" input: a one-field affordance so joining doesn't
// require knowing the /join slash-command.
const joinForm = el("join-form");
if (joinForm) {
  joinForm.addEventListener("submit", (e) => {
    e.preventDefault();
    const input = el("join-input");
    let chan = (input.value || "").trim();
    if (!chan) return;
    if (!isChannel(chan)) chan = "#" + chan;
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ target: "", message: `/join ${chan}` }));
    } else {
      addServer("Not connected — cannot join yet.");
    }
    input.value = "";
  });
}

// The network picker shown when the page is opened without ?network=<name>:
// list the caller's networks as links, so the client has a real entry point
// instead of requiring a hand-crafted URL.
async function renderNetworkPicker() {
  setStatus("choose a network", "error");
  bufnameEl.textContent = "Select a network";
  buftopicEl.textContent = "";
  nicklistEl.hidden = true;
  messagesEl.replaceChildren();
  let nets = [];
  try {
    const list = await (await fetch("/api/v1/me/networks", { headers: { Accept: "application/json" } })).json();
    nets = list.networks || [];
  } catch {
    /* fall through to the empty-state message */
  }
  const intro = document.createElement("li");
  intro.className = "line line-server";
  intro.textContent = nets.length
    ? "Choose a network to open:"
    : "You have no networks yet.";
  messagesEl.appendChild(intro);
  for (const n of nets) {
    const li = document.createElement("li");
    li.className = "line";
    const a = document.createElement("a");
    a.className = "picker-net";
    a.href = `?network=${encodeURIComponent(n.name)}`;
    const tag = n.connected ? " · connected" : n.enabled === false ? " · disabled" : "";
    a.textContent = `▸ ${n.name}${tag}`;
    li.appendChild(a);
    messagesEl.appendChild(li);
  }
  const manageLi = document.createElement("li");
  manageLi.className = "line";
  const manage = document.createElement("a");
  manage.className = "picker-net";
  manage.href = "/console/networks";
  manage.textContent = nets.length ? "⚙ Manage networks" : "⚙ Add a network in the console";
  manageLi.appendChild(manage);
  messagesEl.appendChild(manageLi);
}

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
    await renderNetworkPicker();
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
