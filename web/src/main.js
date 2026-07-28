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
import {
  ApiError,
  errorMessage,
  getJson,
  loadSettings,
  networksFrom,
  saveSettings,
} from "./client-state.js";

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
const alertsEl = el("alerts");
const networkSelect = el("network-select");
const sidebarToggle = el("sidebar-toggle");
const sendButton = composer.querySelector("button[type=submit]");
const joinButton = el("join-form")?.querySelector("button[type=submit]");

const MAX_LINES = 500;
// Bounds against a hostile upstream that streams distinct channels/senders or a
// giant NAMES list: buffers and per-channel members can't grow without limit.
const MAX_BUFFERS = 200;
const MAX_NICKS = 5000;
const SERVER = "*server*";

// ---- client settings (persisted in localStorage) -----------------------
const loadedSettings = loadSettings(() => window.localStorage);
const settings = loadedSettings.settings;

function showAlert(key, text, tone = "warning", action = null) {
  let alert = alertsEl.querySelector(`[data-alert="${CSS.escape(key)}"]`);
  if (!alert) {
    alert = document.createElement("div");
    alert.dataset.alert = key;
    alert.className = `alert alert-${tone}`;
    const copy = document.createElement("span");
    alert.appendChild(copy);
    const dismiss = document.createElement("button");
    dismiss.type = "button";
    dismiss.textContent = "Dismiss";
    dismiss.setAttribute("aria-label", "Dismiss message");
    dismiss.addEventListener("click", () => alert.remove());
    alert.appendChild(dismiss);
    alertsEl.appendChild(alert);
  }
  alert.className = `alert alert-${tone}`;
  alert.firstElementChild.textContent = text;
  const existingAction = alert.querySelector("a");
  if (existingAction) existingAction.remove();
  if (action) {
    const link = document.createElement("a");
    link.href = action.href;
    link.textContent = action.label;
    alert.insertBefore(link, alert.lastElementChild);
  }
}

function clearAlert(key) {
  alertsEl.querySelector(`[data-alert="${CSS.escape(key)}"]`)?.remove();
}

function persistSettings() {
  const warning = saveSettings(() => window.localStorage, settings);
  const storageState = el("storage-state");
  if (warning) {
    storageState.textContent = warning;
    storageState.hidden = false;
    showAlert("storage", warning);
  } else {
    storageState.textContent = "";
    storageState.hidden = true;
    clearAlert("storage");
  }
}

if (loadedSettings.warning) {
  const storageState = el("storage-state");
  storageState.textContent = loadedSettings.warning;
  storageState.hidden = false;
  showAlert("storage", loadedSettings.warning);
}
// "light"/"dark" force the theme via data-theme (CSS overrides prefers-color-
// scheme); "auto" removes it so the OS preference applies.
function applyTheme() {
  const root = document.documentElement;
  if (settings.theme === "light" || settings.theme === "dark") root.dataset.theme = settings.theme;
  else delete root.dataset.theme;
}
applyTheme();

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
  statusEl.title = text;
}

function setComposerAvailable(available) {
  messageInput.disabled = !available;
  sendButton.disabled = !available;
  if (joinButton) joinButton.disabled = !available;
}

function closeMobileSidebar() {
  document.body.classList.remove("sidebar-open");
  if (sidebarToggle) sidebarToggle.setAttribute("aria-expanded", "false");
}

if (sidebarToggle) {
  sidebarToggle.addEventListener("click", () => {
    const open = document.body.classList.toggle("sidebar-open");
    sidebarToggle.setAttribute("aria-expanded", String(open));
  });
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

// Render `text` into `span`, turning http(s) URLs into links. Everything goes
// through text nodes and element *properties* (never innerHTML), and only
// http/https tokens become links — a `javascript:`/`data:` scheme never matches
// URL_RE — so a hostile line still cannot inject markup or an unsafe href.
const URL_RE = /https?:\/\/[^\s<>"']+/g;
function renderText(span, text) {
  URL_RE.lastIndex = 0;
  let last = 0;
  let m;
  while ((m = URL_RE.exec(text)) !== null) {
    if (m.index > last) {
      span.appendChild(document.createTextNode(text.slice(last, m.index)));
    }
    // Trailing sentence punctuation is usually not part of the URL.
    let url = m[0];
    let tail = "";
    const trailing = url.match(/[.,;:!?)\]]+$/);
    if (trailing) {
      tail = trailing[0];
      url = url.slice(0, url.length - tail.length);
    }
    const a = document.createElement("a");
    a.href = url;
    a.textContent = url;
    a.target = "_blank";
    a.rel = "noopener noreferrer";
    a.className = "msg-link";
    span.appendChild(a);
    if (tail) span.appendChild(document.createTextNode(tail));
    last = m.index + m[0].length;
  }
  if (last < text.length) span.appendChild(document.createTextNode(text.slice(last)));
}

function messageRow(line) {
  const row = document.createElement("li");
  row.className = "line line-" + line.kind + (line.mention ? " line-mention" : "");
  const time = document.createElement("span");
  time.className = "ts";
  time.textContent = line.time;
  if (line.title) time.title = line.title; // full date+time on hover
  const from = document.createElement("span");
  from.className = "from";
  from.textContent = line.from ? line.from : "";
  const text = document.createElement("span");
  text.className = "text";
  renderText(text, line.text);
  row.append(time, from, text);
  return row;
}

function renderActive() {
  const b = buffers.get(active);
  bufnameEl.textContent = !b || b.key === SERVER ? "server" : b.display;
  buftopicEl.textContent = b ? b.topic : "";
  // "Load earlier" is offered for a real conversation buffer (channel/DM) whose
  // persisted backlog hasn't been pulled yet, and only when attached (network set).
  const loadEarlierEl = el("load-earlier");
  if (loadEarlierEl) {
    const eligible = !!network && !!b && b.kind !== "server" && !b.historyLoaded;
    loadEarlierEl.hidden = !eligible;
  }
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
  closeMobileSidebar();
  if (!messageInput.disabled) messageInput.focus();
}

// ---- buffer mutation ----------------------------------------------------

function nowHm() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}`;
}

function addLine(bufName, kind, bufKind, from, text) {
  const b = ensureBuffer(bufName, bufKind);
  // A highlight: someone else's channel/DM message that names us.
  const mention = kind === "msg" && from != null && !isMe(from) && mentionsMe(text);
  const line = { time: nowHm(), title: new Date().toLocaleString(), from, text, kind, mention };
  maybeNotify(b, line);
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

// Extract the `time` IRCv3 tag (server-time, ISO-8601) from a tag section, or
// null. Live /ws/ui lines have their tags stripped server-side, but the buffer
// REST endpoint returns raw lines with tags, so history can show real times.
function tagTime(tags) {
  if (!tags) return null;
  for (const t of tags.split(";")) {
    const eq = t.indexOf("=");
    if (eq > 0 && t.slice(0, eq) === "time") return t.slice(eq + 1) || null;
  }
  return null;
}

function parseIrc(line) {
  let rest = line;
  let tags = null;
  if (rest.startsWith("@")) {
    const sp = rest.indexOf(" ");
    tags = rest.slice(1, sp === -1 ? undefined : sp);
    rest = sp === -1 ? "" : rest.slice(sp + 1);
  }
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
  return { tags, nick, command, params: parts };
}

// Is this our own nick? Compared under the casefold, since the upstream may
// echo a different casing than our configured nick.
function isMe(nick) {
  return nick != null && myNick != null && fold(nick) === fold(myNick);
}

// Does `text` mention our nick as a whole token (casefolded)? Splits on runs of
// non-nick characters (an IRC nick is letters/digits and `[]{}\|^`_-`), so
// "hey alice!" highlights but "alicexyz" does not.
function mentionsMe(text) {
  if (myNick == null || typeof text !== "string") return false;
  const me = fold(myNick);
  return fold(text)
    .split(/[^a-z0-9{}[\]\\^`_|-]+/)
    .some((token) => token === me);
}

// Show a desktop notification for a highlight/DM when the tab is backgrounded
// and the user has enabled and granted notifications. Best-effort.
function maybeNotify(b, line) {
  if (
    !settings.notifications ||
    typeof Notification === "undefined" ||
    Notification.permission !== "granted" ||
    !document.hidden
  ) {
    return;
  }
  const isDM = b.kind === "dm";
  if (!(line.mention || isDM)) return;
  const title = isDM ? `DM from ${line.from ?? "?"}` : `${b.display}: ${line.from ?? ""}`;
  try {
    // eslint-disable-next-line no-new
    new Notification(title, { body: line.text, tag: b.key });
  } catch (error) {
    settings.notifications = false;
    persistSettings();
    updateSettingsUI();
    showAlert(
      "notifications",
      errorMessage("show a desktop notification", error),
      "warning",
    );
  }
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
let reconnectAttempt = 0;
let terminalSocket = false;
const RECONNECT_MIN = 1000;
const RECONNECT_MAX = 30000;

function scheduleReconnect() {
  if (reconnectTimer || terminalSocket) return; // one pending attempt at a time
  reconnectDelay = reconnectDelay ? Math.min(reconnectDelay * 2, RECONNECT_MAX) : RECONNECT_MIN;
  reconnectAttempt += 1;
  const jitter = Math.floor(reconnectDelay * 0.25 * Math.random());
  const wait = reconnectDelay + jitter;
  setStatus(
    `reconnect ${reconnectAttempt} in ${Math.max(1, Math.round(wait / 1000))}s`,
    "error",
  );
  reconnectTimer = window.setTimeout(() => {
    reconnectTimer = null;
    connect();
  }, wait);
}

async function reconcileUnavailableNetwork() {
  setStatus(`${network}: checking availability…`, "connecting");
  try {
    const networks = networksFrom(
      await getJson(window.fetch.bind(window), "/api/v1/me/networks"),
    );
    populateNetworkSelector(networks);
    const replacement = networks.find((item) => fold(item.name) === fold(network));
    if (replacement && replacement.enabled !== false && replacement.runtime != null) {
      terminalSocket = false;
      clearAlert("network-unavailable");
      setStatus(`${replacement.name}: reconfigured, reattaching…`, "connecting");
      if (!reconnectTimer) {
        reconnectTimer = window.setTimeout(() => {
          reconnectTimer = null;
          connect();
        }, 250);
      }
      return;
    }
    const reason = replacement
      ? `${replacement.name} is disabled or has no running driver.`
      : `No network named ${network} belongs to this account.`;
    setStatus(`${network} unavailable`, "error");
    showAlert(
      "network-unavailable",
      `${reason} Choose another network or update its configuration.`,
      "error",
      { href: "/console/networks", label: "Manage networks" },
    );
  } catch (error) {
    setStatus(`${network} unavailable`, "error");
    showAlert(
      "network-unavailable",
      `${errorMessage("verify the network after it stopped", error)} Automatic reattachment is paused.`,
      "error",
      { href: "/console/networks", label: "Manage networks" },
    );
  }
}

function connect() {
  terminalSocket = false;
  setComposerAvailable(false);
  setStatus(`attaching to ${network}…`, "connecting");
  // Drop any previous socket so overlapping connections can't both feed events.
  if (socket) {
    const previous = socket;
    socket = null;
    try {
      previous.close();
    } catch (error) {
      showAlert("socket-close", errorMessage("close the previous connection", error));
    }
  }
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  const url = `${proto}://${window.location.host}/ws/ui?network=${encodeURIComponent(network)}`;
  const liveSocket = new WebSocket(url);
  socket = liveSocket;
  liveSocket.addEventListener("open", () => {
    if (socket !== liveSocket) return;
    reconnectDelay = 0; // healthy connection: reset backoff
    reconnectAttempt = 0;
    setComposerAvailable(true);
    setStatus(`attached to ${network}`, "ok");
    clearAlert("socket");
    clearAlert("socket-close");
    clearAlert("network-unavailable");
  });
  liveSocket.addEventListener("error", () => {
    if (socket !== liveSocket) return;
    showAlert(
      "socket",
      `The live connection to ${network} failed. e6irc will keep retrying with bounded backoff.`,
      "error",
    );
  });
  liveSocket.addEventListener("close", (event) => {
    if (socket !== liveSocket) return;
    socket = null;
    setComposerAvailable(false);
    if (terminalSocket) {
      setStatus(`${network} unavailable`, "error");
      return;
    }
    const detail = event.reason ? `: ${event.reason}` : event.code === 1006 ? " unexpectedly" : "";
    setStatus(`live connection closed${detail}`, "error");
    scheduleReconnect();
  });
  liveSocket.addEventListener("message", (ev) => {
    if (socket !== liveSocket) return;
    let event;
    try {
      event = JSON.parse(ev.data);
    } catch {
      showAlert(
        "protocol",
        "The server sent a malformed live event. The event was rejected; other messages remain connected.",
        "error",
      );
      return;
    }
    if (event.t === "line" && typeof event.v === "string") handleLine(event.v);
    else if (event.t === "status" && event.v === "connected") {
      setStatus(`${network}: upstream connected`, "ok");
    } else if (event.t === "status" && event.v === "disconnected") {
      setStatus(`${network}: upstream reconnecting`, "error");
    } else if (event.t === "status" && event.v === "unavailable") {
      terminalSocket = true;
      setComposerAvailable(false);
      reconcileUnavailableNetwork();
    } else {
      showAlert(
        "protocol",
        "The server sent an unsupported live event. The event was rejected; other messages remain connected.",
        "error",
      );
    }
  });
}

// Composer input history: Up/Down recall previously sent lines, like a shell.
const sentHistory = [];
let historyIdx = -1; // -1 = editing a fresh line, not browsing history
let historyDraft = ""; // the in-progress line, restored when browsing past the end
messageInput.addEventListener("keydown", (e) => {
  if (e.key === "ArrowUp") {
    if (historyIdx === -1) {
      if (sentHistory.length === 0) return;
      historyDraft = messageInput.value;
      historyIdx = sentHistory.length - 1;
    } else if (historyIdx > 0) {
      historyIdx -= 1;
    } else {
      return;
    }
    e.preventDefault();
    messageInput.value = sentHistory[historyIdx];
    messageInput.setSelectionRange(messageInput.value.length, messageInput.value.length);
  } else if (e.key === "ArrowDown") {
    if (historyIdx === -1) return;
    e.preventDefault();
    if (historyIdx < sentHistory.length - 1) {
      historyIdx += 1;
      messageInput.value = sentHistory[historyIdx];
    } else {
      historyIdx = -1;
      messageInput.value = historyDraft;
    }
  }
});

composer.addEventListener("submit", (e) => {
  e.preventDefault();
  const text = messageInput.value;
  if (!text) return;
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    addServer("Not connected — your message was not sent.");
    return;
  }
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
  // Record for Up/Down recall (skip a consecutive duplicate; bound the list).
  if (sentHistory[sentHistory.length - 1] !== text) sentHistory.push(text);
  if (sentHistory.length > 100) sentHistory.shift();
  historyIdx = -1;
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

function networkLabel(item) {
  if (item.enabled === false) return "disabled";
  if (item.connected === true) return "connected";
  const lifecycle = item.runtime?.lifecycle;
  return typeof lifecycle === "string" ? lifecycle.replaceAll("_", " ") : "starting";
}

function populateNetworkSelector(networks, failure = null) {
  networkSelect.replaceChildren();
  const choose = document.createElement("option");
  choose.value = "";
  choose.textContent = failure
    ? "Networks unavailable"
    : networks.length
      ? "Choose a network"
      : "No networks";
  networkSelect.appendChild(choose);
  for (const item of networks) {
    const option = document.createElement("option");
    option.value = item.name;
    option.textContent = `${item.name} · ${networkLabel(item)}`;
    option.selected = network !== null && fold(item.name) === fold(network);
    networkSelect.appendChild(option);
  }
  if (network && !networks.some((item) => fold(item.name) === fold(network))) {
    const missing = document.createElement("option");
    missing.value = network;
    missing.textContent = `${network} · unavailable`;
    missing.selected = true;
    networkSelect.appendChild(missing);
  }
}

networkSelect.addEventListener("change", () => {
  const selected = networkSelect.value;
  if (selected && selected !== network) {
    window.location.assign(`/?network=${encodeURIComponent(selected)}`);
  } else if (!selected && network) {
    window.location.assign("/");
  }
});

// The network picker shown when the page is opened without ?network=<name>:
// list the caller's networks as links, so the client has a real entry point
// instead of requiring a hand-crafted URL.
function renderNetworkPicker(networks, failure = null) {
  setStatus(failure ? "network list unavailable" : "choose a network", failure ? "error" : "connecting");
  bufnameEl.textContent = "Select a network";
  buftopicEl.textContent = "";
  nicklistEl.hidden = true;
  messagesEl.replaceChildren();
  const intro = document.createElement("li");
  intro.className = "line line-server";
  intro.textContent = failure
    ? "e6irc could not load your networks. This is an API failure, not an empty account."
    : networks.length
      ? "Choose an always-on network:"
      : "No networks are configured for this account.";
  messagesEl.appendChild(intro);
  for (const item of networks) {
    const li = document.createElement("li");
    li.className = "line";
    const a = document.createElement("a");
    a.className = "picker-net";
    a.href = `/?network=${encodeURIComponent(item.name)}`;
    const name = document.createElement("span");
    name.textContent = item.name;
    const state = document.createElement("small");
    state.textContent = networkLabel(item);
    a.append(name, state);
    li.appendChild(a);
    messagesEl.appendChild(li);
  }
  const manageLi = document.createElement("li");
  manageLi.className = "line picker-actions";
  const manage = document.createElement("a");
  manage.href = "/console/networks";
  manage.textContent = failure
    ? "Open network console"
    : networks.length
      ? "Manage networks"
      : "Add a network";
  manageLi.appendChild(manage);
  if (failure) {
    const retry = document.createElement("a");
    retry.href = "/";
    retry.textContent = "Retry";
    manageLi.appendChild(retry);
  }
  messagesEl.appendChild(manageLi);
}

// ---- load earlier history ----------------------------------------------

// Pull the network's persisted backlog (raw lines, which carry the server-time
// tags the live socket strips) and rebuild the active buffer's message history
// from it — so the user sees older messages than the in-memory ring the socket
// replayed. One-shot per buffer.
async function loadEarlier() {
  const b = buffers.get(active);
  if (!network || !b || b.kind === "server" || b.historyLoaded) return;
  const btn = el("load-earlier");
  if (btn) {
    btn.disabled = true;
    btn.textContent = "Loading…";
  }
  let lines = [];
  try {
    const payload = await getJson(
      window.fetch.bind(window),
      `/api/v1/me/networks/${encodeURIComponent(network)}/buffer?limit=1000`,
    );
    if (!Array.isArray(payload.lines) || payload.lines.some((line) => typeof line !== "string")) {
      throw new ApiError(200, "The server returned an invalid backlog");
    }
    lines = payload.lines;
    clearAlert("history");
  } catch (error) {
    const message = errorMessage("load earlier messages", error);
    addServer(message);
    showAlert("history", message, "error");
    if (btn) {
      btn.disabled = false;
      btn.textContent = "Load earlier messages";
    }
    return;
  }
  const pad = (n) => String(n).padStart(2, "0");
  const rebuilt = [];
  for (const raw of lines) {
    const m = parseIrc(raw);
    if (m.command !== "PRIVMSG" && m.command !== "NOTICE") continue;
    const target = m.params[0] || "";
    const belongs =
      b.kind === "channel"
        ? fold(target) === b.key
        : (isMe(m.nick) ? fold(target) : fold(m.nick || "")) === b.key;
    if (!belongs) continue;
    const kind = m.command === "NOTICE" ? "notice" : "msg";
    const rendered = asMessage(kind, m.nick, m.params[1] ?? "");
    const iso = tagTime(m.tags);
    const d = iso ? new Date(iso) : null;
    const ok = d && !Number.isNaN(d.getTime());
    rebuilt.push({
      time: ok ? `${pad(d.getHours())}:${pad(d.getMinutes())}` : "",
      title: ok ? d.toLocaleString() : "",
      from: rendered.from,
      text: rendered.text,
      kind: rendered.kind,
      mention: false,
    });
  }
  // The persisted backlog is a superset of what the socket replayed, so replace
  // (rather than risk duplicating) and keep only the most recent MAX_LINES.
  b.lines = rebuilt.slice(-MAX_LINES);
  b.historyLoaded = true;
  if (b.key === active) renderActive();
}

const loadEarlierBtn = el("load-earlier");
if (loadEarlierBtn) loadEarlierBtn.addEventListener("click", loadEarlier);

// ---- settings controls --------------------------------------------------

const themeSelect = el("theme-select");
const notifyBtn = el("notify-toggle");

function updateSettingsUI() {
  if (themeSelect) themeSelect.value = settings.theme;
  if (notifyBtn) {
    notifyBtn.textContent = settings.notifications
      ? "Desktop notifications: on"
      : "Desktop notifications: off";
    notifyBtn.setAttribute("aria-pressed", String(settings.notifications));
  }
}
if (themeSelect) {
  themeSelect.addEventListener("change", () => {
    settings.theme = themeSelect.value;
    persistSettings();
    applyTheme();
  });
}
if (notifyBtn) {
  notifyBtn.addEventListener("click", async () => {
    if (!settings.notifications) {
      if (typeof Notification === "undefined") {
        addServer("This browser does not support desktop notifications.");
        return;
      }
      let perm;
      try {
        perm = await Notification.requestPermission();
      } catch (error) {
        const message = errorMessage("request notification permission", error);
        addServer(message);
        showAlert("notifications", message);
        return;
      }
      if (perm !== "granted") {
        addServer("Notification permission was not granted.");
        return;
      }
      settings.notifications = true;
    } else {
      settings.notifications = false;
    }
    persistSettings();
    updateSettingsUI();
  });
}
updateSettingsUI();

// ---- boot ---------------------------------------------------------------

async function boot() {
  ensureBuffer(SERVER, "server");
  setActive(SERVER);
  setComposerAvailable(false);

  try {
    const me = await getJson(window.fetch.bind(window), "/api/v1/me");
    if (me === null || typeof me !== "object" || typeof me.account !== "string") {
      throw new ApiError(200, "The server returned an invalid identity");
    }
    el("account-name").textContent = me.account;
    el("account-link").dataset.shauthUser = me.account;
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
    clearAlert("identity");
  } catch (error) {
    el("account-name").textContent = "identity unavailable";
    showAlert(
      "identity",
      errorMessage("load your signed-in identity", error),
      "error",
      error instanceof ApiError && error.status === 401
        ? { href: "/login", label: "Sign in" }
        : null,
    );
  }

  let networks = [];
  let networkFailure = null;
  try {
    networks = networksFrom(
      await getJson(window.fetch.bind(window), "/api/v1/me/networks"),
    );
    clearAlert("networks");
  } catch (error) {
    networkFailure = error;
    showAlert(
      "networks",
      errorMessage("load your networks", error),
      "error",
      error instanceof ApiError && error.status === 401
        ? { href: "/login", label: "Sign in" }
        : { href: "/console/networks", label: "Open network console" },
    );
  }
  populateNetworkSelector(networks, networkFailure);

  if (!network) {
    renderNetworkPicker(networks, networkFailure);
    return;
  }

  if (!networkFailure) {
    const selected = networks.find((item) => fold(item.name) === fold(network));
    if (!selected) {
      setStatus(`${network} not found`, "error");
      showAlert(
        "network-unavailable",
        `No network named ${network} belongs to this account.`,
        "error",
        { href: "/console/networks", label: "Manage networks" },
      );
      renderNetworkPicker(networks);
      return;
    }
    if (selected.enabled === false || selected.runtime == null) {
      const reason =
        selected.enabled === false
          ? `${selected.name} is disabled.`
          : `${selected.name} has no running driver in this build.`;
      setStatus(`${selected.name} unavailable`, "error");
      showAlert(
        "network-unavailable",
        `${reason} Enable or reconfigure it before opening chat.`,
        "error",
        { href: `/console/networks/${encodeURIComponent(selected.name)}`, label: "Open network" },
      );
      addServer(`${reason} The live socket was not opened.`);
      return;
    }
    // Seed our nick from the stored configuration (overridden by 001/NICK).
    if (typeof selected.nick === "string") myNick = selected.nick;
  }

  connect();
}

boot().catch((error) => {
  setComposerAvailable(false);
  setStatus("client startup failed", "error");
  showAlert("boot", errorMessage("start the chat client", error), "error");
});
