// e6irc web client: a small in-browser IRC client over the /ws/ui socket.
//
// The socket streams line, status, replay-complete, and correlated composer
// result events. This module parses each IRC line, routes it to the right
// buffer (a channel, a direct message, or the server buffer), keeps a
// per-channel member list, and renders the active buffer. All rendering uses
// textContent / DOM APIs — never
// innerHTML with server text — so a hostile upstream line cannot inject markup.
//
// Query parameters:
//   network — the BNC network to attach to (required)

import "./style.css";
import {
  ApiError,
  backlogFrom,
  errorMessage,
  getJson,
  identityFrom,
  loadSettings,
  networkStateLabel,
  networksFrom,
  saveSettings,
} from "./client-state.js";
import {
  MEMBER_RANKS,
  asMessage,
  fold,
  isChannel,
  mergeTimeline,
  messageIdentity,
  nickPrefix,
  parseIrc,
  splitSigil,
  stripSigil,
  tagValue,
} from "./irc-state.js";

const params = new URLSearchParams(window.location.search);
const network = params.get("network");

const el = (id) => document.getElementById(id);
const statusEl = el("status");
const buffersEl = el("buffers");
const messagesEl = el("messages");
const bufnameEl = el("bufname");
const buftopicEl = el("buftopic");
const bufferActionEl = el("buffer-action");
const nicklistEl = el("nicklist");
const nicksEl = el("nicks");
const nickcountEl = el("nickcount");
const composer = el("composer");
const messageInput = el("message");
const alertsEl = el("alerts");
const networkSelect = el("network-select");
const sidebarToggle = el("sidebar-toggle");
const sidebarEl = el("sidebar");
const jumpLatestButton = el("jump-latest");
const sendButton = composer.querySelector("button[type=submit]");
const joinButton = el("join-form")?.querySelector("button[type=submit]");

const MAX_LINES = 500;
// Bounds against a hostile upstream that streams distinct channels/senders or a
// giant NAMES list: buffers and per-channel members can't grow without limit.
const MAX_BUFFERS = 200;
const MAX_NICKS = 5000;
const MAX_PENDING_SENDS = 64;
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
    alert.setAttribute("role", tone === "error" ? "alert" : "status");
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
  alert.setAttribute("role", tone === "error" ? "alert" : "status");
  alert.firstElementChild.textContent = text;
  const existingAction = alert.querySelector(".alert-action");
  if (existingAction) existingAction.remove();
  if (action) {
    const control = action.href ? document.createElement("a") : document.createElement("button");
    control.className = "alert-action";
    control.textContent = action.label;
    if (action.href) {
      control.href = action.href;
    } else {
      control.type = "button";
      control.addEventListener("click", action.onClick);
    }
    alert.insertBefore(control, alert.lastElementChild);
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

// name -> { name, kind: "server"|"channel"|"dm", lines: [], nicks: Map, topic, unread, mentions }
const buffers = new Map();
const namesSnapshots = new Set();
const namesRequested = new Set();
let active = null;
let myNick = null;
let socket = null;
let upstreamConnected = false;
let snapshotComplete = false;
let initialReplay = new Map();
let memberTracking = true;
let nextSendId = 0;
const pendingSends = new Map();

function rememberSentText(text) {
  if (sentHistory[sentHistory.length - 1] !== text) sentHistory.push(text);
  if (sentHistory.length > 100) sentHistory.shift();
  historyIdx = -1;
}

function acceptPendingSend(requestId) {
  const pending = pendingSends.get(requestId);
  if (!pending) return false;
  pendingSends.delete(requestId);
  const { buffer, text } = pending;
  if (buffer) {
    if (text.startsWith("/me ")) {
      addLine(buffer.display, "event", buffer.kind, null, `* ${myNick} ${text.slice(4)}`);
    } else if (!text.startsWith("/")) {
      addLine(buffer.display, "msg", buffer.kind, myNick, text);
    }
  }
  rememberSentText(text);
  return true;
}

function rejectPendingSend(requestId, message) {
  const pending = pendingSends.get(requestId);
  if (!pending) return false;
  pendingSends.delete(requestId);
  rememberSentText(pending.text);
  addServer(message || "Message was not sent.");
  showAlert(
    "send",
    message || "Message was not sent.",
    "error",
    {
      label: "Restore message",
      onClick: () => restoreRejectedMessage(pending.text),
    },
  );
  return true;
}

// A server rejection is an explicit no-send verdict, not permission to retry
// automatically. Restore the exact text for review in the composer, where the
// user remains in control of editing and sending it again.
function restoreRejectedMessage(text) {
  messageInput.value = text;
  historyIdx = -1;
  historyDraft = "";
  messageInput.focus();
  showAlert("send", "Message restored. Review it, then send when ready.", "warning");
}

function rejectAllPendingSends(reason) {
  if (pendingSends.size === 0) return;
  const count = pendingSends.size;
  for (const pending of pendingSends.values()) rememberSentText(pending.text);
  pendingSends.clear();
  addServer(`${count} message(s) were not confirmed before ${reason}.`);
  showAlert(
    "send",
    `${count} message(s) were not confirmed before ${reason}; use input history to retry.`,
    "error",
  );
}

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

function closeMobileSidebar({ restoreFocus = false } = {}) {
  document.body.classList.remove("sidebar-open");
  if (sidebarToggle) sidebarToggle.setAttribute("aria-expanded", "false");
  if (restoreFocus) sidebarToggle?.focus();
}

if (sidebarToggle) {
  sidebarToggle.addEventListener("click", () => {
    const open = document.body.classList.toggle("sidebar-open");
    sidebarToggle.setAttribute("aria-expanded", String(open));
    if (open) sidebarEl?.querySelector(".buf")?.focus();
  });
}

document.addEventListener("keydown", (event) => {
  if (event.key === "Escape" && document.body.classList.contains("sidebar-open")) {
    event.preventDefault();
    closeMobileSidebar({ restoreFocus: true });
  }
});

function requestNames(buffer) {
  if (
    !memberTracking ||
    buffer.kind !== "channel" ||
    !upstreamConnected ||
    !snapshotComplete ||
    !socket ||
    socket.readyState !== WebSocket.OPEN ||
    namesRequested.has(buffer.key)
  ) {
    return;
  }
  namesRequested.add(buffer.key);
  socket.send(JSON.stringify({ target: "", message: `/raw NAMES ${buffer.display}` }));
}

function resyncMemberships() {
  namesRequested.clear();
  namesSnapshots.clear();
  for (const buffer of buffers.values()) {
    if (buffer.kind !== "channel") continue;
    buffer.nicks.clear();
    buffer.membershipKnown = false;
    buffer.membersTruncated = false;
    requestNames(buffer);
  }
  renderNickList();
}

// Buffers and nicks are keyed by their casefold; the original casing is kept in
// `.display` (buffers) / the nick map's value for rendering.
function ensureBuffer(name, kind) {
  const key = fold(name);
  let b = buffers.get(key);
  if (b) return b;
  // At the cap, a *new* buffer overflows into the server buffer rather than
  // growing the map without bound — the content is still shown, never dropped.
  if (buffers.size >= MAX_BUFFERS) {
    showAlert(
      "buffers",
      `The ${MAX_BUFFERS}-conversation display limit was reached. New conversation lines are being shown in the server buffer.`,
    );
    return buffers.get(SERVER);
  }
  b = {
    key,
    display: name,
    kind,
    lines: [],
    nicks: new Map(),
    topic: "",
    unread: 0,
    mentions: 0,
    pendingVisibleMessages: 0,
    historyLoaded: false,
    membershipKnown: false,
    membersTruncated: false,
  };
  buffers.set(key, b);
  renderBufferList();
  requestNames(b);
  return b;
}

// Membership modes (each consumes a nick argument in a MODE line).
const SIGIL_MODE_CHARS = "qaohv";
// Modes that consume a parameter whether set or unset (membership + list +
// key), vs. only when set (limit). Used to keep MODE argument alignment so a
// mixed line like `+o-l nick` maps the nick to `o`, not `l`.
const MODE_ALWAYS_ARG = new Set(["q", "a", "o", "h", "v", "b", "e", "I", "k"]);
const MODE_SET_ARG = new Set(["l"]);

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
    const button = document.createElement("button");
    button.type = "button";
    button.className = "buf" + (b.key === active ? " active" : "");
    button.setAttribute("aria-pressed", String(b.key === active));
    const bufferName = b.key === SERVER ? "server" : b.display;
    const inactive = b.key !== active;
    const unreadLabel = b.unread > 0 && inactive
      ? `, ${b.unread} unread message${b.unread === 1 ? "" : "s"}`
      : "";
    const mentionLabel = b.mentions > 0 && inactive
      ? `, ${b.mentions} mention${b.mentions === 1 ? "" : "s"}`
      : "";
    button.setAttribute("aria-label", `Open ${bufferName}${unreadLabel}${mentionLabel}`);
    const label = document.createElement("span");
    label.className = "buf-name";
    label.textContent = bufferName;
    button.appendChild(label);
    if (b.unread > 0 && inactive) {
      const badge = document.createElement("span");
      badge.className = "badge";
      badge.textContent = String(b.unread);
      badge.setAttribute("aria-hidden", "true");
      button.appendChild(badge);
    }
    if (b.mentions > 0 && inactive) {
      const badge = document.createElement("span");
      badge.className = "mention-badge";
      badge.textContent = `@${b.mentions}`;
      badge.title = `${b.mentions} unread mention${b.mentions === 1 ? "" : "s"}`;
      badge.setAttribute("aria-hidden", "true");
      button.appendChild(badge);
    }
    button.addEventListener("click", () => setActive(b.key));
    li.appendChild(button);
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

function renderActive({ atLatest = true } = {}) {
  const b = buffers.get(active);
  bufnameEl.textContent = !b || b.key === SERVER ? "server" : b.display;
  buftopicEl.textContent = b ? b.topic : "";
  if (!b || b.kind === "server") {
    bufferActionEl.hidden = true;
  } else {
    bufferActionEl.hidden = false;
    bufferActionEl.textContent = b.kind === "channel" ? "Leave" : "Close";
    bufferActionEl.title =
      b.kind === "channel" ? `Leave ${b.display}` : `Close conversation with ${b.display}`;
  }
  // "Load earlier" is offered for a real conversation buffer (channel/DM) whose
  // persisted backlog hasn't been pulled yet, and only when attached (network set).
  const loadEarlierEl = el("load-earlier");
  if (loadEarlierEl) {
    const eligible = !!network && !!b && b.kind !== "server" && !b.historyLoaded;
    loadEarlierEl.hidden = !eligible;
  }
  // Switching buffers replaces a complete historical transcript. Mark that
  // replacement busy and quiet so assistive technology announces only later
  // live additions, not every already-read line as a new message.
  messagesEl.setAttribute("aria-busy", "true");
  messagesEl.setAttribute("aria-live", "off");
  messagesEl.replaceChildren();
  if (b) for (const line of b.lines) messagesEl.appendChild(messageRow(line));
  messagesEl.scrollTop = atLatest ? messagesEl.scrollHeight : 0;
  if (b) b.pendingVisibleMessages = 0;
  renderJumpLatest();
  requestAnimationFrame(() => {
    messagesEl.setAttribute("aria-busy", "false");
    messagesEl.setAttribute("aria-live", "polite");
  });
  renderNickList();
}

function isNearLatest() {
  return messagesEl.scrollHeight - messagesEl.scrollTop - messagesEl.clientHeight < 40;
}

function renderJumpLatest() {
  if (!jumpLatestButton) return;
  const count = buffers.get(active)?.pendingVisibleMessages ?? 0;
  jumpLatestButton.hidden = count === 0;
  if (count === 0) return;
  const label = `${count} new message${count === 1 ? "" : "s"}`;
  jumpLatestButton.textContent = `${label} — jump to latest`;
  jumpLatestButton.setAttribute("aria-label", `${label}. Jump to latest messages.`);
}

messagesEl.addEventListener("scroll", () => {
  if (!isNearLatest()) return;
  const b = buffers.get(active);
  if (!b || b.pendingVisibleMessages === 0) return;
  b.pendingVisibleMessages = 0;
  renderJumpLatest();
});

if (jumpLatestButton) {
  jumpLatestButton.addEventListener("click", () => {
    messagesEl.scrollTop = messagesEl.scrollHeight;
    const b = buffers.get(active);
    if (b) b.pendingVisibleMessages = 0;
    renderJumpLatest();
  });
}

function renderNickList() {
  const b = buffers.get(active);
  if (!memberTracking || !b || b.kind !== "channel") {
    nicklistEl.hidden = true;
    clearAlert("members");
    return;
  }
  nicklistEl.hidden = false;
  // Sort by rank (owner/op/… first) then name, and show the sigil.
  const rankOf = (m) => {
    const p = nickPrefix(m);
    const i = MEMBER_RANKS.findIndex(([, s]) => s === p);
    return i === -1 ? MEMBER_RANKS.length : i;
  };
  const members = [...b.nicks.values()].sort(
    (a, c) => rankOf(a.modes) - rankOf(c.modes) || a.name.localeCompare(c.name),
  );
  nickcountEl.textContent = b.membershipKnown
    ? `${members.length}${b.membersTruncated ? "+" : ""}`
    : "…";
  if (b.membersTruncated) {
    showAlert(
      "members",
      `${b.display} has more than ${MAX_NICKS} members. The list is capped at ${MAX_NICKS}; messages remain unaffected.`,
    );
  } else {
    clearAlert("members");
  }
  nicksEl.replaceChildren();
  for (const m of members) {
    const li = document.createElement("li");
    const button = document.createElement("button");
    button.type = "button";
    button.className = "nick";
    button.title = `Message ${m.name}`;
    button.textContent = nickPrefix(m.modes) + m.name;
    // Native button semantics make click, Enter, and Space equivalent.
    const open = () => setActive(ensureBuffer(m.name, "dm").display);
    button.addEventListener("click", open);
    li.appendChild(button);
    nicksEl.appendChild(li);
  }
}

function setActive(name) {
  active = fold(name);
  const b = buffers.get(active);
  if (b) {
    b.unread = 0;
    b.mentions = 0;
  }
  renderBufferList();
  renderActive();
  closeMobileSidebar();
  if (!messageInput.disabled) messageInput.focus();
}

function closeBuffer(name) {
  const key = fold(name);
  if (key === SERVER || !buffers.delete(key)) return;
  namesSnapshots.delete(key);
  namesRequested.delete(key);
  if (active === key) setActive(SERVER);
  else renderBufferList();
}

bufferActionEl.addEventListener("click", () => {
  const buffer = buffers.get(active);
  if (!buffer || buffer.kind === "server") return;
  if (buffer.kind === "dm") {
    closeBuffer(buffer.key);
    return;
  }
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    addServer(`Not connected — ${buffer.display} was not left.`);
    return;
  }
  socket.send(JSON.stringify({ target: "", message: `/part ${buffer.display}` }));
});

// ---- buffer mutation ----------------------------------------------------

function nowHm() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}`;
}

function lineTime(tags, useCurrentTime = true) {
  const iso = tagValue(tags, "time");
  const date = iso ? new Date(iso) : null;
  if (!date || Number.isNaN(date.getTime())) {
    return useCurrentTime
      ? { time: nowHm(), title: new Date().toLocaleString() }
      : { time: "", title: "" };
  }
  const pad = (value) => String(value).padStart(2, "0");
  return {
    time: `${pad(date.getHours())}:${pad(date.getMinutes())}`,
    title: date.toLocaleString(),
  };
}

function addLine(bufName, kind, bufKind, from, text, tags = null) {
  const b = ensureBuffer(bufName, bufKind);
  // A highlight: someone else's channel/DM message that names us.
  const mention = kind === "msg" && from != null && !isMe(from) && mentionsMe(text);
  const line = {
    ...lineTime(tags),
    from,
    text,
    kind,
    mention,
    identity: messageIdentity(tags),
  };
  maybeNotify(b, line);
  b.lines.push(line);
  if (b.lines.length > MAX_LINES) b.lines.shift();
  if (b.key === active) {
    const nearBottom = isNearLatest();
    messagesEl.appendChild(messageRow(line));
    // Trim on the actual DOM node count — the model was already clamped above,
    // so a guard on `b.lines.length` would never fire and the DOM would grow
    // without bound while pinned to one channel.
    while (messagesEl.children.length > MAX_LINES && messagesEl.firstChild) {
      messagesEl.removeChild(messagesEl.firstChild);
    }
    if (nearBottom) {
      messagesEl.scrollTop = messagesEl.scrollHeight;
      b.pendingVisibleMessages = 0;
    } else {
      b.pendingVisibleMessages += 1;
    }
    renderJumpLatest();
  } else {
    b.unread += 1;
    if (line.mention) b.mentions += 1;
    renderBufferList();
  }
}

const addServer = (text) => addLine(SERVER, "server", "server", null, text);
const addEvent = (chan, text) => addLine(chan, "event", "channel", null, text);

function addNick(chan, nick, render = true) {
  const { name, modes } = splitSigil(nick);
  if (!name) return;
  const b = ensureBuffer(chan, "channel");
  if (b.kind !== "channel") return;
  const key = fold(name);
  if (b.nicks.size >= MAX_NICKS && !b.nicks.has(key)) {
    b.membersTruncated = true;
    if (render && b.key === active) renderNickList();
    return;
  }
  const existing = b.nicks.get(key);
  if (existing) {
    existing.name = name;
    for (const mo of modes) existing.modes.add(mo);
  } else {
    b.nicks.set(key, { name, modes });
  }
  if (render && b.key === active) renderNickList();
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
  if (b.kind !== "channel") return;
  b.topic = topic || "";
  if (b.key === active) buftopicEl.textContent = b.topic;
}

// ---- IRC line parsing + routing ----------------------------------------

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
        addLine(target, r.kind, "channel", r.from, r.text, m.tags);
      } else if (target === "*" || target === "") {
        // A server / global notice (e.g. the bouncer's *bnc* control messages):
        // show it in the server buffer, not a phantom DM keyed on the sender.
        addLine(SERVER, r.kind, "server", r.from, r.text, m.tags);
      } else {
        // A direct message: key the buffer by the other party — the sender,
        // unless the sender is us (a message we sent to `target`).
        const buf = isMe(m.nick) ? target : m.nick || target;
        addLine(buf, r.kind, "dm", r.from, r.text, m.tags);
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
        if (isMe(m.nick)) {
          const channel = m.params[0];
          closeBuffer(channel);
          addServer(`You left ${channel}${reason}.`);
        } else {
          removeNick(m.params[0], m.nick);
          addEvent(m.params[0], `${m.nick || "?"} left${reason}`);
        }
      }
      break;
    case "KICK":
      if (m.params[0] && m.params[1]) {
        const reason = m.params[2] ? ` (${m.params[2]})` : "";
        const by = m.nick ? ` by ${m.nick}` : "";
        if (isMe(m.params[1])) {
          const channel = m.params[0];
          closeBuffer(channel);
          addServer(`You were kicked from ${channel}${by}${reason}.`);
        } else {
          removeNick(m.params[0], m.params[1]);
          addEvent(m.params[0], `${m.params[1]} was kicked${by}${reason}`);
        }
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
      if (!chan) break;
      const buffer = ensureBuffer(chan, "channel");
      if (buffer.kind !== "channel") break;
      if (!namesSnapshots.has(buffer.key)) {
        namesSnapshots.add(buffer.key);
        buffer.nicks.clear();
        buffer.membershipKnown = false;
        buffer.membersTruncated = false;
      }
      for (const nick of (m.params[3] || "").split(" ").filter(Boolean)) {
        addNick(chan, nick, false);
      }
      if (buffer.key === active) renderNickList();
      break;
    }
    case "366": { // end of NAMES: <me> <chan> :End of /NAMES list
      const channel = m.params[1];
      const buffer = channel ? buffers.get(fold(channel)) : null;
      if (buffer) {
        buffer.membershipKnown = true;
        namesSnapshots.delete(buffer.key);
        if (buffer.key === active) renderNickList();
      }
      break;
    }
    default:
      // Numerics and everything else land in the server buffer. Show the human
      // part (the trailing) when there is one, else the whole line.
      addServer(m.params.length ? m.params[m.params.length - 1] : raw);
  }
}

function rememberInitialReplay(lines) {
  initialReplay = new Map();
  for (const line of lines) {
    initialReplay.set(line, (initialReplay.get(line) ?? 0) + 1);
  }
}

function isInitialReplay(line) {
  const count = initialReplay.get(line) ?? 0;
  if (count === 0) return false;
  if (count === 1) initialReplay.delete(line);
  else initialReplay.set(line, count - 1);
  return true;
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
  showAlert(
    "socket",
    `The live connection to ${network} closed. e6irc will retry with bounded backoff.`,
    "error",
    { label: "Retry now", onClick: retryConnectionNow },
  );
  reconnectTimer = window.setTimeout(() => {
    reconnectTimer = null;
    connect();
  }, wait);
}

function retryConnectionNow() {
  if (terminalSocket) return;
  if (reconnectTimer) {
    window.clearTimeout(reconnectTimer);
    reconnectTimer = null;
  }
  connect();
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
  upstreamConnected = false;
  snapshotComplete = false;
  setComposerAvailable(false);
  setStatus(`attaching to ${network}…`, "connecting");
  rejectAllPendingSends("the connection was replaced");
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
    clearAlert("send");
    clearAlert("socket-close");
    clearAlert("network-unavailable");
  });
  liveSocket.addEventListener("error", () => {
    if (socket !== liveSocket) return;
    showAlert(
      "socket",
      `The live connection to ${network} failed. e6irc will keep retrying with bounded backoff.`,
      "error",
      { label: "Retry now", onClick: retryConnectionNow },
    );
  });
  liveSocket.addEventListener("close", (event) => {
    if (socket !== liveSocket) return;
    socket = null;
    rejectAllPendingSends("the live connection closed");
    upstreamConnected = false;
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
    if (event.t === "line" && typeof event.v === "string") {
      if (snapshotComplete || !isInitialReplay(event.v)) handleLine(event.v);
    }
    else if (event.t === "sent" && typeof event.v === "string") {
      if (!acceptPendingSend(event.v)) {
        showAlert("protocol", "The server acknowledged an unknown composer request.", "error");
      }
    } else if (
      event.t === "send-error"
      && typeof event.v === "string"
      && typeof event.message === "string"
    ) {
      if (!rejectPendingSend(event.v, event.message)) {
        showAlert("protocol", "The server rejected an unknown composer request.", "error");
      }
    }
    else if (event.t === "status" && event.v === "connected") {
      const becameConnected = !upstreamConnected;
      upstreamConnected = true;
      setStatus(`${network}: upstream connected`, "ok");
      if (becameConnected && snapshotComplete) resyncMemberships();
    } else if (event.t === "status" && event.v === "disconnected") {
      upstreamConnected = false;
      // The server includes the classified failure summary when it knows why
      // the upstream dropped — say it, don't leave the user guessing.
      const why = typeof event.reason === "string" && event.reason ? ` — ${event.reason}` : "";
      setStatus(`${network}: upstream reconnecting${why}`, "error");
    } else if (event.t === "snapshot" && event.v === "complete") {
      snapshotComplete = true;
      initialReplay.clear();
      if (upstreamConnected) resyncMemberships();
    } else if (event.t === "status" && event.v === "unavailable") {
      terminalSocket = true;
      upstreamConnected = false;
      setComposerAvailable(false);
      clearAlert("socket");
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
  // The server maps correlated {id, target, message} requests (including
  // slash-commands) to one validated IRC line.
  const b = active !== SERVER ? buffers.get(active) : null;
  // In the server buffer there is no target, so plain text would be sent as a
  // raw IRC line and bounce back as "421 Unknown command". Require a /command
  // (e.g. /join #chan) there instead of emitting a bogus line.
  if (!b && !text.startsWith("/")) {
    addServer("No active channel/query — use a /command here (e.g. /join #chan) or pick a buffer.");
    messageInput.focus();
    return;
  }
  if (pendingSends.size >= MAX_PENDING_SENDS) {
    addServer(`Not sending more than ${MAX_PENDING_SENDS} messages without server confirmation.`);
    showAlert(
      "send",
      `The outbound confirmation queue is full (${MAX_PENDING_SENDS}); wait or reconnect before retrying.`,
      "error",
    );
    return;
  }
  const target = b ? b.display : "";
  nextSendId += 1;
  const requestId = nextSendId.toString(36);
  pendingSends.set(requestId, { buffer: b, text });
  try {
    socket.send(JSON.stringify({ id: requestId, target, message: text }));
  } catch (error) {
    pendingSends.delete(requestId);
    addServer("The message could not enter the live connection and was not sent.");
    showAlert("send", errorMessage("send the message", error), "error");
    return;
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
    option.textContent = `${item.name} · ${networkStateLabel(item)}`;
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

function renderNetworkPicker(networks, failure = null) {
  setStatus(failure ? "network list unavailable" : "choose a network", failure ? "error" : "connecting");
  bufnameEl.textContent = "Select a network";
  buftopicEl.textContent = "";
  nicklistEl.hidden = true;
  messagesEl.replaceChildren();
  const intro = document.createElement("li");
  intro.className = "network-picker-intro";
  const panel = document.createElement("div");
  if (failure) panel.setAttribute("role", "alert");
  const title = document.createElement("h2");
  title.textContent = failure ? "Network list unavailable" : "Your chat networks";
  const copy = document.createElement("p");
  copy.textContent = failure
    ? "Could not load your networks. This is an API failure, not an empty account."
    : networks.length
      ? "Choose an always-on network:"
      : "No networks are configured for this account.";
  panel.append(title, copy);
  intro.appendChild(panel);
  if (!failure && networks.length) messagesEl.appendChild(intro);
  for (const item of networks) {
    const li = document.createElement("li");
    li.className = "line";
    const a = document.createElement("a");
    a.className = "picker-net";
    a.href = `/?network=${encodeURIComponent(item.name)}`;
    const name = document.createElement("span");
    name.textContent = item.name;
    const state = document.createElement("small");
    state.textContent = networkStateLabel(item);
    a.append(name, state);
    li.appendChild(a);
    messagesEl.appendChild(li);
  }
  const manageLi = document.createElement("li");
  manageLi.className = "line picker-actions";
  const manage = document.createElement("a");
  const signInRequired = failure instanceof ApiError && failure.status === 401;
  manage.href = signInRequired ? "/login" : "/console/networks";
  manage.textContent = signInRequired
    ? "Sign in"
    : failure
      ? "Open network console"
    : networks.length
      ? "Manage networks"
      : "Add a network";
  manageLi.appendChild(manage);
  if (failure && !signInRequired) {
    const retry = document.createElement("a");
    retry.href = "/";
    retry.textContent = "Retry";
    manageLi.appendChild(retry);
  }
  if (failure || networks.length === 0) {
    const actions = document.createElement("div");
    actions.className = "picker-actions";
    for (const control of Array.from(manageLi.children)) actions.appendChild(control);
    panel.appendChild(actions);
  } else {
    messagesEl.appendChild(manageLi);
  }
  if (failure || networks.length === 0) messagesEl.appendChild(intro);
}

// ---- load earlier history ----------------------------------------------

// Pull the network's persisted backlog and prepend the active buffer's older
// messages. Both persisted and live raw lines retain server-time and msgid
// tags, so overlap has a stable identity and a consistent clock. One-shot per
// buffer.
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
    lines = backlogFrom(
      await getJson(
        window.fetch.bind(window),
        `/api/v1/me/networks/${encodeURIComponent(network)}/buffer?limit=1000`,
      ),
    );
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
    rebuilt.push({
      ...lineTime(m.tags, false),
      from: rendered.from,
      text: rendered.text,
      kind: rendered.kind,
      mention: false,
      identity: messageIdentity(m.tags),
    });
  }
  // History is older context, never authority over the live buffer. Messages
  // can arrive while this request is in flight, and local echoes may not exist
  // in persisted input at all, so replacing `b.lines` loses user-visible data.
  // Stable msgids suppress true overlap; unidentified rows are retained.
  b.lines = mergeTimeline(rebuilt, b.lines, MAX_LINES);
  b.historyLoaded = true;
  // Loading older context is an explicit reader action. Keep that context in
  // view instead of snapping back to the live edge where it cannot be seen.
  if (b.key === active) renderActive({ atLatest: false });
}

async function loadInitialBacklog() {
  try {
    const lines = backlogFrom(
      await getJson(
        window.fetch.bind(window),
        `/api/v1/me/networks/${encodeURIComponent(network)}/buffer?limit=1000`,
      ),
    );
    rememberInitialReplay(lines);
    for (const line of lines) handleLine(line);
    clearAlert("history");
  } catch (error) {
    const message = errorMessage("load initial messages", error);
    addServer(message);
    showAlert("history", message, "error");
  }
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
    const me = identityFrom(await getJson(window.fetch.bind(window), "/api/v1/me"));
    el("account-name").textContent = me.account;
    el("account-link").dataset.shauthUser = me.account;
    el("account-name").title = me.email || "";
    el("account-role").textContent = me.role || "";
    if (me.logoutURL) el("logout-link").href = me.logoutURL;
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
    memberTracking =
      typeof selected.kind !== "string" ||
      selected.kind === "irc" ||
      selected.kind === "local";
  }

  await loadInitialBacklog();
  connect();
}

boot().catch((error) => {
  setComposerAvailable(false);
  setStatus("client startup failed", "error");
  showAlert("boot", errorMessage("start the chat client", error), "error");
});
