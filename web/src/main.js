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
  identityFrom,
  loadSettings,
  networkStateHelp,
  networkStateIsFailure,
  networkStateLabel,
  networksFrom,
  SETTINGS_KEY,
  saveSetting,
} from "./client-state.js";
import { apiContractLoader, getOperationJson } from "./api-contract.js";
import { serializeComposerRequest } from "./composer-request.js";
import {
  NetworkRequestError,
  createNetworkBody,
  updateNetworkBody,
} from "./network-request.js";
import { parseUiEvent } from "./ui-event.js";
import {
  MEMBER_RANKS,
  asMessage,
  chatMessageRoute,
  fold,
  isChannel,
  kickPairs,
  membershipTargets,
  mergeTimeline,
  messageIdentity,
  nickPrefix,
  parseIrc,
  reconcileChannelSnapshot,
  splitSigil,
  stripFormatting,
  stripSigil,
  tagValue,
  topicReply,
} from "./irc-state.js";

const params = new URLSearchParams(window.location.search);
// Reassigned once, at boot, when the URL names no network and one is opened
// for the person instead of making them pick their only one.
let network = params.get("network");
const currentApiContract = apiContractLoader(window.fetch.bind(window));
const apiGet = async (url) => getOperationJson(
  window.fetch.bind(window),
  await currentApiContract(),
  "GET",
  url,
  { cache: "no-store", credentials: "same-origin" },
);

// Mutations take the same contract path as reads: the body is validated against
// the OpenAPI request schema before it leaves the browser, so a field this
// client renames or forgets fails here, with a message naming the field, rather
// than as a 400 the person filling in the form has to interpret.
//
// The session's CSRF token comes from /api/v1/me, read fresh for each mutation
// so a session replaced in another tab never leaves this one holding a stale
// token. The contract layer refuses an unsafe method without it.
const apiSend = async (method, url, json) => getOperationJson(
  window.fetch.bind(window),
  await currentApiContract(),
  method,
  url,
  {
    cache: "no-store",
    credentials: "same-origin",
    csrf: identityFrom(await apiGet("/api/v1/me")).csrfToken,
    json,
  },
);

const el = (id) => document.getElementById(id);
const statusEl = el("status");
const buffersEl = el("buffers");
const messagesEl = el("messages");
const bufnameEl = el("bufname");
const buftopicEl = el("buftopic");
const routeNetworkEl = el("route-network");
const bufferActionEl = el("buffer-action");
const nicklistEl = el("nicklist");
const nicksEl = el("nicks");
const nickcountEl = el("nickcount");
const composer = el("composer");
const messageInput = el("message");
const alertsEl = el("alerts");
const sidebarToggle = el("sidebar-toggle");
const sidebarEl = el("sidebar");
const settingsEl = el("settings");
const rawOutputPanel = el("raw-output-panel");
const rawOutputLines = el("raw-output-lines");
const jumpLatestButton = el("jump-latest");
const sendButton = composer.querySelector("button[type=submit]");
const joinInput = el("join-input");
const joinButton = el("join-form")?.querySelector("button[type=submit]");

const MAX_LINES = 500;
// Explicit history loading may add one full API page in front of the live
// window. Keep both sides bounded without immediately throwing the requested
// older context away just because the live window already reached MAX_LINES.
const MAX_LOADED_LINES = 1500;
// Bounds against a hostile upstream that streams distinct channels/senders or a
// giant NAMES list: buffers and per-channel members can't grow without limit.
const MAX_BUFFERS = 200;
const MAX_NICKS = 5000;
const MAX_PENDING_SENDS = 64;
const MAX_RAW_LINES = 1000;
const SERVER = "*server*";
const rawTape = [];

// ---- client settings (persisted in localStorage) -----------------------
const loadedSettings = loadSettings(() => window.localStorage);
const settings = loadedSettings.settings;

// What was last reported under each key, so a condition that is re-detected on
// a timer is said once: the alert is neither rebuilt (a role=alert whose text
// is reassigned is announced again) nor resurrected after it was dismissed.
// Clearing the key -- the condition ended -- lets it be reported afresh.
const reportedAlerts = new Map();

function showAlert(key, text, tone = "warning", action = null) {
  const report = `${tone}\n${text}\n${action?.label ?? ""}`;
  if (reportedAlerts.get(key) === report) return;
  reportedAlerts.set(key, report);
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
  reportedAlerts.delete(key);
  alertsEl.querySelector(`[data-alert="${CSS.escape(key)}"]`)?.remove();
}

function persistSetting(key) {
  const warning = saveSetting(() => window.localStorage, key, settings[key]);
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
// Channels this client asked to join (folded), so that only those joins move
// the view. Bounded: a channel that never confirms is forgotten with the rest
// when the list is full.
const requestedJoins = new Set();
const MAX_REQUESTED_JOINS = 64;
function rememberRequestedJoins(list) {
  for (const channel of String(list).split(",")) {
    if (!isChannel(channel)) continue;
    if (requestedJoins.size >= MAX_REQUESTED_JOINS) requestedJoins.clear();
    requestedJoins.add(fold(channel));
  }
}
let myNick = null;
let socket = null;
let upstreamConnected = false;
let snapshotComplete = false;
let memberTracking = true;
let nextSendId = 0;
const pendingSends = new Map();

function sendComposer(target, message, requestId = undefined) {
  if (!socket || socket.readyState !== WebSocket.OPEN) return false;
  socket.send(serializeComposerRequest({ id: requestId, target, message }));
  return true;
}

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
  if (joinInput) joinInput.disabled = !available;
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
  // An open modal owns Escape. Cancelling the event here for the rail or the
  // preferences menu beneath it would also cancel the dialog's close request,
  // so the dialog would need a second press.
  if (document.querySelector("dialog[open]")) return;
  if (event.key === "Escape" && document.body.classList.contains("sidebar-open")) {
    event.preventDefault();
    closeMobileSidebar({ restoreFocus: true });
    return;
  }
  if (event.key === "Escape" && settingsEl?.open) {
    event.preventDefault();
    settingsEl.open = false;
    settingsEl.querySelector("summary")?.focus();
  }
});

function requestNames(buffer) {
  if (
    !memberTracking ||
    buffer.kind !== "channel" ||
    !buffer.joined ||
    !upstreamConnected ||
    !snapshotComplete ||
    !socket ||
    socket.readyState !== WebSocket.OPEN ||
    namesRequested.has(buffer.key)
  ) {
    return;
  }
  namesRequested.add(buffer.key);
  try {
    if (!sendComposer("", `/raw NAMES ${buffer.display}`)) {
      namesRequested.delete(buffer.key);
      addServer(`Could not refresh members for ${buffer.display}.`);
    }
  } catch {
    namesRequested.delete(buffer.key);
    addServer(`Could not refresh members for ${buffer.display}.`);
  }
}

function resyncMemberships() {
  namesRequested.clear();
  namesSnapshots.clear();
  for (const buffer of buffers.values()) {
    if (buffer.kind !== "channel" || !buffer.joined) continue;
    buffer.nicks.clear();
    buffer.membershipKnown = false;
    buffer.membersTruncated = false;
    requestNames(buffer);
  }
  renderNickList();
}

function applySessionSnapshot(nick, channels) {
  myNick = nick;
  const current = [...buffers.values()]
    .filter((buffer) => buffer.kind === "channel")
    .map((buffer) => buffer.display);
  const reconciliation = reconcileChannelSnapshot(current, channels);
  for (const channel of reconciliation.removed) {
    const key = fold(channel);
    const buffer = buffers.get(key);
    if (!buffer) continue;
    // A reconnect begins with an empty authoritative membership set and fills
    // it as upstream JOINs are confirmed. Keep the transcript as an archived
    // buffer during that transition; only an explicit PART/KICK closes it.
    buffer.joined = false;
    buffer.nicks.clear();
    buffer.membershipKnown = false;
    buffer.membersTruncated = false;
    namesSnapshots.delete(key);
    namesRequested.delete(key);
  }
  for (const channel of reconciliation.joined) {
    const buffer = ensureBuffer(channel, "channel");
    if (buffer.kind === "channel") buffer.joined = true;
  }
  renderBufferList();
  renderActive();
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
    joined: kind === "channel" ? false : null,
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
    const archived = b.kind === "channel" && !b.joined;
    button.className = "buf" + (b.key === active ? " active" : "") + (archived ? " archived" : "");
    if (b.key === active) button.setAttribute("aria-current", "true");
    const bufferName = b.key === SERVER ? "server" : b.display;
    const inactive = b.key !== active;
    const unreadLabel = b.unread > 0 && inactive
      ? `, ${b.unread} unread message${b.unread === 1 ? "" : "s"}`
      : "";
    const mentionLabel = b.mentions > 0 && inactive
      ? `, ${b.mentions} mention${b.mentions === 1 ? "" : "s"}`
      : "";
    const archivedLabel = archived ? ", past channel, not currently joined" : "";
    button.setAttribute(
      "aria-label",
      `Open ${bufferName}${archivedLabel}${unreadLabel}${mentionLabel}`,
    );
    const label = document.createElement("span");
    label.className = "buf-name";
    label.textContent = bufferName;
    button.appendChild(label);
    if (archived) {
      const state = document.createElement("span");
      state.className = "buffer-state";
      state.textContent = "past";
      state.setAttribute("aria-hidden", "true");
      button.appendChild(state);
    }
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
  if (line.time) time.setAttribute("aria-label", `At ${line.time}`);
  if (line.title) time.title = line.title; // full date+time on hover
  const from = document.createElement("span");
  from.className = "from";
  from.textContent = line.from ? line.from : "";
  if (line.from) from.setAttribute("aria-label", `From ${line.from}`);
  const text = document.createElement("span");
  text.className = "text";
  renderText(text, line.text);
  row.append(time, from, text);
  return row;
}

function rawOutputRow(wire) {
  const row = document.createElement("li");
  const code = document.createElement("code");
  code.className = "raw-wire";
  code.textContent = wire;
  row.append(code);
  return row;
}

function renderRawOutput() {
  if (!rawOutputPanel || !rawOutputLines) return;
  rawOutputPanel.hidden = !settings.rawOutput;
  rawOutputLines.replaceChildren();
  if (!settings.rawOutput) return;
  for (const wire of rawTape) rawOutputLines.append(rawOutputRow(wire));
  rawOutputLines.scrollTop = rawOutputLines.scrollHeight;
}

function recordRawOutput(wire) {
  rawTape.push(wire);
  if (rawTape.length > MAX_RAW_LINES) rawTape.shift();
  if (!settings.rawOutput || !rawOutputLines) return;
  rawOutputLines.append(rawOutputRow(wire));
  while (rawOutputLines.children.length > MAX_RAW_LINES && rawOutputLines.firstChild) {
    rawOutputLines.removeChild(rawOutputLines.firstChild);
  }
  rawOutputLines.scrollTop = rawOutputLines.scrollHeight;
}

function renderActive({ atLatest = true } = {}) {
  const b = buffers.get(active);
  routeNetworkEl.textContent = network || "";
  bufnameEl.textContent = !b || b.key === SERVER ? "server" : b.display;
  buftopicEl.textContent = b ? b.topic : "";
  if (!b || b.kind === "server") {
    bufferActionEl.hidden = true;
  } else {
    bufferActionEl.hidden = false;
    const canLeave = b.kind === "channel" && b.joined;
    bufferActionEl.textContent = canLeave ? "Leave" : "Close";
    const action = canLeave ? `Leave ${b.display}` : `Close conversation with ${b.display}`;
    bufferActionEl.title = action;
    bufferActionEl.setAttribute("aria-label", action);
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

function isAtLatest() {
  return messagesEl.scrollHeight - messagesEl.scrollTop - messagesEl.clientHeight <= 1;
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
  if (!isAtLatest()) return;
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
    const action = `Open conversation with ${m.name}`;
    button.title = action;
    button.setAttribute("aria-label", action);
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
  if (buffer.kind === "dm" || !buffer.joined) {
    closeBuffer(buffer.key);
    return;
  }
  if (!socket || socket.readyState !== WebSocket.OPEN) {
    addServer(`Not connected — ${buffer.display} was not left.`);
    return;
  }
  try {
    if (!sendComposer("", `/part ${buffer.display}`)) {
      addServer(`Not connected — ${buffer.display} was not left.`);
    }
  } catch {
    addServer(`The request to leave ${buffer.display} was not sent.`);
  }
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

function addLine(bufName, kind, bufKind, from, text, tags = null, wire = null) {
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
    wire,
  };
  maybeNotify(b, line);
  b.lines.push(line);
  const lineLimit = b.historyLoaded ? MAX_LOADED_LINES : MAX_LINES;
  if (b.lines.length > lineLimit) b.lines.shift();
  if (b.key === active) {
    const atLatest = isAtLatest();
    messagesEl.appendChild(messageRow(line));
    // Trim on the actual DOM node count — the model was already clamped above,
    // so a guard on `b.lines.length` would never fire and the DOM would grow
    // without bound while pinned to one channel.
    while (messagesEl.children.length > lineLimit && messagesEl.firstChild) {
      messagesEl.removeChild(messagesEl.firstChild);
    }
    if (atLatest) {
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

const addServer = (text, wire = null) => addLine(SERVER, "server", "server", null, text, null, wire);
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
  const conversation = buffers.get(fromKey);
  if (conversation && conversation.kind === "dm" && !buffers.has(fold(toName))) {
    // Sends to the old nick would go nowhere while echoing here as delivered.
    buffers.delete(fromKey);
    conversation.key = fold(toName);
    conversation.display = toName;
    buffers.set(conversation.key, conversation);
    if (active === fromKey) active = conversation.key;
    addEvent(toName, `${stripSigil(from)} is now ${toName}`);
    renderBufferList();
    if (active === conversation.key) renderActive();
  }
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
  b.topic = stripFormatting(topic);
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
    persistSetting("notifications");
    updateSettingsUI();
    showAlert(
      "notifications",
      errorMessage("show a desktop notification", error),
      "warning",
    );
  }
}

function handleLine(raw) {
  recordRawOutput(raw);
  const m = parseIrc(raw);
  switch (m.command) {
    case "001":
      if (m.params[0]) {
        myNick = m.params[0];
        addServer(`connected as ${myNick}`, raw);
      } else {
        addServer(raw, raw);
      }
      break;
    case "PRIVMSG":
    case "NOTICE": {
      const route = chatMessageRoute(
        m,
        myNick,
        (candidate) => buffers.get(fold(candidate))?.kind === "channel",
      );
      if (!route) {
        addServer(raw, raw);
        break;
      }
      const text = m.params[1] ?? "";
      const kind = m.command === "NOTICE" ? "notice" : "msg";
      const r = asMessage(kind, m.nick, text);
      if (route.kind === "channel") {
        addLine(route.target, r.kind, "channel", r.from, r.text, m.tags, raw);
      } else if (route.kind === "server") {
        // A server / global notice (e.g. the bouncer's *bnc* control messages):
        // show it in the server buffer, not a phantom DM keyed on the sender.
        addLine(SERVER, r.kind, "server", r.from, r.text, m.tags, raw);
      } else {
        addLine(route.target, r.kind, "dm", r.from, r.text, m.tags, raw);
      }
      break;
    }
    case "JOIN": {
      const channels = membershipTargets(m.params[0]);
      if (!channels.length) {
        addServer(raw, raw);
        break;
      }
      for (const channel of channels) {
        if (isMe(m.nick)) {
          const buffer = ensureBuffer(channel, "channel");
          if (buffer.kind === "channel") buffer.joined = true;
          // Only a join asked for here moves the view. The bouncer rejoins
          // every channel after an upstream reconnect, and another attached
          // client can join too; following those would yank the reader out of
          // the conversation they are in, once per channel.
          if (requestedJoins.delete(fold(channel))) setActive(channel);
        } else if (m.nick) {
          addNick(channel, m.nick);
          addEvent(channel, `${m.nick} joined`);
        } else {
          addServer(raw, raw);
          break;
        }
      }
      break;
    }
    case "PART": {
      const channels = membershipTargets(m.params[0]);
      if (!channels.length || !m.nick) {
        addServer(raw, raw);
        break;
      }
      const reason = m.params[1] ? ` (${m.params[1]})` : "";
      for (const channel of channels) {
        if (isMe(m.nick)) {
          closeBuffer(channel);
          addServer(`You left ${channel}${reason}.`, raw);
        } else {
          removeNick(channel, m.nick);
          addEvent(channel, `${m.nick} left${reason}`);
        }
      }
      break;
    }
    case "KICK": {
      const pairs = kickPairs(m.params[0], m.params[1]);
      if (!pairs.length) {
        addServer(raw, raw);
        break;
      }
      const reason = m.params[2] ? ` (${m.params[2]})` : "";
      const by = m.nick ? ` by ${m.nick}` : "";
      for (const [channel, target] of pairs) {
        if (isMe(target)) {
          closeBuffer(channel);
          addServer(`You were kicked from ${channel}${by}${reason}.`, raw);
        } else {
          removeNick(channel, target);
          addEvent(channel, `${target} was kicked${by}${reason}`);
        }
      }
      break;
    }
    case "QUIT":
      if (m.nick) {
        const reason = m.params[0] ? ` (${m.params[0]})` : "";
        removeNickEverywhere(m.nick, `${stripSigil(m.nick)} quit${reason}`);
      } else addServer(raw, raw);
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
        addServer(m.params.length ? m.params[m.params.length - 1] : raw, raw);
      }
      break;
    }
    case "NICK":
      if (m.nick && m.params[0]) {
        renameNick(m.nick, m.params[0]);
        if (isMe(m.nick)) myNick = m.params[0];
      } else addServer(raw, raw);
      break;
    case "TOPIC":
      if (m.params[0] && m.params[1] !== undefined) {
        setTopic(m.params[0], m.params[1]);
        addEvent(m.params[0], `${m.nick || "?"} set the topic`);
      } else addServer(raw, raw);
      break;
    case "332": { // RPL_TOPIC: <me> <chan> :topic
      const reply = topicReply(m.params);
      if (reply) setTopic(reply.channel, reply.topic);
      else addServer(raw, raw);
      break;
    }
    case "353": {
      // RPL_NAMREPLY: <me> <sym> <chan> :n1 n2 ...
      const chan = m.params[2];
      if (!chan) {
        addServer(raw, raw);
        break;
      }
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
      } else addServer(raw, raw);
      break;
    }
    default:
      // Numerics and everything else land in the server buffer. Show the human
      // part (the trailing) when there is one, else the whole line.
      addServer(m.params.length ? m.params[m.params.length - 1] : raw, raw);
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
      await apiGet("/api/v1/me/networks"),
    );
    renderNetworkList(networks);
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
      ? `${replacement.name} is disabled or cannot run on this server.`
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
      event = parseUiEvent(ev.data);
    } catch {
      showAlert(
        "protocol",
        "The server sent an invalid live event. The event was rejected; other messages remain connected.",
        "error",
      );
      return;
    }
    if (event.type === "line") {
      handleLine(event.value);
    }
    else if (event.type === "sent") {
      if (!acceptPendingSend(event.value)) {
        showAlert("protocol", "The server acknowledged an unknown composer request.", "error");
      }
    } else if (event.type === "send-error") {
      if (!rejectPendingSend(event.value, event.message)) {
        showAlert("protocol", "The server rejected an unknown composer request.", "error");
      }
    } else if (event.type === "status" && event.value === "connected") {
      const becameConnected = !upstreamConnected;
      upstreamConnected = true;
      setStatus(`${network}: upstream connected`, "ok");
      if (becameConnected && snapshotComplete) resyncMemberships();
    } else if (event.type === "status" && event.value === "disconnected") {
      upstreamConnected = false;
      // The server includes the classified failure summary when it knows why
      // the upstream dropped — say it, don't leave the user guessing.
      const why = event.reason ? ` — ${event.reason}` : "";
      setStatus(`${network}: upstream reconnecting${why}`, "error");
    } else if (event.type === "snapshot") {
      snapshotComplete = true;
      if (upstreamConnected) resyncMemberships();
    } else if (event.type === "session") {
      applySessionSnapshot(event.nick, event.channels);
    } else if (event.type === "status" && event.value === "unavailable") {
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
  let text = messageInput.value;
  if (!text) return;
  if (/^\/help\s*$/i.test(text)) {
    // The help dialog's list is the one copy of the command reference.
    const commands = Array.from(document.querySelectorAll("#help-commands code"), (code) => code.textContent);
    addServer(`Commands: ${commands.join(" · ")}. Other slash commands pass through as IRC commands.`);
    setActive(SERVER);
    messageInput.value = "";
    return;
  }
  const query = text.match(/^\/query(?:\s+(\S+))?(?:\s+([\s\S]+))?$/i);
  if (query) {
    const [, nick, message] = query;
    if (!nick) {
      addServer("/query requires a nickname; nothing was sent.");
      setActive(SERVER);
      return;
    }
    setActive(ensureBuffer(nick, "dm").display);
    if (!message) {
      messageInput.value = "";
      return;
    }
    text = message;
  }
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
  const joining = text.match(/^\/(?:join|j)\s+(\S+)/i);
  if (joining) rememberRequestedJoins(joining[1]);
  nextSendId += 1;
  const requestId = nextSendId.toString(36);
  pendingSends.set(requestId, { buffer: b, text });
  try {
    if (!sendComposer(target, text, requestId)) throw new Error("The live connection closed.");
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
      rememberRequestedJoins(chan);
      try {
        if (!sendComposer("", `/join ${chan}`)) {
          addServer("Not connected — cannot join yet.");
          return;
        }
      } catch {
        addServer("The request to join was not sent.");
        return;
      }
    } else {
      addServer("Not connected — cannot join yet.");
    }
    input.value = "";
  });
}

// ---- Networks in the sidebar -------------------------------------------
//
// The one list of networks. It opens a network, shows its state, and carries
// its settings control, the way a hosted IRC client does. There used to be
// three renderings of this list (a header select, this one, and rows in the
// message area); they were fetched once and then disagreed with each other and
// with the server, so a network parked on rejected credentials kept reading
// "connected". One list, refreshed while the page is visible, cannot.

const networksEl = el("networks");
const networkDialog = el("network-dialog");
const networkForm = el("network-form");
const helpDialog = el("help-dialog");

function renderNetworkList(networks, failure = null) {
  if (!networksEl) return;
  networksEl.replaceChildren();
  if (failure) {
    const row = document.createElement("li");
    row.className = "network-row network-row-empty";
    row.textContent = "Networks unavailable.";
    networksEl.append(row);
    return;
  }
  if (!networks.length) {
    const row = document.createElement("li");
    row.className = "network-row network-row-empty";
    row.textContent = "No networks yet — add one with +.";
    networksEl.append(row);
    return;
  }
  for (const item of networks) {
    const row = document.createElement("li");
    row.className = "network-row";
    row.dataset.network = item.name;
    if (network !== null && fold(item.name) === fold(network)) row.classList.add("is-active");

    const open = document.createElement("a");
    open.className = "network-open";
    // A disabled network still opens: its page says why chat is unavailable and
    // links to where it can be enabled, which a dead row could not.
    open.href = `/?network=${encodeURIComponent(item.name)}`;
    open.setAttribute("aria-label", `Open ${item.name}, ${networkStateLabel(item)}`);
    open.dataset.state = networkStateLabel(item);
    const label = document.createElement("span");
    label.className = "network-name";
    label.textContent = item.name;
    const state = document.createElement("span");
    state.className = "network-state";
    state.textContent = networkStateLabel(item);
    open.append(label, state);

    // A parked driver says why and what repairs it, rather than sitting on two
    // words. Both failures it can park on are fixed in this network's settings,
    // which is the control immediately beside this text.
    const help = networkStateHelp(item);
    if (networkStateIsFailure(item)) {
      row.classList.add("is-failed");
      state.classList.add("network-state-failed");
    }
    if (help) {
      // The label above replaces the link's text for assistive technology, so
      // the repair sentence is attached as its description instead of lost.
      const note = document.createElement("span");
      note.className = "network-help";
      note.id = `network-help-${networksEl.children.length}`;
      note.textContent = help;
      open.setAttribute("aria-describedby", note.id);
      open.append(note);
    }

    // The dialog speaks IRC: nickname, NickServ, server. A bridge's fields are
    // a token and room identifiers, which the console's per-type form owns.
    const irc = item.kind === "irc";
    const cog = document.createElement(irc ? "button" : "a");
    cog.className = "network-cog";
    cog.title = `Settings for ${item.name}`;
    cog.setAttribute("aria-label", `Settings for ${item.name}`);
    cog.textContent = "⚙";
    if (irc) {
      cog.type = "button";
      cog.addEventListener("click", () => void openNetworkDialog(item.name));
    } else {
      cog.href = `/console/networks/${encodeURIComponent(item.name)}`;
    }

    row.append(open, cog);
    networksEl.append(row);
  }
}

function setDialogError(message) {
  const box = el("nf-error");
  if (!box) return;
  box.textContent = message || "";
  box.hidden = !message;
}

// The API names the request field a refusal belongs to. Mark and focus that
// input -- opening Advanced when it lives there -- so the sentence above does
// not have to be matched to a box by eye.
const NETWORK_FIELD_INPUTS = Object.freeze({
  name: "nf-name",
  addr: "nf-addr",
  nick: "nf-nick",
  realname: "nf-realname",
  autojoin: "nf-autojoin",
  sasl_account: "nf-sasl-account",
  sasl_password: "nf-sasl-password",
});

function clearFieldMarks() {
  for (const id of Object.values(NETWORK_FIELD_INPUTS)) {
    el(id)?.removeAttribute("aria-invalid");
    el(id)?.removeAttribute("aria-describedby");
  }
}

function markFieldAtFault(field) {
  const input = el(NETWORK_FIELD_INPUTS[field]);
  if (!input) return;
  if (el("nf-advanced").contains(input)) el("nf-advanced").open = true;
  input.setAttribute("aria-invalid", "true");
  input.setAttribute("aria-describedby", "nf-error");
  input.focus();
}

// The curated networks come from the server's one catalog, so the chat client
// and the console cannot disagree about an endpoint. "Custom" is the client's
// own entry: it means "I will type the server myself".
const CUSTOM_PRESET = "custom";
let networkPresets = [];

function applyPreset() {
  const preset = networkPresets.find((item) => item.id === el("nf-preset").value);
  if (preset) {
    el("nf-name").value = preset.name;
    el("nf-addr").value = preset.addr;
    el("nf-tls").checked = preset.tls;
    return;
  }
  // Custom: the name and server are now the person's to fill in, so show them.
  // Only a known network's own values are cleared -- anything the person typed
  // survives flipping the select back and forth.
  const known = (field) => networkPresets.some((item) => item[field] === el(`nf-${field}`).value);
  if (known("name")) el("nf-name").value = "";
  if (known("addr")) el("nf-addr").value = "";
  el("nf-advanced").open = true;
  el("nf-name").focus();
}

// The reveal switch changes the input's type, which form.reset() does not
// undo: without this a password shown, then cancelled, is still in clear (under
// a button reading "Hide") the next time the dialog opens.
function hideRevealedSecrets() {
  for (const button of document.querySelectorAll("[data-reveal]")) {
    const field = el(button.dataset.reveal);
    if (!field) continue;
    field.type = "password";
    button.textContent = "Show";
    button.setAttribute("aria-pressed", "false");
    button.setAttribute("aria-label", "Show password");
  }
}
// A typed secret does not outlive the dialog it was typed into.
networkDialog?.addEventListener("close", () => {
  networkForm?.reset();
  hideRevealedSecrets();
});

// A required field inside a closed <details> would refuse the submit with no
// visible reason. Open the section the moment the browser reports one.
el("nf-advanced")?.addEventListener("invalid", () => { el("nf-advanced").open = true; }, true);
el("nf-preset")?.addEventListener("change", applyPreset);

// Editing shows what is configured but never a stored password: the API does
// not return one, and this deliberately does not ask it to. Leaving the field
// empty keeps whatever is already sealed, which is why the note changes.
// Each opening gets a number. A slow response for an earlier opening must not
// fill in -- or throw inside -- a later one: two quick clicks on different cogs
// used to be able to save one network's server and nickname under the other's
// name.
let dialogOpening = 0;

async function openNetworkDialog(name = null) {
  if (!networkDialog || !networkForm) return;
  dialogOpening += 1;
  const opening = dialogOpening;
  setDialogError("");
  clearFieldMarks();
  networkForm.reset();
  hideRevealedSecrets();
  networkForm.dataset.editing = name || "";
  const editing = name !== null;
  el("network-dialog-title").textContent = editing ? `Settings — ${name}` : "Add a network";
  el("nf-name").disabled = editing;
  el("nf-name-note").textContent = editing
    ? "The name of a network cannot be changed."
    : "A short label for this connection.";
  el("nf-preset-row").hidden = editing;
  el("nf-clear-row").hidden = !editing;
  el("nf-advanced").open = false;
  el("nf-sasl-password-note").textContent = editing
    ? "Leave blank to keep the stored password. Stored encrypted; never shown again."
    : "Stored encrypted; never shown again once saved.";
  el("nf-tls").checked = true;

  // Shown at once, so the click visibly did something, but not saveable until
  // what it edits has arrived.
  el("nf-save").disabled = true;
  networkForm.setAttribute("aria-busy", "true");
  if (!networkDialog.open) networkDialog.showModal();

  try {
    if (editing) {
      const detail = await apiGet(`/api/v1/me/networks/${encodeURIComponent(name)}`);
      if (opening !== dialogOpening) return;
      el("nf-name").value = detail.name ?? name;
      el("nf-addr").value = detail.addr ?? "";
      el("nf-tls").checked = detail.tls !== false;
      el("nf-nick").value = detail.nick ?? "";
      el("nf-realname").value = detail.realname ?? "";
      el("nf-autojoin").value = Array.isArray(detail.autojoin) ? detail.autojoin.join(", ") : "";
      el("nf-sasl-account").value = detail.sasl_account ?? "";
    } else {
      const catalog = (await apiGet("/api/v1/network-presets")).presets;
      if (opening !== dialogOpening) return;
      networkPresets = catalog;
      const options = [...networkPresets, { id: CUSTOM_PRESET, label: "Another network…" }];
      el("nf-preset").replaceChildren(...options.map((preset) => {
        const option = document.createElement("option");
        option.value = preset.id;
        option.textContent = preset.label;
        return option;
      }));
      // The first curated network (Libera) is the interop target this server is
      // tested against, so it is the default rather than a blank form.
      applyPreset();
      el("nf-nick").value = el("account-link").dataset.shauthUser ?? "";
    }
    el("nf-save").disabled = false;
  } catch (error) {
    if (opening !== dialogOpening) return;
    setDialogError(errorMessage(editing ? `load ${name}` : "load the known networks", error));
    if (editing) {
      // Saving a form that never loaded would overwrite the stored channels
      // and real name with blanks. Save stays off; reopening tries again.
      return;
    }
    // Adding still works without the catalog: the person types the server.
    networkPresets = [];
    el("nf-preset-row").hidden = true;
    el("nf-advanced").open = true;
    el("nf-save").disabled = false;
  } finally {
    if (opening === dialogOpening) networkForm.removeAttribute("aria-busy");
  }

  (editing ? el("nf-sasl-account") : el("nf-nick")).focus();
}

if (networkForm) {
  networkForm.addEventListener("submit", async (event) => {
    event.preventDefault();
    setDialogError("");
    clearFieldMarks();
    const editing = networkForm.dataset.editing || "";
    const save = el("nf-save");
    const name = editing || el("nf-name").value.trim();
    const nick = el("nf-nick").value.trim();
    const account = el("nf-sasl-account").value.trim();
    const password = el("nf-sasl-password").value;

    const fields = {
      name,
      addr: el("nf-addr").value,
      tls: el("nf-tls").checked,
      nick,
      realname: el("nf-realname").value,
      autojoin: el("nf-autojoin").value,
      account,
      password,
      clearing: editing ? el("nf-clear").checked : false,
    };

    // network-request.js owns both shapes and is tested on the difference.
    let body;
    try {
      body = editing ? updateNetworkBody(fields) : createNetworkBody(fields);
    } catch (error) {
      if (!(error instanceof NetworkRequestError)) throw error;
      setDialogError(error.message);
      el("nf-advanced").open = true;
      (account || !password ? el("nf-addr") : el("nf-sasl-account")).focus();
      return;
    }

    save.disabled = true;
    try {
      if (editing) {
        await apiSend("PUT", `/api/v1/me/networks/${encodeURIComponent(editing)}`, body);
      } else {
        await apiSend("POST", "/api/v1/me/networks", body);
      }
      networkDialog.close();
      if (!editing) {
        // A network was added to be used: open it rather than asking the
        // person to find the row that just appeared.
        window.location.assign(`/?network=${encodeURIComponent(name)}`);
        return;
      }
      // Saving restarts the driver, so the list is stale the moment it returns.
      await refreshNetworkList();
      addServer(`Saved ${editing}. The connection restarts with the new settings.`);
    } catch (error) {
      setDialogError(errorMessage(editing ? `save ${editing}` : "add the network", error));
      if (error instanceof ApiError && error.field) markFieldAtFault(error.field);
    } finally {
      save.disabled = false;
    }
  });
}

el("nf-cancel")?.addEventListener("click", () => networkDialog?.close());
el("network-add")?.addEventListener("click", () => void openNetworkDialog(null));

// A pasted password cannot be verified any other way, and this is exactly
// where a silent typo becomes a failed SASL exchange that reads as "wrong
// credentials". The toggle never reveals a stored secret -- only what is
// currently typed into the field.
for (const button of document.querySelectorAll("[data-reveal]")) {
  button.addEventListener("click", () => {
    const field = el(button.dataset.reveal);
    if (!field) return;
    const shown = field.type === "text";
    field.type = shown ? "password" : "text";
    button.textContent = shown ? "Show" : "Hide";
    button.setAttribute("aria-pressed", String(!shown));
    button.setAttribute("aria-label", shown ? "Show password" : "Hide password");
    field.focus();
  });
}

el("help-toggle")?.addEventListener("click", () => helpDialog?.showModal());
el("help-close")?.addEventListener("click", () => helpDialog?.close());

// The wire log is recorded whether or not it is on screen, so this only decides
// visibility. Its one switch lives in the sidebar because it is consulted
// precisely when a connection is misbehaving.
const serverLogLink = el("server-log-link");
function syncServerLogLink() {
  if (!serverLogLink) return;
  serverLogLink.setAttribute("aria-pressed", String(Boolean(settings.rawOutput)));
  serverLogLink.classList.toggle("is-active", Boolean(settings.rawOutput));
}
if (serverLogLink) {
  serverLogLink.addEventListener("click", () => {
    settings.rawOutput = !settings.rawOutput;
    persistSetting("rawOutput");
    renderRawOutput();
    syncServerLogLink();
    if (settings.rawOutput) {
      rawOutputPanel?.scrollIntoView({ block: "nearest" });
    }
  });
}

// What the message area shows when no network is open: nothing to pick from
// here -- the sidebar is the list -- only what to do next.
function renderLanding(networks, failure = null) {
  routeNetworkEl.textContent = "";
  setStatus(failure ? "network list unavailable" : "no network open", failure ? "error" : "connecting");
  bufnameEl.textContent = "Your networks";
  buftopicEl.textContent = "";
  nicklistEl.hidden = true;
  messagesEl.replaceChildren();
  const intro = document.createElement("li");
  intro.className = "network-picker-intro";
  const panel = document.createElement("div");
  if (failure) {
    panel.setAttribute("role", "alert");
    panel.dataset.alert = "networks";
  }
  const title = document.createElement("h2");
  title.textContent = failure ? "Network list unavailable" : "Your chat networks";
  const copy = document.createElement("p");
  copy.textContent = failure
    ? `${errorMessage("load your networks", failure)} This is an API failure, not an empty account.`
    : networks.some((item) => item.enabled !== false && item.runtime != null)
      ? "Choose a network from your list to open it."
      : networks.length
        ? "None of your networks is running. Open one from the list to see why, or add another."
        : "No networks are configured for this account.";
  const actions = document.createElement("div");
  actions.className = "picker-actions";
  const signInRequired = failure instanceof ApiError && failure.status === 401;
  if (signInRequired) {
    const signIn = document.createElement("a");
    signIn.href = "/login";
    signIn.textContent = "Sign in";
    actions.append(signIn);
  } else if (failure) {
    const retry = document.createElement("a");
    retry.href = "/";
    retry.textContent = "Retry";
    actions.append(retry);
  } else {
    // On a phone the list lives in the conversation rail; say how to reach it
    // rather than opening it unasked. Wider screens already show the list.
    if (networks.length && sidebarToggle && sidebarToggle.offsetParent !== null) {
      const show = document.createElement("button");
      show.type = "button";
      show.textContent = "Show my networks";
      show.addEventListener("click", () => sidebarToggle.click());
      actions.append(show);
    }
    const add = document.createElement("button");
    add.type = "button";
    add.textContent = "Add a network";
    add.addEventListener("click", () => void openNetworkDialog(null));
    actions.append(add);
  }
  panel.append(title, copy, actions);
  intro.appendChild(panel);
  messagesEl.appendChild(intro);
}

// Network state changes on the server (a reconnect, a rejected password), so
// the list is re-read while the page is visible. A failed refresh keeps the
// last good list on screen and says so once, rather than blanking it.
const NETWORK_REFRESH_MS = 10_000;
let networkListTimer = null;
let renderedNetworks = null;

// Re-rendering replaces every row, which drops keyboard focus and any hover
// text; so an unchanged list is left alone, and a changed one hands focus back
// to the same control of the same network.
function renderNetworkListKeepingFocus(networks) {
  const rendered = JSON.stringify(networks);
  if (rendered === renderedNetworks) return;
  renderedNetworks = rendered;
  const focused = document.activeElement;
  const row = focused instanceof HTMLElement && networksEl.contains(focused) ? focused.closest(".network-row") : null;
  const name = row?.dataset.network ?? null;
  const control = focused?.classList.contains("network-cog") ? ".network-cog" : ".network-open";
  renderNetworkList(networks);
  if (name === null) return;
  const again = Array.from(networksEl.querySelectorAll(".network-row")).find((item) => item.dataset.network === name);
  again?.querySelector(control)?.focus();
}

async function refreshNetworkList() {
  try {
    renderNetworkListKeepingFocus(networksFrom(await apiGet("/api/v1/me/networks")));
    clearAlert("networks");
  } catch (error) {
    const expired = error instanceof ApiError && error.status === 401;
    showAlert(
      "networks",
      errorMessage("refresh your networks", error),
      "error",
      expired ? { href: "/login", label: "Sign in" } : null,
    );
    // Asking again cannot succeed until the person signs in.
    if (expired && networkListTimer !== null) {
      window.clearInterval(networkListTimer);
      networkListTimer = null;
    }
  }
}
function keepNetworkListCurrent() {
  const refreshWhenShown = () => {
    if (document.visibilityState === "visible" && !networkDialog?.open) void refreshNetworkList();
  };
  networkListTimer = window.setInterval(refreshWhenShown, NETWORK_REFRESH_MS);
  // Coming back to the tab should not show up to ten seconds of stale state.
  document.addEventListener("visibilitychange", refreshWhenShown);
}

// ---- load earlier history ----------------------------------------------

// Pull the network's persisted backlog and prepend the active buffer's older
// messages. Persisted and live raw lines retain any upstream identity tags;
// exact ordered wire overlap handles servers that do not send msgids. One-shot
// per buffer.
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
      await apiGet(
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
    const route = chatMessageRoute(
      m,
      myNick,
      (candidate) => b.kind === "channel" && fold(candidate) === b.key,
    );
    if (!route || route.kind !== b.kind || fold(route.target || "") !== b.key) continue;
    const kind = m.command === "NOTICE" ? "notice" : "msg";
    const rendered = asMessage(kind, m.nick, m.params[1] ?? "");
    rebuilt.push({
      ...lineTime(m.tags, false),
      from: rendered.from,
      text: rendered.text,
      kind: rendered.kind,
      mention: false,
      identity: messageIdentity(m.tags),
      wire: raw,
    });
  }
  // History is older context, never authority over the live buffer. Messages
  // can arrive while this request is in flight, and local echoes may not exist
  // in persisted input at all, so replacing `b.lines` loses user-visible data.
  // Stable msgids suppress true overlap; unidentified rows are retained.
  b.lines = mergeTimeline(rebuilt, b.lines, MAX_LOADED_LINES);
  b.historyLoaded = true;
  // Loading older context is an explicit reader action. Keep that context in
  // view instead of snapping back to the live edge where it cannot be seen.
  if (b.key === active) renderActive({ atLatest: false });
}

const loadEarlierBtn = el("load-earlier");
if (loadEarlierBtn) loadEarlierBtn.addEventListener("click", loadEarlier);

// ---- settings controls --------------------------------------------------

const themeSelect = el("theme-select");
const notifyBtn = el("notify-toggle");

// Another tab (the console's theme picker, a second chat) changed a preference.
window.addEventListener("storage", (event) => {
  if (event.key !== null && event.key !== SETTINGS_KEY) return;
  Object.assign(settings, loadSettings(() => window.localStorage).settings);
  applyTheme();
  updateSettingsUI();
});

function updateSettingsUI() {
  if (themeSelect) themeSelect.value = settings.theme;
  if (notifyBtn) {
    notifyBtn.textContent = settings.notifications
      ? "Desktop notifications: on"
      : "Desktop notifications: off";
    notifyBtn.setAttribute("aria-pressed", String(settings.notifications));
  }
  syncServerLogLink();
  renderRawOutput();
}
if (themeSelect) {
  themeSelect.addEventListener("change", () => {
    settings.theme = themeSelect.value;
    persistSetting("theme");
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
    persistSetting("notifications");
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
    const me = identityFrom(await apiGet("/api/v1/me"));
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
      await apiGet("/api/v1/me/networks"),
    );
    clearAlert("networks");
  } catch (error) {
    networkFailure = error;
  }
  if (!network) {
    // Opening a sole network is not a choice, so nobody is asked to make it.
    // With several, which one to open is the person's decision: the client
    // does not pick "the first" on their behalf.
    const available = networks.filter((item) => item.enabled !== false && item.runtime != null);
    if (available.length === 1) {
      const [chosen] = available;
      network = chosen.name;
      window.history.replaceState(null, "", `/?network=${encodeURIComponent(network)}`);
      renderActive();
    }
  }
  renderNetworkList(networks, networkFailure);
  // A landing page that failed to load offers Retry instead; everywhere else
  // the list keeps following the server, including after a failed first read.
  if (network || !networkFailure) keepNetworkListCurrent();

  if (!network) {
    renderLanding(networks, networkFailure);
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
      renderLanding(networks);
      return;
    }
    if (selected.enabled === false || selected.runtime == null) {
      const reason =
        selected.enabled === false
          ? `${selected.name} is disabled.`
          : `${selected.name} cannot run on this server.`;
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

  connect();
}

boot().catch((error) => {
  setComposerAvailable(false);
  setStatus("client startup failed", "error");
  showAlert("boot", errorMessage("start the chat client", error), "error");
});
