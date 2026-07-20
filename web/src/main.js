// e6irc web client glue. Nearly everything is declarative htmx; this
// file only wires the live socket URL from the page's query parameters
// and keeps the message list scrolled to the newest line.
//
// Query parameters:
//   network  — the BNC network to attach to (required for chat)
//   channel  — the channel the composer targets (optional)

import "./style.css";

const htmx = window.htmx;
if (!htmx) throw new Error("the vendored htmx runtime did not load");

const params = new URLSearchParams(window.location.search);
const network = params.get("network");
const channel = params.get("channel") || "";

const chat = document.getElementById("chat");
const target = document.getElementById("target");
const buffer = document.getElementById("buffer");
const status = document.getElementById("status");
const accountName = document.getElementById("account-name");

const identityResponse = await fetch("/api/v1/me", {
  headers: { Accept: "application/json" },
});
if (!identityResponse.ok) {
  throw new Error(`identity request failed with HTTP ${identityResponse.status}`);
}
const identity = await identityResponse.json();
if (typeof identity.account !== "string" || identity.account.length === 0) {
  throw new Error("identity response did not contain an account name");
}
accountName.textContent = identity.account;

target.value = channel;

if (network) {
  // Point the ws extension at the live UI socket, then let htmx take over.
  chat.setAttribute("ws-connect", `/ws/ui?network=${encodeURIComponent(network)}`);
  htmx.process(chat);
} else {
  status.textContent = "add ?network=<name> to the URL to connect";
  status.className = "status status-error";
}

// Reflect socket lifecycle in the status pill.
chat.addEventListener("htmx:wsOpen", () => {
  status.textContent = `attached to ${network}`;
  status.className = "status status-ok";
});
chat.addEventListener("htmx:wsClose", () => {
  status.textContent = "disconnected";
  status.className = "status status-error";
});

// Keep the newest line in view unless the user has scrolled up.
const observer = new MutationObserver(() => {
  const nearBottom =
    buffer.scrollHeight - buffer.scrollTop - buffer.clientHeight < 40;
  if (nearBottom) buffer.scrollTop = buffer.scrollHeight;
});
observer.observe(buffer, { childList: true });

// Clear the composer after each send.
chat.addEventListener("htmx:wsAfterSend", () => {
  const message = document.getElementById("message");
  message.value = "";
  message.focus();
});
