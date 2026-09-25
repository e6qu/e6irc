// SPDX-License-Identifier: AGPL-3.0-or-later

export class UiEventError extends Error {
  constructor() {
    super("The server sent an invalid live event.");
    this.name = "UiEventError";
  }
}

function object(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function onlyKeys(value, keys) {
  return Object.keys(value).every((key) => keys.includes(key));
}

function invalid() {
  throw new UiEventError();
}

// A replay cursor is opaque: the server names a ring position with it and the
// client hands it back unchanged. Non-empty text is all the client checks.
function cursor(value) {
  return typeof value === "string" && value.length > 0;
}

function eventFrom(value) {
  if (!object(value) || typeof value.t !== "string") invalid();
  switch (value.t) {
    case "line":
      if (!onlyKeys(value, ["t", "v", "cursor"]) || typeof value.v !== "string" || !cursor(value.cursor)) invalid();
      return Object.freeze({ type: "line", value: value.v, cursor: value.cursor });
    case "sent":
      if (!onlyKeys(value, ["t", "v"]) || typeof value.v !== "string") invalid();
      return Object.freeze({ type: "sent", value: value.v });
    case "send-error":
      if (
        !onlyKeys(value, ["t", "v", "message"]) ||
        typeof value.v !== "string" ||
        typeof value.message !== "string"
      ) invalid();
      return Object.freeze({ type: "send-error", value: value.v, message: value.message });
    case "snapshot":
      if (!onlyKeys(value, ["t", "v", "cursor"]) || value.v !== "complete" || !cursor(value.cursor)) invalid();
      return Object.freeze({ type: "snapshot", cursor: value.cursor });
    case "replay":
      if (!onlyKeys(value, ["t", "v"]) || value.v !== "full") invalid();
      return Object.freeze({ type: "replay" });
    case "session":
      if (
        !onlyKeys(value, ["t", "nick", "channels", "isupport"]) ||
        typeof value.nick !== "string" ||
        value.nick.length === 0 ||
        !Array.isArray(value.channels) ||
        !value.channels.every((channel) => typeof channel === "string" && channel.length > 0) ||
        !Array.isArray(value.isupport) ||
        !value.isupport.every((token) => typeof token === "string" && token.length > 0)
      ) invalid();
      return Object.freeze({
        type: "session",
        nick: value.nick,
        channels: Object.freeze([...value.channels]),
        isupport: Object.freeze([...value.isupport]),
      });
    case "status":
      if (!onlyKeys(value, ["t", "v", "reason"]) || typeof value.v !== "string") invalid();
      if (value.v === "connected" || value.v === "unavailable") {
        if (value.reason !== undefined) invalid();
        return Object.freeze({ type: "status", value: value.v, reason: null });
      }
      if (value.v === "disconnected" && (value.reason === undefined || typeof value.reason === "string")) {
        return Object.freeze({ type: "status", value: value.v, reason: value.reason ?? null });
      }
      invalid();
      break;
    default:
      invalid();
  }
}

export function parseUiEvent(frame) {
  if (typeof frame !== "string") invalid();
  try {
    return eventFrom(JSON.parse(frame));
  } catch (error) {
    if (error instanceof UiEventError) throw error;
    invalid();
  }
}
