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

function eventFrom(value) {
  if (!object(value) || typeof value.t !== "string" || typeof value.v !== "string") invalid();
  switch (value.t) {
    case "line":
    case "sent":
      if (!onlyKeys(value, ["t", "v"])) invalid();
      return Object.freeze({ type: value.t, value: value.v });
    case "send-error":
      if (!onlyKeys(value, ["t", "v", "message"]) || typeof value.message !== "string") invalid();
      return Object.freeze({ type: "send-error", value: value.v, message: value.message });
    case "snapshot":
      if (!onlyKeys(value, ["t", "v"]) || value.v !== "complete") invalid();
      return Object.freeze({ type: "snapshot" });
    case "status":
      if (!onlyKeys(value, ["t", "v", "reason"])) invalid();
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
