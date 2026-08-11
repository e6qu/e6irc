// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError } from "./api-contract.js";

export { ApiError };

export const SETTINGS_KEY = "e6irc.settings";
export const DEFAULT_SETTINGS = Object.freeze({
  theme: "auto",
  notifications: false,
});

const THEMES = new Set(["auto", "light", "dark"]);

function defaults() {
  return { ...DEFAULT_SETTINGS };
}

function resolveStorage(storage) {
  return typeof storage === "function" ? storage() : storage;
}

function normalizeSettings(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return { settings: defaults(), repaired: true };
  }
  const settings = defaults();
  let repaired = Object.keys(value).some(
    (key) => key !== "theme" && key !== "notifications",
  );
  if (THEMES.has(value.theme)) settings.theme = value.theme;
  else if (value.theme !== undefined) repaired = true;
  if (typeof value.notifications === "boolean") settings.notifications = value.notifications;
  else if (value.notifications !== undefined) repaired = true;
  return { settings, repaired };
}

export function loadSettings(storage) {
  let raw;
  try {
    raw = resolveStorage(storage).getItem(SETTINGS_KEY);
  } catch {
    return {
      settings: defaults(),
      warning: "Browser storage is unavailable. Preferences will last only until this tab closes.",
    };
  }
  if (raw === null) return { settings: defaults(), warning: null };
  let decoded;
  try {
    decoded = JSON.parse(raw);
  } catch {
    return {
      settings: defaults(),
      warning: "Saved browser preferences were unreadable and have been reset for this tab.",
    };
  }
  const normalized = normalizeSettings(decoded);
  return {
    settings: normalized.settings,
    warning: normalized.repaired
      ? "Saved browser preferences contained unsupported values and were repaired for this tab."
      : null,
  };
}

export function saveSettings(storage, settings) {
  try {
    resolveStorage(storage).setItem(
      SETTINGS_KEY,
      JSON.stringify(normalizeSettings(settings).settings),
    );
    return null;
  } catch {
    return "Browser storage rejected this change. The preference will last only until this tab closes.";
  }
}

export function identityFrom(payload) {
  return Object.freeze({
    account: payload.account,
    email: payload.email,
    role: payload.role,
    logoutURL: payload.logout_url,
  });
}

function networkSummary(value) {
  return Object.freeze({
    name: value.name,
    kind: value.kind,
    nick: value.nick,
    enabled: value.enabled,
    connected: value.connected,
    state: value.runtime?.state ?? null,
    runtime: value.runtime === null ? null : Object.freeze({ state: value.runtime.state }),
  });
}

export function networksFrom(payload) {
  return Object.freeze(payload.networks.map(networkSummary));
}

export function backlogFrom(payload) {
  return Object.freeze([...payload.lines]);
}

export function networkStateLabel(network) {
  if (network.enabled === false) return "disabled";
  if (network.connected === true) return "connected";
  return network.state?.replaceAll("_", " ") || "starting";
}

export function errorMessage(action, error) {
  if (error instanceof ApiError && error.status === 401) {
    return `Your session expired while trying to ${action}. Sign in again.`;
  }
  const detail = error instanceof Error && error.message ? ` ${error.message}.` : "";
  return `Could not ${action}.${detail}`;
}
