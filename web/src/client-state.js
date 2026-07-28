// SPDX-License-Identifier: AGPL-3.0-or-later

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

// Load and validate browser preferences without hiding storage corruption or
// denial. The caller owns presentation, so this pure boundary returns a
// warning rather than touching the DOM.
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

// Persist already-normalized preferences. A null result is success; a string
// is an actionable user-facing failure that the caller must surface.
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

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

// Fetch one JSON document and preserve the HTTP failure's status and
// problem+json detail. Callers can distinguish "empty data" from "the API
// failed" without repeating response checks at every request site.
export async function getJson(fetcher, url) {
  const response = await fetcher(url, { headers: { Accept: "application/json" } });
  if (!response.ok) {
    let detail = "";
    try {
      const problem = await response.json();
      detail =
        typeof problem.detail === "string"
          ? problem.detail
          : typeof problem.title === "string"
            ? problem.title
            : "";
    } catch {
      // The status remains authoritative when an intermediary returns HTML or
      // an empty body; this is an explicit degraded error, not a success path.
    }
    throw new ApiError(response.status, detail || `Request failed with HTTP ${response.status}`);
  }
  try {
    return await response.json();
  } catch {
    throw new ApiError(response.status, "The server returned invalid JSON");
  }
}

export function networksFrom(payload) {
  if (
    payload === null ||
    typeof payload !== "object" ||
    !Array.isArray(payload.networks) ||
    payload.networks.some(
      (network) =>
        network === null ||
        typeof network !== "object" ||
        typeof network.name !== "string" ||
        !network.name,
    )
  ) {
    throw new ApiError(200, "The server returned an invalid network list");
  }
  return payload.networks;
}

export function errorMessage(action, error) {
  if (error instanceof ApiError && error.status === 401) {
    return `Your session expired while trying to ${action}. Sign in again.`;
  }
  const detail = error instanceof Error && error.message ? ` ${error.message}.` : "";
  return `Could not ${action}.${detail}`;
}
