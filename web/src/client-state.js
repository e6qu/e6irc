// SPDX-License-Identifier: AGPL-3.0-or-later

export const SETTINGS_KEY = "e6irc.settings";
export const DEFAULT_SETTINGS = Object.freeze({
  theme: "auto",
  notifications: false,
});

const THEMES = new Set(["auto", "light", "dark"]);
const NETWORK_STATES = new Set([
  "connecting",
  "connected",
  "reconnecting",
  "authentication_failed",
  "registration_failed",
]);
const IDENTITY_KEYS = new Set([
  "account",
  "email",
  "role",
  "provider",
  "release_revision",
  "csrf_token",
  "logout_url",
]);
const NETWORK_LIST_KEYS = new Set(["networks"]);

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

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

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
    } catch {}
    throw new ApiError(response.status, detail || `Request failed with HTTP ${response.status}`);
  }
  try {
    return await response.json();
  } catch {
    throw new ApiError(response.status, "The server returned invalid JSON");
  }
}

function optionalString(value) {
  return value === undefined || value === null ? null : typeof value === "string" ? value : undefined;
}

function hasOnlyKeys(value, allowed) {
  return Object.keys(value).every((key) => allowed.has(key));
}

export function identityFrom(payload) {
  if (
    payload === null ||
    typeof payload !== "object" ||
    Array.isArray(payload) ||
    !hasOnlyKeys(payload, IDENTITY_KEYS)
  ) {
    throw new ApiError(200, "The server returned an invalid identity");
  }
  const { account } = payload;
  const email = optionalString(payload.email);
  const role = optionalString(payload.role);
  const provider = optionalString(payload.provider);
  const releaseRevision = optionalString(payload.release_revision);
  const logoutURL = optionalString(payload.logout_url);
  const csrfToken = payload.csrf_token;
  if (
    typeof account !== "string" ||
    !account.trim() ||
    email === undefined ||
    role === undefined ||
    provider === undefined ||
    releaseRevision === undefined ||
    (csrfToken !== undefined && typeof csrfToken !== "string") ||
    logoutURL === undefined ||
    (logoutURL !== null && (!logoutURL.startsWith("/") || logoutURL.startsWith("//")))
  ) {
    throw new ApiError(200, "The server returned an invalid identity");
  }
  return Object.freeze({ account, email, role, logoutURL });
}

function networkSummary(value) {
  if (value === null || typeof value !== "object") return null;
  const { name, enabled, connected, runtime } = value;
  if (
    typeof name !== "string" ||
    !name.trim() ||
    typeof enabled !== "boolean" ||
    (connected !== null && typeof connected !== "boolean") ||
    (runtime !== null && (typeof runtime !== "object" || Array.isArray(runtime)))
  ) {
    return null;
  }
  if (runtime === null) {
    return connected === null ? Object.freeze({ name, enabled, connected, state: null }) : null;
  }
  if (typeof runtime.state !== "string" || !NETWORK_STATES.has(runtime.state)) return null;
  if (connected !== (runtime.state === "connected")) return null;
  return Object.freeze({ name, enabled, connected, state: runtime.state });
}

export function networksFrom(payload) {
  if (
    payload === null ||
    typeof payload !== "object" ||
    Array.isArray(payload) ||
    !hasOnlyKeys(payload, NETWORK_LIST_KEYS) ||
    !Array.isArray(payload.networks)
  ) {
    throw new ApiError(200, "The server returned an invalid network list");
  }
  const networks = payload.networks.map(networkSummary);
  if (networks.some((network) => network === null)) {
    throw new ApiError(200, "The server returned an invalid network list");
  }
  return Object.freeze(networks);
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
