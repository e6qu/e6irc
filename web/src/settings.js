// SPDX-License-Identifier: AGPL-3.0-or-later

export const SETTINGS_KEY = "e6irc.settings";
export const DEFAULT_SETTINGS = Object.freeze({
  theme: "auto",
  notifications: false,
  rawOutput: false,
});

const THEMES = new Set(["auto", "light", "dark"]);

function defaults() {
  return { ...DEFAULT_SETTINGS };
}

function storageValue(storage) {
  return typeof storage === "function" ? storage() : storage;
}

function normalized(value) {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    return { settings: defaults(), repaired: true };
  }
  const settings = defaults();
  let repaired = Object.keys(value).some(
    (key) => key !== "theme" && key !== "notifications" && key !== "rawOutput",
  );
  if (THEMES.has(value.theme)) settings.theme = value.theme;
  else if (value.theme !== undefined) repaired = true;
  if (typeof value.notifications === "boolean") settings.notifications = value.notifications;
  else if (value.notifications !== undefined) repaired = true;
  if (typeof value.rawOutput === "boolean") settings.rawOutput = value.rawOutput;
  else if (value.rawOutput !== undefined) repaired = true;
  return { settings, repaired };
}

export function loadSettings(storage) {
  let raw;
  try {
    raw = storageValue(storage).getItem(SETTINGS_KEY);
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
  const result = normalized(decoded);
  return {
    settings: result.settings,
    warning: result.repaired
      ? "Saved browser preferences contained unsupported values and were repaired for this tab."
      : null,
  };
}

export function saveSettings(storage, settings) {
  try {
    storageValue(storage).setItem(SETTINGS_KEY, JSON.stringify(normalized(settings).settings));
    return null;
  } catch {
    return "Browser storage rejected this change. The preference will last only until this tab closes.";
  }
}
