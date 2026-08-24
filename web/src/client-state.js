// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError } from "./api-contract.js";
export { DEFAULT_SETTINGS, SETTINGS_KEY, loadSettings, saveSettings } from "./settings.js";

export { ApiError };

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

/**
 * What to do about a state, for the states where there is something to do.
 *
 * A driver that parks on rejected credentials stops re-dialling deliberately,
 * so it sits there indefinitely reading "authentication rejected" -- two words
 * that name the event and say nothing about the repair. These are the states
 * worth a sentence, and each is fixed in the same place: that network's own
 * settings, which is now one control away from the label.
 */
export function networkStateHelp(network) {
  if (network.enabled === false) return "This network is turned off.";
  switch (network.state) {
    case "authentication_rejected":
      return "The network rejected the NickServ account or password. Open settings to correct them.";
    case "registration_rejected":
      return "The network refused the nickname or registration details. Open settings to change them.";
    default:
      return null;
  }
}

/** Whether a state is a parked failure rather than progress toward connected. */
export function networkStateIsFailure(network) {
  return network.state === "authentication_rejected" || network.state === "registration_rejected";
}

export function errorMessage(action, error) {
  if (error instanceof ApiError && error.status === 401) {
    return `Your session expired while trying to ${action}. Sign in again.`;
  }
  const detail = error instanceof Error && error.message ? ` ${error.message}.` : "";
  return `Could not ${action}.${detail}`;
}
