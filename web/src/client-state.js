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

export function errorMessage(action, error) {
  if (error instanceof ApiError && error.status === 401) {
    return `Your session expired while trying to ${action}. Sign in again.`;
  }
  const detail = error instanceof Error && error.message ? ` ${error.message}.` : "";
  return `Could not ${action}.${detail}`;
}
