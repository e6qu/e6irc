// SPDX-License-Identifier: AGPL-3.0-or-later

import { ApiError } from "./api-contract.js";
export { DEFAULT_SETTINGS, SETTINGS_KEY, loadSettings, saveSetting } from "./settings.js";

export { ApiError };

export function identityFrom(payload) {
  return Object.freeze({
    account: payload.account,
    email: payload.email,
    role: payload.role,
    logoutURL: payload.logout_url,
    csrfToken: payload.csrf_token,
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
    failureCode: value.runtime?.last_error?.code ?? null,
    failureDetail: value.runtime?.last_error?.diagnostic ?? null,
    runtime: value.runtime === null ? null : Object.freeze({
      state: value.runtime.state,
      failureCode: value.runtime.last_error?.code ?? null,
    }),
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
  // No runtime means no driver exists for this network on this server (its
  // bridge was not built in). It is not on its way anywhere, so it must not
  // read "starting" forever; the console says "not running" for the same fact.
  if (network.runtime === null) return "not running";
  return network.state?.replaceAll("_", " ") || "starting";
}

/**
 * What to do about a state, for the states where there is something to do.
 *
 * A driver that parks stops re-dialling deliberately, so its failed lifecycle
 * remains visible indefinitely. The lifecycle says that work stopped and the
 * latest typed failure says why; together they select a repair beside that
 * network's own settings control.
 */
export function networkStateHelp(network) {
  if (network.enabled === false) return "This network is disabled.";
  if (network.connected === true) return null;
  // The network's own words are the most useful thing on the row: "SASL access
  // only" or "Trying to reconnect too fast" says what no classification can.
  // Without them the advice points at the Server log, where they would be.
  const said = network.failureDetail ? `The network said: “${network.failureDetail}”` : null;
  const repair = stateRepair(network, said ? "" : " Open Server log for its reason.");
  // A refusal with no specific repair (a throttle, a ban) still has the
  // network's own words, and they are the whole point.
  if (repair === null) return said;
  return said ? `${repair} ${said}` : repair;
}

function stateRepair(network, whereToLook) {
  switch (network.failureCode) {
    case "authentication_rejected":
      return "The network rejected the NickServ account or password. Open settings to correct them.";
    case "nickname_in_use":
      return "The nickname is in use on this network. Choose another in settings, or wait for the old session to time out.";
    case "server_password_required":
      return "The network requires a server password. Enter it in settings, as Server password under Advanced.";
    case "server_password_rejected":
      return "The network rejected the server password. Correct it in settings, as Server password under Advanced.";
    case "registration_rejected":
      return `The network refused registration.${whereToLook} If verified SASL is required, add your NickServ account and password in settings.`;
  }
  if (network.state === "authentication_failed") {
    return "Authentication stopped this connection. Open settings to replace or remove the stored NickServ credentials.";
  }
  if (network.state === "registration_failed") {
    return `IRC registration stopped this connection.${whereToLook} Correct the network settings to try again.`;
  }
  return null;
}

/** Whether a state is a parked failure rather than progress toward connected. */
export function networkStateIsFailure(network) {
  return network.state === "authentication_failed" || network.state === "registration_failed";
}

export function errorMessage(action, error) {
  if (error instanceof ApiError && error.status === 401) {
    return `Your session expired while trying to ${action}. Sign in again.`;
  }
  const sentence = error instanceof Error ? error.message.trim() : "";
  const detail = sentence ? ` ${/[.!?]$/.test(sentence) ? sentence : `${sentence}.`}` : "";
  return `Could not ${action}.${detail}`;
}
