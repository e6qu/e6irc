// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Bodies for the two network-configuration endpoints.
//
// They take deliberately different credential shapes, and conflating them is an
// easy mistake to make: the first version of the settings dialog sent the
// replace shape to both and was caught only by the request-schema check.
//
//   POST /api/v1/me/networks          flat sasl_account / sasl_password,
//                                     realname required -- nothing exists yet
//                                     to preserve or erase.
//   PUT  /api/v1/me/networks/{name}   a tagged keep | remove | set action, so an
//                                     omitted password can never ambiguously
//                                     mean either "leave the stored one alone"
//                                     or "delete it".
//
// Shaping them here, away from the DOM, is what makes both testable.

export class NetworkRequestError extends Error {
  constructor(message) {
    super(message);
    this.name = "NetworkRequestError";
  }
}

/** Split an auto-join box into channels, on commas or whitespace. */
export function autojoinList(value) {
  return String(value ?? "")
    .split(/[\s,]+/)
    .map((entry) => entry.trim())
    .filter(Boolean);
}

/**
 * The credential half of a replace.
 *
 * An account with no password is a legitimate `set`: it renames the identity
 * and keeps the sealed secret. A password with no account is not -- there is
 * nothing for it to authenticate as -- so it is refused here, where the form
 * can point at the empty field, rather than by the server.
 */
export function credentialAction({ clearing = false, account = "", password = "" } = {}) {
  if (clearing) return { action: "remove" };
  const trimmed = account.trim();
  if (!trimmed && !password) return { action: "keep" };
  if (!trimmed) {
    throw new NetworkRequestError("Enter the NickServ account this password belongs to.");
  }
  return { action: "set", account: trimmed, ...(password ? { password } : {}) };
}

function connection({ addr, tls, nick, autojoin }) {
  const dialled = String(addr ?? "").trim();
  const nickname = String(nick ?? "").trim();
  if (!dialled) throw new NetworkRequestError("Enter the server to connect to.");
  if (!nickname) throw new NetworkRequestError("Enter a nickname.");
  return {
    addr: dialled,
    tls: Boolean(tls),
    nick: nickname,
    autojoin: autojoinList(autojoin),
  };
}

/**
 * Body for creating an IRC network.
 *
 * realname is required by the contract, and an empty box is not a reason to
 * fail: a client that omits it sends the nickname, which is what an IRC client
 * conventionally does anyway.
 */
export function createNetworkBody(form) {
  const base = connection(form);
  const name = String(form.name ?? "").trim();
  if (!name) throw new NetworkRequestError("Name this network.");
  const account = String(form.account ?? "").trim();
  const password = form.password ?? "";
  if (password && !account) {
    throw new NetworkRequestError("Enter the NickServ account this password belongs to.");
  }
  return {
    kind: "irc",
    name,
    ...base,
    realname: String(form.realname ?? "").trim() || base.nick,
    ...(account ? { sasl_account: account } : {}),
    ...(password ? { sasl_password: password } : {}),
  };
}

/**
 * Body for replacing an IRC network's mutable configuration.
 *
 * realname is optional here, and an empty box means "no real name" rather than
 * "unchanged", which the contract expresses as null.
 */
export function updateNetworkBody(form) {
  const realname = String(form.realname ?? "").trim();
  return {
    ...connection(form),
    realname: realname || null,
    credentials: credentialAction(form),
  };
}
