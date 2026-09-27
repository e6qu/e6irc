// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Bodies for the two network-configuration endpoints.
//
// They take deliberately different credential shapes, and conflating them is an
// easy mistake to make: the first version of the settings dialog sent the
// replace shape to both and was caught only by the request-schema check.
//
//   POST /api/v1/me/networks          flat sasl_account / sasl_password /
//                                     server_password, realname required --
//                                     nothing exists yet to preserve or erase.
//   PUT  /api/v1/me/networks/{name}   a tagged keep | remove | set action for
//                                     the SASL credentials and another for the
//                                     server password, so an omitted password
//                                     can never ambiguously mean either "leave
//                                     the stored one alone" or "delete it"; and
//                                     the channels whose stored key is kept.
//
// Shaping them here, away from the DOM, is what makes both testable.

/**
 * A refusal made before anything is sent. `field` is the request field at
 * fault, in the API's own vocabulary, so the form marks the same box whether
 * the refusal came from here or from the server.
 */
export class NetworkRequestError extends Error {
  constructor(field, message) {
    super(message);
    this.name = "NetworkRequestError";
    this.field = field;
  }
}

// What begins a channel name (RFC 2811).
const CHANNEL_PREFIX = /^[#&+!]/;

/**
 * Split an auto-join box into entries. Commas separate entries; within one,
 * the channel comes first and a keyed channel's key after it, as `/join
 * #staff key` takes them. That is the API's own entry, `#channel` or
 * `#channel key`, which the server splits at its first space, so the word
 * after a channel is its key whatever it begins with: `#staff #pw` is #staff
 * with the key `#pw`. Separating entries by spaces as well used to read that
 * as two channels and save the key as a channel to join. A key is never
 * repeated in a refusal: it is a secret.
 */
export function autojoinList(value) {
  const entries = [];
  for (const segment of String(value ?? "").split(",")) {
    const words = segment.split(/\s+/).filter(Boolean);
    if (words.length === 0) continue;
    const [channel, key, ...extra] = words;
    if (!CHANNEL_PREFIX.test(channel)) {
      throw new NetworkRequestError(
        "autojoin",
        "Each auto-join entry must start with a channel: a name begins with #, &, + or !, and a key goes after its channel (#staff key).",
      );
    }
    if (extra.length > 0) {
      throw new NetworkRequestError(
        "autojoin",
        `${channel} is followed by more than one word; an entry is a channel and at most one key. Separate channels with commas (#staff key, #rust).`,
      );
    }
    entries.push(key === undefined ? channel : `${channel} ${key}`);
  }
  return entries;
}

/** The channel an auto-join entry names, without its key. */
function entryChannel(entry) {
  return entry.split(" ")[0];
}

/** One channel name, compared the way the server compares a kept key's. */
function sameChannel(a, b) {
  const lower = (name) => name.replace(/[A-Z]/g, (letter) => letter.toLowerCase());
  return lower(a) === lower(b);
}

const REMOVE_KEY_CONTROL = (channel) => `“Remove the stored key for ${channel}”`;

/**
 * The channel-key half of a replace: which stored keys are kept.
 *
 * A key is write-only, so the box shows a keyed channel without it. Listed
 * that way, the channel keeps its stored key unless its Remove box is ticked;
 * written with a key after it, that key replaces the stored one; left out of
 * the list, its key goes with it. A key typed after a channel whose Remove box
 * is ticked would not be saved, so it is refused rather than dropped.
 * `storedKeyed` is what the server reported before the edit.
 */
export function autojoinKeysAction({ entries = [], storedKeyed = [], removingKeys = [] } = {}) {
  const keep = [];
  for (const channel of storedKeyed) {
    const entry = entries.find((candidate) => sameChannel(entryChannel(candidate), channel));
    if (entry === undefined) continue;
    const removing = removingKeys.some((removed) => sameChannel(removed, channel));
    const typed = entry.includes(" ");
    if (removing && typed) {
      throw new NetworkRequestError(
        "autojoin",
        `${REMOVE_KEY_CONTROL(channel)} is ticked, so the key typed after it would not be saved. Untick it to save the new key, or delete the key to remove the stored one.`,
      );
    }
    if (!removing && !typed) keep.push(channel);
  }
  return { keep };
}

const REMOVE_CONTROL = "“Remove the stored account and password”";

/**
 * The credential half of a replace.
 *
 * An account with no password is a legitimate `set`: it renames the identity
 * and keeps the sealed secret. A password with no account is not -- there is
 * nothing for it to authenticate as -- so it is refused here, where the form
 * can point at the empty field, rather than by the server.
 *
 * Two edits say one thing on screen and would send another, so both are
 * refused rather than resolved: a typed account or password under a ticked
 * Remove (the typed values would be thrown away), and a stored account blanked
 * without ticking Remove (an empty box would be sent as `keep`).
 * `storedAccount` is what the server reported before the edit.
 */
export function credentialAction({ clearing = false, account = "", password = "", storedAccount = "" } = {}) {
  const trimmed = account.trim();
  if (clearing) {
    if (trimmed || password) {
      throw new NetworkRequestError(
        "sasl_password",
        `${REMOVE_CONTROL} is ticked, so the typed account and password would not be saved. Untick it to save them, or clear them to remove the stored ones.`,
      );
    }
    return { action: "remove" };
  }
  if (!trimmed && !password) {
    if (storedAccount) {
      throw new NetworkRequestError(
        "sasl_account",
        `The NickServ account box was emptied but ${storedAccount} is still stored. Enter the account to keep authenticating, or tick ${REMOVE_CONTROL}.`,
      );
    }
    return { action: "keep" };
  }
  if (!trimmed) {
    throw new NetworkRequestError("sasl_account", "Enter the NickServ account this password belongs to.");
  }
  return { action: "set", account: trimmed, ...(password ? { password } : {}) };
}

const REMOVE_SERVER_PASSWORD_CONTROL = "“Remove the stored server password”";

// The server's `ServerPassword` rule: the value must fit one `PASS :` line.
// Mirrored so a refusal is shown at the box; the server remains the authority.
const SERVER_PASSWORD_MAX_BYTES = 504;

/** A typed server password, or a refusal naming its box. Never trimmed. */
function checkedServerPassword(value) {
  const password = String(value ?? "");
  if (/[\r\n\0]/.test(password)) {
    throw new NetworkRequestError("server_password", "A server password cannot contain a line break or a NUL character.");
  }
  if (new TextEncoder().encode(password).length > SERVER_PASSWORD_MAX_BYTES) {
    throw new NetworkRequestError("server_password", `A server password cannot exceed ${SERVER_PASSWORD_MAX_BYTES} bytes.`);
  }
  return password;
}

/**
 * The server-password half of a replace: keep what is sealed when the box is
 * empty, set a typed one, remove on the tick. A value typed under a ticked
 * Remove would not be saved, so it is refused rather than dropped.
 */
export function serverPasswordAction({ clearingServerPassword = false, serverPassword = "" } = {}) {
  const password = checkedServerPassword(serverPassword);
  if (clearingServerPassword) {
    if (password) {
      throw new NetworkRequestError(
        "server_password",
        `${REMOVE_SERVER_PASSWORD_CONTROL} is ticked, so the typed server password would not be saved. Untick it to save it, or clear it to remove the stored one.`,
      );
    }
    return { action: "remove" };
  }
  return password ? { action: "set", password } : { action: "keep" };
}

// The server's `UpstreamUsername` grammar. Mirrored here only so a refusal can
// be shown before a round trip; the server remains the authority.
const USERNAME = /^[A-Za-z0-9][A-Za-z0-9_-]{0,9}$/;
const USERNAME_RULE = "letters, digits, - and _ only, starting with a letter or digit, at most 10 characters";

/**
 * The `USER` parameter, which an upstream shows as the ident.
 *
 * The API requires one and never derives it. A blank box means the nickname,
 * as the form says -- but a nickname may hold characters a username may not,
 * and then the person is asked for one rather than handed a rewritten one.
 */
function usernameFor(typed, nickname) {
  const username = String(typed ?? "").trim();
  if (username) {
    if (!USERNAME.test(username)) {
      throw new NetworkRequestError("username", `That username cannot be used: ${USERNAME_RULE}.`);
    }
    return username;
  }
  if (!USERNAME.test(nickname)) {
    throw new NetworkRequestError(
      "username",
      `Enter a username. The nickname ${nickname} cannot double as one: ${USERNAME_RULE}.`,
    );
  }
  return nickname;
}

function connection({ addr, tls, nick, username, autojoin }) {
  const dialled = String(addr ?? "").trim();
  const nickname = String(nick ?? "").trim();
  if (!dialled) throw new NetworkRequestError("addr", "Enter the server to connect to.");
  if (!nickname) throw new NetworkRequestError("nick", "Enter a nickname.");
  return {
    addr: dialled,
    tls: Boolean(tls),
    nick: nickname,
    username: usernameFor(username, nickname),
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
  if (!name) throw new NetworkRequestError("name", "Name this network.");
  const account = String(form.account ?? "").trim();
  const password = form.password ?? "";
  const serverPassword = checkedServerPassword(form.serverPassword);
  if (password && !account) {
    throw new NetworkRequestError("sasl_account", "Enter the NickServ account this password belongs to.");
  }
  return {
    kind: "irc",
    name,
    ...base,
    realname: String(form.realname ?? "").trim() || base.nick,
    ...(account ? { sasl_account: account } : {}),
    ...(password ? { sasl_password: password } : {}),
    ...(serverPassword ? { server_password: serverPassword } : {}),
  };
}

/**
 * Body for testing a connection before it is saved: the same fields the
 * network would use, without a name (nothing is stored).
 */
export function preflightNetworkBody(form) {
  const base = connection(form);
  const account = String(form.account ?? "").trim();
  const password = form.password ?? "";
  const serverPassword = checkedServerPassword(form.serverPassword);
  if (password && !account) {
    throw new NetworkRequestError("sasl_account", "Enter the NickServ account this password belongs to.");
  }
  if (account && !password) {
    throw new NetworkRequestError("sasl_password", "Enter the password for this NickServ account.");
  }
  return {
    ...base,
    realname: String(form.realname ?? "").trim() || base.nick,
    ...(account ? { sasl_account: account } : {}),
    ...(password ? { sasl_password: password } : {}),
    ...(serverPassword ? { server_password: serverPassword } : {}),
  };
}

/**
 * Body for replacing an IRC network's mutable configuration.
 *
 * An IRC network always has a real name -- the server refuses null for one --
 * so an empty box means what the form says it means, on edit exactly as on
 * create: the nickname is used.
 */
export function updateNetworkBody(form) {
  const base = connection(form);
  return {
    ...base,
    realname: String(form.realname ?? "").trim() || base.nick,
    autojoin_keys: autojoinKeysAction({
      entries: base.autojoin,
      storedKeyed: form.storedKeyed ?? [],
      removingKeys: form.removingKeys ?? [],
    }),
    credentials: credentialAction(form),
    server_password: serverPasswordAction(form),
  };
}
