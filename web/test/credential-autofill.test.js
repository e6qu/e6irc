// SPDX-License-Identifier: AGPL-3.0-or-later
//
// The only credential a browser holds for this origin is the e6irc login. A
// field marked `username` or `current-password` tells the password manager
// "this is that login", so it offers -- or silently fills -- the e6irc password
// into a field whose value is then sent to a third-party IRC network or bridge
// provider and stored as its secret. Only the pages that really do take the
// e6irc login may use those tokens.

import assert from "node:assert/strict";
import { readdir, readFile } from "node:fs/promises";
import test from "node:test";

const root = new URL("../../", import.meta.url);
const templates = new URL("crates/e6ircd/templates/", root);

// Pages whose form IS the e6irc account: signing in, creating the first
// administrator, accepting an invitation, and changing the account password.
const E6IRC_LOGIN_PAGES = new Set(["login.html", "bootstrap.html", "invite.html", "console_account.html", "device.html"]);

async function documents() {
  const found = [["web/index.html", await readFile(new URL("web/index.html", root), "utf8")]];
  for (const name of (await readdir(templates)).sort()) {
    if (name.endsWith(".html") && !E6IRC_LOGIN_PAGES.has(name)) {
      found.push([`templates/${name}`, await readFile(new URL(name, templates), "utf8")]);
    }
  }
  return found;
}

test("no third-party credential field invites the e6irc login to be autofilled", async () => {
  const offenders = [];
  for (const [path, html] of await documents()) {
    for (const [tag] of html.matchAll(/<input\b[^>]*>/g)) {
      const token = tag.match(/\bautocomplete="([^"]*)"/)?.[1];
      if (token === "username" || token === "current-password") offenders.push(`${path}: ${tag}`);
    }
  }
  assert.deepEqual(offenders, []);
});

test("every password input outside the login pages declares new-password", async () => {
  const offenders = [];
  for (const [path, html] of await documents()) {
    for (const [tag] of html.matchAll(/<input\b[^>]*\btype="password"[^>]*>/g)) {
      if (!/\bautocomplete="new-password"/.test(tag)) offenders.push(`${path}: ${tag}`);
    }
  }
  assert.deepEqual(offenders, []);
});
