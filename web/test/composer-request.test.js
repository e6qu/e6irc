// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import test from "node:test";

import { ComposerRequestError, serializeComposerRequest } from "../src/composer-request.js";

test("composer serializer emits the two closed request shapes", () => {
  assert.equal(
    serializeComposerRequest({ id: "send-1", target: "#rust", message: "hello" }),
    '{"target":"#rust","message":"hello","id":"send-1"}',
  );
  assert.equal(
    serializeComposerRequest({ target: "", message: "/join #rust" }),
    '{"target":"","message":"/join #rust"}',
  );
});

test("composer serializer rejects malformed and unknown request fields", () => {
  for (const request of [
    null,
    [],
    {},
    { target: "#rust" },
    { message: "hello" },
    { target: 1, message: "hello" },
    { target: "#rust", message: 1 },
    { id: null, target: "#rust", message: "hello" },
    { id: "", target: "#rust", message: "hello" },
    { id: "bad_id", target: "#rust", message: "hello" },
    { id: "x".repeat(65), target: "#rust", message: "hello" },
    { target: "#rust", message: "hello", extra: true },
  ]) {
    assert.throws(() => serializeComposerRequest(request), ComposerRequestError);
  }
});
