// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import test from "node:test";

import { UiEventError, parseUiEvent } from "../src/ui-event.js";

test("live event parser accepts the closed server event contract", () => {
  assert.deepEqual(parseUiEvent('{"t":"line","v":"PING :server","cursor":"7:42"}'), {
    type: "line",
    value: "PING :server",
    cursor: "7:42",
  });
  assert.deepEqual(parseUiEvent('{"t":"replay","v":"full"}'), { type: "replay" });
  assert.deepEqual(parseUiEvent('{"t":"sent","v":"a1"}'), { type: "sent", value: "a1" });
  assert.deepEqual(parseUiEvent('{"t":"send-error","v":"a1","message":"not sent"}'), {
    type: "send-error",
    value: "a1",
    message: "not sent",
  });
  assert.deepEqual(parseUiEvent('{"t":"snapshot","v":"complete","cursor":"7:42"}'), {
    type: "snapshot",
    cursor: "7:42",
  });
  assert.deepEqual(
    parseUiEvent('{"t":"session","nick":"alice","channels":["#one","#Two"],"isupport":["PREFIX=(ov)@+"]}'),
    { type: "session", nick: "alice", channels: ["#one", "#Two"], isupport: ["PREFIX=(ov)@+"] },
  );
  assert.deepEqual(parseUiEvent('{"t":"status","v":"connected"}'), {
    type: "status",
    value: "connected",
    reason: null,
  });
  assert.deepEqual(
    parseUiEvent('{"t":"status","v":"disconnected","reason":"connection lost"}'),
    { type: "status", value: "disconnected", reason: "connection lost" },
  );
  assert.deepEqual(parseUiEvent('{"t":"status","v":"unavailable"}'), {
    type: "status",
    value: "unavailable",
    reason: null,
  });
});

test("live event parser rejects every malformed or unsupported shape", () => {
  for (const frame of [
    "not JSON",
    "null",
    "[]",
    "true",
    "42",
    '"text"',
    "{}",
    '{"t":"line"}',
    '{"t":"line","v":1}',
    '{"t":"line","v":"ok"}',
    '{"t":"line","v":"ok","cursor":""}',
    '{"t":"line","v":"ok","cursor":7}',
    '{"t":"line","v":"ok","cursor":"7:1","extra":true}',
    '{"t":"snapshot","v":"complete"}',
    '{"t":"snapshot","v":"partial","cursor":"7:1"}',
    '{"t":"replay","v":"partial"}',
    '{"t":"replay","v":"full","cursor":"7:1"}',
    '{"t":"session","nick":"","channels":[],"isupport":[]}',
    '{"t":"session","nick":"alice","channels":"#one","isupport":[]}',
    '{"t":"session","nick":"alice","channels":[1],"isupport":[]}',
    '{"t":"session","nick":"alice","channels":[],"isupport":[],"extra":true}',
    '{"t":"session","nick":"alice","channels":[]}',
    '{"t":"session","nick":"alice","channels":[],"isupport":"PREFIX=(ov)@+"}',
    '{"t":"session","nick":"alice","channels":[],"isupport":[""]}',
    '{"t":"status","v":"connected","reason":"unexpected"}',
    '{"t":"status","v":"disconnected","reason":1}',
    '{"t":"status","v":"unknown"}',
    '{"t":"unknown","v":"value"}',
  ]) {
    assert.throws(() => parseUiEvent(frame), UiEventError);
  }
  assert.throws(() => parseUiEvent(new Uint8Array()), UiEventError);
});
