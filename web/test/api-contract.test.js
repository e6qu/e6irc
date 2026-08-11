// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import test from "node:test";

import {
  ApiSchemaError,
  getOperationJson,
  operationResponseSchema,
  parseApiSchema,
  parseOperationResponse,
} from "../src/api-contract.js";

const responseSchema = {
  type: "object",
  additionalProperties: false,
  required: ["name", "enabled", "state"],
  properties: {
    name: { type: "string", minLength: 1 },
    enabled: { type: "boolean" },
    state: { type: "string", enum: ["connected", "disconnected"] },
    reason: { type: ["string", "null"] },
    rows: { type: "array", items: { type: "integer", minimum: 1 } },
  },
};

test("schema parser returns a closed immutable projection", () => {
  const parsed = parseApiSchema(responseSchema, {
    name: "Libera",
    enabled: true,
    state: "connected",
    reason: null,
    rows: [1, 2],
  }, "network response");
  assert.deepEqual(parsed, {
    name: "Libera",
    enabled: true,
    state: "connected",
    reason: null,
    rows: [1, 2],
  });
  assert(Object.isFrozen(parsed));
  assert(Object.isFrozen(parsed.rows));
});

test("schema parser rejects incompatible and drifted JSON before a view uses it", () => {
  for (const value of [
    null,
    [],
    { name: "Libera", enabled: true },
    { name: "", enabled: true, state: "connected" },
    { name: "Libera", enabled: "yes", state: "connected" },
    { name: "Libera", enabled: true, state: "unknown" },
    { name: "Libera", enabled: true, state: "connected", rows: [0] },
    { name: "Libera", enabled: true, state: "connected", extra: true },
  ]) {
    assert.throws(() => parseApiSchema(responseSchema, value, "network response"), ApiSchemaError);
  }
});

test("schema parser enforces response status, constants, and array bounds", async () => {
  const document = {
    paths: {
      "/api/v1/me/widgets": {
        post: {
          responses: {
            201: { content: { "application/json": { schema: {
              type: "object", additionalProperties: false, required: ["created", "ids"], properties: {
                created: { const: true },
                ids: { type: "array", minItems: 1, uniqueItems: true, items: { type: "integer", minimum: 1 } },
              },
            } } } },
          },
        },
      },
    },
  };
  const response = new Response(JSON.stringify({ created: true, ids: [1, 2] }), { status: 201 });
  assert.deepEqual(await getOperationJson(async () => response, document, "POST", "/api/v1/me/widgets"), {
    created: true,
    ids: [1, 2],
  });
  for (const value of [
    { created: false, ids: [1] },
    { created: true, ids: [] },
    { created: true, ids: [1, 1] },
  ]) {
    assert.throws(() => parseOperationResponse(document, "POST", "/api/v1/me/widgets", value, "API response", 201), ApiSchemaError);
  }
  assert.throws(
    () => operationResponseSchema(document, "POST", "/api/v1/me/widgets"),
    ApiSchemaError,
  );
});

test("operation parser selects the exact documented path before parsing", () => {
  const document = {
    paths: {
      "/api/v1/me/networks/{name}": {
        get: { responses: { 200: { content: { "application/json": { schema: responseSchema } } } } },
      },
    },
  };
  assert.equal(operationResponseSchema(document, "GET", "/api/v1/me/networks/libera"), responseSchema);
  assert.deepEqual(parseOperationResponse(document, "GET", "/api/v1/me/networks/libera", {
    name: "Libera",
    enabled: true,
    state: "connected",
  }), { name: "Libera", enabled: true, state: "connected" });
  assert.throws(
    () => operationResponseSchema(document, "GET", "/api/v1/me/networks"),
    ApiSchemaError,
  );
});
