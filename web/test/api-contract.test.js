// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import test from "node:test";

import {
  ApiSchemaError,
  apiContractLoader,
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
  let request;
  assert.deepEqual(await getOperationJson(async (url, options) => {
    request = { url, options };
    return response;
  }, document, "POST", "/api/v1/me/widgets", { method: "GET" }), {
    created: true,
    ids: [1, 2],
  });
  assert.deepEqual(request, {
    url: "/api/v1/me/widgets",
    options: { method: "POST", headers: { Accept: "application/json" } },
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

test("operation requests preserve an API problem detail", async () => {
  await assert.rejects(
    getOperationJson(
      async () => new Response(JSON.stringify({ title: "Profile storage unavailable" }), {
        status: 503,
        headers: { "content-type": "application/problem+json" },
      }),
      { paths: {} },
      "PATCH",
      "/api/v1/me/profile",
    ),
    /Profile storage unavailable/,
  );
});

test("contract loader rejects a failed response without preserving stale state", async () => {
  let attempts = 0;
  const load = apiContractLoader(async () => {
    attempts += 1;
    if (attempts === 1) return new Response("not JSON", { status: 200 });
    return new Response(JSON.stringify({ paths: {} }), { status: 200 });
  });
  await assert.rejects(load());
  assert.deepEqual(await load(), { paths: {} });
  assert.equal(attempts, 2);
});
