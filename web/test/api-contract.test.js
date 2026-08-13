// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from "node:assert/strict";
import test from "node:test";

import {
  ApiSchemaError,
  apiContractLoader,
  getOperationJson,
  operationRequestSchema,
  operationResponseSchema,
  parseApiSchema,
  parseOperationPath,
  parseOperationQuery,
  parseOperationResponse,
  serializeOperationRequest,
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

test("schema parser rejects malformed constraints instead of weakening a projection", () => {
  const valid = { name: "Libera", enabled: true, state: "connected" };
  for (const schema of [
    { ...responseSchema, type: "record" },
    { ...responseSchema, type: [] },
    { ...responseSchema, enum: "connected" },
    { ...responseSchema, oneOf: [] },
    { ...responseSchema, minLength: -1 },
    { ...responseSchema, minimum: Number.NaN },
    { ...responseSchema, pattern: 42 },
    { ...responseSchema, properties: [] },
    { ...responseSchema, required: ["missing"] },
    { ...responseSchema, additionalProperties: true },
  ]) {
    assert.throws(() => parseApiSchema(schema, valid, "network response"), ApiSchemaError);
  }
  assert.throws(
    () => parseApiSchema({ type: "string", pattern: "[" }, "Libera", "network response"),
    ApiSchemaError,
  );
  for (const schema of [
    {},
    { type: "array", items: { type: "record" } },
    { type: "array" },
    { type: "object", additionalProperties: false, properties: { nested: { type: "record" } } },
  ]) {
    assert.throws(() => parseApiSchema(schema, schema.type === "array" ? [] : {}, "network response"), ApiSchemaError);
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

test("operation parser gives a literal path precedence over a template", () => {
  const literalSchema = {
    type: "object", additionalProperties: false, required: ["preflight"],
    properties: { preflight: { const: true } },
  };
  const templateSchema = {
    type: "object", additionalProperties: false, required: ["name"],
    properties: { name: { type: "string" } },
  };
  const document = {
    paths: {
      "/api/v1/me/networks/{name}": { get: { responses: { 200: { content: { "application/json": { schema: templateSchema } } } } } },
      "/api/v1/me/networks/preflight": { get: { responses: { 200: { content: { "application/json": { schema: literalSchema } } } } } },
    },
  };
  assert.deepEqual(parseOperationResponse(document, "GET", "/api/v1/me/networks/preflight", { preflight: true }), { preflight: true });
});

test("operation parser rejects ambiguous templates", () => {
  const schema = { type: "object", additionalProperties: false };
  const document = {
    paths: {
      "/api/v1/me/widgets/{name}": { get: { responses: { 200: { content: { "application/json": { schema } } } } } },
      "/api/v1/me/widgets/{id}": { get: { responses: { 200: { content: { "application/json": { schema } } } } } },
    },
  };
  assert.throws(
    () => operationResponseSchema(document, "GET", "/api/v1/me/widgets/current"),
    /ambiguous paths/,
  );
});

test("operation parser rejects invalid queries before a request leaves the browser", async () => {
  const document = {
    paths: {
      "/api/v1/me/widgets": {
        get: {
          parameters: [
            { name: "limit", in: "query", schema: { type: "integer", minimum: 1, maximum: 100 } },
            { name: "active", in: "query", required: true, schema: { type: "boolean" } },
          ],
          responses: { 200: { content: { "application/json": { schema: { type: "object" } } } } },
        },
      },
    },
  };
  parseOperationQuery(document, "GET", "/api/v1/me/widgets?limit=10&active=true");
  for (const query of ["?limit=0&active=true", "?limit=1.5&active=true", "?limit=10&active=yes", "?limit=10", "?limit=10&active=true&extra=x", "?limit=10&active=true&limit=11"]) {
    assert.throws(() => parseOperationQuery(document, "GET", `/api/v1/me/widgets${query}`), ApiSchemaError);
  }
  let requested = false;
  await assert.rejects(getOperationJson(async () => {
    requested = true;
    return new Response();
  }, document, "GET", "/api/v1/me/widgets?limit=0&active=true"), ApiSchemaError);
  assert.equal(requested, false);
});

test("operation parser rejects URLs outside the origin-relative API", async () => {
  const document = {
    paths: {
      "/api/v1/me/widgets": {
        get: { responses: { 200: { content: { "application/json": { schema: { type: "object" } } } } } },
      },
    },
  };
  for (const url of ["widgets", "/console", "/api/v1/me/widgets#stale", "https://example.test/api/v1/me/widgets", "//example.test/api/v1/me/widgets"]) {
    assert.throws(() => parseOperationQuery(document, "GET", url), ApiSchemaError);
  }
  let requested = false;
  await assert.rejects(getOperationJson(async () => {
    requested = true;
    return new Response();
  }, document, "GET", "https://example.test/api/v1/me/widgets"), ApiSchemaError);
  assert.equal(requested, false);
});

test("operation parser rejects invalid path parameters before a request leaves the browser", async () => {
  const document = {
    paths: {
      "/api/v1/me/widgets/{id}": {
        get: {
          parameters: [{ name: "id", in: "path", required: true, schema: { type: "integer", minimum: 1 } }],
          responses: { 200: { content: { "application/json": { schema: { type: "object" } } } } },
        },
      },
    },
  };
  parseOperationPath(document, "GET", "/api/v1/me/widgets/42");
  for (const path of ["/api/v1/me/widgets/0", "/api/v1/me/widgets/1.5", "/api/v1/me/widgets/nope"]) {
    assert.throws(() => parseOperationPath(document, "GET", path), ApiSchemaError);
  }
  let requested = false;
  await assert.rejects(getOperationJson(async () => {
    requested = true;
    return new Response();
  }, document, "GET", "/api/v1/me/widgets/nope"), ApiSchemaError);
  assert.equal(requested, false);
});

test("operation parser rejects parameters with unsupported wire types", () => {
  const document = {
    paths: {
      "/api/v1/me/widgets": {
        get: {
          parameters: [{ name: "ids", in: "query", schema: { type: "array", items: { type: "integer" } } }],
          responses: { 200: { content: { "application/json": { schema: { type: "object" } } } } },
        },
      },
    },
  };
  assert.throws(() => parseOperationQuery(document, "GET", "/api/v1/me/widgets?ids=1"), ApiSchemaError);
});

test("operation parser requires documented path parameters", () => {
  const document = {
    paths: {
      "/api/v1/me/widgets/{id}": {
        get: {
          parameters: [{ name: "id", in: "path", schema: { type: "integer" } }],
          responses: { 200: { content: { "application/json": { schema: { type: "object" } } } } },
        },
      },
    },
  };
  assert.throws(() => parseOperationPath(document, "GET", "/api/v1/me/widgets/1"), ApiSchemaError);
});

test("operation parser rejects malformed parameter collections", () => {
  const document = {
    paths: {
      "/api/v1/me/widgets": {
        get: {
          parameters: {},
          responses: { 200: { content: { "application/json": { schema: { type: "object" } } } } },
        },
      },
    },
  };
  assert.throws(() => parseOperationQuery(document, "GET", "/api/v1/me/widgets"), ApiSchemaError);
});

test("operation parser rejects parameters the browser cannot enforce", () => {
  for (const parameter of [
    { name: "authorization", in: "header", schema: { type: "string" } },
    { name: "session", in: "cookie", schema: { type: "string" } },
    { name: "limit", in: "query", schema: { type: "array" } },
    { name: "limit", in: "query", schema: { type: "string" } },
  ]) {
    const document = {
      paths: {
        "/api/v1/me/widgets": {
          get: {
            parameters: [parameter, ...(parameter.in === "query" ? [parameter] : [])],
            responses: { 200: { content: { "application/json": { schema: { type: "object", additionalProperties: false } } } } },
          },
        },
      },
    };
    assert.throws(() => parseOperationQuery(document, "GET", "/api/v1/me/widgets"), ApiSchemaError);
  }
});

test("operation request serializer closes and validates documented JSON", () => {
  const document = {
    paths: {
      "/api/v1/me/widgets/{name}": {
        patch: {
          requestBody: { required: true, content: { "application/json": { schema: {
            type: "object", additionalProperties: false, required: ["enabled"], properties: {
              enabled: { type: "boolean" }, label: { type: "string", minLength: 1 },
            },
          } } } },
          responses: {},
        },
      },
    },
  };
  assert.deepEqual(operationRequestSchema(document, "PATCH", "/api/v1/me/widgets/libera"), {
    type: "object", additionalProperties: false, required: ["enabled"], properties: {
      enabled: { type: "boolean" }, label: { type: "string", minLength: 1 },
    },
  });
  assert.equal(
    serializeOperationRequest(document, "PATCH", "/api/v1/me/widgets/libera", { enabled: true }),
    '{"enabled":true}',
  );
  for (const value of [{}, { enabled: "true" }, { enabled: true, extra: true }]) {
    assert.throws(
      () => serializeOperationRequest(document, "PATCH", "/api/v1/me/widgets/libera", value),
      ApiSchemaError,
    );
  }
  assert.throws(
    () => operationRequestSchema(document, "DELETE", "/api/v1/me/widgets/libera"),
    ApiSchemaError,
  );
});

test("operation request serializer accepts exactly one complete union branch", () => {
  const document = {
    paths: {
      "/api/v1/admin/accounts/{id}": {
        patch: {
          requestBody: { required: true, content: { "application/json": { schema: {
            oneOf: [
              { type: "object", additionalProperties: false, required: ["suspended"], properties: { suspended: { type: "boolean" } } },
              { type: "object", additionalProperties: false, required: ["administrator"], properties: { administrator: { type: "boolean" } } },
            ],
          } } } },
          responses: {},
        },
      },
    },
  };
  assert.equal(
    serializeOperationRequest(document, "PATCH", "/api/v1/admin/accounts/1", { suspended: true }),
    '{"suspended":true}',
  );
  assert.equal(
    serializeOperationRequest(document, "PATCH", "/api/v1/admin/accounts/1", { administrator: false }),
    '{"administrator":false}',
  );
  for (const value of [{}, { suspended: true, administrator: false }]) {
    assert.throws(
      () => serializeOperationRequest(document, "PATCH", "/api/v1/admin/accounts/1", value),
      ApiSchemaError,
    );
  }
});

test("operation requests serialize only contract-checked JSON", async () => {
  const document = {
    paths: {
      "/api/v1/me/widgets": {
        post: {
          requestBody: { required: true, content: { "application/json": { schema: {
            type: "object", additionalProperties: false, required: ["enabled"], properties: {
              enabled: { type: "boolean" },
            },
          } } } },
          responses: { 204: { description: "updated" } },
        },
      },
    },
  };
  let request;
  assert.equal(await getOperationJson(async (url, options) => {
    request = { url, options };
    return new Response(null, { status: 204 });
  }, document, "POST", "/api/v1/me/widgets", { json: { enabled: true } }), undefined);
  assert.deepEqual(request, {
    url: "/api/v1/me/widgets",
    options: {
      method: "POST",
      headers: { Accept: "application/json" },
      body: '{"enabled":true}',
    },
  });
  await assert.rejects(
    getOperationJson(async () => new Response(), document, "POST", "/api/v1/me/widgets", { json: {} }),
    ApiSchemaError,
  );
  await assert.rejects(
    getOperationJson(async () => new Response(), document, "POST", "/api/v1/me/widgets", { body: "{}" }),
    ApiSchemaError,
  );
  await assert.rejects(
    getOperationJson(async () => new Response(), document, "POST", "/api/v1/me/widgets"),
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
      { paths: { "/api/v1/me/profile": { patch: { responses: {} } } } },
      "PATCH",
      "/api/v1/me/profile",
    ),
    /Profile storage unavailable/,
  );
});

test("undeclared operations fail before a request leaves the browser", async () => {
  let requested = false;
  await assert.rejects(
    getOperationJson(
      async () => {
        requested = true;
        return new Response();
      },
      { paths: {} },
      "GET",
      "/api/v1/me/security-activity",
    ),
    ApiSchemaError,
  );
  assert.equal(requested, false);
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
