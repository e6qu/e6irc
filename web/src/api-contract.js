// SPDX-License-Identifier: AGPL-3.0-or-later

export const MAX_API_JSON_BYTES = 1024 * 1024;

export class ApiError extends Error {
  constructor(status, message) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

export class ApiSchemaError extends ApiError {
  constructor(message) {
    super(200, message);
    this.name = "ApiSchemaError";
  }
}

function schemaError(label, path) {
  throw new ApiSchemaError(`The server returned an invalid ${label} at ${path}.`);
}

function objectValue(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function matchesType(value, type) {
  if (type === "null") return value === null;
  if (type === "array") return Array.isArray(value);
  if (type === "object") return objectValue(value);
  if (type === "string") return typeof value === "string";
  if (type === "boolean") return typeof value === "boolean";
  if (type === "integer") return Number.isSafeInteger(value);
  if (type === "number") return typeof value === "number" && Number.isFinite(value);
  return false;
}

export function parseApiSchema(schema, value, label = "API response", path = "$") {
  if (!objectValue(schema)) throw new ApiSchemaError(`The ${label} schema is invalid.`);
  if ("const" in schema && !Object.is(schema.const, value)) schemaError(label, path);
  if (Array.isArray(schema.oneOf)) {
    const matches = schema.oneOf.flatMap((candidate) => {
      try {
        return [parseApiSchema(candidate, value, label, path)];
      } catch (error) {
        if (error instanceof ApiSchemaError) return [];
        throw error;
      }
    });
    if (matches.length !== 1) schemaError(label, path);
    return matches[0];
  }
  if (schema.type !== undefined) {
    const types = Array.isArray(schema.type) ? schema.type : [schema.type];
    if (!types.some((type) => matchesType(value, type))) schemaError(label, path);
  }
  if (Array.isArray(schema.enum) && !schema.enum.some((entry) => Object.is(entry, value))) {
    schemaError(label, path);
  }
  if (typeof value === "string") {
    if (Number.isInteger(schema.minLength) && value.length < schema.minLength) schemaError(label, path);
    if (Number.isInteger(schema.maxLength) && value.length > schema.maxLength) schemaError(label, path);
    if (typeof schema.pattern === "string" && !(new RegExp(schema.pattern).test(value))) schemaError(label, path);
    return value;
  }
  if (typeof value === "number") {
    if (typeof schema.minimum === "number" && value < schema.minimum) schemaError(label, path);
    if (typeof schema.maximum === "number" && value > schema.maximum) schemaError(label, path);
    return value;
  }
  if (Array.isArray(value)) {
    if (Number.isInteger(schema.minItems) && value.length < schema.minItems) schemaError(label, path);
    if (Number.isInteger(schema.maxItems) && value.length > schema.maxItems) schemaError(label, path);
    if (schema.uniqueItems === true && new Set(value.map((item) => JSON.stringify(item))).size !== value.length) {
      schemaError(label, path);
    }
    if (!objectValue(schema.items)) schemaError(label, path);
    return Object.freeze(value.map((item, index) => parseApiSchema(schema.items, item, label, `${path}[${index}]`)));
  }
  if (!objectValue(value)) return value;

  const properties = objectValue(schema.properties) ? schema.properties : {};
  const required = Array.isArray(schema.required) ? new Set(schema.required) : new Set();
  for (const field of required) {
    if (!(field in value)) schemaError(label, `${path}.${field}`);
  }
  if (schema.additionalProperties === false && Object.keys(value).some((field) => !(field in properties))) {
    schemaError(label, path);
  }
  const parsed = {};
  for (const [field, fieldSchema] of Object.entries(properties)) {
    if (field in value) parsed[field] = parseApiSchema(fieldSchema, value[field], label, `${path}.${field}`);
  }
  return Object.freeze(parsed);
}

function matchingPath(paths, pathname) {
  const actual = pathname.split("/");
  return Object.entries(paths).find(([candidate]) => {
    const expected = candidate.split("/");
    return expected.length === actual.length
      && expected.every((segment, index) => /^\{[^}]+\}$/.test(segment) || segment === actual[index]);
  });
}

export function operationResponseSchema(document, method, url, status = 200) {
  if (!objectValue(document) || !objectValue(document.paths)) {
    throw new ApiSchemaError("The API contract document is invalid.");
  }
  const pathname = new URL(url, "https://e6irc.invalid").pathname;
  const match = matchingPath(document.paths, pathname);
  const operation = match?.[1]?.[method.toLowerCase()];
  const schema = operation?.responses?.[String(status)]?.content?.["application/json"]?.schema;
  if (!objectValue(schema)) {
    throw new ApiSchemaError(`The API contract does not describe ${method.toUpperCase()} ${pathname}.`);
  }
  return schema;
}

export function parseOperationResponse(document, method, url, value, label = "API response", status = 200) {
  return parseApiSchema(operationResponseSchema(document, method, url, status), value, label);
}

export async function readApiJson(response) {
  const length = Number(response.headers.get("content-length"));
  if (Number.isFinite(length) && length > MAX_API_JSON_BYTES) {
    throw new ApiError(response.status, "The API response is too large. Reload and try again.");
  }
  const text = await response.text();
  if (new TextEncoder().encode(text).byteLength > MAX_API_JSON_BYTES) {
    throw new ApiError(response.status, "The API response is too large. Reload and try again.");
  }
  try {
    return JSON.parse(text);
  } catch {
    throw new ApiError(response.status, "The API response contains invalid JSON. Reload and try again.");
  }
}

export function requireApiObject(value, status, message = "The API response is invalid. Reload and try again.") {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    throw new ApiError(status, message);
  }
  return value;
}

async function apiFailure(response) {
  let value;
  try {
    value = await readApiJson(response);
  } catch (error) {
    if (error instanceof ApiError) {
      throw new ApiError(response.status, `Request failed with HTTP ${response.status}: ${error.message}`);
    }
    throw error;
  }
  const problem = requireApiObject(value, response.status, "The server returned an invalid error response.");
  const detail = typeof problem.detail === "string"
    ? problem.detail
    : typeof problem.title === "string"
      ? problem.title
      : "";
  if (!detail) throw new ApiError(response.status, "The server returned an invalid error response.");
  throw new ApiError(response.status, detail);
}

export async function getApiObject(fetcher, url, options = {}) {
  const response = await fetcher(url, {
    ...options,
    headers: { Accept: "application/json", ...options.headers },
  });
  if (!response.ok) await apiFailure(response);
  return requireApiObject(await readApiJson(response), response.status);
}

export async function loadApiContract(fetcher) {
  return getApiObject(fetcher, "/api/v1/openapi.json", { cache: "no-store", credentials: "same-origin" });
}

export async function getOperationJson(fetcher, document, method, url, options = {}) {
  const response = await fetcher(url, {
    ...options,
    headers: { Accept: "application/json", ...options.headers },
  });
  if (!response.ok) await apiFailure(response);
  if (response.status === 204) return undefined;
  return parseOperationResponse(document, method, url, await readApiJson(response), "API response", response.status);
}
