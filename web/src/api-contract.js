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

function declaredOperation(document, method, url) {
  if (!objectValue(document) || !objectValue(document.paths)) {
    throw new ApiSchemaError("The API contract document is invalid.");
  }
  const base = "https://e6irc.invalid";
  const parsed = new URL(url, base);
  if (parsed.origin !== base || !parsed.pathname.startsWith("/api/v1/")) {
    throw new ApiSchemaError("The API request URL is invalid.");
  }
  const pathname = parsed.pathname;
  const match = matchingPath(document.paths, pathname);
  const operation = match?.[1]?.[method.toLowerCase()];
  if (!objectValue(operation)) {
    throw new ApiSchemaError(`The API contract does not describe ${method.toUpperCase()} ${pathname}.`);
  }
  return { pathname, path: match[0], operation };
}

function queryValue(schema, value, label, path) {
  if (schema.type === "boolean") {
    if (value === "true") return true;
    if (value === "false") return false;
    schemaError(label, path);
  }
  if (schema.type === "integer") {
    if (!/^-?(?:0|[1-9][0-9]*)$/.test(value)) schemaError(label, path);
    const parsed = Number(value);
    if (!Number.isSafeInteger(parsed)) schemaError(label, path);
    return parsed;
  }
  if (schema.type === "number") {
    if (!/^-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?$/.test(value)) schemaError(label, path);
    const parsed = Number(value);
    if (!Number.isFinite(parsed)) schemaError(label, path);
    return parsed;
  }
  return value;
}

function parameterSchema(parameter, label) {
  if (!objectValue(parameter.schema) || !["string", "boolean", "integer", "number"].includes(parameter.schema.type)) {
    throw new ApiSchemaError(`The ${label} schema is invalid.`);
  }
  return parameter.schema;
}

function operationParameters(operation, label) {
  if (operation.parameters === undefined) return [];
  if (!Array.isArray(operation.parameters)) {
    throw new ApiSchemaError(`The ${label} schema is invalid.`);
  }
  return operation.parameters;
}

export function parseOperationQuery(document, method, url, label = "API query") {
  const { operation } = declaredOperation(document, method, url);
  const parameters = operationParameters(operation, label);
  const schemas = new Map();
  for (const parameter of parameters) {
    if (!objectValue(parameter) || parameter.in !== "query" || typeof parameter.name !== "string" || parameter.name === "") {
      if (objectValue(parameter) && parameter.in !== "query") continue;
      throw new ApiSchemaError(`The ${label} schema is invalid.`);
    }
    if (schemas.has(parameter.name)) throw new ApiSchemaError(`The ${label} schema is invalid.`);
    schemas.set(parameter.name, { ...parameter, schema: parameterSchema(parameter, label) });
  }
  const query = new URL(url, "https://e6irc.invalid").searchParams;
  for (const name of new Set(query.keys())) {
    const parameter = schemas.get(name);
    if (!parameter || query.getAll(name).length !== 1) schemaError(label, `$.${name}`);
    parseApiSchema(parameter.schema, queryValue(parameter.schema, query.get(name), label, `$.${name}`), label, `$.${name}`);
  }
  for (const [name, parameter] of schemas) {
    if (parameter.required === true && !query.has(name)) schemaError(label, `$.${name}`);
  }
}

export function parseOperationPath(document, method, url, label = "API path") {
  const { pathname, path, operation } = declaredOperation(document, method, url);
  const parameters = operationParameters(operation, label);
  const schemas = new Map();
  for (const parameter of parameters) {
    if (!objectValue(parameter) || parameter.in !== "path" || typeof parameter.name !== "string" || parameter.name === "" || parameter.required !== true) {
      if (objectValue(parameter) && parameter.in !== "path") continue;
      throw new ApiSchemaError(`The ${label} schema is invalid.`);
    }
    if (schemas.has(parameter.name)) throw new ApiSchemaError(`The ${label} schema is invalid.`);
    schemas.set(parameter.name, parameterSchema(parameter, label));
  }
  const actual = pathname.split("/");
  const expected = path.split("/");
  for (let index = 0; index < expected.length; index += 1) {
    const match = /^\{([^}]+)\}$/.exec(expected[index]);
    if (!match) continue;
    const schema = schemas.get(match[1]);
    if (!schema) throw new ApiSchemaError(`The ${label} schema is invalid.`);
    let value;
    try {
      value = decodeURIComponent(actual[index]);
    } catch {
      schemaError(label, `$.${match[1]}`);
    }
    parseApiSchema(schema, queryValue(schema, value, label, `$.${match[1]}`), label, `$.${match[1]}`);
  }
  for (const [name] of schemas) {
    if (!path.includes(`{${name}}`)) throw new ApiSchemaError(`The ${label} schema is invalid.`);
  }
}

function matchingPath(paths, pathname) {
  const exact = paths[pathname];
  if (objectValue(exact)) return [pathname, exact];
  const actual = pathname.split("/");
  const matches = Object.entries(paths).filter(([candidate]) => {
    const expected = candidate.split("/");
    return expected.length === actual.length
      && expected.every((segment, index) => /^\{[^}]+\}$/.test(segment) || segment === actual[index]);
  });
  if (matches.length > 1) {
    throw new ApiSchemaError(`The API contract has ambiguous paths for ${pathname}.`);
  }
  return matches[0];
}

export function operationResponseSchema(document, method, url, status = 200) {
  const { pathname, operation } = declaredOperation(document, method, url);
  const schema = operation?.responses?.[String(status)]?.content?.["application/json"]?.schema;
  if (!objectValue(schema)) {
    throw new ApiSchemaError(`The API contract does not describe ${method.toUpperCase()} ${pathname}.`);
  }
  return schema;
}

export function operationRequestSchema(document, method, url) {
  const { pathname, operation } = declaredOperation(document, method, url);
  const schema = operation.requestBody?.content?.["application/json"]?.schema;
  if (!objectValue(schema)) {
    throw new ApiSchemaError(`The API contract does not describe a JSON request body for ${method.toUpperCase()} ${pathname}.`);
  }
  return schema;
}

export function serializeOperationRequest(document, method, url, value, label = "API request") {
  return JSON.stringify(parseApiSchema(operationRequestSchema(document, method, url), value, label));
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

export function apiContractLoader(fetcher) {
  let contract;
  return async () => {
    contract ??= loadApiContract(fetcher).catch((error) => {
      contract = undefined;
      throw error;
    });
    return contract;
  };
}

export async function getOperationJson(fetcher, document, method, url, options = {}) {
  const { operation } = declaredOperation(document, method, url);
  parseOperationPath(document, method, url);
  parseOperationQuery(document, method, url);
  const { json, body: ignoredBody, ...request } = options;
  if (ignoredBody !== undefined) {
    throw new ApiSchemaError("JSON API requests must use the json option.");
  }
  if (json === undefined && operation.requestBody?.required === true) {
    throw new ApiSchemaError(`The API contract requires a JSON request body for ${method.toUpperCase()} ${new URL(url, "https://e6irc.invalid").pathname}.`);
  }
  if (json !== undefined) {
    request.body = serializeOperationRequest(document, method, url, json);
  }
  const response = await fetcher(url, {
    ...request,
    method,
    headers: { Accept: "application/json", ...request.headers },
  });
  if (!response.ok) await apiFailure(response);
  if (response.status === 204) return undefined;
  return parseOperationResponse(document, method, url, await readApiJson(response), "API response", response.status);
}
