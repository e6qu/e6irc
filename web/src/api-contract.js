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

function validSchemaType(type) {
  return ["null", "array", "object", "string", "boolean", "integer", "number"].includes(type);
}

function schemaTypes(schema, label) {
  if (!("type" in schema)) return [];
  const types = Array.isArray(schema.type) ? schema.type : [schema.type];
  if (types.length === 0 || types.some((type) => !validSchemaType(type)) || new Set(types).size !== types.length) {
    throw new ApiSchemaError(`The ${label} schema is invalid.`);
  }
  return types;
}

function nonNegativeInteger(schema, key, label) {
  if (key in schema && (!Number.isSafeInteger(schema[key]) || schema[key] < 0)) {
    throw new ApiSchemaError(`The ${label} schema is invalid.`);
  }
}

function finiteNumber(schema, key, label) {
  if (key in schema && (typeof schema[key] !== "number" || !Number.isFinite(schema[key]))) {
    throw new ApiSchemaError(`The ${label} schema is invalid.`);
  }
}

function closedObjectSchema(schema, label) {
  if (schema.additionalProperties !== false) {
    throw new ApiSchemaError(`The ${label} schema is invalid.`);
  }
  if ("properties" in schema && !objectValue(schema.properties)) {
    throw new ApiSchemaError(`The ${label} schema is invalid.`);
  }
  if ("required" in schema && !Array.isArray(schema.required)) {
    throw new ApiSchemaError(`The ${label} schema is invalid.`);
  }
  const properties = schema.properties ?? {};
  const required = schema.required ?? [];
  if (required.some((field) => typeof field !== "string" || !(field in properties)) || new Set(required).size !== required.length) {
    throw new ApiSchemaError(`The ${label} schema is invalid.`);
  }
  return { properties, required };
}

function validateApiSchema(schema, label) {
  if (!objectValue(schema)) throw new ApiSchemaError(`The ${label} schema is invalid.`);
  const types = schemaTypes(schema, label);
  if (types.length === 0 && !("oneOf" in schema) && !("const" in schema) && !("enum" in schema)) {
    throw new ApiSchemaError(`The ${label} schema is invalid.`);
  }
  if ("enum" in schema && (!Array.isArray(schema.enum) || schema.enum.length === 0)) {
    throw new ApiSchemaError(`The ${label} schema is invalid.`);
  }
  const requiresType = (keys, allowed) => {
    if (keys.some((key) => key in schema) && !types.some((type) => allowed.includes(type))) {
      throw new ApiSchemaError(`The ${label} schema is invalid.`);
    }
  };
  requiresType(["minLength", "maxLength", "pattern"], ["string"]);
  requiresType(["minimum", "maximum"], ["integer", "number"]);
  requiresType(["items", "minItems", "maxItems", "uniqueItems"], ["array"]);
  requiresType(["properties", "required", "additionalProperties"], ["object"]);
  if ("oneOf" in schema) {
    if (!Array.isArray(schema.oneOf) || schema.oneOf.length === 0) {
      throw new ApiSchemaError(`The ${label} schema is invalid.`);
    }
    for (const branch of schema.oneOf) validateApiSchema(branch, label);
  }
  nonNegativeInteger(schema, "minLength", label);
  nonNegativeInteger(schema, "maxLength", label);
  nonNegativeInteger(schema, "minItems", label);
  nonNegativeInteger(schema, "maxItems", label);
  finiteNumber(schema, "minimum", label);
  finiteNumber(schema, "maximum", label);
  if (Number.isSafeInteger(schema.minLength) && Number.isSafeInteger(schema.maxLength) && schema.minLength > schema.maxLength) {
    throw new ApiSchemaError(`The ${label} schema is invalid.`);
  }
  if (Number.isSafeInteger(schema.minItems) && Number.isSafeInteger(schema.maxItems) && schema.minItems > schema.maxItems) {
    throw new ApiSchemaError(`The ${label} schema is invalid.`);
  }
  if (typeof schema.minimum === "number" && typeof schema.maximum === "number" && schema.minimum > schema.maximum) {
    throw new ApiSchemaError(`The ${label} schema is invalid.`);
  }
  if ("pattern" in schema) {
    if (typeof schema.pattern !== "string") throw new ApiSchemaError(`The ${label} schema is invalid.`);
    try {
      new RegExp(schema.pattern);
    } catch {
      throw new ApiSchemaError(`The ${label} schema is invalid.`);
    }
  }
  if ("uniqueItems" in schema && typeof schema.uniqueItems !== "boolean") {
    throw new ApiSchemaError(`The ${label} schema is invalid.`);
  }
  if (types.includes("array")) {
    if (!objectValue(schema.items)) throw new ApiSchemaError(`The ${label} schema is invalid.`);
    validateApiSchema(schema.items, label);
  }
  if (types.includes("object")) {
    const { properties } = closedObjectSchema(schema, label);
    for (const property of Object.values(properties)) validateApiSchema(property, label);
  }
  return types;
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

function jsonIdentity(value) {
  if (Array.isArray(value)) return `[${value.map(jsonIdentity).join(",")}]`;
  if (objectValue(value)) {
    return `{${Object.keys(value).sort().map((key) => `${JSON.stringify(key)}:${jsonIdentity(value[key])}`).join(",")}}`;
  }
  return JSON.stringify(value);
}

export function parseApiSchema(schema, value, label = "API response", path = "$") {
  const types = validateApiSchema(schema, label);
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
  if (types.length > 0 && !types.some((type) => matchesType(value, type))) schemaError(label, path);
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
    if (schema.uniqueItems === true && new Set(value.map(jsonIdentity)).size !== value.length) {
      schemaError(label, path);
    }
    if (!objectValue(schema.items)) schemaError(label, path);
    return Object.freeze(value.map((item, index) => parseApiSchema(schema.items, item, label, `${path}[${index}]`)));
  }
  if (!objectValue(value)) return value;

  const { properties, required: requiredFields } = closedObjectSchema(schema, label);
  const required = new Set(requiredFields);
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
  if (parsed.origin !== base || parsed.hash !== "" || !parsed.pathname.startsWith("/api/v1/")) {
    throw new ApiSchemaError("The API request URL is invalid.");
  }
  const pathname = parsed.pathname;
  const match = matchingPath(document.paths, pathname);
  const operation = match?.[1]?.[method.toLowerCase()];
  if (!objectValue(operation)) {
    throw new ApiSchemaError(`The API contract does not describe ${method.toUpperCase()} ${pathname}.`);
  }
  operationParameters(operation, "API operation");
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
  const names = new Set();
  return operation.parameters.map((parameter) => {
    if (!objectValue(parameter)
      || !["path", "query"].includes(parameter.in)
      || typeof parameter.name !== "string"
      || parameter.name === ""
      || (parameter.required !== undefined && typeof parameter.required !== "boolean")
      || (parameter.in === "path" && parameter.required !== true)
      || (parameter.style !== undefined && parameter.style !== (parameter.in === "path" ? "simple" : "form"))
      || (parameter.explode !== undefined && parameter.explode !== (parameter.in === "query"))
      || (parameter.allowReserved !== undefined && parameter.allowReserved !== false)
      || parameter.allowEmptyValue !== undefined
      || parameter.content !== undefined) {
      throw new ApiSchemaError(`The ${label} schema is invalid.`);
    }
    const name = `${parameter.in}:${parameter.name}`;
    if (names.has(name)) throw new ApiSchemaError(`The ${label} schema is invalid.`);
    names.add(name);
    parameterSchema(parameter, label);
    validateApiSchema(parameter.schema, label);
    return parameter;
  });
}

export function parseOperationQuery(document, method, url, label = "API query") {
  const { operation } = declaredOperation(document, method, url);
  const parameters = operationParameters(operation, label);
  const schemas = new Map();
  for (const parameter of parameters) {
    if (parameter.in !== "query") continue;
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
    if (parameter.in !== "path") continue;
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
  const schema = declaredResponse(operation, method, pathname, status)?.content?.["application/json"]?.schema;
  if (!objectValue(schema)) {
    throw new ApiSchemaError(`The API contract does not describe ${method.toUpperCase()} ${pathname}.`);
  }
  return schema;
}

function declaredResponse(operation, method, pathname, status) {
  const response = operation.responses?.[String(status)];
  if (!objectValue(response)) {
    throw new ApiSchemaError(`The API contract does not describe ${method.toUpperCase()} ${pathname}.`);
  }
  return response;
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
  if (response.status === 204) {
    declaredResponse(operation, method, new URL(url, "https://e6irc.invalid").pathname, response.status);
    return undefined;
  }
  return parseOperationResponse(document, method, url, await readApiJson(response), "API response", response.status);
}
