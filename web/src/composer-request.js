// SPDX-License-Identifier: AGPL-3.0-or-later

const REQUEST_KEYS = new Set(["id", "target", "message"]);

export class ComposerRequestError extends Error {
  constructor() {
    super("The composer request is invalid.");
    this.name = "ComposerRequestError";
  }
}

function validId(value) {
  return typeof value === "string" && /^[A-Za-z0-9-]{1,64}$/.test(value);
}

export function serializeComposerRequest(request) {
  if (
    request === null ||
    typeof request !== "object" ||
    Array.isArray(request) ||
    !Object.keys(request).every((key) => REQUEST_KEYS.has(key)) ||
    typeof request.target !== "string" ||
    typeof request.message !== "string" ||
    (request.id !== undefined && !validId(request.id))
  ) {
    throw new ComposerRequestError();
  }
  const frame = { target: request.target, message: request.message };
  if (request.id !== undefined) frame.id = request.id;
  return JSON.stringify(frame);
}
