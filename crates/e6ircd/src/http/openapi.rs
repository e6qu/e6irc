//! The served OpenAPI description.

use super::*;

/// OpenAPI 3.1 description of the REST surface. Hand-authored and kept in
/// step with the routes above; consumers use it to generate clients.
pub(super) async fn openapi() -> Response {
    let bearer = serde_json::json!([{ "bearer": [] }]);
    let ok_json = serde_json::json!({
        "200": { "description": "OK", "content": { "application/json": {} } }
    });
    let channel_name_parameter = serde_json::json!([
        { "name": "name", "in": "path", "required": true,
            "schema": { "type": "string" } }
    ]);
    let channel_access_parameters = serde_json::json!([
        { "name": "name", "in": "path", "required": true,
            "schema": { "type": "string" } },
        { "name": "account", "in": "path", "required": true,
            "schema": { "type": "string" } }
    ]);
    let page_limit_parameter = || {
        serde_json::json!({ "name": "limit", "in": "query",
            "schema": { "type": "integer", "minimum": 1, "maximum": 1000,
                "default": 100 } })
    };
    let admin_cursor_parameters = || {
        vec![
            page_limit_parameter(),
            serde_json::json!({ "name": "before_id", "in": "query",
                "schema": { "type": "integer", "format": "int64", "minimum": 1 } }),
        ]
    };
    let mut account_directory_parameters = admin_cursor_parameters();
    account_directory_parameters.push(serde_json::json!({
        "name": "name", "in": "query",
        "schema": { "type": "string", "maxLength": 64 }
    }));
    let mut registered_channel_parameters = admin_cursor_parameters();
    registered_channel_parameters.extend([
        serde_json::json!({ "name": "name", "in": "query",
            "schema": { "type": "string", "maxLength": 50 } }),
        serde_json::json!({ "name": "founder", "in": "query",
            "schema": { "type": "string", "maxLength": 64 } }),
    ]);
    let mut server_ban_parameters = admin_cursor_parameters();
    server_ban_parameters.extend([
        serde_json::json!({ "name": "kind", "in": "query",
            "schema": { "type": "string", "enum": ["kline", "dline", "xline"] } }),
        serde_json::json!({ "name": "mask", "in": "query",
            "schema": { "type": "string", "maxLength": 512 } }),
    ]);
    let mut audit_parameters = admin_cursor_parameters();
    audit_parameters.extend([
        serde_json::json!({ "name": "actor", "in": "query",
            "schema": { "type": "string", "maxLength": 128 } }),
        serde_json::json!({ "name": "action", "in": "query",
            "schema": { "type": "string", "maxLength": 64 } }),
        serde_json::json!({ "name": "target", "in": "query",
            "schema": { "type": "string", "maxLength": 512 } }),
    ]);
    let connection_cursor_parameters = || {
        vec![
            page_limit_parameter(),
            serde_json::json!({ "name": "before_id", "in": "query",
                "schema": { "type": "string", "pattern": "^[1-9][0-9]*$" } }),
        ]
    };
    let mut own_connection_parameters = connection_cursor_parameters();
    own_connection_parameters.extend([
        serde_json::json!({ "name": "nick", "in": "query",
            "schema": { "type": "string", "maxLength": 64 } }),
        serde_json::json!({ "name": "transport", "in": "query",
            "schema": { "type": "string",
                "enum": ["tcp", "tls", "websocket", "local"] } }),
        serde_json::json!({ "name": "oper", "in": "query",
            "schema": { "type": "boolean" } }),
    ]);
    let mut admin_connection_parameters = own_connection_parameters.clone();
    admin_connection_parameters.push(serde_json::json!({
        "name": "account", "in": "query",
        "schema": { "type": "string", "maxLength": 64 }
    }));
    let connection_mutation_parameters = || {
        vec![
            serde_json::json!({ "name": "id", "in": "path", "required": true,
                "schema": { "type": "string", "pattern": "^[1-9][0-9]*$" } }),
            serde_json::json!({ "name": "reason", "in": "query",
                "schema": { "type": "string", "maxLength": 300 } }),
        ]
    };
    let spec = serde_json::json!({
        "openapi": "3.1.0",
        "info": {
            "title": "e6irc REST API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Account, connection, policy, monitoring, credential, and BNC-network management for e6ircd.",
        },
        "components": {
            "securitySchemes": {
                "bearer": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "A personal access token (see POST /api/v1/me/tokens).",
                }
            }
        },
        "paths": {
            "/healthz": {
                "get": { "summary": "Liveness probe", "responses": {
                    "200": { "description": "the literal string \"ok\"" } } }
            },
            "/readyz": {
                "get": { "summary": "Core and PostgreSQL readiness probe", "responses": {
                    "200": { "description": "all configured dependencies are ready" },
                    "503": { "description": "the core heartbeat is stale or PostgreSQL is unavailable" } } }
            },
            "/api/v1/server": {
                "get": { "summary": "Server name, network name, version", "responses": ok_json }
            },
            "/api/v1/auth/app-passwords": {
                "post": {
                    "summary": "Exchange an account password for a new app password",
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": { "type": "object",
                            "required": ["account", "password", "label"],
                            "properties": {
                                "account": { "type": "string", "minLength": 1, "maxLength": 64 },
                                "password": { "type": "string", "minLength": 1, "maxLength": 512 },
                                "label": { "type": "string", "maxLength": 64 } } } } } },
                    "responses": { "201": { "description": "the app password (shown once)" },
                        "400": { "description": "invalid account, password, or label" },
                        "401": { "description": "bad credentials" },
                        "503": { "description": "no database configured" } }
                }
            },
            "/api/v1/me": {
                "get": { "summary": "The authenticated account", "security": bearer,
                    "responses": ok_json }
            },
            "/api/v1/me/sessions": {
                "get": {
                    "summary": "List your active browser sessions",
                    "description": "Returns at most 32 owner-scoped stable IDs, creation/expiry times, login method, provider, bounded User-Agent provenance, and whether a row is the request's current cookie session. A new login atomically revokes the oldest active row at the cap. Session tokens and hashes are never returned.",
                    "security": bearer,
                    "responses": {
                        "200": { "description": "unexpired browser sessions, current first" },
                        "503": { "description": "database unavailable" }
                    }
                }
            },
            "/api/v1/me/sessions/{id}": {
                "delete": {
                    "summary": "Revoke one of your browser sessions",
                    "description": "The session ID is scoped to the authenticated account in the deletion query. Revoking the current cookie session also clears its browser cookie.",
                    "security": bearer,
                    "parameters": [{ "name": "id", "in": "path", "required": true,
                        "schema": { "type": "integer", "format": "int64" } }],
                    "responses": {
                        "204": { "description": "session revoked" },
                        "404": { "description": "session does not exist or belongs to another account" },
                        "503": { "description": "database unavailable" }
                    }
                }
            },
            "/api/v1/me/connections": {
                "get": {
                    "summary": "Filter and page your live IRC connections",
                    "description": "Returns only registered connections currently authenticated to the caller. IDs and next_before_id are exact decimal strings so JavaScript clients cannot round them. IDs identify exact live resources; before_id selects strictly older connections, so concurrent accepts cannot duplicate into an older page.",
                    "security": bearer,
                    "parameters": own_connection_parameters,
                    "responses": {
                        "200": { "description": "owner-scoped connection posture and next_before_id cursor" },
                        "400": { "description": "invalid limit, cursor, or exact filter" },
                        "401": { "description": "authentication required" },
                        "503": { "description": "live core unavailable" }
                    }
                }
            },
            "/api/v1/me/connections/{id}": {
                "delete": {
                    "summary": "Disconnect one of your exact live IRC connections",
                    "description": "Core ownership is rechecked against the authenticated account at mutation time. Another account's or a stale ID is indistinguishable from a missing resource.",
                    "security": bearer,
                    "parameters": connection_mutation_parameters(),
                    "responses": {
                        "204": { "description": "connection disconnected" },
                        "400": { "description": "invalid ID or reason" },
                        "404": { "description": "connection is stale, missing, or belongs to another account" },
                        "503": { "description": "live core unavailable" }
                    }
                }
            },
            "/api/v1/auth/oidc/{provider}/start": {
                "get": { "summary": "Begin interactive OIDC login (redirects to the provider)",
                    "description": "Redirects the browser to the provider's authorization endpoint (code flow + PKCE) and sets a state-binding cookie the callback requires.",
                    "parameters": [{ "name": "provider", "in": "path", "required": true,
                        "schema": { "type": "string" } }],
                    "responses": { "307": { "description": "redirect into the provider" },
                        "404": { "description": "unknown provider" } } }
            },
            "/api/v1/auth/oidc/{provider}/callback": {
                "get": { "summary": "OIDC redirect-back: exchange the code and establish the session",
                    "description": "Verifies the state-binding cookie, exchanges the authorization code (with PKCE) for tokens, validates the ID token, provisions or logs into the account, and sets the session cookie.",
                    "parameters": [
                        { "name": "provider", "in": "path", "required": true, "schema": { "type": "string" } },
                        { "name": "code", "in": "query", "required": false, "schema": { "type": "string" } },
                        { "name": "state", "in": "query", "required": false, "schema": { "type": "string" } }
                    ],
                    "responses": { "303": { "description": "logged in; session cookie set" },
                        "401": { "description": "state/code/token validation failed" } } }
            },
            "/api/v1/auth/oidc/{provider}/sso": {
                "get": { "summary": "Silently probe for an existing SSO session (prompt=none)",
                    "description": "Redirects to the provider with prompt=none. If the browser already has an SSO session the callback logs you in with no prompt; otherwise it bounces to /?sso=none.",
                    "parameters": [{ "name": "provider", "in": "path", "required": true,
                        "schema": { "type": "string" } }],
                    "responses": { "307": { "description": "redirect into the provider" },
                        "404": { "description": "unknown provider" } } }
            },
            "/api/v1/auth/logout": {
                "get": { "summary": "RP-initiated logout: end the local and provider SSO sessions",
                    "description": "Clears the e6irc session, then redirects the browser to the OIDC provider's end-session endpoint (id_token_hint + post_logout_redirect_uri) so the provider's SSO session is ended too. Local-account sessions return directly to e6irc; incomplete OIDC logout configuration fails closed.",
                    "responses": { "303": { "description": "redirect to the provider (or /) after clearing the session" } } },
                "post": { "summary": "Local logout: clear the e6irc session only",
                    "responses": { "204": { "description": "session cleared" } } }
            },
            "/api/v1/auth/oidc/backchannel-logout": {
                "post": {
                    "summary": "OIDC Back-Channel Logout 1.0 receiver",
                    "description": "Verifies a signed logout_token against the configured issuer's discovery document and JWKS, rejects replayed tokens, and revokes every local session correlated by sid or sub.",
                    "requestBody": { "required": true, "content": {
                        "application/x-www-form-urlencoded": { "schema": {
                            "type": "object", "required": ["logout_token"],
                            "properties": { "logout_token": { "type": "string" } }
                        } }
                    } },
                    "responses": {
                        "200": { "description": "correlated sessions revoked" },
                        "400": { "description": "invalid or replayed logout token" },
                        "502": { "description": "OIDC provider discovery or JWKS failed" },
                        "503": { "description": "database unavailable" }
                    }
                }
            },
            "/api/v1/auth/oidc/frontchannel-logout": {
                "get": {
                    "summary": "OIDC Front-Channel Logout 1.0 receiver",
                    "description": "Revokes local sessions correlated by the exact configured issuer and sid, clears the browser session cookie, and returns a non-cacheable response.",
                    "parameters": [
                        { "name": "iss", "in": "query", "required": true,
                            "schema": { "type": "string", "format": "uri" } },
                        { "name": "sid", "in": "query", "required": true,
                            "schema": { "type": "string" } }
                    ],
                    "responses": {
                        "200": { "description": "correlated sessions revoked" },
                        "400": { "description": "missing or invalid issuer/session identifier" },
                        "503": { "description": "database unavailable" }
                    }
                }
            },
            "/api/v1/auth/oidc/{provider}/link": {
                "get": { "summary": "Link an OIDC identity to your account (redirects to the provider)",
                    "security": bearer,
                    "parameters": [{ "name": "provider", "in": "path", "required": true,
                        "schema": { "type": "string" } }],
                    "responses": { "307": { "description": "redirect into the provider" },
                        "404": { "description": "unknown provider" },
                        "409": { "description": "identity already linked to another account (on return)" } } }
            },
            "/api/v1/me/identities": {
                "get": { "summary": "List OIDC identities linked to your account",
                    "security": bearer, "responses": ok_json }
            },
            "/api/v1/me/identities/{id}": {
                "delete": {
                    "summary": "Unlink one of your OIDC identities and revoke its browser sessions",
                    "security": bearer,
                    "parameters": [{ "name": "id", "in": "path", "required": true,
                        "schema": { "type": "integer" } }],
                    "responses": {
                        "204": { "description": "identity unlinked and its sessions revoked" },
                        "404": { "description": "identity is not linked to this account" },
                        "409": { "description": "last login method; add a local password or another identity first" },
                        "503": { "description": "database unavailable" }
                    }
                }
            },
            "/api/v1/auth/device/start": {
                "post": { "summary": "Begin an RFC 8628 device authorization grant",
                    "responses": { "200": { "description": "device_code, user_code, verification_uri" } } }
            },
            "/api/v1/auth/device/token": {
                "post": { "summary": "Poll for the device grant's token",
                    "responses": { "200": { "description": "access_token once approved" },
                        "400": { "description": "authorization_pending / expired_token / invalid_grant" } } }
            },
            "/api/v1/auth/device/approve": {
                "post": { "summary": "Approve a device grant by user_code", "security": bearer,
                    "responses": { "204": { "description": "approved" },
                        "404": { "description": "no such pending code" } } }
            },
            "/api/v1/me/tokens": {
                "get": { "summary": "List your personal access tokens (never the token)",
                    "security": bearer, "responses": ok_json },
                "post": { "summary": "Mint a personal access token (shown once)",
                    "security": bearer, "responses": ok_json }
            },
            "/api/v1/me/tokens/{id}": {
                "delete": { "summary": "Revoke one of your personal access tokens",
                    "security": bearer,
                    "responses": { "204": { "description": "revoked" },
                        "404": { "description": "no such token" } } }
            },
            "/api/v1/me/read-markers": {
                "get": { "summary": "List your read markers (draft/read-marker) per target",
                    "security": bearer, "responses": ok_json }
            },
            "/api/v1/me/password": {
                "put": {
                    "summary": "Change your primary local-account password",
                    "description": "Creates a first primary password for an OIDC-only account when current_password is omitted. Existing primary passwords require their current value; an app password cannot authorize rotation.",
                    "security": bearer,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["new_password"],
                            "properties": {
                                "current_password": { "type": "string", "minLength": 1, "maxLength": 512 },
                                "new_password": { "type": "string", "minLength": 1, "maxLength": 512 }
                            }
                        }
                    } } },
                    "responses": {
                        "204": { "description": "primary password changed" },
                        "400": { "description": "password is empty or exceeds 512 bytes" },
                        "401": { "description": "current primary password is incorrect" },
                        "409": { "description": "current_password omitted but a primary password already exists" },
                        "503": { "description": "database unavailable" }
                    }
                }
            },
            "/api/v1/me/channels": {
                "get": {
                    "summary": "List registered channels you founded with durable configuration",
                    "security": bearer,
                    "responses": {
                        "200": { "description": "channels, retained topics, KEEPTOPIC, MLOCK, and access grants" },
                        "503": { "description": "database unavailable" }
                    }
                },
                "post": {
                    "summary": "Register a live channel currently operated by your account",
                    "description": "An identified live session for the authenticated account must be a channel operator. The current topic, founder row, and audit record are stored before the live ownership map changes.",
                    "security": bearer,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": {
                            "type": "object",
                            "additionalProperties": false,
                            "required": ["name"],
                            "properties": {
                                "name": { "type": "string", "pattern": "^[#&+!]" }
                            }
                        }
                    } } },
                    "responses": {
                        "201": { "description": "registered and applied" },
                        "400": { "description": "invalid channel name" },
                        "409": { "description": "not joined as an operator, already registered, registration pending, or account cap reached" },
                        "503": { "description": "core or database unavailable" }
                    }
                }
            },
            "/api/v1/me/channels/{name}": {
                "get": {
                    "summary": "Read one registered channel you founded",
                    "security": bearer,
                    "parameters": channel_name_parameter,
                    "responses": {
                        "200": { "description": "durable channel configuration" },
                        "404": { "description": "no such channel owned by this account" }
                    }
                },
                "patch": {
                    "summary": "Change a retained topic, KEEPTOPIC, MLOCK, or founder",
                    "description": "The body is a tagged operation: set_topic, set_keeptopic, set_mlock, or transfer_founder. Exactly one storage-confirmed mutation is applied.",
                    "security": bearer,
                    "parameters": channel_name_parameter,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": {
                            "oneOf": [
                                {
                                    "type": "object",
                                    "additionalProperties": false,
                                    "required": ["action"],
                                    "properties": {
                                        "action": { "const": "set_topic" },
                                        "topic": {
                                            "type": ["string", "null"],
                                            "description": "Retained topic, at most 390 UTF-8 bytes"
                                        }
                                    }
                                },
                                {
                                    "type": "object",
                                    "additionalProperties": false,
                                    "required": ["action", "enabled"],
                                    "properties": {
                                        "action": { "const": "set_keeptopic" },
                                        "enabled": { "type": "boolean" }
                                    }
                                },
                                {
                                    "type": "object",
                                    "additionalProperties": false,
                                    "required": ["action"],
                                    "properties": {
                                        "action": { "const": "set_mlock" },
                                        "mlock": { "type": ["string", "null"] }
                                    }
                                },
                                {
                                    "type": "object",
                                    "additionalProperties": false,
                                    "required": ["action", "account"],
                                    "properties": {
                                        "action": { "const": "transfer_founder" },
                                        "account": {
                                            "type": "string",
                                            "minLength": 1,
                                            "description": "Registered account name, at most 64 UTF-8 bytes"
                                        }
                                    }
                                }
                            ]
                        }
                    } } },
                    "responses": {
                        "200": { "description": "stored and applied" },
                        "400": { "description": "invalid operation or value" },
                        "404": { "description": "no such owned channel or target account" },
                        "409": { "description": "retained topic requested while KEEPTOPIC is off" },
                        "503": { "description": "core or database unavailable" }
                    }
                },
                "delete": {
                    "summary": "Unregister a channel you founded and remove all durable settings",
                    "security": bearer,
                    "parameters": channel_name_parameter,
                    "responses": {
                        "200": { "description": "unregistered" },
                        "404": { "description": "no such owned channel" },
                        "503": { "description": "core or database unavailable" }
                    }
                }
            },
            "/api/v1/me/channels/{name}/access/{account}": {
                "put": {
                    "summary": "Set auto-op/auto-voice access for a registered account",
                    "security": bearer,
                    "parameters": channel_access_parameters,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": { "type": "object", "additionalProperties": false, "required": ["flags"],
                            "properties": {
                                "flags": {
                                    "type": "string",
                                    "pattern": "^(o|v|ov|vo)$"
                                }
                            } }
                    } } },
                    "responses": {
                        "200": { "description": "stored and applied" },
                        "400": { "description": "invalid flags" },
                        "404": { "description": "no such owned channel or registered account" },
                        "409": { "description": "access list is full" }
                    }
                },
                "delete": {
                    "summary": "Remove one channel access grant",
                    "security": bearer,
                    "parameters": channel_access_parameters,
                    "responses": {
                        "200": { "description": "removed" },
                        "404": { "description": "no such owned channel" }
                    }
                }
            },
            "/api/v1/me/credentials": {
                "get": { "summary": "List the account's credentials", "security": bearer,
                    "responses": ok_json }
            },
            "/api/v1/me/credentials/{id}": {
                "delete": { "summary": "Revoke an app password", "security": bearer,
                    "parameters": [{ "name": "id", "in": "path", "required": true,
                        "schema": { "type": "integer" } }],
                    "responses": { "204": { "description": "revoked" },
                        "404": { "description": "no such credential" } } }
            },
            "/api/v1/me/networks": {
                "get": { "summary": "List the account's BNC networks with live upstream status",
                    "description": "Each network includes stored configuration, `connected` (true/false, or null with no running handle), and an owner-safe `runtime` object when its driver is active: lifecycle/timestamps, connect latency, attempts/errors, attached clients, traffic, and in-memory buffer usage.",
                    "security": bearer, "responses": ok_json },
                "post": { "summary": "Create a BNC network and start its driver",
                    "security": bearer,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": { "type": "object",
                            "required": ["name", "addr", "nick"],
                            "properties": {
                                "name": { "type": "string" },
                                "addr": { "type": "string" },
                                "tls": { "type": "boolean" },
                                "nick": { "type": "string" },
                                "realname": { "type": "string" },
                                "autojoin": { "type": "array", "items": { "type": "string" } },
                                "sasl_account": { "type": "string" },
                                "sasl_password": { "type": "string" } } } } } },
                    "responses": { "201": { "description": "created" },
                        "409": { "description": "duplicate name, or upstream secret with no master key" } } }
            },
            "/api/v1/me/networks/{name}": {
                "get": { "summary": "Read one BNC network and its live runtime diagnostics",
                    "security": bearer,
                    "parameters": [{ "name": "name", "in": "path", "required": true,
                        "schema": { "type": "string" } }],
                    "responses": { "200": { "description": "stored configuration and runtime counters; secrets are presence booleans only" },
                        "404": { "description": "no such network" } } },
                "patch": { "summary": "Enable or disable a BNC network (start/stop its driver)",
                    "security": bearer,
                    "parameters": [{ "name": "name", "in": "path", "required": true,
                        "schema": { "type": "string" } }],
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": { "type": "object", "required": ["enabled"],
                            "properties": { "enabled": { "type": "boolean" } } } } } },
                    "responses": { "200": { "description": "new enabled state" },
                        "404": { "description": "no such network" },
                        "409": { "description": "cannot start (stored secret, no master key)" } } },
                "delete": { "summary": "Delete a BNC network and stop its driver",
                    "security": bearer,
                    "parameters": [{ "name": "name", "in": "path", "required": true,
                        "schema": { "type": "string" } }],
                    "responses": { "204": { "description": "deleted" },
                        "404": { "description": "no such network" } } }
            },
            "/api/v1/me/networks/{name}/buffer": {
                "get": { "summary": "Recent buffered upstream lines for a network (oldest-first)",
                    "security": bearer,
                    "parameters": [
                        { "name": "name", "in": "path", "required": true,
                            "schema": { "type": "string" } },
                        { "name": "limit", "in": "query", "required": false,
                            "schema": { "type": "integer", "minimum": 1, "maximum": 1000 } }],
                    "responses": { "200": { "description": "buffered lines" },
                        "400": { "description": "limit outside 1–1000" },
                        "404": { "description": "no such network" } } }
            },
            "/api/v1/history": {
                "get": { "summary": "Paged message history for the account", "security": bearer,
                    "responses": ok_json }
            },
            "/api/v1/admin/accounts": {
                "get": { "summary": "Filter and page administrator-safe account posture (admin only)",
                    "description": "Returns stable account IDs newest-first. before_id selects strictly older accounts, so concurrent registration cannot duplicate or skip rows. The optional name filter is exact under RFC1459 case-folding. Counts omit expired browser sessions and personal access tokens; no credential, token, session, identity-subject, or network-secret material is returned.",
                    "security": bearer,
                    "parameters": account_directory_parameters,
                    "responses": { "200": { "description": "account posture entries and next_before_id cursor" },
                        "400": { "description": "invalid limit, cursor, or exact account filter" },
                        "403": { "description": "not an admin account" } } }
            },
            "/api/v1/admin/connections": {
                "get": {
                    "summary": "Filter and page all live IRC connections (admin only)",
                    "description": "Returns a bounded newest-first projection of registered clients across TCP, TLS, WebSocket, and the local in-process transport. IDs and next_before_id are exact decimal strings so JavaScript clients cannot round them. Nick and account filters use RFC1459 case-folding. before_id selects strictly older connections, so concurrent accepts cannot duplicate into an older page.",
                    "security": bearer,
                    "parameters": admin_connection_parameters,
                    "responses": {
                        "200": { "description": "connection posture entries and next_before_id cursor" },
                        "400": { "description": "invalid limit, cursor, or exact filter" },
                        "403": { "description": "not an admin account" },
                        "503": { "description": "live core unavailable" }
                    }
                }
            },
            "/api/v1/admin/connections/{id}": {
                "delete": {
                    "summary": "Disconnect one exact live IRC connection (admin only)",
                    "description": "Targets the immutable connection resource rather than resolving a mutable nick. The shared core disconnect path emits the terminal ERROR, operator notice, and audit record.",
                    "security": bearer,
                    "parameters": connection_mutation_parameters(),
                    "responses": {
                        "204": { "description": "connection disconnected" },
                        "400": { "description": "invalid ID or reason" },
                        "403": { "description": "not an admin account" },
                        "404": { "description": "stale or missing connection" },
                        "503": { "description": "live core unavailable" }
                    }
                }
            },
            "/api/v1/admin/channels": {
                "get": { "summary": "Filter and page registered-channel policy (admin only)",
                    "description": "Returns stable registration IDs newest-first. before_id selects strictly older rows, so concurrent registration cannot duplicate or skip entries. Optional channel and founder filters are exact under RFC1459 case-folding.",
                    "security": bearer,
                    "parameters": registered_channel_parameters,
                    "responses": { "200": { "description": "registered-channel posture and next_before_id cursor" },
                        "400": { "description": "invalid limit, cursor, channel, or founder filter" },
                        "403": { "description": "not an admin account" } } }
            },
            "/api/v1/admin/bans": {
                "get": { "summary": "Filter and page persisted K/D/X-line policy (admin only)",
                    "description": "Returns stable policy IDs newest-first. before_id selects strictly older rows, so concurrent policy additions cannot duplicate or skip entries. Kind is a closed exact filter; mask matching is exact under RFC1459 case-folding while display casing is preserved.",
                    "security": bearer,
                    "parameters": server_ban_parameters,
                    "responses": { "200": { "description": "server-ban policy and next_before_id cursor" },
                        "400": { "description": "invalid limit, cursor, kind, or mask filter" },
                        "403": { "description": "not an admin account" } } }
            },
            "/api/v1/admin/audit": {
                "get": { "summary": "Filter and page the privileged-action audit log (admin only)",
                    "description": "Returns stable audit entry IDs newest-first. before_id selects strictly older entries, so concurrent appends cannot duplicate or skip rows. Actor, action, and target filters are exact.",
                    "security": bearer,
                    "parameters": audit_parameters,
                    "responses": { "200": { "description": "audit entries and next_before_id cursor" },
                        "400": { "description": "invalid limit, cursor, or exact filter" },
                        "403": { "description": "not an admin account" } } }
            },
            "/api/v1/admin/stats": {
                "get": { "summary": "Aggregate server counts (admin only)",
                    "security": bearer,
                    "responses": { "200": { "description": "counts" },
                        "403": { "description": "not an admin account" } } }
            },
            "/api/v1/admin/observability": {
                "get": { "summary": "Live telemetry and bounded history (admin only)",
                    "security": bearer,
                    "parameters": [{ "name": "minutes", "in": "query",
                        "schema": { "type": "integer", "minimum": 1, "maximum": 10080,
                            "default": 60 } }],
                    "responses": { "200": { "description": "current snapshot and historical samples" },
                        "400": { "description": "history range outside 1–10080 minutes" },
                        "403": { "description": "not an admin account" },
                        "503": { "description": "monitoring storage unavailable" } } }
            },
            "/api/v1/admin/metrics": {
                "get": { "summary": "Prometheus exposition (admin only)",
                    "security": bearer,
                    "responses": { "200": { "description": "Prometheus text exposition" },
                        "403": { "description": "not an admin account" } } }
            }
        }
    });
    (
        [(header::CONTENT_TYPE, "application/json")],
        spec.to_string(),
    )
        .into_response()
}
