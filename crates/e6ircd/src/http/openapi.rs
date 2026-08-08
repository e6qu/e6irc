//! The served OpenAPI description.

use super::*;

/// Build the OpenAPI 3.1 description consumed by generated clients.
fn document() -> serde_json::Value {
    let authenticated = serde_json::json!([
        { "bearer": [] },
        { "browserSession": [] },
        { "secureBrowserSession": [] }
    ]);
    let ok_json = serde_json::json!({
        "200": { "description": "OK", "content": { "application/json": {} } }
    });
    let identity_response = serde_json::json!({
        "200": { "description": "authenticated identity", "content": { "application/json": {
            "schema": { "type": "object", "required": ["account"], "additionalProperties": false,
                "properties": {
                    "account": { "type": "string", "minLength": 1 },
                    "email": { "type": ["string", "null"] },
                    "role": { "type": ["string", "null"] },
                    "provider": { "type": ["string", "null"] },
                    "release_revision": { "type": ["string", "null"] },
                    "csrf_token": { "type": "string" },
                    "logout_url": { "type": "string", "pattern": "^/[^/]" }
                }
            }
        } } }
    });
    let network_summary = serde_json::json!({
        "type": "object", "required": ["name", "enabled", "connected", "runtime"],
        "properties": {
            "name": { "type": "string", "minLength": 1 },
            "enabled": { "type": "boolean" },
            "connected": { "type": ["boolean", "null"] },
            "runtime": { "oneOf": [
                { "type": "null" },
                { "type": "object", "required": ["state"], "additionalProperties": true,
                    "properties": { "state": { "type": "string", "enum": [
                        "connecting", "connected", "reconnecting", "authentication_failed", "registration_failed"
                    ] } } }
            ] }
        }
    });
    let network_list_response = serde_json::json!({
        "200": { "description": "owner-scoped network summaries", "content": { "application/json": {
            "schema": { "type": "object", "required": ["networks"], "additionalProperties": false,
                "properties": { "networks": { "type": "array", "items": network_summary } }
            }
        } } }
    });
    let buffer_response = serde_json::json!({
        "200": { "description": "buffered lines", "content": { "application/json": {
            "schema": { "type": "object", "required": ["lines"], "additionalProperties": false,
                "properties": { "lines": { "type": "array", "items": { "type": "string" } } }
            }
        } } }
    });
    let channel_name_parameter = serde_json::json!([
        { "name": "name", "in": "path", "required": true,
            "schema": { "type": "string" } }
    ]);
    let network_name_parameter = channel_name_parameter.clone();
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
    let confirmation_body = serde_json::json!({
        "required": true,
        "content": { "application/json": {
            "schema": {
                "type": "object",
                "required": ["confirmation"],
                "additionalProperties": false,
                "properties": { "confirmation": { "type": "string", "maxLength": 64 } }
            }
        } }
    });
    serde_json::json!({
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
                    "description": "An expiring personal access token. GET/HEAD operations require read, mutations require write, administrator routes additionally require administrator, and IRC SASL OAUTHBEARER requires irc.",
                },
                "browserSession": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": "e6irc_session",
                    "description": "The development-mode opaque browser session. Unsafe REST methods also require the session-bound value from /api/v1/me in X-E6IRC-CSRF.",
                },
                "secureBrowserSession": {
                    "type": "apiKey",
                    "in": "cookie",
                    "name": "__Host-e6irc_session",
                    "description": "The production Secure, host-bound opaque browser session. Unsafe REST methods also require the session-bound value from /api/v1/me in X-E6IRC-CSRF.",
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
            "/api/v1/openapi.json": {
                "get": {
                    "summary": "This complete OpenAPI 3.1 contract",
                    "responses": {
                        "200": { "description": "method/path set validated against the router" },
                        "500": { "description": "the compiled router and contract disagree" }
                    }
                }
            },
            "/api/v1/auth/app-passwords": {
                "post": {
                    "summary": "Exchange an account password for a new app password",
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": { "type": "object", "additionalProperties": false,
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
                "get": { "summary": "The authenticated account", "security": authenticated,
                    "responses": identity_response }
            },
            "/api/v1/me/profile": {
                "get": {
                    "summary": "Read your private account profile",
                    "security": authenticated,
                    "responses": { "200": { "description": "account and optional contact_email" } }
                },
                "patch": {
                    "summary": "Replace or remove your private contact email",
                    "description": "The address is parsed and bounded before storage. JSON null removes it. The audit event records only replaced/removed, never the address.",
                    "security": authenticated,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": {
                            "type": "object",
                            "required": ["contact_email"],
                            "properties": {
                                "contact_email": {
                                    "type": ["string", "null"],
                                    "maxLength": 254
                                }
                            }
                        }
                    } } },
                    "responses": {
                        "204": { "description": "profile updated" },
                        "400": { "description": "invalid contact email" }
                    }
                }
            },
            "/api/v1/me/account": {
                "delete": {
                    "summary": "Permanently delete your account",
                    "description": "Requires a cookie-authenticated browser session, session-bound CSRF, and the exact display-cased account name. Founded channels must be transferred or dropped first. The account, credentials, sessions, networks, private history, and account-owned buffers are removed atomically and the name is permanently retired.",
                    "security": authenticated,
                    "requestBody": confirmation_body,
                    "responses": {
                        "204": { "description": "account deleted and browser cookie cleared" },
                        "400": { "description": "confirmation does not match" },
                        "401": { "description": "browser session required" },
                        "409": { "description": "account founds channels or is the final effective administrator" },
                        "503": { "description": "database or live runtime unavailable" }
                    }
                }
            },
            "/api/v1/me/export": {
                "get": {
                    "summary": "Download a versioned JSON export of your retained account data",
                    "description": "Includes profile, non-secret credential metadata, identities, browser-session provenance, network configuration without sealed passwords, read markers, founded channels, messages, BNC buffer, and security activity. Secret digests, hashes, bearer values, identity tokens, and sealed upstream passwords are excluded.",
                    "security": authenticated,
                    "responses": {
                        "200": { "description": "attachment containing the account export" },
                        "404": { "description": "account no longer exists" },
                        "503": { "description": "database unavailable" }
                    }
                }
            },
            "/api/v1/me/security-activity": {
                "get": {
                    "summary": "Page your security and administrator activity",
                    "description": "Returns events where the account is the exact RFC1459-folded actor or target. before_id selects strictly older rows.",
                    "security": authenticated,
                    "parameters": admin_cursor_parameters(),
                    "responses": {
                        "200": { "description": "activity entries and next_before_id cursor" },
                        "400": { "description": "invalid limit or cursor" },
                        "503": { "description": "database unavailable" }
                    }
                }
            },
            "/api/v1/me/sessions": {
                "get": {
                    "summary": "List your active browser sessions",
                    "description": "Returns at most 32 owner-scoped stable IDs, creation/expiry times, login method, provider, bounded User-Agent provenance, and whether a row is the request's current cookie session. A new login atomically revokes the oldest active row at the cap. Session tokens and hashes are never returned.",
                    "security": authenticated,
                    "responses": {
                        "200": { "description": "unexpired browser sessions, current first" },
                        "503": { "description": "database unavailable" }
                    }
                },
                "delete": {
                    "summary": "Revoke every other active browser session",
                    "description": "Requires the explicit `except=current` selector and a cookie-authenticated browser session. The database deletion is atomic, preserves the authorizing session, and returns the number revoked.",
                    "security": authenticated,
                    "parameters": [{ "name": "except", "in": "query", "required": true,
                        "schema": { "type": "string", "enum": ["current"] } }],
                    "responses": {
                        "200": { "description": "other browser sessions revoked" },
                        "400": { "description": "missing or invalid selector" },
                        "401": { "description": "browser cookie session required" },
                        "503": { "description": "database unavailable" }
                    }
                }
            },
            "/api/v1/me/sessions/{id}": {
                "delete": {
                    "summary": "Revoke one of your browser sessions",
                    "description": "The session ID is scoped to the authenticated account in the deletion query. Revoking the current cookie session also clears its browser cookie.",
                    "security": authenticated,
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
                    "security": authenticated,
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
                    "security": authenticated,
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
                    "security": authenticated,
                    "parameters": [{ "name": "provider", "in": "path", "required": true,
                        "schema": { "type": "string" } }],
                    "responses": { "307": { "description": "redirect into the provider" },
                        "404": { "description": "unknown provider" },
                        "409": { "description": "identity already linked to another account (on return)" } } }
            },
            "/api/v1/me/identities": {
                "get": { "summary": "List OIDC identities linked to your account and available link providers",
                    "security": authenticated, "responses": ok_json }
            },
            "/api/v1/me/identities/{id}": {
                "delete": {
                    "summary": "Unlink one of your OIDC identities and revoke its browser sessions",
                    "security": authenticated,
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
                "post": {
                    "summary": "Approve a device grant from a browser session",
                    "description": "Requires the cookie-authenticated session and its X-E6IRC-CSRF header. Personal access tokens cannot mint a replacement bearer through device approval.",
                    "responses": { "204": { "description": "approved" },
                        "401": { "description": "browser session required" },
                        "403": { "description": "invalid or missing CSRF token" },
                        "404": { "description": "no such pending code" } } }
            },
            "/api/v1/me/tokens": {
                "get": {
                    "summary": "List your expiring scoped personal access tokens (never the token)",
                    "description": "Returns the stable identifier, label, creation and expiry timestamps, and the closed scope set. Token material and hashes are never returned.",
                    "security": authenticated, "responses": ok_json },
                "post": {
                    "summary": "Mint an expiring scoped personal access token (shown once)",
                    "description": "Requires a browser session and its X-E6IRC-CSRF header. Existing bearer tokens cannot expand their own grant.",
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": {
                            "type": "object",
                            "required": ["label"],
                            "properties": {
                                "label": { "type": "string", "minLength": 1, "maxLength": 64 },
                                "scopes": {
                                    "type": "array", "minItems": 1, "maxItems": 4,
                                    "uniqueItems": true,
                                    "items": { "type": "string",
                                        "enum": ["read", "write", "administrator", "irc"] },
                                    "default": ["read", "write", "irc"]
                                },
                                "expires_in_days": {
                                    "type": "integer", "minimum": 1, "maximum": 365,
                                    "default": 30
                                }
                            }
                        }
                    } } },
                    "responses": {
                        "201": { "description": "token material, exact scopes, and bounded lifetime" },
                        "400": { "description": "invalid label, empty/unknown scopes, or lifetime" },
                        "403": { "description": "the issuing bearer lacks write scope" },
                        "409": { "description": "the account token cap is reached" }
                    }
                }
            },
            "/api/v1/me/tokens/{id}": {
                "delete": { "summary": "Revoke one of your personal access tokens",
                    "security": authenticated,
                    "responses": { "204": { "description": "revoked" },
                        "404": { "description": "no such token" } } }
            },
            "/api/v1/me/read-markers": {
                "get": { "summary": "List your read markers (draft/read-marker) per target",
                    "security": authenticated, "responses": ok_json }
            },
            "/api/v1/me/password": {
                "put": {
                    "summary": "Change your primary local-account password",
                    "description": "Creates a first primary password for an OIDC-only account when current_password is omitted. Existing primary passwords require their current value; an app password cannot authorize rotation.",
                    "security": authenticated,
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
                    "security": authenticated,
                    "responses": {
                        "200": { "description": "channels, retained topics, KEEPTOPIC, MLOCK, and access grants" },
                        "503": { "description": "database unavailable" }
                    }
                },
                "post": {
                    "summary": "Register a live channel currently operated by your account",
                    "description": "An identified live session for the authenticated account must be a channel operator. The current topic, founder row, and audit record are stored before the live ownership map changes.",
                    "security": authenticated,
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
                    "security": authenticated,
                    "parameters": channel_name_parameter,
                    "responses": {
                        "200": { "description": "durable channel configuration" },
                        "404": { "description": "no such channel owned by this account" }
                    }
                },
                "patch": {
                    "summary": "Change a retained topic, KEEPTOPIC, MLOCK, or founder",
                    "description": "The body is a tagged operation: set_topic, set_keeptopic, set_mlock, or transfer_founder. Exactly one storage-confirmed mutation is applied.",
                    "security": authenticated,
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
                    "security": authenticated,
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
                    "security": authenticated,
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
                    "security": authenticated,
                    "parameters": channel_access_parameters,
                    "responses": {
                        "200": { "description": "removed" },
                        "404": { "description": "no such owned channel" }
                    }
                }
            },
            "/api/v1/me/credentials": {
                "get": { "summary": "List the account's credentials", "security": authenticated,
                    "responses": ok_json },
                "post": {
                    "summary": "Mint an app password for the current browser-session account",
                    "description": "Requires a cookie-authenticated browser session and session-bound CSRF. Bearer tokens cannot mint credentials.",
                    "security": authenticated,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": { "type": "object", "required": ["label"], "additionalProperties": false,
                            "properties": { "label": { "type": "string", "minLength": 1, "maxLength": 64 } } }
                    } } },
                    "responses": {
                        "201": { "description": "the app password, shown once" },
                        "400": { "description": "invalid label" },
                        "401": { "description": "browser session required" },
                        "403": { "description": "invalid or missing CSRF token" },
                        "409": { "description": "credential cap reached" },
                        "503": { "description": "database unavailable" }
                    }
                }
            },
            "/api/v1/me/credentials/{id}": {
                "delete": { "summary": "Revoke an app password", "security": authenticated,
                    "parameters": [{ "name": "id", "in": "path", "required": true,
                        "schema": { "type": "integer" } }],
                    "responses": { "204": { "description": "revoked" },
                        "404": { "description": "no such credential" } } }
            },
            "/api/v1/me/networks": {
                "get": { "summary": "List the account's BNC networks with live upstream status",
                    "description": "Each network includes stored configuration, `connected` (true/false, or null with no running handle), and an owner-safe `runtime` object when its driver is active: lifecycle/timestamps, a credential-safe last-error code and summary, connect latency, attempts/errors, attached clients, traffic, and in-memory buffer usage.",
                    "security": authenticated, "responses": network_list_response },
                "post": { "summary": "Create a BNC network and start its driver",
                    "description": "kind defaults to `irc`. IRC requires addr/nick and optional paired SASL credentials. Matrix requires an HTTP(S) homeserver in addr, a provider user in nick, tls=true, and sasl_password. Discord requires tls=true, empty nick, a bot token in sasl_password, and an optional HTTP(S) API base in addr. Slack requires tls=true, empty nick, a bot token in sasl_account, an app token in sasl_password, and an optional HTTP(S) API base in addr. realname is IRC-only.",
                    "security": authenticated,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": { "type": "object", "additionalProperties": false,
                            "required": ["name", "addr", "nick"],
                            "properties": {
                                "kind": { "type": "string", "enum": ["irc", "matrix", "discord", "slack"], "default": "irc" },
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
            "/api/v1/me/networks/preflight": {
                "post": {
                    "summary": "Qualify an IRC upstream without saving it",
                    "description": "Uses the production DNS-vetting, TCP/TLS, capability negotiation, and optional SASL registration path. The connection closes after the welcome and no channels are joined.",
                    "security": authenticated,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": { "type": "object", "additionalProperties": false,
                            "required": ["addr", "nick"],
                            "properties": {
                                "addr": { "type": "string", "minLength": 1, "maxLength": 255 },
                                "tls": { "type": "boolean" },
                                "nick": { "type": "string", "minLength": 1, "maxLength": 64 },
                                "realname": { "type": "string", "maxLength": 128 },
                                "sasl_account": { "type": "string", "minLength": 1, "maxLength": 255, "writeOnly": true },
                                "sasl_password": { "type": "string", "minLength": 1, "maxLength": 512, "writeOnly": true }
                            } } } } },
                    "responses": {
                        "200": {
                            "description": "DNS, transport, and registration timings plus the server-confirmed nickname",
                            "content": { "application/json": { "schema": {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["ok", "resolved_addresses", "dns_ms", "connect_ms", "registration_ms", "confirmed_nick"],
                                "properties": {
                                    "ok": { "const": true },
                                    "resolved_addresses": { "type": "integer", "minimum": 1 },
                                    "dns_ms": { "type": "integer", "format": "int64", "minimum": 0 },
                                    "connect_ms": { "type": "integer", "format": "int64", "minimum": 0 },
                                    "registration_ms": { "type": "integer", "format": "int64", "minimum": 0 },
                                    "confirmed_nick": { "type": "string", "minLength": 1, "maxLength": 64 }
                                }
                            } } }
                        },
                        "400": { "description": "invalid address, identity, or incomplete credentials" },
                        "502": { "description": "typed upstream DNS, transport, TLS, authentication, or registration failure" }
                    }
                }
            },
            "/api/v1/me/networks/{name}": {
                "get": { "summary": "Read one BNC network and its live runtime diagnostics",
                    "security": authenticated,
                    "parameters": network_name_parameter,
                    "responses": { "200": { "description": "stored configuration and runtime counters; secrets are presence booleans only" },
                        "404": { "description": "no such network" } } },
                "put": { "summary": "Replace a BNC network's mutable configuration and restart its driver",
                    "description": "The stored kind selects the same IRC/Matrix/Discord/Slack field contract documented on create. The credential action is required and explicit: `keep` preserves write-only values; `remove` clears paired IRC SASL and is rejected for bridges; `set` replaces supplied values. IRC requires account and may omit password to preserve it. Matrix/Discord accept only password. Slack accepts account, password, or both and preserves an omitted token.",
                    "security": authenticated,
                    "parameters": network_name_parameter,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": { "type": "object", "additionalProperties": false,
                            "required": ["addr", "tls", "nick", "credentials"],
                            "properties": {
                                "addr": { "type": "string" },
                                "tls": { "type": "boolean" },
                                "nick": { "type": "string" },
                                "realname": { "type": "string" },
                                "autojoin": { "type": "array", "items": { "type": "string" } },
                                "credentials": {
                                    "oneOf": [
                                        { "type": "object", "additionalProperties": false,
                                            "required": ["action"],
                                            "properties": { "action": { "const": "keep" } } },
                                        { "type": "object", "additionalProperties": false,
                                            "required": ["action"],
                                            "properties": { "action": { "const": "remove" } } },
                                        { "type": "object", "additionalProperties": false,
                                            "required": ["action"],
                                            "properties": {
                                                "action": { "const": "set" },
                                                "account": { "type": "string" },
                                                "password": { "type": "string" }
                                            } }
                                    ]
                                }
                            } } } } },
                    "responses": { "204": { "description": "updated and live driver replaced" },
                        "400": { "description": "invalid kind-specific configuration or credential action" },
                        "404": { "description": "no such network" },
                        "409": { "description": "cannot seal credentials or start replacement driver" } } },
                "patch": { "summary": "Enable or disable a BNC network (start/stop its driver)",
                    "security": authenticated,
                    "parameters": network_name_parameter,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": { "type": "object", "additionalProperties": false, "required": ["enabled"],
                            "properties": { "enabled": { "type": "boolean" } } } } } },
                    "responses": { "200": { "description": "new enabled state" },
                        "404": { "description": "no such network" },
                        "409": { "description": "cannot start (stored secret, no master key)" } } },
                "delete": { "summary": "Delete a BNC network and stop its driver",
                    "security": authenticated,
                    "parameters": network_name_parameter,
                    "responses": { "204": { "description": "deleted" },
                        "404": { "description": "no such network" } } }
            },
            "/api/v1/me/networks/{name}/buffer": {
                "get": { "summary": "Recent buffered upstream lines for a network (oldest-first)",
                    "security": authenticated,
                    "parameters": [
                        { "name": "name", "in": "path", "required": true,
                            "schema": { "type": "string" } },
                        { "name": "limit", "in": "query", "required": false,
                            "schema": { "type": "integer", "minimum": 1, "maximum": 1000 } }],
                    "responses": { "200": buffer_response["200"],
                        "400": { "description": "limit outside 1–1000" },
                        "404": { "description": "no such network" } } }
            },
            "/api/v1/history": {
                "get": { "summary": "Paged message history for the account", "security": authenticated,
                    "responses": ok_json }
            },
            "/api/v1/admin/accounts": {
                "get": { "summary": "Filter and page administrator-safe account posture (admin only)",
                    "description": "Returns stable account IDs newest-first. before_id selects strictly older accounts, so concurrent registration cannot duplicate or skip rows. The optional name filter is exact under RFC1459 case-folding. Counts omit expired browser sessions and personal access tokens; no credential, token, session, identity-subject, or network-secret material is returned.",
                    "security": authenticated,
                    "parameters": account_directory_parameters,
                    "responses": { "200": { "description": "account posture entries and next_before_id cursor" },
                        "400": { "description": "invalid limit, cursor, or exact account filter" },
                        "403": { "description": "not an admin account" } } },
                "post": {
                    "summary": "Create a local account immediately (admin only)",
                    "security": authenticated,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": {
                            "type": "object",
                            "required": ["account", "password"],
                            "additionalProperties": false,
                            "properties": {
                                "account": { "type": "string", "maxLength": 64 },
                                "password": { "type": "string", "maxLength": 512 },
                                "contact_email": { "type": ["string", "null"], "maxLength": 254 },
                                "administrator": { "type": "boolean", "default": false }
                            }
                        }
                    } } },
                    "responses": {
                        "201": { "description": "account created" },
                        "400": { "description": "invalid account, password, or contact email" },
                        "409": { "description": "account name exists or is retired" },
                        "503": { "description": "database unavailable" }
                    }
                }
            },
            "/api/v1/me/networks/{name}/operations": {
                "get": { "summary": "Read bounded network Operations data",
                    "description": "Returns the owner-scoped, render-ready Operations projection: live lifecycle and traffic, bounded failure history, persisted backlog summary, and the newest 100 detached upstream lines. Secret material is never returned.",
                    "security": authenticated,
                    "parameters": network_name_parameter,
                    "responses": { "200": { "description": "network Operations projection" },
                        "404": { "description": "no such network" },
                        "503": { "description": "database unavailable" } } }
            },
            "/api/v1/admin/accounts/{id}": {
                "patch": {
                    "summary": "Change account suspension or durable administrator authority (admin only)",
                    "description": "Exactly one desired state is accepted per request. Suspension commits credential revocation and an audit record before the live core and owned-network registry are reconciled. Self-suspension, self-demotion, and removing or suspending the last active effective durable-or-configured administrator are rejected.",
                    "security": authenticated,
                    "parameters": [{
                        "name": "id",
                        "in": "path",
                        "required": true,
                        "schema": { "type": "integer", "minimum": 1 }
                    }],
                    "requestBody": {
                        "required": true,
                        "content": {
                            "application/json": {
                                "schema": {
                                    "type": "object",
                                    "properties": {
                                        "suspended": { "type": "boolean" },
                                        "administrator": { "type": "boolean" }
                                    },
                                    "additionalProperties": false,
                                    "oneOf": [
                                        { "required": ["suspended"] },
                                        { "required": ["administrator"] }
                                    ]
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": { "description": "account state and live runtime reconciled" },
                        "400": { "description": "invalid account ID or request body" },
                        "403": { "description": "not an admin account" },
                        "404": { "description": "no such account" },
                        "409": { "description": "self-targeting, last administrator, or invalid owned-network configuration" },
                        "503": { "description": "database or live runtime unavailable" }
                    }
                },
                "delete": {
                    "summary": "Permanently delete an account (admin only)",
                    "description": "Requires the exact display-cased account name. Self-deletion must use the self-service route. Founded channels must be transferred or dropped first; the final active effective durable-or-configured administrator is protected. Successful deletion revokes live access, purges account-owned data, stops networks, and retires the name.",
                    "security": authenticated,
                    "parameters": [{
                        "name": "id", "in": "path", "required": true,
                        "schema": { "type": "integer", "minimum": 1 }
                    }],
                    "requestBody": confirmation_body,
                    "responses": {
                        "200": { "description": "account deleted and live resources stopped" },
                        "400": { "description": "confirmation does not match" },
                        "404": { "description": "no such account" },
                        "409": { "description": "self target, founded channels, or final effective administrator" },
                        "503": { "description": "database or live runtime unavailable" }
                    }
                }
            },
            "/api/v1/admin/invitations": {
                "get": {
                    "summary": "List live account invitations without bearer values (admin only)",
                    "security": authenticated,
                    "parameters": admin_cursor_parameters(),
                    "responses": {
                        "200": { "description": "pending, unexpired invitation metadata and next_before_id cursor" },
                        "400": { "description": "invalid limit or cursor" },
                        "403": { "description": "not an admin account" }
                    }
                },
                "post": {
                    "summary": "Issue a single-use account invitation (admin only)",
                    "description": "Returns the bearer invitation link once. Only its SHA-256 digest is stored.",
                    "security": authenticated,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": {
                            "type": "object",
                            "required": ["account", "expires_in_days"],
                            "additionalProperties": false,
                            "properties": {
                                "account": { "type": "string", "maxLength": 64 },
                                "contact_email": { "type": ["string", "null"], "maxLength": 254 },
                                "expires_in_days": { "type": "integer", "minimum": 1, "maximum": 30 },
                                "administrator": { "type": "boolean", "default": false }
                            }
                        }
                    } } },
                    "responses": {
                        "201": { "description": "invitation link shown once" },
                        "400": { "description": "invalid account, email, or lifetime" },
                        "409": { "description": "name unavailable or administrator invitation cap reached" },
                        "503": { "description": "database unavailable" }
                    }
                }
            },
            "/api/v1/admin/invitations/{id}": {
                "delete": {
                    "summary": "Revoke one pending account invitation (admin only)",
                    "security": authenticated,
                    "parameters": [{
                        "name": "id", "in": "path", "required": true,
                        "schema": { "type": "integer", "minimum": 1 }
                    }],
                    "responses": {
                        "204": { "description": "invitation revoked" },
                        "404": { "description": "invitation is absent, expired, consumed, or already revoked" },
                        "503": { "description": "database unavailable" }
                    }
                }
            },
            "/api/v1/admin/connections": {
                "get": {
                    "summary": "Filter and page all live IRC connections (admin only)",
                    "description": "Returns a bounded newest-first projection of registered clients across TCP, TLS, WebSocket, and the local in-process transport. IDs and next_before_id are exact decimal strings so JavaScript clients cannot round them. Nick and account filters use RFC1459 case-folding. before_id selects strictly older connections, so concurrent accepts cannot duplicate into an older page.",
                    "security": authenticated,
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
                    "security": authenticated,
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
                    "security": authenticated,
                    "parameters": registered_channel_parameters,
                    "responses": { "200": { "description": "registered-channel posture and next_before_id cursor" },
                        "400": { "description": "invalid limit, cursor, channel, or founder filter" },
                        "403": { "description": "not an admin account" } } }
            },
            "/api/v1/admin/channels/{name}": {
                "delete": {
                    "summary": "Unregister one registered channel (admin only)",
                    "description": "Uses the same ordered core control path as ChanServ DROP. The canonical channel name is validated before its durable registration and live state are removed, and the action is audited.",
                    "security": authenticated,
                    "parameters": [{ "name": "name", "in": "path", "required": true,
                        "schema": { "type": "string" } }],
                    "responses": {
                        "204": { "description": "channel unregistered" },
                        "400": { "description": "invalid channel name" },
                        "403": { "description": "not an admin account" },
                        "404": { "description": "channel is not registered" },
                        "503": { "description": "channel control unavailable" }
                    }
                }
            },
            "/api/v1/admin/bans": {
                "get": { "summary": "Filter and page persisted K/D/X-line policy (admin only)",
                    "description": "Returns stable policy IDs newest-first. before_id selects strictly older rows, so concurrent policy additions cannot duplicate or skip entries. Kind is a closed exact filter; mask matching is exact under RFC1459 case-folding while display casing is preserved.",
                    "security": authenticated,
                    "parameters": server_ban_parameters,
                    "responses": { "200": { "description": "server-ban policy and next_before_id cursor" },
                        "400": { "description": "invalid limit, cursor, kind, or mask filter" },
                        "403": { "description": "not an admin account" } } }
                ,"post": { "summary": "Create or refresh a K/D/X-line policy (admin only)",
                    "description": "Uses the core-owned oper policy path, so persistence, immediate enforcement, matching-session disconnects, and audit provenance commit together.",
                    "security": authenticated,
                    "requestBody": { "required": true, "content": { "application/json": { "schema": {
                        "type": "object", "required": ["kind", "mask"],
                        "properties": { "kind": { "type": "string", "enum": ["kline", "dline", "xline"] }, "mask": { "type": "string" }, "reason": { "type": "string" } }
                    } } } },
                    "responses": { "201": { "description": "server ban created" }, "400": { "description": "invalid kind or mask" }, "403": { "description": "not an admin account" }, "409": { "description": "conflicting policy mutation" }, "503": { "description": "server-ban control unavailable" } } }
            },
            "/api/v1/admin/bans/{id}": {
                "delete": { "summary": "Delete one immutable server-ban resource (admin only)",
                    "description": "Resolves the stable directory ID before submitting the matching policy removal through the core. A stale ID cannot delete a recreated visible mask.",
                    "security": authenticated,
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "integer", "format": "int64" } }],
                    "responses": { "204": { "description": "server ban removed" }, "400": { "description": "invalid ID" }, "403": { "description": "not an admin account" }, "404": { "description": "server ban no longer exists" }, "409": { "description": "conflicting policy mutation" }, "503": { "description": "server-ban control unavailable" } } }
            },
            "/api/v1/admin/audit": {
                "get": { "summary": "Filter and page the privileged-action audit log (admin only)",
                    "description": "Returns stable audit entry IDs newest-first. before_id selects strictly older entries, so concurrent appends cannot duplicate or skip rows. Actor, action, and target filters are exact.",
                    "security": authenticated,
                    "parameters": audit_parameters,
                    "responses": { "200": { "description": "audit entries and next_before_id cursor" },
                        "400": { "description": "invalid limit, cursor, or exact filter" },
                        "403": { "description": "not an admin account" } } }
            },
            "/api/v1/admin/stats": {
                "get": { "summary": "Aggregate server counts and live totals (admin only)",
                    "security": authenticated,
                    "responses": { "200": { "description": "counts, server identity, and live totals" },
                        "403": { "description": "not an admin account" } } }
            },
            "/api/v1/admin/configuration": {
                "get": { "summary": "Read revisioned managed configuration (admin only)",
                    "description": "Returns the compare-and-swap revision, redacted operational settings, and the configuration console's secret-free runtime/bootstrap status. OIDC client secrets, oper passwords, upstream SASL passwords, and secret bridge accounts are never returned.",
                    "security": authenticated,
                    "responses": { "200": { "description": "redacted settings, revision, and runtime/bootstrap status" }, "403": { "description": "not an admin account" }, "503": { "description": "managed configuration unavailable" } } },
                "patch": { "summary": "Update revisioned scalar managed configuration", "description": "Updates typed scalar settings while retaining OIDC, operator, and network credential collections from the current revision. A live BNC listener change is applied before persistence and rolled back if persistence fails.", "security": authenticated,
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["revision", "settings"], "properties": { "revision": { "type": "integer" }, "settings": { "type": "object", "description": "Scalar managed settings; credential collections are not accepted here." } } } } } },
                    "responses": { "200": { "description": "configuration revision advanced and restart_required indicator" }, "400": { "description": "invalid settings or BNC listener" }, "403": { "description": "not an admin account" }, "409": { "description": "stale revision" }, "503": { "description": "configuration or BNC listener unavailable" } } }
            },
            "/api/v1/admin/configuration/opers": {
                "post": { "summary": "Add an IRC operator to managed configuration", "security": authenticated,
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["revision", "name", "password"], "properties": { "revision": { "type": "integer" }, "name": { "type": "string" }, "password": { "type": "string", "writeOnly": true } } } } } },
                    "responses": { "200": { "description": "configuration revision advanced" }, "400": { "description": "invalid operator" }, "403": { "description": "not an admin account" }, "409": { "description": "stale revision or master key unavailable" }, "503": { "description": "configuration unavailable" } } }
            },
            "/api/v1/admin/configuration/opers/{name}": {
                "delete": { "summary": "Remove an IRC operator from managed configuration", "security": authenticated,
                    "parameters": [{ "name": "name", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["revision"], "properties": { "revision": { "type": "integer" } } } } } },
                    "responses": { "200": { "description": "configuration revision advanced" }, "400": { "description": "invalid operator" }, "403": { "description": "not an admin account" }, "409": { "description": "stale revision" }, "503": { "description": "configuration unavailable" } } }
            },
            "/api/v1/admin/configuration/oidc-providers": {
                "post": { "summary": "Add an OIDC provider to managed configuration", "security": authenticated,
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["revision", "name", "issuer_url", "client_id", "client_secret", "token_endpoint_auth_method"], "properties": { "revision": { "type": "integer" }, "name": { "type": "string" }, "issuer_url": { "type": "string" }, "client_id": { "type": "string" }, "client_secret": { "type": "string", "writeOnly": true }, "scopes": { "type": "array", "items": { "type": "string" } }, "allowed_email_domains": { "type": "array", "items": { "type": "string" } }, "end_session_endpoint": { "type": "string" }, "token_endpoint_auth_method": { "type": "string", "enum": ["client_secret_basic", "client_secret_post"] } } } } } },
                    "responses": { "200": { "description": "configuration revision advanced" }, "400": { "description": "invalid provider" }, "403": { "description": "not an admin account" }, "409": { "description": "stale revision or master key unavailable" }, "503": { "description": "configuration unavailable" } } }
            },
            "/api/v1/admin/configuration/oidc-providers/{name}": {
                "delete": { "summary": "Remove an OIDC provider from managed configuration", "security": authenticated,
                    "parameters": [{ "name": "name", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["revision"], "properties": { "revision": { "type": "integer" } } } } } },
                    "responses": { "200": { "description": "configuration revision advanced" }, "400": { "description": "invalid provider" }, "403": { "description": "not an admin account" }, "409": { "description": "stale revision" }, "503": { "description": "configuration unavailable" } } }
            },
            "/api/v1/admin/configuration/networks": {
                "post": { "summary": "Add a managed server network", "security": authenticated,
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["revision", "name", "kind", "tls", "buffer_cap"], "properties": { "revision": { "type": "integer" }, "name": { "type": "string" }, "owner": { "type": "string" }, "kind": { "type": "string", "enum": ["irc", "local", "matrix", "discord", "slack"] }, "addr": { "type": "string" }, "tls": { "type": "boolean" }, "nick": { "type": "string" }, "realname": { "type": "string" }, "autojoin": { "type": "array", "items": { "type": "string" } }, "buffer_cap": { "type": "integer", "minimum": 1 }, "sasl_account": { "type": "string", "writeOnly": true }, "sasl_password": { "type": "string", "writeOnly": true } } } } } },
                    "responses": { "200": { "description": "configuration revision advanced" }, "400": { "description": "invalid network" }, "403": { "description": "not an admin account" }, "409": { "description": "stale revision or master key unavailable" }, "503": { "description": "configuration unavailable" } } }
            },
            "/api/v1/admin/configuration/networks/{name}": {
                "delete": { "summary": "Remove a managed server network", "security": authenticated,
                    "parameters": [{ "name": "name", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["revision"], "properties": { "revision": { "type": "integer" }, "owner": { "type": "string" } } } } } },
                    "responses": { "200": { "description": "configuration revision advanced" }, "400": { "description": "invalid network" }, "403": { "description": "not an admin account" }, "409": { "description": "stale revision" }, "503": { "description": "configuration unavailable" } } }
            },
            "/api/v1/admin/networks": {
                "get": { "summary": "Fleet-wide BNC network inventory (admin only)",
                    "description": "Every account's networks with stored configuration (credentials as presence booleans only) and live driver runtime state, ordered by owner and network name.",
                    "security": authenticated,
                    "responses": { "200": { "description": "networks with runtime snapshots" },
                        "403": { "description": "not an admin account" } } }
            },
            "/api/v1/admin/networks/{owner}/{name}": {
                "patch": { "summary": "Change one owner's network lifecycle (admin only)",
                    "description": "Persists the enabled state and starts or stops the same always-on driver as the owner API. The administrator is retained as the audit actor.",
                    "security": authenticated,
                    "parameters": [{ "name": "owner", "in": "path", "required": true, "schema": { "type": "string" } }, { "name": "name", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "required": ["enabled"], "properties": { "enabled": { "type": "boolean" } } } } } },
                    "responses": { "200": { "description": "network lifecycle updated" }, "403": { "description": "not an admin account" }, "404": { "description": "network or bouncer missing" }, "503": { "description": "database unavailable" } } }
            },
            "/api/v1/admin/observability": {
                "get": { "summary": "Live telemetry and bounded history (admin only)",
                    "security": authenticated,
                    "parameters": [{ "name": "minutes", "in": "query",
                        "schema": { "type": "integer", "minimum": 1, "maximum": 10080,
                            "default": 60 } }],
                    "responses": { "200": { "description": "current snapshot and historical samples" },
                        "400": { "description": "history range outside 1–10080 minutes" },
                        "403": { "description": "not an admin account" },
                        "503": { "description": "monitoring storage unavailable" } } }
            },
            "/api/v1/admin/monitoring": {
                "get": { "summary": "Render-ready monitoring projection (admin only)",
                    "description": "Returns the bounded administrator monitoring view used by API clients, including current health, historical charts, queue state, latency, and the fixed error ledger.",
                    "security": authenticated,
                    "parameters": [{ "name": "minutes", "in": "query", "schema": { "type": "integer", "enum": [60, 360, 1440, 10080], "default": 60 } }],
                    "responses": { "200": { "description": "monitoring view" }, "400": { "description": "unsupported monitoring window" }, "403": { "description": "not an admin account" } }
                }
            },
            "/api/v1/admin/metrics": {
                "get": { "summary": "Prometheus exposition (admin only)",
                    "security": authenticated,
                    "responses": { "200": { "description": "Prometheus text exposition" },
                        "403": { "description": "not an admin account" } } }
            }
        }
    })
}

/// The route macro in `http::mod` is the source of truth for method/path
/// existence; the OpenAPI document owns schemas and response semantics. Compare
/// both complete sets so drift is a loud server error and a unit-test failure,
/// not a representative-path assertion that can miss a newly added endpoint.
fn validate_documented_operations(spec: &serde_json::Value) -> Result<(), String> {
    let paths = spec
        .get("paths")
        .and_then(serde_json::Value::as_object)
        .ok_or_else(|| "OpenAPI paths is not an object".to_string())?;
    let methods = ["get", "post", "put", "patch", "delete"];
    let actual: std::collections::BTreeSet<(&str, &str)> = paths
        .iter()
        .flat_map(|(path, item)| {
            methods
                .into_iter()
                .filter(move |method| item.get(*method).is_some())
                .map(move |method| (path.as_str(), method))
        })
        .collect();
    let expected: std::collections::BTreeSet<(&str, &str)> =
        super::DOCUMENTED_ROUTE_OPERATIONS.iter().copied().collect();
    if actual == expected {
        return Ok(());
    }
    let missing: Vec<String> = expected
        .difference(&actual)
        .map(|(path, method)| format!("{} {}", method.to_ascii_uppercase(), path))
        .collect();
    let extra: Vec<String> = actual
        .difference(&expected)
        .map(|(path, method)| format!("{} {}", method.to_ascii_uppercase(), path))
        .collect();
    Err(format!(
        "OpenAPI/router operation mismatch; missing from spec: [{}]; absent from router: [{}]",
        missing.join(", "),
        extra.join(", ")
    ))
}

/// Serve the validated contract. A drifted build does not hand automation a
/// plausible but incomplete schema.
pub(super) async fn openapi() -> Response {
    let spec = document();
    if let Err(error) = validate_documented_operations(&spec) {
        eprintln!("http: {error}");
        return problem(
            StatusCode::INTERNAL_SERVER_ERROR,
            "OpenAPI contract is inconsistent",
            Some(&error),
        );
    }
    (
        [(header::CONTENT_TYPE, "application/json")],
        spec.to_string(),
    )
        .into_response()
}

#[cfg(test)]
mod tests {
    #[test]
    fn openapi_covers_every_documented_router_operation_exactly() {
        let spec = super::document();
        assert_eq!(super::validate_documented_operations(&spec), Ok(()));
    }
}
