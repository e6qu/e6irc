//! The served OpenAPI description.

use super::*;

/// OpenAPI 3.1 description of the REST surface. Hand-authored and kept in
/// step with the routes above; consumers use it to generate clients.
pub(super) async fn openapi() -> Response {
    let bearer = serde_json::json!([{ "bearer": [] }]);
    let ok_json = serde_json::json!({
        "200": { "description": "OK", "content": { "application/json": {} } }
    });
    let spec = serde_json::json!({
        "openapi": "3.1.0",
        "info": {
            "title": "e6irc REST API",
            "version": env!("CARGO_PKG_VERSION"),
            "description": "Account, credential, and BNC-network management for e6ircd.",
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
                                "account": { "type": "string" },
                                "password": { "type": "string" },
                                "label": { "type": "string" } } } } } },
                    "responses": { "200": { "description": "the app password (shown once)" },
                        "401": { "description": "bad credentials" },
                        "503": { "description": "no database configured" } }
                }
            },
            "/api/v1/me": {
                "get": { "summary": "The authenticated account", "security": bearer,
                    "responses": ok_json }
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
            "/api/v1/me/credentials": {
                "get": { "summary": "List the account's credentials", "security": bearer,
                    "responses": ok_json }
            },
            "/api/v1/me/credentials/{id}": {
                "delete": { "summary": "Revoke a credential", "security": bearer,
                    "parameters": [{ "name": "id", "in": "path", "required": true,
                        "schema": { "type": "integer" } }],
                    "responses": { "204": { "description": "revoked" },
                        "404": { "description": "no such credential" } } }
            },
            "/api/v1/me/networks": {
                "get": { "summary": "List the account's BNC networks with live upstream status",
                    "description": "Each network includes `connected`: true/false when the always-on driver holds a live handle, or null when no handle is live (e.g. not yet started).",
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
                        "404": { "description": "no such network" } } }
            },
            "/api/v1/history": {
                "get": { "summary": "Paged message history for the account", "security": bearer,
                    "responses": ok_json }
            },
            "/api/v1/admin/accounts": {
                "get": { "summary": "List all accounts (admin only)", "security": bearer,
                    "responses": { "200": { "description": "account names" },
                        "403": { "description": "not an admin account" } } }
            },
            "/api/v1/admin/channels": {
                "get": { "summary": "List registered channels + founders (admin only)",
                    "security": bearer,
                    "responses": { "200": { "description": "channels" },
                        "403": { "description": "not an admin account" } } }
            },
            "/api/v1/admin/bans": {
                "get": { "summary": "List server bans — K/D/X-lines with kind (admin only)",
                    "security": bearer,
                    "responses": { "200": { "description": "server bans" },
                        "403": { "description": "not an admin account" } } }
            },
            "/api/v1/admin/audit": {
                "get": { "summary": "Query the oper audit log, newest-first (admin only)",
                    "security": bearer,
                    "parameters": [ { "name": "limit", "in": "query",
                        "schema": { "type": "integer" } } ],
                    "responses": { "200": { "description": "audit entries" },
                        "403": { "description": "not an admin account" } } }
            },
            "/api/v1/admin/stats": {
                "get": { "summary": "Aggregate server counts (admin only)",
                    "security": bearer,
                    "responses": { "200": { "description": "counts" },
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
