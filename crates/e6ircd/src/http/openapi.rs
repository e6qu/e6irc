//! The served OpenAPI description.

use super::*;

/// The responses every authenticated operation can produce before its handler
/// runs, because authentication and admission produce them: no or invalid
/// credential (`401`), a suspended account, denied token scope, or missing
/// CSRF value (`403`), the per-account request budget (`429`), and no database
/// or a failed lookup (`503`). Merged into each such operation under its own
/// route-specific responses, which take precedence when they name the same
/// status.
fn standard_authenticated_responses() -> serde_json::Map<String, serde_json::Value> {
    let mut responses = serde_json::Map::new();
    for (status, description) in [
        (
            "401",
            "not signed in, or the token or session is invalid or expired",
        ),
        (
            "403",
            "the account is suspended, the token lacks the scope this method needs, or a cookie-authenticated unsafe method carried no valid X-E6IRC-CSRF value",
        ),
        (
            "429",
            "the account's request budget is spent; Retry-After gives the seconds to wait",
        ),
        (
            "503",
            "no database configured, or the database is unavailable",
        ),
    ] {
        responses.insert(
            status.to_string(),
            serde_json::json!({ "description": description }),
        );
    }
    responses
}

/// Whether an operation's `security` admits an account credential (a bearer or
/// a browser session) rather than the deployment's monitoring token alone.
fn operation_authenticates_an_account(operation: &serde_json::Value) -> bool {
    operation["security"]
        .as_array()
        .is_some_and(|requirements| {
            requirements.iter().any(|requirement| {
                requirement.as_object().is_some_and(|schemes| {
                    schemes.keys().any(|scheme| scheme != "monitoringBearer")
                })
            })
        })
}

/// Every operation's JSON object in the description, for the passes that
/// complete them.
fn each_operation(spec: &mut serde_json::Value, mut visit: impl FnMut(&mut serde_json::Value)) {
    let Some(paths) = spec["paths"].as_object_mut() else {
        return;
    };
    for item in paths.values_mut() {
        let Some(item) = item.as_object_mut() else {
            continue;
        };
        item.values_mut().for_each(&mut visit);
    }
}

/// Give every account-authenticated operation the shared admission responses
/// it lacks, keeping any it already states.
fn merge_standard_authenticated_responses(spec: &mut serde_json::Value) {
    each_operation(spec, |operation| {
        if !operation_authenticates_an_account(operation) {
            return;
        }
        let Some(responses) = operation["responses"].as_object_mut() else {
            return;
        };
        for (status, response) in standard_authenticated_responses() {
            responses.entry(status).or_insert(response);
        }
    });
}

/// Give every operation with a path parameter the `400` its extractor
/// produces for a value that does not parse (`PathParams`), keeping any `400`
/// the operation already describes.
fn merge_path_parameter_responses(spec: &mut serde_json::Value) {
    each_operation(spec, |operation| {
        let has_path_parameter = operation["parameters"]
            .as_array()
            .is_some_and(|parameters| parameters.iter().any(|parameter| parameter["in"] == "path"));
        let Some(responses) = operation["responses"]
            .as_object_mut()
            .filter(|_| has_path_parameter)
        else {
            return;
        };
        responses.entry("400").or_insert_with(|| {
            serde_json::json!({ "description": "a path parameter does not parse as its schema (a problem document)" })
        });
    });
}

/// What an operation whose handler requires a recent sign-in
/// (`RecentlyAuthenticated`) adds to its `403`.
const REAUTHENTICATION_RESPONSE: &str = "the session has not signed in within the last 10 minutes: problem type urn:e6irc:problem:reauthentication-required; re-authenticate (POST /api/v1/me/reauthenticate) and retry";

/// Whether a documented operation's handler takes `extractor`, read from its
/// signature ([`super::documented_route_arguments`]).
fn operations_extracting<T: 'static>() -> std::collections::BTreeSet<(&'static str, &'static str)> {
    let extractor = std::any::TypeId::of::<T>();
    super::documented_route_arguments()
        .into_iter()
        .filter(|(_, _, arguments)| arguments.contains(&extractor))
        .map(|(path, method, _)| (path, method))
        .collect()
}

/// What an operation whose handler spends the per-address authentication
/// budget (`RateLimited`) answers when it is spent.
const RATE_LIMITED_RESPONSE: &str =
    "this address's authentication budget is spent; Retry-After gives the seconds to wait";

/// The responses the service's own bounds produce, before any handler runs:
/// the request deadline (`408`) and body limit (`413`) for every request, and
/// the per-address in-flight bound (`429`) for every request the admission
/// bounds see — all but the probes.
fn service_wide_responses(admitted: bool) -> serde_json::Map<String, serde_json::Value> {
    let mut responses = serde_json::Map::new();
    responses.insert(
        "408".into(),
        serde_json::json!({ "description": "the request passed the 30-second deadline (a problem document)" }),
    );
    responses.insert(
        "413".into(),
        serde_json::json!({ "description": "the request body is larger than 1 MiB (a problem document)" }),
    );
    if admitted {
        responses.insert(
            "429".into(),
            serde_json::json!({ "description": "this address has 32 requests in flight; Retry-After gives the seconds to wait" }),
        );
    }
    responses
}

/// Whether a documented operation's handler takes `RateLimited`.
fn rate_limited_operations() -> std::collections::BTreeSet<(&'static str, &'static str)> {
    operations_extracting::<RateLimited>()
}

/// The operation `method` on `path`, when the document has it.
fn operation_mut<'a>(
    spec: &'a mut serde_json::Value,
    path: &str,
    method: &str,
) -> Option<&'a mut serde_json::Map<String, serde_json::Value>> {
    spec["paths"]
        .get_mut(path)?
        .get_mut(method)?
        .get_mut("responses")?
        .as_object_mut()
}

/// Give every operation whose handler spends the authentication budget its
/// `429`, and every operation the service's bounds apply to theirs, keeping
/// any the operation already states. Derived from the handlers and the router,
/// so a new rate-limited route cannot be served without saying it can refuse.
fn merge_service_responses(spec: &mut serde_json::Value) {
    for (path, method) in rate_limited_operations() {
        if let Some(responses) = operation_mut(spec, path, method) {
            responses
                .entry("429")
                .or_insert_with(|| serde_json::json!({ "description": RATE_LIMITED_RESPONSE }));
        }
    }
    for (path, method) in operations_extracting::<RecentlyAuthenticated>() {
        if let Some(responses) = operation_mut(spec, path, method) {
            let forbidden = responses
                .entry("403")
                .or_insert_with(|| serde_json::json!({ "description": "" }));
            let described = forbidden["description"].as_str().unwrap_or_default();
            forbidden["description"] = serde_json::Value::String(if described.is_empty() {
                REAUTHENTICATION_RESPONSE.to_string()
            } else {
                format!("{described}; or {REAUTHENTICATION_RESPONSE}")
            });
        }
    }
    for &(path, method) in super::DOCUMENTED_ROUTE_OPERATIONS {
        let admitted = !super::PROBE_PATHS.contains(&path);
        if let Some(responses) = operation_mut(spec, path, method) {
            for (status, response) in service_wide_responses(admitted) {
                responses.entry(status).or_insert(response);
            }
        }
    }
}

fn document() -> serde_json::Value {
    let mut spec = operations();
    merge_standard_authenticated_responses(&mut spec);
    merge_path_parameter_responses(&mut spec);
    merge_service_responses(&mut spec);
    spec
}

fn operations() -> serde_json::Value {
    let authenticated = serde_json::json!([
        { "bearer": [] },
        { "browserSession": [] },
        { "secureBrowserSession": [] }
    ]);
    // Operations about the browser session itself, or that mint or redirect
    // authority over the account: a bearer is refused before the handler
    // exists (`BrowserSession` / `SessionMutation`), so the contract does not
    // advertise one.
    let browser_session_only = serde_json::json!([
        { "browserSession": [] },
        { "secureBrowserSession": [] }
    ]);
    let ok_json = serde_json::json!({
        "200": { "description": "OK", "content": { "application/json": {} } }
    });
    let json_response = |description: &str, schema: serde_json::Value| {
        serde_json::json!({
            "200": { "description": description, "content": {
                "application/json": { "schema": schema }
            } }
        })
    };
    let json_response_status = |status: u16, description: &str, schema: serde_json::Value| {
        serde_json::json!({
            status.to_string(): { "description": description, "content": {
                "application/json": { "schema": schema }
            } }
        })
    };
    let ok_detail_schema = serde_json::json!({
        "type": "object", "additionalProperties": false, "required": ["ok", "detail"],
        "properties": { "ok": { "const": true }, "detail": { "type": "string" } }
    });
    let message_schema = serde_json::json!({
        "type": "object", "additionalProperties": false, "required": ["message"],
        "properties": { "message": { "type": "string" } }
    });
    let history_response = json_response(
        "paged message history",
        serde_json::json!({
            "type": "object", "additionalProperties": false,
            "required": ["target", "messages"],
            "properties": {
                "target": { "type": "string" },
                "messages": { "type": "array", "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["msgid", "time", "from", "kind", "body"],
                    "properties": {
                        "msgid": { "type": "string" }, "time": { "type": "string", "format": "date-time" },
                        "from": { "type": "string" }, "kind": { "type": "string", "enum": ["PRIVMSG", "NOTICE"] },
                        "body": { "type": "string" }
                    }
                }}
            }
        }),
    );
    let app_password_created_response = json_response_status(
        201,
        "the app password, shown once",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["app_password", "label", "note"],
            "properties": { "app_password": { "type": "string", "minLength": 1 }, "label": { "type": "string" }, "note": { "type": "string" } }
        }),
    );
    let authorization_url_response = json_response(
        "the provider URL for the page to navigate to; the sealed flow cookie is set on this answer",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["authorization_url"],
            "properties": { "authorization_url": { "type": "string", "format": "uri" } }
        }),
    );
    let token_created_response = json_response_status(
        201,
        "token material, exact scopes, and bounded lifetime",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["token", "label", "scopes", "expires_in_days", "note"],
            "properties": { "token": { "type": "string", "minLength": 1 }, "label": { "type": "string" }, "scopes": { "type": "array", "minItems": 1, "items": { "type": "string", "enum": ["read", "write", "administrator", "irc"] } }, "expires_in_days": { "type": "integer", "minimum": 1, "maximum": 365 }, "note": { "type": "string" } }
        }),
    );
    let revision_response = json_response(
        "configuration revision advanced",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["revision", "message"],
            "properties": { "revision": { "type": "integer", "minimum": 0 }, "message": { "type": "string" } }
        }),
    );
    let configuration_patch_response = json_response(
        "configuration revision advanced and restart_required indicator",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["revision", "restart_required"],
            "properties": { "revision": { "type": "integer", "minimum": 0 }, "restart_required": { "type": "boolean" } }
        }),
    );
    let network_created_response = json_response_status(
        201,
        "created",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["name", "attach"],
            "properties": { "name": { "type": "string", "minLength": 1 }, "attach": { "type": "string", "minLength": 1 } }
        }),
    );
    let network_enabled_response = json_response(
        "new enabled state",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["name", "enabled"],
            "properties": { "name": { "type": "string", "minLength": 1 }, "enabled": { "type": "boolean" } }
        }),
    );
    let admin_network_enabled_response = json_response(
        "network lifecycle updated",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["owner", "name", "enabled"],
            "properties": { "owner": { "type": "string", "minLength": 1 }, "name": { "type": "string", "minLength": 1 }, "enabled": { "type": "boolean" } }
        }),
    );
    let account_created_response = json_response_status(
        201,
        "account created",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["id", "account", "administrator"],
            "properties": { "id": { "type": "integer", "minimum": 1 }, "account": { "type": "string", "minLength": 1 }, "administrator": { "type": "boolean" } }
        }),
    );
    let account_state_response = json_response(
        "account state and live runtime reconciled",
        serde_json::json!({
            "oneOf": [
                { "type": "object", "additionalProperties": false, "required": ["account_id", "suspended", "message"], "properties": { "account_id": { "type": "integer", "minimum": 1 }, "suspended": { "type": "boolean" }, "message": { "type": "string" } } },
                { "type": "object", "additionalProperties": false, "required": ["account_id", "administrator", "message"], "properties": { "account_id": { "type": "integer", "minimum": 1 }, "administrator": { "type": "boolean" }, "message": { "type": "string" } } }
            ]
        }),
    );
    let invitation_created_response = json_response_status(
        201,
        "invitation link shown once",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["account", "administrator", "expires_in_days", "invitation_url", "note"],
            "properties": { "account": { "type": "string", "minLength": 1 }, "administrator": { "type": "boolean" }, "expires_in_days": { "type": "integer", "minimum": 1, "maximum": 30 }, "invitation_url": { "type": "string", "minLength": 1 }, "note": { "type": "string" } }
        }),
    );
    let revoked_sessions_response = json_response(
        "other browser sessions revoked",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["revoked"],
            "properties": { "revoked": { "type": "integer", "minimum": 0 } }
        }),
    );
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
    // The one description of a server password wherever one is accepted: the
    // create, connection-test, and managed-network requests.
    let server_password_schema = serde_json::json!({
        "type": ["string", "null"], "minLength": 1,
        "maxLength": e6irc_client::ServerPassword::MAX_LEN, "writeOnly": true,
        "description": "The network's connection password, sent as PASS before registration; only for a private server that requires one. Stored sealed; never returned."
    });
    let network_response_schema = serde_json::json!({
        "type": "object", "additionalProperties": false,
        "required": ["name", "kind", "addr", "tls", "nick", "username", "realname", "autojoin", "sasl_account", "has_sasl_account", "has_sasl_password", "has_server_password", "enabled", "connected", "runtime"],
        "properties": {
            "name": { "type": "string", "minLength": 1 },
            "kind": { "type": "string", "enum": ["irc", "local", "matrix", "discord", "slack"] },
            "addr": { "type": "string" }, "tls": { "type": "boolean" }, "nick": { "type": "string" },
            "username": { "type": ["string", "null"], "description": "IRC user name (ident); null for a bridge." },
            "realname": { "type": ["string", "null"] },
            "autojoin": { "type": "array", "items": { "type": "string" } },
            "sasl_account": { "type": ["string", "null"] },
            "has_sasl_account": { "type": "boolean" }, "has_sasl_password": { "type": "boolean" }, "has_server_password": { "type": "boolean" },
            "enabled": { "type": "boolean" }, "connected": { "type": ["boolean", "null"] },
            "runtime": { "oneOf": [
                { "type": "null" },
                { "type": "object", "additionalProperties": false,
                    "required": ["state", "state_changed_at", "next_retry_at", "recent_failures", "connected_at", "last_input_at", "last_output_at", "last_error_at", "last_error", "connect_latency_ms", "connection_attempts", "errors", "attached_clients", "traffic", "buffer"],
                    "properties": {
                        "state": { "type": "string", "enum": ["connecting", "connected", "reconnecting", "authentication_failed", "registration_failed"] },
                        "state_changed_at": { "type": "string" }, "next_retry_at": { "type": ["string", "null"] },
                        "recent_failures": { "type": "array", "maxItems": crate::bouncer::NETWORK_FAILURE_HISTORY_LIMIT, "items": {
                            "type": "object", "additionalProperties": false, "required": ["at", "code", "summary"],
                            "properties": { "at": { "type": "string" }, "code": { "type": "string" }, "summary": { "type": "string" } }
                        } },
                        "connected_at": { "type": ["string", "null"] }, "last_input_at": { "type": ["string", "null"] },
                        "last_output_at": { "type": ["string", "null"] }, "last_error_at": { "type": ["string", "null"] },
                        "last_error": { "oneOf": [
                            { "type": "null" },
                            { "type": "object", "additionalProperties": false, "required": ["code", "summary"],
                                "properties": { "code": { "type": "string" }, "summary": { "type": "string" }, "diagnostic": { "type": "string", "maxLength": 160 } } }
                        ] },
                        "connect_latency_ms": { "type": ["integer", "null"], "minimum": 0 },
                        "connection_attempts": { "type": "integer", "minimum": 0 }, "errors": { "type": "integer", "minimum": 0 },
                        "attached_clients": { "type": "integer", "minimum": 0 },
                        "traffic": { "type": "object", "additionalProperties": false, "required": ["lines_in", "bytes_in", "lines_out", "bytes_out"],
                            "properties": { "lines_in": { "type": "integer", "minimum": 0 }, "bytes_in": { "type": "integer", "minimum": 0 }, "lines_out": { "type": "integer", "minimum": 0 }, "bytes_out": { "type": "integer", "minimum": 0 } } },
                        "buffer": { "type": "object", "additionalProperties": false, "required": ["lines", "capacity"],
                            "properties": { "lines": { "type": "integer", "minimum": 0 }, "capacity": { "type": "integer", "minimum": 1 } } }
                    }
                }
            ] }
        }
    });
    let network_list_response = serde_json::json!({
        "200": { "description": "owner-scoped network summaries", "content": { "application/json": {
            "schema": { "type": "object", "required": ["networks"], "additionalProperties": false,
                "properties": { "networks": { "type": "array", "items": network_response_schema.clone() } }
            }
        } } }
    });
    let mut owned_admin_network_schema = network_response_schema.clone();
    owned_admin_network_schema["properties"]
        .as_object_mut()
        .expect("network response properties are an object")
        .insert(
            "owner".into(),
            serde_json::json!({ "type": "string", "minLength": 1 }),
        );
    owned_admin_network_schema["required"]
        .as_array_mut()
        .expect("network response required fields are an array")
        .push(serde_json::json!("owner"));
    let admin_networks_response = json_response(
        "networks with runtime snapshots",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["networks"],
            "properties": { "networks": { "type": "array", "items": { "oneOf": [
                owned_admin_network_schema,
                { "type": "object", "additionalProperties": false, "required": ["owner", "name", "kind", "enabled", "connected", "runtime", "shared"],
                    "properties": { "owner": { "const": "shared" }, "name": { "type": "string", "minLength": 1 }, "kind": { "type": "string", "enum": ["irc", "local", "matrix", "discord", "slack"] }, "enabled": { "const": true }, "connected": { "type": "boolean" }, "runtime": network_response_schema["properties"]["runtime"].clone(), "shared": { "const": true } } }
            ] } } }
        }),
    );
    let buffer_response = serde_json::json!({
        "200": { "description": "buffered lines", "content": { "application/json": {
            "schema": { "type": "object", "required": ["lines"], "additionalProperties": false,
                "properties": { "lines": { "type": "array", "maxItems": 1000,
                    "items": { "type": "string", "maxLength": e6irc_proto::message::MAX_SERVER_FRAME_LEN } } }
            }
        } } }
    });
    let logs_response = json_response(
        "bounded redacted operational events",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["entries"],
            "properties": { "entries": { "type": "array", "maxItems": 1000, "items": {
                "type": "object", "additionalProperties": false,
                "required": ["at_ms", "component", "severity", "message"],
                "properties": {
                    "at_ms": { "type": "integer", "minimum": 0 },
                    "component": { "type": "string", "enum": ["accept", "connection_setup", "tls_handshake", "read", "write", "send_queue", "database", "bouncer", "http"] },
                    "severity": { "const": "error" },
                    "message": { "const": "An operational error was recorded." }
                }
            } } }
        }),
    );
    let network_response = json_response(
        "stored network configuration and runtime",
        network_response_schema.clone(),
    );
    let network_operations_response = json_response(
        "network runtime and persisted backlog",
        serde_json::json!({
            "type": "object", "additionalProperties": false,
            "required": ["enabled", "runtime", "storage", "recent_lines"],
            "properties": {
                "enabled": { "type": "boolean" },
                "runtime": network_response_schema["properties"]["runtime"].clone(),
                "storage": { "type": "object", "additionalProperties": false,
                    "required": ["lines", "oldest_at", "newest_at"],
                    "properties": {
                        "lines": { "type": "integer", "minimum": 0 },
                        "oldest_at": { "type": ["string", "null"] },
                        "newest_at": { "type": ["string", "null"] }
                    }
                },
                "recent_lines": { "type": "array", "maxItems": 100,
                    "items": { "type": "string", "maxLength": e6irc_proto::message::MAX_SERVER_FRAME_LEN } }
            }
        }),
    );
    let profile_response = json_response(
        "account and optional contact email",
        serde_json::json!({
            "type": "object", "additionalProperties": false,
            "required": ["account", "contact_email"],
            "properties": {
                "account": { "type": "string", "minLength": 1 },
                "contact_email": { "type": ["string", "null"] }
            }
        }),
    );
    let browser_sessions_response = json_response(
        "unexpired browser sessions, current first",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["sessions"],
            "properties": { "sessions": { "type": "array", "items": {
                "type": "object", "additionalProperties": false,
                "required": ["id", "created_at", "expires_at", "method", "provider", "user_agent", "current"],
                "properties": {
                    "id": { "type": "integer", "minimum": 1 },
                    "created_at": { "type": "string" },
                    "expires_at": { "type": "string" },
                    "method": { "type": "string", "enum": ["local", "oidc"] },
                    "provider": { "type": ["string", "null"] },
                    "user_agent": { "type": ["string", "null"] },
                    "current": { "type": "boolean" }
                }
            } } }
        }),
    );
    let connection_page_response = json_response(
        "connection posture entries and next_before_id cursor",
        serde_json::json!({
            "type": "object", "additionalProperties": false,
            "required": ["connections", "next_before_id"],
            "properties": {
                "connections": { "type": "array", "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["id", "nick", "user", "host", "account", "oper", "transport", "connected_at", "idle_seconds", "channels"],
                    "properties": {
                        "id": { "type": "string", "pattern": "^[1-9][0-9]*$" },
                        "nick": { "type": "string" }, "user": { "type": "string" }, "host": { "type": "string" },
                        "account": { "type": ["string", "null"] }, "oper": { "type": "boolean" },
                        "transport": { "type": "string", "enum": ["tcp", "tls", "websocket", "local"] },
                        "connected_at": { "type": "string" }, "idle_seconds": { "type": "integer", "minimum": 0 },
                        "channels": { "type": "array", "items": { "type": "string" } }
                    }
                } },
                "next_before_id": { "type": ["string", "null"], "pattern": "^[1-9][0-9]*$" }
            }
        }),
    );
    let credentials_response = json_response(
        "account credential metadata",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["credentials"],
            "properties": { "credentials": { "type": "array", "items": {
                "type": "object", "additionalProperties": false,
                "required": ["id", "kind", "label", "created_at", "last_used_at"],
                "properties": {
                    "id": { "type": "integer", "minimum": 1 },
                    "kind": { "type": "string", "enum": ["local_password", "app_password"] },
                    "label": { "type": ["string", "null"] },
                    "created_at": { "type": "string" }, "last_used_at": { "type": ["string", "null"] }
                }
            } } }
        }),
    );
    let identities_response = json_response(
        "linked identity and provider metadata",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["identities", "link_providers"],
            "properties": {
                "identities": { "type": "array", "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["id", "issuer", "subject", "created_at"],
                    "properties": {
                        "id": { "type": "integer", "minimum": 1 }, "issuer": { "type": "string" },
                        "subject": { "type": "string" }, "created_at": { "type": "string" }
                    }
                } },
                "link_providers": { "type": "array", "items": { "type": "string" } }
            }
        }),
    );
    let tokens_response = json_response(
        "personal access token metadata",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["tokens"],
            "properties": { "tokens": { "type": "array", "items": {
                "type": "object", "additionalProperties": false,
                "required": ["id", "label", "created_at", "expires_at", "scopes"],
                "properties": {
                    "id": { "type": "integer", "minimum": 1 }, "label": { "type": "string" },
                    "created_at": { "type": "string" }, "expires_at": { "type": "string" },
                    "scopes": { "type": "array", "items": { "type": "string", "enum": ["read", "write", "administrator", "irc"] } }
                }
            } } }
        }),
    );
    let security_activity_response = json_response(
        "security activity entries and next_before_id cursor",
        serde_json::json!({
            "type": "object", "additionalProperties": false,
            "required": ["activity", "next_before_id"],
            "properties": {
                "activity": { "type": "array", "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["id", "actor", "action", "target", "detail", "at"],
                    "properties": {
                        "id": { "type": "integer", "minimum": 1 }, "actor": { "type": "string" },
                        "action": { "type": "string" }, "target": { "type": "string" },
                        "detail": { "type": "string" }, "at": { "type": "string" }
                    }
                } },
                "next_before_id": { "type": ["integer", "null"], "minimum": 1 }
            }
        }),
    );
    let read_markers_response = json_response(
        "read markers",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["markers"],
            "properties": { "markers": { "type": "array", "items": {
                "type": "object", "additionalProperties": false,
                "required": ["target", "timestamp"],
                "properties": { "target": { "type": "string" }, "timestamp": { "type": "string" } }
            } } }
        }),
    );
    let accounts_response = json_response(
        "account posture entries and next_before_id cursor",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["accounts", "next_before_id"],
            "properties": {
                "accounts": { "type": "array", "items": { "type": "object", "additionalProperties": false,
                    "required": ["id", "name", "created_at", "authentication", "resources", "administrator", "administrator_sources", "suspended", "current"],
                    "properties": {
                        "id": { "type": "integer", "minimum": 1 }, "name": { "type": "string" }, "created_at": { "type": "string" },
                        "authentication": { "type": "object", "additionalProperties": false, "required": ["local_password", "app_passwords", "api_tokens", "oidc_identities", "browser_sessions"],
                            "properties": { "local_password": { "type": "boolean" }, "app_passwords": { "type": "integer", "minimum": 0 }, "api_tokens": { "type": "integer", "minimum": 0 }, "oidc_identities": { "type": "integer", "minimum": 0 }, "browser_sessions": { "type": "integer", "minimum": 0 } } },
                        "resources": { "type": "object", "additionalProperties": false, "required": ["networks", "founded_channels"], "properties": { "networks": { "type": "integer", "minimum": 0 }, "founded_channels": { "type": "integer", "minimum": 0 } } },
                        "administrator": { "type": "boolean" }, "administrator_sources": { "type": "object", "additionalProperties": false, "required": ["durable", "configuration"], "properties": { "durable": { "type": "boolean" }, "configuration": { "type": "boolean" } } },
                        "suspended": { "type": "boolean" }, "current": { "type": "boolean" }
                    }
                } }, "next_before_id": { "type": ["integer", "null"], "minimum": 1 }
            }
        }),
    );
    let invitations_response = json_response(
        "pending invitation metadata and next_before_id cursor",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["invitations", "next_before_id"],
            "properties": { "invitations": { "type": "array", "items": { "type": "object", "additionalProperties": false,
                "required": ["id", "account", "contact_email", "administrator", "created_by", "created_at", "expires_at"],
                "properties": { "id": { "type": "integer", "minimum": 1 }, "account": { "type": "string" }, "contact_email": { "type": ["string", "null"] }, "administrator": { "type": "boolean" }, "created_by": { "type": "string" }, "created_at": { "type": "string" }, "expires_at": { "type": "string" } }
            } }, "next_before_id": { "type": ["integer", "null"], "minimum": 1 } }
        }),
    );
    let channels_response = json_response(
        "registered-channel posture and next_before_id cursor",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["channels", "next_before_id"],
            "properties": { "channels": { "type": "array", "items": { "type": "object", "additionalProperties": false,
                "required": ["id", "name", "founder", "created_at", "policy"],
                "properties": { "id": { "type": "integer", "minimum": 1 }, "name": { "type": "string" }, "founder": { "type": "string" }, "created_at": { "type": "string" }, "policy": { "type": "object", "additionalProperties": false, "required": ["keeptopic", "topic_retained", "mlock", "access_entries"], "properties": { "keeptopic": { "type": "boolean" }, "topic_retained": { "type": "boolean", "description": "Whether a retained topic is stored; the topic text itself is not returned here." }, "mlock": { "type": "string" }, "access_entries": { "type": "integer", "minimum": 0 } } } }
            } }, "next_before_id": { "type": ["integer", "null"], "minimum": 1 } }
        }),
    );
    let bans_response = json_response(
        "server-ban policy and next_before_id cursor",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["bans", "next_before_id"],
            "properties": { "bans": { "type": "array", "items": { "type": "object", "additionalProperties": false,
                "required": ["id", "mask", "reason", "set_by", "kind", "created_at"],
                "properties": { "id": { "type": "integer", "minimum": 1 }, "mask": { "type": "string" }, "reason": { "type": "string" }, "set_by": { "type": "string" }, "kind": { "type": "string", "enum": ["kline", "dline", "xline"] }, "created_at": { "type": "string" } }
            } }, "next_before_id": { "type": ["integer", "null"], "minimum": 1 } }
        }),
    );
    let audit_response = json_response(
        "audit entries and next_before_id cursor",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["audit", "next_before_id"],
            "properties": { "audit": { "type": "array", "items": { "type": "object", "additionalProperties": false,
                "required": ["id", "actor", "action", "target", "detail", "at"],
                "properties": { "id": { "type": "integer", "minimum": 1 }, "actor": { "type": "string" }, "action": { "type": "string" }, "target": { "type": "string" }, "detail": { "type": "string" }, "at": { "type": "string" } }
            } }, "next_before_id": { "type": ["integer", "null"], "minimum": 1 } }
        }),
    );
    let owned_channel_schema = serde_json::json!({
        "type": "object", "additionalProperties": false,
        "required": ["name", "founder", "keeptopic", "topic", "topic_setter", "topic_set_at", "mlock", "access"],
        "properties": {
            "name": { "type": "string" }, "founder": { "type": "string" }, "keeptopic": { "type": "boolean" },
            "topic": { "type": ["string", "null"] }, "topic_setter": { "type": ["string", "null"] }, "topic_set_at": { "type": ["integer", "null"], "minimum": 0 }, "mlock": { "type": ["string", "null"] },
            "access": { "type": "array", "items": { "type": "object", "additionalProperties": false, "required": ["account", "flags"], "properties": { "account": { "type": "string" }, "flags": { "type": "string", "enum": ["o", "v", "ov", "vo"] } } } }
        }
    });
    let owned_channels_response = json_response(
        "founder-owned channels",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["channels"],
            "properties": { "channels": { "type": "array", "items": owned_channel_schema.clone() } }
        }),
    );
    let owned_channel_response = json_response("founder-owned channel", owned_channel_schema);
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
    let tls_schema = serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["cert_path", "key_path"],
        "properties": {
            "cert_path": { "type": "string" },
            "key_path": { "type": "string" }
        }
    });
    let listener_schema = serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["addr"],
        "properties": {
            "addr": { "type": "string" },
            "tls": { "oneOf": [tls_schema, { "type": "null" }] },
            "websocket": { "type": "boolean" }
        }
    });
    let registration_schema = serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "before_connect": { "type": "boolean" },
            "require_email": { "type": "boolean" }
        }
    });
    let limits_schema = serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "max_connections_per_ip": { "type": ["integer", "null"], "minimum": 1 },
            "command_burst": { "type": "integer", "minimum": 1, "maximum": 10000 },
            "command_rate": { "type": "integer", "minimum": 1, "maximum": 10000 },
            "trusted_proxies": { "type": "array", "items": { "type": "string" } },
            "auth_rate_burst": { "type": ["integer", "null"], "minimum": 1 },
            "api_rate_burst": { "type": "integer", "minimum": 1 },
            "administrator_api_rate_burst": { "type": "integer", "minimum": 1 },
            "registration_burst": { "type": ["integer", "null"], "minimum": 1 }
        }
    });
    let observability_schema = serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "enabled": { "type": "boolean" },
            "sample_interval_seconds": { "type": "integer", "minimum": 5, "maximum": 300 },
            "retention_hours": { "type": "integer", "minimum": 1, "maximum": 2160 }
        }
    });
    let storage_schema = serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "history_retention_days": { "type": "integer", "minimum": 1, "maximum": 3650 },
            "audit_retention_days": { "type": "integer", "minimum": 1, "maximum": 3650 }
        }
    });
    // The collections the configuration read returns. Named once: the read
    // serves them, and the write accepts them back unchanged, so both sides
    // have to mean the same shape.
    let opers_schema = serde_json::json!({
        "type": "array", "items": { "type": "object", "additionalProperties": false,
            "required": ["name", "password"], "properties": { "name": { "type": "string" }, "password": { "type": "string" } } }
    });
    let oidc_providers_schema = serde_json::json!({
        "type": "array", "items": { "type": "object", "additionalProperties": false,
            "required": ["name", "issuer_url", "client_id", "client_secret", "account_claim", "scopes", "allowed_email_domains", "end_session_endpoint", "token_endpoint_auth_method"],
            "properties": { "name": { "type": "string" }, "issuer_url": { "type": "string" }, "client_id": { "type": "string" }, "client_secret": { "type": "string" }, "account_claim": { "type": "string", "enum": ["preferred_username", "email"] }, "scopes": { "type": "array", "items": { "type": "string" } }, "allowed_email_domains": { "type": "array", "items": { "type": "string" } }, "end_session_endpoint": { "type": ["string", "null"] }, "token_endpoint_auth_method": { "type": "string", "enum": ["client_secret_basic", "client_secret_post"] } } }
    });
    let networks_schema = serde_json::json!({
        "type": "array", "items": { "type": "object", "additionalProperties": false,
            "required": ["name", "owner", "kind", "addr", "tls", "nick", "username", "realname", "autojoin", "buffer_cap", "sasl_account", "sasl_password", "server_password"],
            "properties": { "name": { "type": "string" }, "owner": { "type": ["string", "null"] }, "kind": { "type": "string", "enum": ["irc", "local", "matrix", "discord", "slack"] }, "addr": { "type": "string" }, "tls": { "type": "boolean" }, "nick": { "type": "string" }, "username": { "type": ["string", "null"] }, "realname": { "type": ["string", "null"] }, "autojoin": { "type": "array", "items": { "type": "string" } }, "buffer_cap": { "type": "integer", "minimum": 1 }, "sasl_account": { "type": ["string", "null"] }, "sasl_password": { "type": ["string", "null"] }, "server_password": { "type": "null", "description": "Always null on read: a stored server password is never returned." } } }
    });
    let scalar_settings_schema = serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "server_name", "network_name", "description", "motd", "nicklen", "sendq",
            "core_queue", "core_workers", "max_hot_channels", "listeners", "registration", "limits",
            "observability", "storage", "bnc_addr", "bnc_tls", "public_url", "secure_cookies",
            "admin_accounts"
        ],
        "properties": {
            "server_name": { "type": "string" },
            "network_name": { "type": "string" },
            "description": { "type": "string" },
            "motd": { "type": "array", "items": { "type": "string" } },
            "nicklen": { "type": "integer", "minimum": 10, "maximum": 64 },
            "sendq": { "type": "integer", "minimum": 1, "maximum": crate::config::MAX_SENDQ },
            "core_queue": { "type": "integer", "minimum": 1, "maximum": crate::config::MAX_CORE_QUEUE },
            "core_workers": { "type": "integer", "minimum": 1, "maximum": crate::config::MAX_CORE_WORKERS },
            "max_hot_channels": { "type": "integer", "minimum": 1, "maximum": crate::config::MAX_HOT_CHANNELS },
            "listeners": { "type": "array", "items": listener_schema },
            "registration": registration_schema,
            "limits": limits_schema,
            "observability": observability_schema,
            "storage": storage_schema,
            "bnc_addr": { "type": ["string", "null"] },
            "bnc_tls": {
                "oneOf": [tls_schema, { "type": "null" }],
                "description": "The attach listener's certificate. Required unless bnc_addr is a loopback address: attaching clients send their account password."
            },
            "public_url": { "type": ["string", "null"] },
            "secure_cookies": { "type": "boolean" },
            "admin_accounts": { "type": "array", "items": { "type": "string" } },
            // Optional, and only as read: the credential collections are kept
            // from the current revision, and each has its own endpoint. They
            // are accepted here so that reading this resource, changing one
            // scalar and sending it back is not refused for echoing fields it
            // was given; a *changed* one is refused by name.
            "oidc_providers": oidc_providers_schema,
            "opers": opers_schema,
            "networks": networks_schema,
            "credentials_from_bootstrap": { "type": "boolean" }
        }
    });
    let mut configuration_settings_schema = scalar_settings_schema.clone();
    configuration_settings_schema["required"]
        .as_array_mut()
        .expect("configuration settings required fields are an array")
        .extend([
            serde_json::json!("opers"),
            serde_json::json!("oidc_providers"),
            serde_json::json!("networks"),
            serde_json::json!("credentials_from_bootstrap"),
        ]);
    let managed_network_variant = |kind: &str, required: &[&str], mut schema: serde_json::Value| {
        let properties = schema["properties"]
            .as_object_mut()
            .expect("network properties");
        properties.insert("kind".into(), serde_json::json!({ "const": kind }));
        let required_fields = schema["required"]
            .as_array_mut()
            .expect("network required fields");
        required_fields.push(serde_json::json!("kind"));
        required_fields.extend(required.iter().map(|field| serde_json::json!(field)));
        schema
    };
    let managed_network_request_schema = serde_json::json!({ "oneOf": [
        managed_network_variant("irc", &["revision", "name", "addr", "tls", "nick", "username", "realname", "autojoin", "buffer_cap"], serde_json::json!({ "type": "object", "additionalProperties": false, "required": [], "properties": { "revision": { "type": "integer" }, "name": { "type": "string" }, "owner": { "type": ["string", "null"] }, "addr": { "type": "string" }, "tls": { "type": "boolean" }, "nick": { "type": "string" }, "username": { "type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_-]{0,9}$", "description": "IRC user name (ident) sent in USER. Required for kind=irc; never derived from the nick." }, "realname": { "type": "string" }, "autojoin": { "type": "array", "items": { "type": "string" } }, "buffer_cap": { "type": "integer", "minimum": 1 }, "sasl_account": { "type": ["string", "null"], "writeOnly": true }, "sasl_password": { "type": ["string", "null"], "writeOnly": true }, "server_password": server_password_schema.clone() } })),
        managed_network_variant("local", &["revision", "name", "addr", "tls", "nick", "username", "realname", "autojoin", "buffer_cap"], serde_json::json!({ "type": "object", "additionalProperties": false, "required": [], "properties": { "revision": { "type": "integer" }, "name": { "type": "string" }, "owner": { "type": ["string", "null"] }, "addr": { "type": "string" }, "tls": { "type": "boolean" }, "nick": { "type": "string" }, "username": { "type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_-]{0,9}$", "description": "IRC user name (ident) sent in USER. Required for kind=irc; never derived from the nick." }, "realname": { "type": "string" }, "autojoin": { "type": "array", "items": { "type": "string" } }, "buffer_cap": { "type": "integer", "minimum": 1 } } })),
        managed_network_variant("matrix", &["revision", "name", "addr", "tls", "nick", "autojoin", "buffer_cap", "sasl_password"], serde_json::json!({ "type": "object", "additionalProperties": false, "required": [], "properties": { "revision": { "type": "integer" }, "name": { "type": "string" }, "owner": { "type": ["string", "null"] }, "addr": { "type": "string" }, "tls": { "type": "boolean" }, "nick": { "type": "string" }, "autojoin": { "type": "array", "items": { "type": "string" } }, "buffer_cap": { "type": "integer", "minimum": 1 }, "sasl_password": { "type": "string", "writeOnly": true } } })),
        managed_network_variant("discord", &["revision", "name", "addr", "tls", "autojoin", "buffer_cap", "sasl_password"], serde_json::json!({ "type": "object", "additionalProperties": false, "required": [], "properties": { "revision": { "type": "integer" }, "name": { "type": "string" }, "owner": { "type": ["string", "null"] }, "addr": { "type": "string" }, "tls": { "type": "boolean" }, "autojoin": { "type": "array", "items": { "type": "string" } }, "buffer_cap": { "type": "integer", "minimum": 1 }, "sasl_password": { "type": "string", "writeOnly": true } } })),
        managed_network_variant("slack", &["revision", "name", "addr", "tls", "autojoin", "buffer_cap", "sasl_account", "sasl_password"], serde_json::json!({ "type": "object", "additionalProperties": false, "required": [], "properties": { "revision": { "type": "integer" }, "name": { "type": "string" }, "owner": { "type": ["string", "null"] }, "addr": { "type": "string" }, "tls": { "type": "boolean" }, "autojoin": { "type": "array", "items": { "type": "string" } }, "buffer_cap": { "type": "integer", "minimum": 1 }, "sasl_account": { "type": "string", "writeOnly": true }, "sasl_password": { "type": "string", "writeOnly": true } } }))
    ] });
    let configuration_response = json_response(
        "redacted settings, revision, and runtime/bootstrap status",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["revision", "updated_by", "updated_at", "settings", "runtime"],
            "properties": {
                "revision": { "type": "integer", "minimum": 0 }, "updated_by": { "type": "string" }, "updated_at": { "type": "string" }, "settings": configuration_settings_schema,
                "runtime": { "type": "object", "additionalProperties": false, "required": ["bound_bnc_addr", "http_bind", "has_master_key", "master_key_count", "release_revision", "network_drivers"],
                    "properties": { "bound_bnc_addr": { "type": ["string", "null"] }, "http_bind": { "type": ["string", "null"] }, "has_master_key": { "type": "boolean" }, "master_key_count": { "type": "integer", "minimum": 0 }, "release_revision": { "type": ["string", "null"] }, "network_drivers": { "type": "array", "items": { "type": "string", "enum": ["irc", "local", "matrix", "discord", "slack"] } } }
                }
            }
        }),
    );
    let latency_snapshot_schema = serde_json::json!({
        "type": "object", "additionalProperties": false,
        "required": ["count", "sum_us", "max_us", "p50_us", "p95_us", "p99_us"],
        "properties": {
            "count": { "type": "integer", "minimum": 0 }, "sum_us": { "type": "integer", "minimum": 0 }, "max_us": { "type": "integer", "minimum": 0 },
            "p50_us": { "type": "integer", "minimum": 0 }, "p95_us": { "type": "integer", "minimum": 0 }, "p99_us": { "type": "integer", "minimum": 0 }
        }
    });
    let queue_snapshot_schema = serde_json::json!({
        "type": "object", "additionalProperties": false,
        "required": ["depth", "capacity", "mode", "mode_switches"],
        "properties": {
            "depth": { "type": "integer", "minimum": 0 }, "capacity": { "type": "integer", "minimum": 1 },
            "mode": { "type": "string", "enum": ["fifo", "lifo"] }, "mode_switches": { "type": "integer", "minimum": 0 }
        }
    });
    let snapshot_schema = serde_json::json!({
        "type": "object", "additionalProperties": false,
        "required": ["schema_version", "sampled_at_ms", "uptime_seconds", "core_heartbeat_age_ms", "active_connections", "registered_connections", "unregistered_connections", "channels", "connections_opened_total", "connections_closed_total", "connections_rejected_total", "irc_lines_in_total", "irc_bytes_in_total", "irc_lines_out_total", "irc_bytes_out_total", "bnc_lines_in_total", "bnc_bytes_in_total", "bnc_lines_out_total", "bnc_bytes_out_total", "bnc_client_connections", "bnc_client_connections_opened_total", "sendq_kills_total", "http_requests_total", "http_server_errors_total", "database_requests_total", "bnc_networks", "bnc_connected", "queues", "database_pool", "errors", "error_last_seen_ms", "core_latency", "database_latency", "http_latency"],
        "properties": {
            "schema_version": { "type": "integer", "const": crate::observability::SNAPSHOT_SCHEMA_VERSION }, "sampled_at_ms": { "type": "integer", "minimum": 0 }, "uptime_seconds": { "type": "integer", "minimum": 0 }, "core_heartbeat_age_ms": { "type": "integer", "minimum": 0 },
            "active_connections": { "type": "integer", "minimum": 0 }, "registered_connections": { "type": "integer", "minimum": 0 }, "unregistered_connections": { "type": "integer", "minimum": 0 }, "channels": { "type": "integer", "minimum": 0 },
            "connections_opened_total": { "type": "integer", "minimum": 0 }, "connections_closed_total": { "type": "integer", "minimum": 0 }, "connections_rejected_total": { "type": "integer", "minimum": 0 },
            "irc_lines_in_total": { "type": "integer", "minimum": 0 }, "irc_bytes_in_total": { "type": "integer", "minimum": 0 }, "irc_lines_out_total": { "type": "integer", "minimum": 0 }, "irc_bytes_out_total": { "type": "integer", "minimum": 0 },
            "bnc_lines_in_total": { "type": "integer", "minimum": 0 }, "bnc_bytes_in_total": { "type": "integer", "minimum": 0 }, "bnc_lines_out_total": { "type": "integer", "minimum": 0 }, "bnc_bytes_out_total": { "type": "integer", "minimum": 0 },
            "bnc_client_connections": { "type": "integer", "minimum": 0 }, "bnc_client_connections_opened_total": { "type": "integer", "minimum": 0 }, "sendq_kills_total": { "type": "integer", "minimum": 0 }, "http_requests_total": { "type": "integer", "minimum": 0 }, "http_server_errors_total": { "type": "integer", "minimum": 0 }, "database_requests_total": { "type": "integer", "minimum": 0 }, "bnc_networks": { "type": "integer", "minimum": 0 }, "bnc_connected": { "type": "integer", "minimum": 0 },
            "database_pool": {
                "type": ["object", "null"],
                "description": "The shared PostgreSQL pool; null on a server without a database.",
                "additionalProperties": false,
                "required": ["size", "idle", "max", "acquire_timeouts_total"],
                "properties": {
                    "size": { "type": "integer", "minimum": 0, "description": "Connections open now, idle or in use." },
                    "idle": { "type": "integer", "minimum": 0 },
                    "max": { "type": "integer", "minimum": 2, "maximum": 200, "description": "database.max_connections, or its host-sized default." },
                    "acquire_timeouts_total": { "type": "integer", "minimum": 0, "description": "Pool acquires that waited the whole acquire timeout and failed." }
                }
            },
            "queues": { "type": "object", "additionalProperties": queue_snapshot_schema, "properties": {} },
            "errors": { "type": "object", "additionalProperties": { "type": "integer", "minimum": 0 }, "properties": {} },
            "error_last_seen_ms": { "type": "object", "additionalProperties": { "type": "integer", "minimum": 0 }, "properties": {} },
            "core_latency": latency_snapshot_schema, "database_latency": latency_snapshot_schema, "http_latency": latency_snapshot_schema
        }
    });
    let observability_response = json_response(
        "current snapshot and historical samples",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["current", "history"],
            "properties": { "current": snapshot_schema, "history": { "type": "array", "items": snapshot_schema } }
        }),
    );
    let application_metric_schema = serde_json::json!({
        "type": "object", "additionalProperties": false,
        "required": ["name", "label", "value", "unit", "status"],
        "properties": {
            "name": { "type": "string" }, "label": { "type": "string" },
            "value": { "type": "number", "minimum": 0 }, "unit": { "type": "string" },
            "status": { "type": "string", "const": "available" }
        }
    });
    let application_observation_response = json_response(
        "current application observation",
        serde_json::json!({
            "type": "object", "additionalProperties": false,
            "required": ["schema_version", "observed_at", "resources"],
            "properties": {
                "schema_version": { "type": "string", "const": "e6qu.monitoring/v2" },
                "observed_at": { "type": "string", "format": "date-time" },
                "resources": { "type": "array", "minItems": 1, "items": {
                    "type": "object", "additionalProperties": false,
                    "required": ["id", "name", "kind", "health", "metrics"],
                    "properties": {
                        "id": { "type": "string" }, "name": { "type": "string" }, "kind": { "type": "string" },
                        "health": { "type": "string", "enum": ["healthy", "degraded", "unhealthy", "unknown"] },
                        "metrics": { "type": "array", "items": application_metric_schema }
                    }
                } }
            }
        }),
    );
    let stats_response = json_response(
        "counts, server identity, and live totals",
        serde_json::json!({
            "type": "object", "additionalProperties": false,
            "required": ["server", "network", "accounts", "registered_channels", "server_bans", "version", "live"],
            "properties": {
                "server": { "type": "string" }, "network": { "type": "string" }, "accounts": { "type": "integer", "minimum": 0 }, "registered_channels": { "type": "integer", "minimum": 0 }, "server_bans": { "type": "integer", "minimum": 0 }, "version": { "type": "string" },
                "live": { "type": "object", "additionalProperties": false, "required": ["connections", "connected_upstreams", "upstreams", "traffic", "errors"], "properties": { "connections": { "type": "integer", "minimum": 0 }, "connected_upstreams": { "type": "integer", "minimum": 0 }, "upstreams": { "type": "integer", "minimum": 0 }, "traffic": { "type": "integer", "minimum": 0 }, "errors": { "type": "integer", "minimum": 0 } } }
            }
        }),
    );
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
                },
                "monitoringBearer": {
                    "type": "http",
                    "scheme": "bearer",
                    "description": "The deployment-owned E6IRC_MONITORING_TOKEN. It grants read-only access only to the application observation endpoint.",
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
            "/api/v1/monitoring/observation": {
                "get": {
                    "summary": "Deployment-neutral application observation",
                    "description": "Publishes real fixed-cardinality process, IRC, BNC, queue, error, and uptime metrics using e6qu.monitoring/v2. e6irc is not itself a priced resource, so the application contract deliberately omits cost_estimate.",
                    "security": [{ "monitoringBearer": [] }],
                    "responses": {
                        "200": application_observation_response["200"],
                        "401": { "description": "missing or invalid monitoring bearer token (a problem document; WWW-Authenticate names the Bearer realm)" }
                    }
                }
            },
            "/api/v1/server": {
                "get": { "summary": "Server name, network name, version", "responses": ok_json }
            },
            "/api/v1/network-presets": {
                "get": {
                    "summary": "Curated public IRC networks and their published connection defaults",
                    "responses": json_response("the preset catalog", serde_json::json!({
                        "type": "object", "additionalProperties": false, "required": ["presets"],
                        "properties": { "presets": { "type": "array", "maxItems": 32, "items": {
                            "type": "object", "additionalProperties": false,
                            "required": ["id", "label", "name", "addr", "tls"],
                            "properties": {
                                "id": { "type": "string", "minLength": 1, "maxLength": 64 },
                                "label": { "type": "string", "minLength": 1, "maxLength": 64 },
                                "name": { "type": "string", "minLength": 1, "maxLength": 64 },
                                "addr": { "type": "string", "minLength": 1, "maxLength": 255 },
                                "tls": { "type": "boolean" }
                            } } } }
                    }))
                }
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
                                "label": { "type": "string", "minLength": 1, "maxLength": 64 } } } } } },
                    "responses": { "201": { "description": "the app password (shown once)" },
                        "400": { "description": "invalid account, password, or label" },
                        "401": { "description": "bad credentials" },
                        "409": { "description": "the account already holds the most app passwords allowed; revoke one first" },
                        "429": { "description": "the account name has spent its password attempts for the window, or this address its authentication budget; Retry-After says when to try again" },
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
                    "responses": profile_response
                },
                "patch": {
                    "summary": "Replace or remove your private contact email",
                    "description": "Requires a cookie-authenticated browser session and its X-E6IRC-CSRF header. The address is parsed and bounded before storage. JSON null removes it. The audit event records only replaced/removed, never the address.",
                    "security": browser_session_only,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": {
                            "type": "object",
                            "additionalProperties": false,
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
                    "security": browser_session_only,
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
                        "200": { "description": "attachment containing the account export; the download is abandoned if the client reads nothing for 30 seconds" },
                        "404": { "description": "account no longer exists" },
                        "429": { "description": "the account's request budget is spent, or the server is producing as many account exports as it allows at once (two); Retry-After gives the seconds to wait" },
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
                        "200": security_activity_response["200"],
                        "400": { "description": "invalid limit or cursor" },
                        "503": { "description": "database or absolute public URL unavailable" }
                    }
                }
            },
            "/api/v1/me/sessions": {
                "get": {
                    "summary": "List your active browser sessions",
                    "description": "Returns at most 32 owner-scoped stable IDs, creation/expiry times, login method, provider, bounded User-Agent provenance, and whether a row is the request's current cookie session. A new login atomically revokes the oldest active row at the cap. Session tokens and hashes are never returned.",
                    "security": authenticated,
                    "responses": {
                        "200": browser_sessions_response["200"],
                        "503": { "description": "database unavailable" }
                    }
                },
                "delete": {
                    "summary": "Revoke every other active browser session",
                    "description": "Requires the explicit `except=current` selector and a cookie-authenticated browser session. The database deletion is atomic, preserves the authorizing session, and returns the number revoked.",
                    "security": browser_session_only,
                    "parameters": [{ "name": "except", "in": "query", "required": true,
                        "schema": { "type": "string", "enum": ["current"] } }],
                    "responses": {
                        "200": revoked_sessions_response["200"],
                        "400": { "description": "missing or invalid selector" },
                        "401": { "description": "browser cookie session required" },
                        "503": { "description": "database unavailable" }
                    }
                }
            },
            "/api/v1/me/sessions/{id}": {
                "delete": {
                    "summary": "Revoke one of your browser sessions",
                    "description": "Requires a cookie-authenticated browser session and its X-E6IRC-CSRF header: browser sessions are managed by browser sessions, one at a time or all but the current one alike, so a bearer cannot sign its owner out of every browser. The session ID is scoped to the authenticated account in the deletion query. Revoking the current cookie session also clears its browser cookie.",
                    "security": browser_session_only,
                    "parameters": [{ "name": "id", "in": "path", "required": true,
                        "schema": { "type": "integer", "format": "int64", "minimum": 1 } }],
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
                        "200": connection_page_response["200"],
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
                    "description": "Redirects the browser to the provider's authorization endpoint (code flow + PKCE) and sets an HttpOnly cookie carrying the sealed, ten-minute flow the callback requires. The server keeps no per-flow state.",
                    "parameters": [{ "name": "provider", "in": "path", "required": true,
                        "schema": { "type": "string" } }],
                    "responses": { "307": { "description": "redirect into the provider" },
                        "404": { "description": "unknown provider" },
                        "429": { "description": "the client's authentication rate limit is spent; Retry-After gives the seconds until it holds a token again" },
                        "502": { "description": "the provider is unreachable or its discovery document is unusable" } } }
            },
            "/api/v1/auth/oidc/{provider}/callback": {
                "get": { "summary": "OIDC redirect-back: exchange the code and establish the session",
                    "description": "Opens the sealed flow in the state cookie and requires its state to equal the returned one, for this provider, within ten minutes; exchanges the authorization code (with PKCE) for tokens, validates the ID token, provisions or logs into the account, and sets the session cookie. Every response to a callback that proved the browser's flow clears the state cookie, so a flow is answered once; the authorization code itself is single-use at the provider. A first login provisions an account named exactly by the provider's configured claim; a name already in use or retired is refused with 409 (the server never picks a different name for a person). An email names an account only when it is verified and the provider has an allowed-domain policy (403 otherwise). A flow answered once is refused if its cookie is presented again (401). As RFC 6749 §4.1.2 requires, response parameters other than these (Google's `authuser`, `hd` and `prompt`, Keycloak's and Microsoft Entra's `session_state`, a granted `scope`) are ignored: what is trusted is the verified ID token.",
                    "parameters": [
                        { "name": "provider", "in": "path", "required": true, "schema": { "type": "string" } },
                        { "name": "code", "in": "query", "required": false, "schema": { "type": "string" } },
                        { "name": "state", "in": "query", "required": false, "schema": { "type": "string" } },
                        { "name": "error", "in": "query", "required": false, "schema": { "type": "string" }, "description": "The provider's refusal (RFC 6749 §4.1.2.1); a silent probe's login_required bounces to /?sso=none, and its consent_required begins an ordinary authorization request." },
                        { "name": "iss", "in": "query", "required": false, "schema": { "type": "string" }, "description": "Must equal the provider's issuer when present (RFC 9207)." }
                    ],
                    "responses": { "303": { "description": "logged in and session cookie set; or identity linked (to /?linked=1); or a silent probe found no provider session (to /?sso=none)" },
                        "307": { "description": "a silent probe answered consent_required: redirect into an ordinary authorization request" },
                        "400": { "description": "the query is malformed, or is missing code or state" },
                        "401": { "description": "the flow cookie is missing, expired, for another provider, or bound to a different state; code or token validation failed, the provider refused, or no usable account claim" },
                        "403": { "description": "the identity is outside the provider's allowed email domains, or the account cannot start a session or gain an identity, or a first sign-in would name an account by an email the provider has not verified or with no allowed-domain policy configured" },
                        "404": { "description": "unknown provider" },
                        "409": { "description": "first login: the claim's account name is already taken or retired; or link: identity already linked to another account" },
                        "502": { "description": "the provider is unreachable or its discovery document is unusable" },
                        "503": { "description": "no database configured, or account or session storage failed" } } }
            },
            "/api/v1/auth/oidc/{provider}/sso": {
                "get": { "summary": "Silently probe for an existing SSO session (prompt=none)",
                    "description": "Redirects to the provider with prompt=none. If the browser already has an SSO session the callback logs you in with no prompt; otherwise it bounces to /?sso=none.",
                    "parameters": [{ "name": "provider", "in": "path", "required": true,
                        "schema": { "type": "string" } }],
                    "responses": { "307": { "description": "redirect into the provider" },
                        "404": { "description": "unknown provider" },
                        "429": { "description": "the client's authentication rate limit is spent; Retry-After gives the seconds until it holds a token again" },
                        "502": { "description": "the provider is unreachable or its discovery document is unusable" } } }
            },
            "/api/v1/auth/logout": {
                "post": { "summary": "Sign out: end the e6irc session and, for a provider session, the provider's SSO session",
                    "description": "Ends the browser session named by the session cookie, then redirects the browser to the OIDC provider's end-session endpoint (id_token_hint + post_logout_redirect_uri) when an identity provider asserted the session, so the provider's SSO session is ended too; a local session goes to /auth/signed-out. Incomplete OIDC logout configuration fails closed and keeps the session. A request that carries a session cookie must prove its session's CSRF value in the `X-E6IRC-CSRF` header (a script) or the `csrf` form field (a sign-out form, which the browser then follows as a navigation); never in the URL. A request with no session has nothing to end.",
                    "requestBody": { "required": false, "content": {
                        "application/x-www-form-urlencoded": { "schema": {
                            "type": "object", "additionalProperties": false, "required": ["csrf"],
                            "properties": { "csrf": { "type": "string" } }
                        } }
                    } },
                    "responses": { "303": { "description": "session cleared (or none was presented): redirect to the provider's end-session endpoint, or to /auth/signed-out" },
                        "403": { "description": "session cookie presented without its CSRF value" },
                        "503": { "description": "database unavailable, or the OIDC provider or public URL is not configured for coordinated logout" } } }
            },
            "/api/v1/me/reauthenticate": {
                "post": { "summary": "Prove the browser session's person again with the primary password",
                    "description": "Step-up re-authentication: operations that mint or redirect lasting access to the account (tokens, app passwords, device approval, identity linking, a first password, the recovery email, deleting the account) need a sign-in from the last 10 minutes and are otherwise refused 403 with problem type `urn:e6irc:problem:reauthentication-required`. This records one for the calling session. The password check is the login's (per-address budget, per-account attempt throttle). An account without a primary password uses `POST /api/v1/me/reauthenticate/oidc/{provider}`.",
                    "security": browser_session_only,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": { "type": "object", "additionalProperties": false,
                            "required": ["password"],
                            "properties": { "password": { "type": "string", "minLength": 1, "maxLength": 512, "writeOnly": true } } }
                    } } },
                    "responses": { "204": { "description": "this session counts as recently authenticated for the next 10 minutes" },
                        "400": { "description": "the password is empty or longer than 512 bytes (`field` names it)" },
                        "401": { "description": "the password is incorrect (`field` names it), or not signed in" },
                        "429": { "description": "the account has spent its password attempts for the window, or this address its authentication budget; Retry-After says when to try again" } } }
            },
            "/api/v1/me/reauthenticate/oidc/{provider}": {
                "post": { "summary": "Prove the browser session's person again at an identity provider",
                    "description": "Answers the provider URL to navigate to, and sets the sealed flow cookie. The provider is asked to authenticate afresh (`prompt=login`, `max_age=0`); its callback accepts only an identity linked to this account whose `auth_time` is within the last 10 minutes, marks this session recently authenticated, and returns to /console/account?reauthenticated=1.",
                    "security": browser_session_only,
                    "parameters": [{ "name": "provider", "in": "path", "required": true,
                        "schema": { "type": "string" } }],
                    "responses": {
                        "200": authorization_url_response["200"],
                        "404": { "description": "unknown provider" },
                        "502": { "description": "the provider is unreachable or its discovery document is unusable" } } }
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
                    "description": "Revokes local sessions correlated by the exact configured issuer and sid and returns a non-cacheable response. The browser session cookie is cleared only when it named one of the sessions this logout revoked, so a page that makes a browser load this URL cannot sign out anyone else.",
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
                "post": { "summary": "Link an OIDC identity to your account",
                    "description": "Requires a cookie-authenticated browser session and its X-E6IRC-CSRF header: whoever completes the flow at the provider becomes a login identity of the account, so a bearer cannot start it. Answers the provider URL for the page to navigate to and sets the sealed flow cookie, so the session's CSRF value never travels in a URL. The callback attaches the returned identity and redirects to /?linked=1.",
                    "security": browser_session_only,
                    "parameters": [{ "name": "provider", "in": "path", "required": true,
                        "schema": { "type": "string" } }],
                    "responses": {
                        "200": authorization_url_response["200"],
                        "401": { "description": "browser session required" },
                        "404": { "description": "unknown provider" },
                        "409": { "description": "identity already linked to another account (on return)" },
                        "502": { "description": "the provider is unreachable or its discovery document is unusable" } } }
            },
            "/api/v1/me/identities": {
                "get": { "summary": "List OIDC identities linked to your account and available link providers",
                    "security": authenticated, "responses": identities_response }
            },
            "/api/v1/me/identities/{id}": {
                "delete": {
                    "summary": "Unlink one of your OIDC identities and revoke its browser sessions",
                    "description": "Requires a cookie-authenticated browser session and its X-E6IRC-CSRF header.",
                    "security": browser_session_only,
                    "parameters": [{ "name": "id", "in": "path", "required": true,
                        "schema": { "type": "integer", "minimum": 1 } }],
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
                    "responses": { "200": { "description": "device_code, user_code, verification_uri" },
                        "503": { "description": "database or absolute public URL unavailable" } } }
            },
            "/api/v1/auth/device/token": {
                "post": { "summary": "Poll for the device grant's token",
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": {
                            "type": "object", "additionalProperties": false,
                            "required": ["device_code"],
                            "properties": { "device_code": { "type": "string", "minLength": 1 } }
                        }
                    } } },
                    "responses": { "200": { "description": "access_token once approved" },
                        "503": { "description": "no database configured, or the database is unavailable" },
                        "400": { "description": "RFC 8628 error: authorization_pending, expired_token, invalid_grant, or access_denied — the grant was approved but its account is at the personal access token cap, suspended, or gone; the grant is consumed and polling must stop" } } }
            },
            "/api/v1/auth/device/approve": {
                "post": {
                    "summary": "Approve a device grant from a browser session",
                    "description": "Requires the cookie-authenticated session and its X-E6IRC-CSRF header. Personal access tokens cannot mint a replacement bearer through device approval.",
                    "security": browser_session_only,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": {
                            "type": "object", "additionalProperties": false,
                            "required": ["user_code"],
                            "properties": { "user_code": { "type": "string", "minLength": 1 } }
                        }
                    } } },
                    "responses": { "204": { "description": "approved" },
                        "400": { "description": "invalid JSON body" },
                        "401": { "description": "browser session required" },
                        "409": { "description": "the approving account already holds the most personal access tokens allowed; the grant stays pending" },
                        "403": { "description": "invalid or missing CSRF token" },
                        "404": { "description": "no such pending code" } } }
            },
            "/api/v1/me/tokens": {
                "get": {
                    "summary": "List your expiring scoped personal access tokens (never the token)",
                    "description": "Returns the stable identifier, label, creation and expiry timestamps, and the closed scope set. Token material and hashes are never returned.",
                    "security": authenticated, "responses": tokens_response },
                "post": {
                    "summary": "Mint an expiring scoped personal access token (shown once)",
                    "description": "Requires a browser session and its X-E6IRC-CSRF header. Existing bearer tokens cannot expand their own grant.",
                    "security": browser_session_only,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": {
                            "type": "object",
                            "additionalProperties": false,
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
                        "201": token_created_response["201"],
                        "400": { "description": "invalid label, empty/unknown scopes, or lifetime" },
                        "403": { "description": "invalid or missing CSRF token" },
                        "409": { "description": "the account token cap is reached" }
                    }
                }
            },
            "/api/v1/me/tokens/{id}": {
                "delete": { "summary": "Revoke one of your personal access tokens",
                    "security": authenticated,
                    "parameters": [{ "name": "id", "in": "path", "required": true,
                        "schema": { "type": "integer", "minimum": 1 } }],
                    "responses": { "204": { "description": "revoked" },
                        "404": { "description": "no such token" } } }
            },
            "/api/v1/me/read-markers": {
                "get": { "summary": "List your read markers (draft/read-marker) per target",
                    "security": authenticated, "responses": read_markers_response }
            },
            "/api/v1/me/password": {
                "put": {
                    "summary": "Change your primary local-account password",
                    "description": "Requires a cookie-authenticated browser session and its X-E6IRC-CSRF header. Creates a first primary password for an OIDC-only account when current_password is omitted. Existing primary passwords require their current value; an app password cannot authorize rotation. Every other browser session of the account is signed out in the same transaction; app passwords and personal access tokens are separately managed credentials and are left unchanged, and the response says so.",
                    "security": browser_session_only,
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
                        "200": json_response("primary password changed; other browser sessions signed out", serde_json::json!({
                            "type": "object", "additionalProperties": false, "required": ["detail"],
                            "properties": { "detail": { "type": "string", "const": super::credentials::PASSWORD_CHANGE_DETAIL } }
                        }))["200"],
                        "400": { "description": "password is empty or exceeds 512 bytes" },
                        "401": { "description": "current primary password is incorrect" },
                        "403": { "description": "current_password omitted (a first password) and the session has not signed in within the last 10 minutes: problem type urn:e6irc:problem:reauthentication-required; re-authenticate and retry. Also a suspended account or a missing X-E6IRC-CSRF value" },
                        "409": { "description": "current_password omitted but a primary password already exists" },
                        "429": { "description": "the account has spent its password attempts for the window; Retry-After says when to try again" },
                        "503": { "description": "database unavailable" }
                    }
                }
            },
            "/api/v1/me/channels": {
                "get": {
                    "summary": "List registered channels you founded with durable configuration",
                    "security": authenticated,
                    "responses": {
                        "200": owned_channels_response["200"],
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
                                "name": { "type": "string", "pattern": "^#", "minLength": 2, "maxLength": crate::sanitize::CHANNELLEN }
                            }
                        }
                    } } },
                    "responses": {
                        "201": json_response_status(201, "registered and applied", ok_detail_schema.clone())["201"],
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
                        "200": owned_channel_response["200"],
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
                        "200": json_response("stored and applied", ok_detail_schema.clone())["200"],
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
                        "200": json_response("unregistered", ok_detail_schema.clone())["200"],
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
                        "200": json_response("stored and applied", ok_detail_schema.clone())["200"],
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
                        "200": json_response("removed", ok_detail_schema.clone())["200"],
                        "404": { "description": "no such owned channel" }
                    }
                }
            },
            "/api/v1/me/credentials": {
                "get": { "summary": "List the account's credentials", "security": authenticated,
                    "responses": credentials_response },
                "post": {
                    "summary": "Mint an app password for the current browser-session account",
                    "description": "Requires a cookie-authenticated browser session and session-bound CSRF. Bearer tokens cannot mint credentials.",
                    "security": browser_session_only,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": { "type": "object", "required": ["label"], "additionalProperties": false,
                            "properties": { "label": { "type": "string", "minLength": 1, "maxLength": 64 } } }
                    } } },
                    "responses": {
                        "201": app_password_created_response["201"],
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
                        "schema": { "type": "integer", "minimum": 1 } }],
                    "responses": { "204": { "description": "revoked" },
                        "404": { "description": "no such credential" } } }
            },
            "/api/v1/me/networks": {
                "get": { "summary": "List the account's BNC networks with live upstream status",
                    "description": "Each network includes stored configuration, `connected` (true/false, or null with no running handle), and an owner-safe `runtime` object when its driver is active: lifecycle/timestamps, a credential-safe last-error code and summary, connect latency, attempts/errors, attached clients, traffic, and in-memory buffer usage.",
                    "security": authenticated, "responses": network_list_response },
                "post": { "summary": "Create a BNC network and start its driver",
                    "description": "Every request explicitly selects one driver and its complete connection intent. IRC requires addr, tls, nick, username, realname, and autojoin, with paired optional SASL credentials and an optional server_password (PASS, 400 with field=server_password when it cannot travel in one line); username is the IRC user name sent in USER, is never derived from the nick, and is refused for every other kind. Matrix requires an HTTP(S) homeserver, tls=true, provider user, autojoin, and password. Discord requires tls=true, autojoin, and a bot token. Slack requires tls=true, autojoin, bot token, and app token. An empty bridge addr explicitly selects that provider's built-in endpoint.",
                    "security": authenticated,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": { "oneOf": [
                            { "type": "object", "additionalProperties": false,
                                "required": ["kind", "name", "addr", "tls", "nick", "username", "realname", "autojoin"],
                                "properties": { "kind": { "const": "irc" }, "name": { "type": "string" }, "addr": { "type": "string" }, "tls": { "type": "boolean" }, "nick": { "type": "string" }, "username": { "type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_-]{0,9}$", "description": "IRC user name (ident) sent in USER. Required for kind=irc; never derived from the nick." }, "realname": { "type": "string" }, "autojoin": { "type": "array", "items": { "type": "string" } }, "sasl_account": { "type": ["string", "null"] }, "sasl_password": { "type": ["string", "null"] }, "server_password": server_password_schema.clone() } },
                            { "type": "object", "additionalProperties": false,
                                "required": ["kind", "name", "addr", "tls", "nick", "autojoin", "sasl_password"],
                                "properties": { "kind": { "const": "matrix" }, "name": { "type": "string" }, "addr": { "type": "string" }, "tls": { "const": true }, "nick": { "type": "string" }, "autojoin": { "type": "array", "items": { "type": "string" } }, "sasl_password": { "type": "string", "writeOnly": true } } },
                            { "type": "object", "additionalProperties": false,
                                "required": ["kind", "name", "addr", "tls", "autojoin", "sasl_password"],
                                "properties": { "kind": { "const": "discord" }, "name": { "type": "string" }, "addr": { "type": "string" }, "tls": { "const": true }, "autojoin": { "type": "array", "items": { "type": "string" } }, "sasl_password": { "type": "string", "writeOnly": true } } },
                            { "type": "object", "additionalProperties": false,
                                "required": ["kind", "name", "addr", "tls", "autojoin", "sasl_account", "sasl_password"],
                                "properties": { "kind": { "const": "slack" }, "name": { "type": "string" }, "addr": { "type": "string" }, "tls": { "const": true }, "autojoin": { "type": "array", "items": { "type": "string" } }, "sasl_account": { "type": "string", "writeOnly": true }, "sasl_password": { "type": "string", "writeOnly": true } } }
                        ] } } } },
                    "responses": { "201": network_created_response["201"],
                        "400": { "description": "invalid name, address, identity, or kind-specific configuration; an upstream inside the server's own network is refused" },
                        "404": { "description": "the bouncer is not enabled on this server" },
                        "409": { "description": "duplicate name, or upstream secret with no master key" },
                        "503": { "description": "database or network registry unavailable" } } }
            },
            "/api/v1/me/network-preflight": {
                "post": {
                    "summary": "Qualify an IRC upstream without saving it",
                    "description": "Uses the production DNS-vetting, TCP/TLS, optional server password (PASS), capability negotiation, optional SASL registration, and configured channel-join path. The connection closes after the probe.",
                    "security": authenticated,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": { "type": "object", "additionalProperties": false,
                            "required": ["addr", "tls", "nick", "username", "realname"],
                            "properties": {
                                "addr": { "type": "string", "minLength": 1, "maxLength": 255 },
                                "tls": { "type": "boolean" },
                                "nick": { "type": "string", "minLength": 1, "maxLength": 64 },
                                "username": { "type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_-]{0,9}$", "description": "IRC user name (ident) sent in USER; never derived from the nick." },
                                "realname": { "type": "string", "minLength": 1, "maxLength": 128 },
                                "autojoin": { "type": "array", "items": { "type": "string" } },
                                "sasl_account": { "type": ["string", "null"], "minLength": 1, "maxLength": 255, "writeOnly": true },
                                "sasl_password": { "type": ["string", "null"], "minLength": 1, "maxLength": 512, "writeOnly": true },
                                "server_password": server_password_schema.clone()
                            } } } } },
                    "responses": {
                        "200": {
                            "description": "DNS, transport, and registration timings; the test joins no channels",
                            "content": { "application/json": { "schema": {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["ok", "resolved_addresses", "dns_ms", "connect_ms", "registration_ms", "confirmed_nick", "sasl_mechanism"],
                                "properties": {
                                    "ok": { "const": true },
                                    "resolved_addresses": { "type": "integer", "minimum": 1 },
                                    "dns_ms": { "type": "integer", "format": "int64", "minimum": 0 },
                                    "connect_ms": { "type": "integer", "format": "int64", "minimum": 0 },
                                    "registration_ms": { "type": "integer", "format": "int64", "minimum": 0 },
                                    "confirmed_nick": { "type": "string", "minLength": 1, "maxLength": 64 },
                                    "sasl_mechanism": {
                                        "description": "the SASL mechanism that logged in, the strongest the network offered for the configured password; null when no account is configured",
                                        "enum": ["SCRAM-SHA-512", "SCRAM-SHA-256", "PLAIN", null]
                                    }
                                }
                            } } }
                        },
                        "400": { "description": "invalid address, identity, or incomplete credentials" },
                        "409": { "description": "the account's network with this upstream and nickname is running and holds the nickname; disable it to test its settings" },
                        "429": { "description": "this account already has a connection test running, has started six in the last minute, or the server is running as many as it allows at once; Retry-After gives the seconds to wait" },
                        "502": { "description": "typed upstream DNS, transport, TLS, authentication, or registration failure" }
                    }
                }
            },
            "/api/v1/me/networks/{name}/account-registration": {
                "post": {
                    "summary": "Send one guided NickServ account-registration command",
                    "description": "Queues the same standard IRC service messages available through `/msg NickServ`: REGISTER requests an email and VERIFY REGISTER submits its code. The upstream must already be connected. Replies are ordinary IRC lines in the network transcript. Sensitive command self-echoes are redacted before persistence.",
                    "security": authenticated,
                    "parameters": network_name_parameter,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": { "oneOf": [
                            { "type": "object", "additionalProperties": false,
                                "required": ["action", "email", "password"],
                                "properties": {
                                    "action": { "const": "register" },
                                    "email": { "type": "string", "format": "email", "maxLength": 254 },
                                    "password": { "type": "string", "minLength": 1, "maxLength": 200, "writeOnly": true }
                                } },
                            { "type": "object", "additionalProperties": false,
                                "required": ["action", "code"],
                                "properties": {
                                    "action": { "const": "verify" },
                                    "code": { "type": "string", "minLength": 1, "maxLength": 200, "writeOnly": true }
                                } }
                        ] } } } },
                    "responses": {
                        "202": {
                            "description": "command accepted by the connected network queue",
                            "content": { "application/json": { "schema": {
                                "type": "object",
                                "additionalProperties": false,
                                "required": ["queued", "command", "transcript"],
                                "properties": {
                                    "queued": { "const": true },
                                    "command": { "type": "string", "enum": ["register", "verify"] },
                                    "transcript": { "type": "string", "minLength": 1 }
                                }
                            } } }
                        },
                        "400": { "description": "invalid email, password, code, or command size" },
                        "409": { "description": "not an IRC network or no connected driver" },
                        "429": { "description": "bounded upstream command queue is full; nothing was sent, and Retry-After gives the seconds to wait" },
                        "404": { "description": "no owner-scoped network with this name" },
                        "503": { "description": "database unavailable" }
                    }
                }
            },
            "/api/v1/me/networks/{name}": {
                "get": { "summary": "Read one BNC network and its live runtime diagnostics",
                    "security": authenticated,
                    "parameters": network_name_parameter,
                    "responses": { "200": network_response["200"],
                        "404": { "description": "no such network" } } },
                "put": { "summary": "Replace a BNC network's mutable configuration and restart its driver",
                    "description": "The stored kind selects the same IRC/Matrix/Discord/Slack field contract documented on create. The credential action is required and explicit: `keep` preserves write-only values; `remove` clears paired IRC SASL and is rejected for bridges; `set` replaces supplied values. IRC requires account and may omit password to preserve it. Matrix/Discord accept only password. Slack accepts account, password, or both and preserves an omitted token. The server-password action is required and explicit too: `keep` preserves the stored value, `remove` clears it, `set` replaces it; only an IRC network accepts `remove` or `set` (400 with field=server_password otherwise). A stored secret never follows the network to a new destination: when the IRC host or port changes, TLS is turned off, or a bridge's API base or homeserver moves to another origin, a secret carried over unchanged (by `keep`, or by replacing only the other half of a pair) is a 409 naming `credentials` or `server_password`; enter it again or remove it.",
                    "security": authenticated,
                    "parameters": network_name_parameter,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": { "type": "object", "additionalProperties": false,
                            "required": ["addr", "tls", "nick", "autojoin", "credentials", "server_password"],
                            "properties": {
                                "addr": { "type": "string" },
                                "tls": { "type": "boolean" },
                                "nick": { "type": "string" },
                                "username": { "type": "string", "pattern": "^[A-Za-z0-9][A-Za-z0-9_-]{0,9}$", "description": "IRC user name (ident) sent in USER. Required when the stored network is kind=irc (400 with field=username when absent or invalid); refused for a bridge." },
                                "realname": { "type": "string", "description": "IRC real name sent in USER. Required when the stored network is kind=irc (400 with field=realname when absent); refused for a bridge." },
                                "autojoin": { "type": "array", "items": { "type": "string" }, "description": "The complete channel (or bridge room) list; PUT replaces the whole configuration, so it is required and an empty list joins nothing." },
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
                                },
                                "server_password": {
                                    "oneOf": [
                                        { "type": "object", "additionalProperties": false,
                                            "required": ["action"],
                                            "properties": { "action": { "const": "keep" } } },
                                        { "type": "object", "additionalProperties": false,
                                            "required": ["action"],
                                            "properties": { "action": { "const": "remove" } } },
                                        { "type": "object", "additionalProperties": false,
                                            "required": ["action", "password"],
                                            "properties": {
                                                "action": { "const": "set" },
                                                "password": { "type": "string", "minLength": 1, "maxLength": e6irc_client::ServerPassword::MAX_LEN, "writeOnly": true }
                                            } }
                                    ]
                                }
                            } } } } },
                    "responses": { "204": { "description": "updated and live driver replaced" },
                        "400": { "description": "invalid kind-specific configuration or credential action" },
                        "404": { "description": "no such network" },
                        "409": { "description": "cannot seal credentials or start replacement driver, or a stored secret would be sent to a new destination (field names it)" } } },
                "patch": { "summary": "Enable or disable a BNC network (start/stop its driver)",
                    "security": authenticated,
                    "parameters": network_name_parameter,
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": { "type": "object", "additionalProperties": false, "required": ["enabled"],
                            "properties": { "enabled": { "type": "boolean" } } } } } },
                    "responses": { "200": network_enabled_response["200"],
                        "400": { "description": "invalid JSON body" },
                        "404": { "description": "no such network" },
                        "409": { "description": "cannot start (stored secret, no master key)" } } },
                "delete": { "summary": "Delete a BNC network and stop its driver",
                    "security": authenticated,
                    "parameters": network_name_parameter,
                    "responses": { "204": { "description": "deleted" },
                        "404": { "description": "no such network" } } }
            },
            "/api/v1/me/networks/{name}/buffer": {
                "get": { "summary": "Read the bounded owner-scoped component log (oldest-first)",
                    "description": "Returns the active component's bounded live stream, or persisted history after it stops. It includes safe lifecycle notices and never includes credentials.",
                    "security": authenticated,
                    "parameters": [
                        { "name": "name", "in": "path", "required": true,
                            "schema": { "type": "string" } },
                        { "name": "limit", "in": "query", "required": false,
                            "schema": { "type": "integer", "minimum": 1, "maximum": 1000, "default": super::networks::DEFAULT_BUFFER_READ_LIMIT } },
                        { "name": "through", "in": "query", "required": false,
                            "description": "A `/ws/ui` replay cursor: only the running network's buffered lines at or before it, so a reader holding every line after it receives none twice.",
                            "schema": { "type": "string", "minLength": 1 } }],
                    "responses": { "200": buffer_response["200"],
                        "400": { "description": "limit outside 1–1000, or `through` is not a cursor (`field` names it)" },
                        "404": { "description": "no such network" },
                        "409": { "description": "`through` names no position of the running network's buffer (another buffer lifetime), or the network is stopped and its lines are persisted history without positions; read without `through`" } } }
            },
            "/ws/ui": {
                "get": { "summary": "The web client's live chat socket for one of your networks",
                    "description": "A WebSocket upgrade (RFC 6455): send `Connection: Upgrade`, `Upgrade: websocket`, and the handshake headers. A browser's `Origin` must be this application's (the configured public URL, else the `Host` it addressed). The socket first sends the network's status, its session snapshot, the replayed lines (after `after`, when that cursor is still in the ring), and a snapshot boundary, then live events; every server frame is one JSON event. A client frame is a composer request `{\"id\", \"target\", \"message\"}` answered by a `sent` or `send-error` event; sending needs the `write` scope or a browser session. The socket closes with code 1008 and a reason when policy refuses it — the account already holds 32 live sockets, or the session or token that opened it was revoked or expired (the client should not retry by itself) — and with 1013 when that credential could not be re-checked (reconnecting authenticates again).",
                    "security": authenticated,
                    "parameters": [
                        { "name": "network", "in": "query", "required": true,
                            "description": "One of your networks, by name.",
                            "schema": { "type": "string", "minLength": 1 } },
                        { "name": "after", "in": "query", "required": false,
                            "description": "The replay cursor of the last line the client holds; replay continues after it, or says it cannot.",
                            "schema": { "type": "string", "minLength": 1 } }
                    ],
                    "responses": {
                        "101": { "description": "Switching Protocols: the live chat socket (see the description for its events and close codes)" },
                        "400": { "description": "not a valid WebSocket upgrade, or an invalid query (a problem document)" },
                        "403": { "description": "the Origin is not this application's, or the credential is refused as for any authenticated read" },
                        "404": { "description": "no such network of yours, or the bouncer is not enabled" },
                        "426": { "description": "the WebSocket version is not supported (a problem document)" }
                    } }
            },
            "/api/v1/history": {
                "get": { "summary": "Paged message history for the account", "security": authenticated,
                    "parameters": [
                        { "name": "target", "in": "query", "required": true,
                            "schema": { "type": "string", "minLength": 1 } },
                        { "name": "before", "in": "query", "required": false,
                            "schema": { "type": "string", "format": "date-time" } },
                        { "name": "after", "in": "query", "required": false,
                            "schema": { "type": "string", "format": "date-time" } },
                        { "name": "limit", "in": "query", "required": false,
                            "schema": { "type": "integer", "minimum": 1, "maximum": 500, "default": 50 } }
                    ],
                    "responses": { "200": history_response["200"],
                        "400": { "description": "invalid window, timestamp, or limit; `field` names the query parameter at fault. Pages are positioned by time only: a message id is not an accepted `before` or `after`" },
                        "403": { "description": "not allowed to read this channel" },
                        "503": { "description": "database unavailable" } } }
            },
            "/api/v1/admin/accounts": {
                "get": { "summary": "Filter and page administrator-safe account posture (admin only)",
                    "description": "Returns stable account IDs newest-first. before_id selects strictly older accounts, so concurrent registration cannot duplicate or skip rows. The optional name filter is exact under RFC1459 case-folding. Counts omit expired browser sessions and personal access tokens; no credential, token, session, identity-subject, or network-secret material is returned.",
                    "security": authenticated,
                    "parameters": account_directory_parameters,
                    "responses": { "200": accounts_response["200"],
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
                        "201": account_created_response["201"],
                        "400": { "description": "invalid account, password, or contact email" },
                        "409": { "description": "account name exists, is retired, or is a configured administrator (created only by OIDC sign-in or the bootstrap/recovery flows)" },
                        "503": { "description": "database unavailable" }
                    }
                }
            },
            "/api/v1/me/networks/{name}/operations": {
                "get": { "summary": "Read bounded network Operations data",
                    "description": "Returns owner-scoped typed runtime state, persisted backlog metadata, and the newest 100 detached upstream lines. Secret material is never returned.",
                    "security": authenticated,
                    "parameters": network_name_parameter,
                    "responses": { "200": network_operations_response["200"],
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
                                    "oneOf": [
                                        {
                                            "type": "object",
                                            "additionalProperties": false,
                                            "required": ["suspended"],
                                            "properties": {
                                                "suspended": { "type": "boolean" }
                                            }
                                        },
                                        {
                                            "type": "object",
                                            "additionalProperties": false,
                                            "required": ["administrator"],
                                            "properties": {
                                                "administrator": { "type": "boolean" }
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    },
                    "responses": {
                        "200": account_state_response["200"],
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
                        "200": json_response("account deleted and live resources stopped", message_schema.clone())["200"],
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
                        "200": invitations_response["200"],
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
                        "201": invitation_created_response["201"],
                        "400": { "description": "invalid account, email, or lifetime" },
                        "409": { "description": "name unavailable (exists, retired, invited, or a configured administrator) or administrator invitation cap reached" },
                        "503": { "description": "database or absolute public URL unavailable" }
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
                        "200": connection_page_response["200"],
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
                    "responses": { "200": channels_response["200"],
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
                    "responses": { "200": bans_response["200"],
                        "400": { "description": "invalid limit, cursor, kind, or mask filter" },
                        "403": { "description": "not an admin account" } } }
                ,"post": { "summary": "Create or refresh a K/D/X-line policy (admin only)",
                    "description": "Uses the core-owned oper policy path, so persistence, immediate enforcement, matching-session disconnects, and audit provenance commit together.",
                    "security": authenticated,
                    "requestBody": { "required": true, "content": { "application/json": { "schema": {
                        "type": "object", "additionalProperties": false, "required": ["kind", "mask"],
                        "properties": { "kind": { "type": "string", "enum": ["kline", "dline", "xline"] }, "mask": { "type": "string" }, "reason": { "type": "string" } }
                    } } } },
                    "responses": { "201": json_response_status(201, "server ban created", message_schema.clone())["201"], "400": { "description": "invalid kind or mask" }, "403": { "description": "not an admin account" }, "409": { "description": "conflicting policy mutation" }, "503": { "description": "server-ban control unavailable" } } }
            },
            "/api/v1/admin/bans/{id}": {
                "delete": { "summary": "Delete one immutable server-ban resource (admin only)",
                    "description": "Resolves the stable directory ID before submitting the matching policy removal through the core. A stale ID cannot delete a recreated visible mask.",
                    "security": authenticated,
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "integer", "format": "int64", "minimum": 1 } }],
                    "responses": { "204": { "description": "server ban removed" }, "400": { "description": "invalid ID" }, "403": { "description": "not an admin account" }, "404": { "description": "server ban no longer exists" }, "409": { "description": "conflicting policy mutation" }, "503": { "description": "server-ban control unavailable" } } }
            },
            "/api/v1/admin/audit": {
                "get": { "summary": "Filter and page the privileged-action audit log (admin only)",
                    "description": "Returns stable audit entry IDs newest-first. before_id selects strictly older entries, so concurrent appends cannot duplicate or skip rows. Actor, action, and target filters are exact.",
                    "security": authenticated,
                    "parameters": audit_parameters,
                    "responses": { "200": audit_response["200"],
                        "400": { "description": "invalid limit, cursor, or exact filter" },
                        "403": { "description": "not an admin account" } } }
            },
            "/api/v1/admin/stats": {
                "get": { "summary": "Aggregate server counts and live totals (admin only)",
                    "security": authenticated,
                    "responses": { "200": stats_response["200"],
                        "403": { "description": "not an admin account" } } }
            },
            "/api/v1/admin/configuration": {
                "get": { "summary": "Read revisioned managed configuration (admin only)",
                    "description": "Returns the compare-and-swap revision, redacted operational settings, and the configuration console's secret-free runtime/bootstrap status. OIDC client secrets, oper passwords, upstream SASL passwords, and secret bridge accounts are never returned.",
                    "security": authenticated,
                    "responses": { "200": configuration_response["200"], "403": { "description": "not an admin account" }, "503": { "description": "managed configuration unavailable" } } },
                "patch": { "summary": "Update revisioned scalar managed configuration", "description": "Updates typed scalar settings while retaining OIDC, operator, and network credential collections from the current revision. Those collections may be sent back exactly as read (so a read-modify-write of one scalar works); a changed one is refused by name, never silently dropped. A live BNC listener change is applied before persistence and rolled back if persistence fails.", "security": authenticated,
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "additionalProperties": false, "required": ["revision", "settings"], "properties": { "revision": { "type": "integer" }, "settings": scalar_settings_schema } } } } },
                    "responses": { "200": configuration_patch_response["200"], "400": { "description": "invalid settings or BNC listener" }, "403": { "description": "not an admin account" }, "409": { "description": "stale revision" }, "503": { "description": "configuration or BNC listener unavailable" } } }
            },
            "/api/v1/admin/configuration/opers": {
                "post": { "summary": "Add an IRC operator to managed configuration", "security": authenticated,
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "additionalProperties": false, "required": ["revision", "name", "password"], "properties": { "revision": { "type": "integer" }, "name": { "type": "string" }, "password": { "type": "string", "writeOnly": true } } } } } },
                    "responses": { "200": revision_response["200"], "400": { "description": "invalid operator" }, "403": { "description": "not an admin account" }, "409": { "description": "stale revision or master key unavailable" }, "503": { "description": "configuration unavailable" } } }
            },
            "/api/v1/admin/configuration/opers/{name}": {
                "delete": { "summary": "Remove an IRC operator from managed configuration", "security": authenticated,
                    "parameters": [{ "name": "name", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "additionalProperties": false, "required": ["revision"], "properties": { "revision": { "type": "integer" } } } } } },
                    "responses": { "200": revision_response["200"], "400": { "description": "invalid operator" }, "403": { "description": "not an admin account" }, "409": { "description": "stale revision" }, "503": { "description": "configuration unavailable" } } }
            },
            "/api/v1/admin/configuration/oidc-providers": {
                "post": { "summary": "Add an OIDC provider to managed configuration", "security": authenticated,
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "additionalProperties": false, "required": ["revision", "name", "issuer_url", "client_id", "client_secret", "account_claim", "token_endpoint_auth_method"], "properties": { "revision": { "type": "integer" }, "name": { "type": "string" }, "issuer_url": { "type": "string" }, "client_id": { "type": "string" }, "client_secret": { "type": "string", "writeOnly": true }, "account_claim": { "type": "string", "enum": ["preferred_username", "email"] }, "scopes": { "type": "array", "items": { "type": "string" } }, "allowed_email_domains": { "type": "array", "items": { "type": "string" } }, "end_session_endpoint": { "type": ["string", "null"] }, "token_endpoint_auth_method": { "type": "string", "enum": ["client_secret_basic", "client_secret_post"] } } } } } },
                    "responses": { "200": revision_response["200"], "400": { "description": "invalid provider" }, "403": { "description": "not an admin account" }, "409": { "description": "stale revision or master key unavailable" }, "503": { "description": "configuration unavailable" } } }
            },
            "/api/v1/admin/configuration/oidc-providers/{name}": {
                "delete": { "summary": "Remove an OIDC provider from managed configuration", "security": authenticated,
                    "parameters": [{ "name": "name", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "additionalProperties": false, "required": ["revision"], "properties": { "revision": { "type": "integer" } } } } } },
                    "responses": { "200": revision_response["200"], "400": { "description": "invalid provider" }, "403": { "description": "not an admin account" }, "409": { "description": "stale revision" }, "503": { "description": "configuration unavailable" } } }
            },
            "/api/v1/admin/configuration/networks": {
                "post": { "summary": "Add a managed server network", "security": authenticated,
                    "requestBody": { "required": true, "content": { "application/json": { "schema": managed_network_request_schema } } },
                    "responses": { "200": revision_response["200"], "400": { "description": "invalid network" }, "403": { "description": "not an admin account" }, "409": { "description": "stale revision or master key unavailable" }, "503": { "description": "configuration unavailable" } } }
            },
            "/api/v1/admin/configuration/networks/{name}": {
                "delete": { "summary": "Remove a managed server network", "security": authenticated,
                    "parameters": [{ "name": "name", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "additionalProperties": false, "required": ["revision", "owner"], "properties": { "revision": { "type": "integer" }, "owner": { "type": ["string", "null"] } } } } } },
                    "responses": { "200": revision_response["200"], "400": { "description": "invalid network" }, "403": { "description": "not an admin account" }, "409": { "description": "stale revision" }, "503": { "description": "configuration unavailable" } } }
            },
            "/api/v1/admin/networks": {
                "get": { "summary": "Fleet-wide BNC network inventory (admin only)",
                    "description": "Every account's networks with stored configuration (credentials as presence booleans only) and live driver runtime state, ordered by owner and network name.",
                    "security": authenticated,
                    "responses": { "200": admin_networks_response["200"],
                        "403": { "description": "not an admin account" } } }
            },
            "/api/v1/admin/networks/{owner}/{name}": {
                "patch": { "summary": "Change one owner's network lifecycle (admin only)",
                    "description": "Persists the enabled state and starts or stops the same always-on driver as the owner API. The administrator is retained as the audit actor.",
                    "security": authenticated,
                    "parameters": [{ "name": "owner", "in": "path", "required": true, "schema": { "type": "string" } }, { "name": "name", "in": "path", "required": true, "schema": { "type": "string" } }],
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "additionalProperties": false, "required": ["enabled"], "properties": { "enabled": { "type": "boolean" } } } } } },
                    "responses": { "200": admin_network_enabled_response["200"], "400": { "description": "invalid JSON body" }, "403": { "description": "not an admin account" }, "404": { "description": "network or bouncer missing" }, "409": { "description": "the owner is suspended, or the stored network cannot start" }, "503": { "description": "database unavailable" } } }
            },
            "/api/v1/admin/observability": {
                "get": { "summary": "Live telemetry and bounded history (admin only)",
                    "description": "Returns the current snapshot and up to 1,000 historical samples of the same schema version.",
                    "security": authenticated,
                    "parameters": [{ "name": "minutes", "in": "query",
                        "schema": { "type": "integer", "minimum": 1, "maximum": 10080,
                            "default": 60 } }],
                    "responses": { "200": observability_response["200"],
                        "400": { "description": "history range outside 1–10080 minutes" },
                        "403": { "description": "not an admin account" },
                        "503": { "description": "monitoring storage unavailable" } } }
            },
            "/api/v1/admin/logs": {
                "get": { "summary": "Read recent redacted operational events (admin only)",
                    "description": "Returns at most 1,000 in-memory events from fixed server components. Event details never include request data, IRC traffic, or secrets.",
                    "security": authenticated,
                    "responses": { "200": logs_response["200"], "403": { "description": "not an admin account" } }
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

/// Two route patterns that one concrete URL satisfies, if any exist.
///
/// The router sends such a URL to the more literal pattern, so the value that
/// happens to spell a sibling's literal segment can never be addressed through
/// the template: a network named `preflight` was unreachable while a
/// `preflight` verb sat beside `{name}`. Patterns collide when they have the
/// same length and every position holds equal literals or at least one
/// parameter; resources keep verbs out of the positions their names occupy.
fn colliding_route_patterns<'a>(
    patterns: &std::collections::BTreeSet<&'a str>,
) -> Option<(&'a str, &'a str)> {
    let is_parameter = |segment: &str| segment.starts_with('{') && segment.ends_with('}');
    let collides = |left: &str, right: &str| {
        left.split('/').count() == right.split('/').count()
            && left
                .split('/')
                .zip(right.split('/'))
                .all(|(left, right)| left == right || is_parameter(left) || is_parameter(right))
    };
    patterns.iter().enumerate().find_map(|(index, left)| {
        patterns
            .iter()
            .skip(index + 1)
            .find(|right| collides(left, right))
            .map(|right| (*left, *right))
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
    // Every response-status omission is reported together: an author fixing
    // the contract should see the whole list, not one entry per attempt.
    let mut undocumented_statuses = Vec::new();
    let rate_limited = rate_limited_operations();
    let recently_authenticated = operations_extracting::<RecentlyAuthenticated>();
    let patterns = expected.iter().map(|(path, _)| *path).collect();
    if let Some((left, right)) = colliding_route_patterns(&patterns) {
        return Err(format!(
            "route patterns {left} and {right} match the same URL, so one resource name is unreachable"
        ));
    }
    if actual != expected {
        let missing: Vec<String> = expected
            .difference(&actual)
            .map(|(path, method)| format!("{} {}", method.to_ascii_uppercase(), path))
            .collect();
        let extra: Vec<String> = actual
            .difference(&expected)
            .map(|(path, method)| format!("{} {}", method.to_ascii_uppercase(), path))
            .collect();
        return Err(format!(
            "OpenAPI/router operation mismatch; missing from spec: [{}]; absent from router: [{}]",
            missing.join(", "),
            extra.join(", ")
        ));
    }

    for (path, item) in paths {
        let item = item
            .as_object()
            .ok_or_else(|| format!("OpenAPI path {path} is not an object"))?;
        if item.contains_key("parameters") {
            return Err(format!(
                "OpenAPI path {path} has unsupported path-item parameters"
            ));
        }
        let path_parameters: std::collections::BTreeSet<&str> = path
            .split('/')
            .filter_map(|segment| segment.strip_prefix('{')?.strip_suffix('}'))
            .collect();
        for method in methods {
            let Some(operation) = item.get(method) else {
                continue;
            };
            let parameters: &[serde_json::Value] = match operation.get("parameters") {
                Some(parameters) => parameters
                    .as_array()
                    .ok_or_else(|| format!("OpenAPI {method} {path} parameters is not an array"))?,
                None => &[],
            };
            let mut documented_path_parameters = std::collections::BTreeSet::new();
            let mut documented_query_parameters = std::collections::BTreeSet::new();
            for parameter in parameters {
                let Some(parameter) = parameter.as_object() else {
                    return Err(format!(
                        "OpenAPI {method} {path} has a non-object parameter"
                    ));
                };
                let name = parameter
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .filter(|name| !name.is_empty())
                    .ok_or_else(|| format!("OpenAPI {method} {path} has an unnamed parameter"))?;
                let location = parameter.get("in").and_then(serde_json::Value::as_str);
                if !matches!(location, Some("path" | "query")) {
                    return Err(format!(
                        "OpenAPI {method} {path} parameter {name} has an unsupported location"
                    ));
                }
                let schema = parameter
                    .get("schema")
                    .and_then(serde_json::Value::as_object)
                    .ok_or_else(|| {
                        format!("OpenAPI {method} {path} parameter {name} has no schema")
                    })?;
                if !matches!(
                    schema.get("type").and_then(serde_json::Value::as_str),
                    Some("string" | "boolean" | "integer" | "number")
                ) {
                    return Err(format!(
                        "OpenAPI {method} {path} parameter {name} has an unsupported schema"
                    ));
                }
                if location == Some("path") {
                    if parameter
                        .get("required")
                        .and_then(serde_json::Value::as_bool)
                        != Some(true)
                    {
                        return Err(format!(
                            "OpenAPI {method} {path} path parameter {name} is not required"
                        ));
                    }
                    if !documented_path_parameters.insert(name) {
                        return Err(format!(
                            "OpenAPI {method} {path} duplicates path parameter {name}"
                        ));
                    }
                } else if !documented_query_parameters.insert(name) {
                    return Err(format!(
                        "OpenAPI {method} {path} duplicates query parameter {name}"
                    ));
                }
            }
            if documented_path_parameters != path_parameters {
                return Err(format!(
                    "OpenAPI {method} {path} path parameters differ; documented: [{}], template: [{}]",
                    documented_path_parameters
                        .into_iter()
                        .collect::<Vec<_>>()
                        .join(", "),
                    path_parameters.into_iter().collect::<Vec<_>>().join(", ")
                ));
            }
            // The statuses the framework produces before a handler runs are
            // knowable from the operation's shape: admission for every
            // account-authenticated operation, and a body or query rejection
            // (`400`) for every operation that takes a JSON body or documents
            // a query parameter. A client validating against the document must
            // find them.
            let responses = operation
                .get("responses")
                .and_then(serde_json::Value::as_object)
                .ok_or_else(|| format!("OpenAPI {method} {path} has no responses"))?;
            let admitted = !super::PROBE_PATHS.contains(&path.as_str());
            for status in service_wide_responses(admitted).keys() {
                if !responses.contains_key(status) {
                    undocumented_statuses.push(format!(
                        "{} {path} does not document the service-wide {status}",
                        method.to_ascii_uppercase()
                    ));
                }
            }
            if recently_authenticated
                .iter()
                .any(|&(gated, verb)| gated == path && verb == method)
                && !responses
                    .get("403")
                    .and_then(|response| response["description"].as_str())
                    .is_some_and(|description| {
                        description.contains(super::REAUTHENTICATION_REQUIRED)
                    })
            {
                undocumented_statuses.push(format!(
                    "{} {path} requires a recent sign-in but its 403 does not name {}",
                    method.to_ascii_uppercase(),
                    super::REAUTHENTICATION_REQUIRED
                ));
            }
            if rate_limited
                .iter()
                .any(|&(limited, verb)| limited == path && verb == method)
                && !responses.contains_key("429")
            {
                undocumented_statuses.push(format!(
                    "{} {path} spends the authentication budget but does not document 429",
                    method.to_ascii_uppercase()
                ));
            }
            if operation_authenticates_an_account(operation) {
                for status in standard_authenticated_responses().keys() {
                    if !responses.contains_key(status) {
                        undocumented_statuses.push(format!(
                            "{} {path} is authenticated but does not document {status}",
                            method.to_ascii_uppercase()
                        ));
                    }
                }
            }
            let takes_json_body = operation
                .pointer("/requestBody/content/application~1json")
                .is_some();
            if (takes_json_body || !documented_query_parameters.is_empty())
                && !responses.contains_key("400")
            {
                undocumented_statuses.push(format!(
                    "{} {path} takes a JSON body or query parameters but does not document 400",
                    method.to_ascii_uppercase()
                ));
            }
        }
    }
    if !undocumented_statuses.is_empty() {
        return Err(format!(
            "OpenAPI responses incomplete: [{}]",
            undocumented_statuses.join("; ")
        ));
    }
    Ok(())
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
    const CONSOLE_READ_OPERATIONS: &[(&str, &str)] = &[
        ("/api/v1/admin/observability", "get"),
        ("/api/v1/admin/logs", "get"),
        ("/api/v1/admin/stats", "get"),
        ("/api/v1/admin/accounts", "get"),
        ("/api/v1/admin/invitations", "get"),
        ("/api/v1/admin/connections", "get"),
        ("/api/v1/admin/channels", "get"),
        ("/api/v1/admin/bans", "get"),
        ("/api/v1/admin/audit", "get"),
        ("/api/v1/admin/configuration", "get"),
        ("/api/v1/admin/networks", "get"),
        ("/api/v1/me/profile", "get"),
        ("/api/v1/me/sessions", "get"),
        ("/api/v1/me/connections", "get"),
        ("/api/v1/me/identities", "get"),
        ("/api/v1/me/tokens", "get"),
        ("/api/v1/me/read-markers", "get"),
        ("/api/v1/me/credentials", "get"),
        ("/api/v1/me/networks", "get"),
        ("/api/v1/me/networks/{name}", "get"),
        ("/api/v1/me/networks/{name}/operations", "get"),
        ("/api/v1/me/networks/{name}/buffer", "get"),
        ("/api/v1/me/channels", "get"),
    ];
    const CONSOLE_JSON_MUTATIONS: &[(&str, &str, &str)] = &[
        ("/api/v1/admin/accounts", "post", "201"),
        ("/api/v1/admin/accounts/{id}", "patch", "200"),
        ("/api/v1/admin/accounts/{id}", "delete", "200"),
        ("/api/v1/admin/bans", "post", "201"),
        ("/api/v1/admin/configuration", "patch", "200"),
        ("/api/v1/admin/configuration/networks", "post", "200"),
        (
            "/api/v1/admin/configuration/networks/{name}",
            "delete",
            "200",
        ),
        ("/api/v1/admin/configuration/oidc-providers", "post", "200"),
        (
            "/api/v1/admin/configuration/oidc-providers/{name}",
            "delete",
            "200",
        ),
        ("/api/v1/admin/configuration/opers", "post", "200"),
        ("/api/v1/admin/configuration/opers/{name}", "delete", "200"),
        ("/api/v1/admin/invitations", "post", "201"),
        ("/api/v1/admin/networks/{owner}/{name}", "patch", "200"),
        ("/api/v1/me/channels", "post", "201"),
        ("/api/v1/me/channels/{name}", "patch", "200"),
        ("/api/v1/me/channels/{name}", "delete", "200"),
        ("/api/v1/me/channels/{name}/access/{account}", "put", "200"),
        (
            "/api/v1/me/channels/{name}/access/{account}",
            "delete",
            "200",
        ),
        ("/api/v1/me/credentials", "post", "201"),
        ("/api/v1/me/networks", "post", "201"),
        ("/api/v1/me/network-preflight", "post", "200"),
        ("/api/v1/me/networks/{name}", "patch", "200"),
        ("/api/v1/me/sessions", "delete", "200"),
        ("/api/v1/me/tokens", "post", "201"),
    ];
    const CONSOLE_JSON_REQUESTS: &[(&str, &str)] = &[
        ("/api/v1/admin/accounts", "post"),
        ("/api/v1/admin/accounts/{id}", "patch"),
        ("/api/v1/admin/accounts/{id}", "delete"),
        ("/api/v1/admin/bans", "post"),
        ("/api/v1/admin/configuration", "patch"),
        ("/api/v1/admin/configuration/networks", "post"),
        ("/api/v1/admin/configuration/networks/{name}", "delete"),
        ("/api/v1/admin/configuration/oidc-providers", "post"),
        (
            "/api/v1/admin/configuration/oidc-providers/{name}",
            "delete",
        ),
        ("/api/v1/admin/configuration/opers", "post"),
        ("/api/v1/admin/configuration/opers/{name}", "delete"),
        ("/api/v1/admin/invitations", "post"),
        ("/api/v1/admin/networks/{owner}/{name}", "patch"),
        ("/api/v1/me/profile", "patch"),
        ("/api/v1/me/account", "delete"),
        ("/api/v1/me/password", "put"),
        ("/api/v1/me/channels", "post"),
        ("/api/v1/me/channels/{name}", "patch"),
        ("/api/v1/me/channels/{name}/access/{account}", "put"),
        ("/api/v1/me/credentials", "post"),
        ("/api/v1/me/networks", "post"),
        ("/api/v1/me/network-preflight", "post"),
        ("/api/v1/me/networks/{name}", "put"),
        ("/api/v1/me/networks/{name}", "patch"),
        ("/api/v1/me/tokens", "post"),
    ];
    const CHAT_READ_OPERATIONS: &[(&str, &str)] = &[
        ("/api/v1/me", "get"),
        ("/api/v1/me/networks", "get"),
        ("/api/v1/me/networks/{name}", "get"),
        ("/api/v1/me/networks/{name}/buffer", "get"),
        ("/api/v1/network-presets", "get"),
    ];

    #[test]
    fn openapi_covers_every_documented_router_operation_exactly() {
        let spec = super::document();
        assert_eq!(super::validate_documented_operations(&spec), Ok(()));
    }

    /// Which operations spend the authentication budget is read from their
    /// handlers' signatures, so the contract says so for each without anyone
    /// listing them — and a document that drops one is refused.
    #[test]
    fn every_rate_limited_operation_documents_its_429() {
        let limited = super::rate_limited_operations();
        for operation in [
            ("/api/v1/auth/oidc/{provider}/callback", "get"),
            ("/api/v1/auth/oidc/frontchannel-logout", "get"),
            ("/api/v1/auth/device/start", "post"),
            ("/api/v1/auth/device/token", "post"),
            ("/api/v1/auth/app-passwords", "post"),
        ] {
            assert!(limited.contains(&operation), "{operation:?} not detected");
        }
        assert!(!limited.contains(&("/api/v1/me", "get")));
        let spec = super::document();
        for (path, method) in &limited {
            let responses = &spec["paths"][path][method]["responses"];
            assert!(responses["429"].is_object(), "{method} {path}");
            assert!(responses["408"].is_object() && responses["413"].is_object());
        }
        assert_eq!(
            spec["paths"]["/api/v1/auth/device/start"]["post"]["responses"]["429"]["description"],
            super::RATE_LIMITED_RESPONSE
        );
        let mut dropped = spec.clone();
        dropped["paths"]["/api/v1/auth/oidc/{provider}/callback"]["get"]["responses"]
            .as_object_mut()
            .expect("responses")
            .remove("429");
        let error = super::validate_documented_operations(&dropped).expect_err("dropped 429");
        assert!(error.contains("callback"), "{error}");
    }

    /// The service's own bounds answer before any handler: every operation
    /// can meet the deadline and the body limit, and every one the admission
    /// bounds see can meet the per-address in-flight bound.
    #[test]
    fn every_operation_documents_the_service_wide_statuses() {
        let spec = super::document();
        for &(path, method) in super::super::DOCUMENTED_ROUTE_OPERATIONS {
            let responses = &spec["paths"][path][method]["responses"];
            for status in ["408", "413"] {
                assert!(
                    responses[status].is_object(),
                    "{method} {path} lacks {status}"
                );
            }
            assert_eq!(
                responses["429"].is_object(),
                !super::super::PROBE_PATHS.contains(&path),
                "{method} {path}"
            );
        }
        let mut dropped = spec.clone();
        dropped["paths"]["/api/v1/server"]["get"]["responses"]
            .as_object_mut()
            .expect("responses")
            .remove("413");
        assert!(super::validate_documented_operations(&dropped).is_err());
    }

    #[test]
    fn a_literal_segment_beside_a_parameter_is_a_route_collision() {
        let table = |paths: &[&'static str]| paths.iter().copied().collect();
        assert_eq!(
            super::colliding_route_patterns(&table(&[
                "/api/v1/me/networks",
                "/api/v1/me/networks/preflight",
                "/api/v1/me/networks/{name}",
                "/api/v1/me/networks/{name}/buffer",
            ])),
            Some((
                "/api/v1/me/networks/preflight",
                "/api/v1/me/networks/{name}"
            ))
        );
        assert_eq!(
            super::colliding_route_patterns(&table(&[
                "/api/v1/admin/networks/{owner}/{name}",
                "/api/v1/admin/networks/shared/{name}",
            ])),
            Some((
                "/api/v1/admin/networks/shared/{name}",
                "/api/v1/admin/networks/{owner}/{name}"
            ))
        );
        // A literal one level above a parameter's subtree shadows nothing: no
        // URL has both lengths.
        assert_eq!(
            super::colliding_route_patterns(&table(&[
                "/api/v1/auth/oidc/backchannel-logout",
                "/api/v1/auth/oidc/{provider}/start",
                "/api/v1/me/network-preflight",
                "/api/v1/me/networks/{name}",
            ])),
            None
        );
    }

    /// The server has one channel type (`CHANTYPES=#`); a contract that also
    /// offers `&`, `+`, and `!` documents requests that can only be refused.
    #[test]
    fn channel_registration_documents_the_channel_names_the_server_accepts() {
        let spec = super::document();
        let name = &spec["paths"]["/api/v1/me/channels"]["post"]["requestBody"]["content"]["application/json"]
            ["schema"]["properties"]["name"];
        let pattern = name["pattern"].as_str().expect("channel name pattern");
        assert_eq!(pattern, "^#");
        assert_eq!(name["maxLength"], crate::sanitize::CHANNELLEN);
        for refused in ["&local", "+modeless", "!safe"] {
            assert!(!crate::sanitize::valid_channel_name(refused), "{refused}");
        }
    }

    #[test]
    fn network_operations_reuses_the_network_runtime_contract() {
        let spec = super::document();
        let network_runtime = &spec["paths"]["/api/v1/me/networks/{name}"]["get"]["responses"]["200"]
            ["content"]["application/json"]["schema"]["properties"]["runtime"];
        let operations_runtime = &spec["paths"]["/api/v1/me/networks/{name}/operations"]["get"]["responses"]
            ["200"]["content"]["application/json"]["schema"]["properties"]["runtime"];
        assert_eq!(operations_runtime, network_runtime);
    }

    #[test]
    fn openapi_rejects_a_route_path_parameter_missing_from_an_operation() {
        let mut spec = super::document();
        spec["paths"]["/api/v1/me/tokens/{id}"]["delete"]
            .as_object_mut()
            .expect("token deletion operation")
            .remove("parameters");
        assert!(
            super::validate_documented_operations(&spec)
                .expect_err("missing path parameter must reject the contract")
                .contains("/api/v1/me/tokens/{id} path parameters differ")
        );
    }

    #[test]
    fn openapi_rejects_path_item_parameters() {
        let mut spec = super::document();
        spec["paths"]["/api/v1/me/tokens/{id}"]["parameters"] = serde_json::json!([]);
        assert!(
            super::validate_documented_operations(&spec)
                .expect_err("unsupported path-item parameters must reject the contract")
                .contains("unsupported path-item parameters")
        );
    }

    #[test]
    fn database_identifier_path_parameters_are_positive() {
        let spec = super::document();
        for path in [
            "/api/v1/me/sessions/{id}",
            "/api/v1/me/identities/{id}",
            "/api/v1/me/tokens/{id}",
            "/api/v1/me/credentials/{id}",
            "/api/v1/admin/accounts/{id}",
            "/api/v1/admin/invitations/{id}",
            "/api/v1/admin/bans/{id}",
        ] {
            for (_, operation) in spec["paths"][path].as_object().expect("documented path") {
                assert_eq!(operation["parameters"][0]["schema"]["minimum"], 1, "{path}");
            }
        }
    }

    #[test]
    fn console_reads_have_closed_json_response_schemas() {
        let spec = super::document();
        for (path, method) in CONSOLE_READ_OPERATIONS {
            let schema = &spec["paths"][path][method]["responses"]["200"]["content"]["application/json"]
                ["schema"];
            assert_eq!(schema["type"], "object", "{method} {path}");
            assert_eq!(schema["additionalProperties"], false, "{method} {path}");
        }
    }

    #[test]
    fn console_json_mutations_have_closed_response_schemas() {
        let spec = super::document();
        for (path, method, status) in CONSOLE_JSON_MUTATIONS {
            let schema = &spec["paths"][path][method]["responses"][status]["content"]["application/json"]
                ["schema"];
            assert!(schema.is_object(), "{method} {path}");
            if schema.get("oneOf").is_none() {
                assert_eq!(schema["type"], "object", "{method} {path}");
                assert_eq!(schema["additionalProperties"], false, "{method} {path}");
            }
        }
    }

    #[test]
    fn console_json_requests_have_closed_object_branches() {
        fn assert_closed_object_branch(schema: &serde_json::Value, path: &str, method: &str) {
            if let Some(branches) = schema.get("oneOf").and_then(serde_json::Value::as_array) {
                assert!(!branches.is_empty(), "{method} {path}");
                for branch in branches {
                    assert_closed_object_branch(branch, path, method);
                }
                return;
            }
            assert_eq!(schema["type"], "object", "{method} {path}");
            assert_eq!(schema["additionalProperties"], false, "{method} {path}");
        }

        let spec = super::document();
        for (path, method) in CONSOLE_JSON_REQUESTS {
            let schema = &spec["paths"][path][method]["requestBody"]["content"]["application/json"]
                ["schema"];
            assert_closed_object_branch(schema, path, method);
        }
    }

    /// `PUT` is a full replacement: the contract and the parser agree that the
    /// autojoin list cannot be omitted, where omission once cleared it.
    #[test]
    fn network_replace_requires_the_autojoin_list() {
        let spec = super::document();
        let replace = &spec["paths"]["/api/v1/me/networks/{name}"]["put"]["requestBody"]["content"]
            ["application/json"]["schema"];
        let required: Vec<&str> = replace["required"]
            .as_array()
            .expect("required list")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        assert!(required.contains(&"autojoin"), "{required:?}");
        assert!(
            replace["properties"]["realname"]["description"]
                .as_str()
                .is_some_and(|text| text.contains("Required when the stored network is kind=irc")),
            "{replace}"
        );
        let without = serde_json::json!({
            "addr": "irc.example.net:6697", "tls": true, "nick": "n",
            "username": "n", "realname": "n",
            "credentials": { "action": "keep" }, "server_password": { "action": "keep" }
        });
        let refused = serde_json::from_value::<super::UpdateNetwork>(without.clone())
            .err()
            .expect("an omitted autojoin is refused");
        assert!(refused.to_string().contains("autojoin"), "{refused}");
        let mut with = without;
        with["autojoin"] = serde_json::json!([]);
        assert!(serde_json::from_value::<super::UpdateNetwork>(with).is_ok());
    }

    #[test]
    fn network_request_optionality_matches_the_kind_contract() {
        let spec = super::document();
        let create = &spec["paths"]["/api/v1/me/networks"]["post"]["requestBody"]["content"]["application/json"]
            ["schema"]["oneOf"];
        assert_eq!(create[0]["properties"]["realname"]["type"], "string");
        for field in ["sasl_account", "sasl_password"] {
            assert_eq!(
                create[0]["properties"][field]["type"],
                serde_json::json!(["string", "null"]),
                "IRC {field}",
            );
        }
        let managed = &spec["paths"]["/api/v1/admin/configuration/networks"]["post"]["requestBody"]
            ["content"]["application/json"]["schema"]["oneOf"];
        assert_eq!(managed.as_array().map(Vec::len), Some(5));
        assert_eq!(managed[0]["properties"]["kind"]["const"], "irc");
        assert_eq!(managed[4]["properties"]["kind"]["const"], "slack");
        assert!(managed[3]["properties"].get("nick").is_none());
        assert!(managed[2]["properties"].get("realname").is_none());
        for variant in [1, 2, 3] {
            assert_eq!(
                create[variant]["properties"]["sasl_password"]["type"],
                "string"
            );
        }
        assert_eq!(create[3]["properties"]["sasl_account"]["type"], "string");
        let preflight = &spec["paths"]["/api/v1/me/network-preflight"]["post"]["requestBody"]["content"]
            ["application/json"]["schema"];
        assert_eq!(preflight["properties"]["realname"]["type"], "string");
        for field in ["sasl_account", "sasl_password"] {
            assert_eq!(
                preflight["properties"][field]["type"],
                serde_json::json!(["string", "null"]),
                "preflight {field}",
            );
        }
    }

    /// The server password is write-only everywhere it is accepted, a boolean
    /// wherever it is reported, and an explicit action on replace — never an
    /// omitted field that would have to mean keep or erase.
    #[test]
    fn the_server_password_is_write_only_and_replaced_by_an_explicit_action() {
        let spec = super::document();
        let create = &spec["paths"]["/api/v1/me/networks"]["post"]["requestBody"]["content"]["application/json"]
            ["schema"]["oneOf"];
        let pass = &create[0]["properties"]["server_password"];
        assert_eq!(pass["type"], serde_json::json!(["string", "null"]));
        assert_eq!(pass["writeOnly"], true);
        assert_eq!(pass["maxLength"], e6irc_client::ServerPassword::MAX_LEN);
        for variant in [1, 2, 3] {
            assert!(
                create[variant]["properties"]
                    .get("server_password")
                    .is_none()
            );
        }
        let preflight = &spec["paths"]["/api/v1/me/network-preflight"]["post"]["requestBody"]["content"]
            ["application/json"]["schema"];
        assert_eq!(
            preflight["properties"]["server_password"]["writeOnly"],
            true
        );
        let replace = &spec["paths"]["/api/v1/me/networks/{name}"]["put"]["requestBody"]["content"]
            ["application/json"]["schema"];
        assert!(
            replace["required"]
                .as_array()
                .expect("required")
                .contains(&serde_json::json!("server_password"))
        );
        let actions: Vec<_> = replace["properties"]["server_password"]["oneOf"]
            .as_array()
            .expect("tagged actions")
            .iter()
            .map(|branch| branch["properties"]["action"]["const"].clone())
            .collect();
        assert_eq!(actions, ["keep", "remove", "set"]);
        let network = &spec["paths"]["/api/v1/me/networks/{name}"]["get"]["responses"]["200"]["content"]
            ["application/json"]["schema"];
        assert_eq!(
            network["properties"]["has_server_password"]["type"],
            "boolean"
        );
        assert!(network["properties"].get("server_password").is_none());
        let managed = &spec["paths"]["/api/v1/admin/configuration/networks"]["post"]["requestBody"]
            ["content"]["application/json"]["schema"]["oneOf"];
        assert_eq!(
            managed[0]["properties"]["server_password"]["writeOnly"],
            true
        );
        for variant in [1, 2, 3, 4] {
            assert!(
                managed[variant]["properties"]
                    .get("server_password")
                    .is_none()
            );
        }
    }

    #[test]
    fn browser_chat_reads_have_closed_json_response_schemas() {
        let spec = super::document();
        for (path, method) in CHAT_READ_OPERATIONS {
            let schema = &spec["paths"][path][method]["responses"]["200"]["content"]["application/json"]
                ["schema"];
            assert_eq!(schema["type"], "object", "{method} {path}");
            assert_eq!(schema["additionalProperties"], false, "{method} {path}");
        }
    }

    #[test]
    fn network_response_accepts_the_local_driver() {
        let spec = super::document();
        let kinds = &spec["paths"]["/api/v1/me/networks"]["get"]["responses"]["200"]["content"]["application/json"]
            ["schema"]["properties"]["networks"]["items"]["properties"]["kind"]["enum"];
        assert!(
            kinds
                .as_array()
                .is_some_and(|values| values.contains(&serde_json::json!("local")))
        );
    }
}
