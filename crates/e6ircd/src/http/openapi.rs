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
    let app_password_created_response = json_response_status(
        201,
        "the app password, shown once",
        serde_json::json!({
            "type": "object", "additionalProperties": false, "required": ["app_password", "label", "note"],
            "properties": { "app_password": { "type": "string", "minLength": 1 }, "label": { "type": "string" }, "note": { "type": "string" } }
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
    let network_response_schema = serde_json::json!({
        "type": "object", "additionalProperties": false,
        "required": ["name", "kind", "addr", "tls", "nick", "realname", "autojoin", "sasl_account", "has_sasl_account", "has_sasl_password", "enabled", "connected", "runtime"],
        "properties": {
            "name": { "type": "string", "minLength": 1 },
            "kind": { "type": "string", "enum": ["irc", "local", "matrix", "discord", "slack"] },
            "addr": { "type": "string" }, "tls": { "type": "boolean" }, "nick": { "type": "string" },
            "realname": { "type": ["string", "null"] },
            "autojoin": { "type": "array", "items": { "type": "string" } },
            "sasl_account": { "type": ["string", "null"] },
            "has_sasl_account": { "type": "boolean" }, "has_sasl_password": { "type": "boolean" },
            "enabled": { "type": "boolean" }, "connected": { "type": ["boolean", "null"] },
            "runtime": { "oneOf": [
                { "type": "null" },
                { "type": "object", "additionalProperties": false,
                    "required": ["state", "state_changed_at", "next_retry_at", "recent_failures", "connected_at", "last_input_at", "last_output_at", "last_error_at", "last_error", "connect_latency_ms", "connection_attempts", "errors", "attached_clients", "traffic", "buffer"],
                    "properties": {
                        "state": { "type": "string", "enum": ["connecting", "connected", "reconnecting", "authentication_failed", "registration_failed"] },
                        "state_changed_at": { "type": "string" }, "next_retry_at": { "type": ["string", "null"] },
                        "recent_failures": { "type": "array", "items": {
                            "type": "object", "additionalProperties": false, "required": ["at", "code", "summary"],
                            "properties": { "at": { "type": "string" }, "code": { "type": "string" }, "summary": { "type": "string" } }
                        } },
                        "connected_at": { "type": ["string", "null"] }, "last_input_at": { "type": ["string", "null"] },
                        "last_output_at": { "type": ["string", "null"] }, "last_error_at": { "type": ["string", "null"] },
                        "last_error": { "oneOf": [
                            { "type": "null" },
                            { "type": "object", "additionalProperties": false, "required": ["code", "summary"],
                                "properties": { "code": { "type": "string" }, "summary": { "type": "string" } } }
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
                "properties": { "lines": { "type": "array", "items": { "type": "string" } } }
            }
        } } }
    });
    let network_response = json_response(
        "stored network configuration and runtime",
        network_response_schema,
    );
    let network_operations_response = json_response(
        "network Operations projection",
        serde_json::json!({
            "type": "object", "additionalProperties": false,
            "required": ["state", "connected", "state_changed", "next_retry", "recent_failures", "connected_since", "last_input", "last_output", "last_error", "last_error_reason", "connect_latency", "connection_attempts", "errors", "attached_clients", "traffic_in", "traffic_out", "lines_in", "lines_out", "memory_buffer", "stored_lines", "stored_oldest", "stored_newest", "recent_lines"],
            "properties": {
                "state": { "type": "string" }, "connected": { "type": "boolean" }, "state_changed": { "type": "string" }, "next_retry": { "type": "string" },
                "recent_failures": { "type": "array", "items": { "type": "string" } }, "connected_since": { "type": "string" },
                "last_input": { "type": "string" }, "last_output": { "type": "string" }, "last_error": { "type": "string" },
                "last_error_reason": { "type": "string" }, "connect_latency": { "type": "string" },
                "connection_attempts": { "type": "integer", "minimum": 0 }, "errors": { "type": "integer", "minimum": 0 },
                "attached_clients": { "type": "integer", "minimum": 0 }, "traffic_in": { "type": "string" }, "traffic_out": { "type": "string" },
                "lines_in": { "type": "integer", "minimum": 0 }, "lines_out": { "type": "integer", "minimum": 0 },
                "memory_buffer": { "type": "string" }, "stored_lines": { "type": "integer", "minimum": 0 },
                "stored_oldest": { "type": "string" }, "stored_newest": { "type": "string" }, "recent_lines": { "type": "array", "items": { "type": "string" } }
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
                "properties": { "id": { "type": "integer", "minimum": 1 }, "name": { "type": "string" }, "founder": { "type": "string" }, "created_at": { "type": "string" }, "policy": { "type": "object", "additionalProperties": false, "required": ["keeptopic", "topic_retained", "mlock", "access_entries"], "properties": { "keeptopic": { "type": "boolean" }, "topic_retained": { "type": ["string", "null"] }, "mlock": { "type": "string" }, "access_entries": { "type": "integer", "minimum": 0 } } } }
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
            "command_burst": { "type": ["integer", "null"], "minimum": 1 },
            "trusted_proxies": { "type": "array", "items": { "type": "string" } },
            "auth_rate_burst": { "type": ["integer", "null"], "minimum": 1 },
            "api_rate_burst": { "type": ["integer", "null"], "minimum": 1 },
            "administrator_api_rate_burst": { "type": ["integer", "null"], "minimum": 1 },
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
    let scalar_settings_schema = serde_json::json!({
        "type": "object",
        "additionalProperties": false,
        "required": [
            "server_name", "network_name", "description", "motd", "nicklen", "sendq",
            "core_queue", "core_workers", "max_hot_channels", "listeners", "registration", "limits",
            "observability", "storage", "bnc_addr", "public_url", "secure_cookies",
            "admin_accounts"
        ],
        "properties": {
            "server_name": { "type": "string" },
            "network_name": { "type": "string" },
            "description": { "type": "string" },
            "motd": { "type": "array", "items": { "type": "string" } },
            "nicklen": { "type": "integer", "minimum": 1, "maximum": 64 },
            "sendq": { "type": "integer", "minimum": 1 },
            "core_queue": { "type": "integer", "minimum": 1 },
            "core_workers": { "type": "integer", "minimum": 1 },
            "max_hot_channels": { "type": "integer", "minimum": 1 },
            "listeners": { "type": "array", "items": listener_schema },
            "registration": registration_schema,
            "limits": limits_schema,
            "observability": observability_schema,
            "storage": storage_schema,
            "bnc_addr": { "type": ["string", "null"] },
            "public_url": { "type": ["string", "null"] },
            "secure_cookies": { "type": "boolean" },
            "admin_accounts": { "type": "array", "items": { "type": "string" } }
        }
    });
    let mut configuration_settings_schema = scalar_settings_schema.clone();
    let configuration_properties = configuration_settings_schema["properties"]
        .as_object_mut()
        .expect("configuration settings properties are an object");
    configuration_properties.insert("opers".into(), serde_json::json!({
        "type": "array", "items": { "type": "object", "additionalProperties": false,
            "required": ["name", "password"], "properties": { "name": { "type": "string" }, "password": { "type": "string" } } }
    }));
    configuration_properties.insert("oidc_providers".into(), serde_json::json!({
        "type": "array", "items": { "type": "object", "additionalProperties": false,
            "required": ["name", "issuer_url", "client_id", "client_secret", "scopes", "allowed_email_domains", "end_session_endpoint", "token_endpoint_auth_method"],
            "properties": { "name": { "type": "string" }, "issuer_url": { "type": "string" }, "client_id": { "type": "string" }, "client_secret": { "type": "string" }, "scopes": { "type": "array", "items": { "type": "string" } }, "allowed_email_domains": { "type": "array", "items": { "type": "string" } }, "end_session_endpoint": { "type": ["string", "null"] }, "token_endpoint_auth_method": { "type": "string", "enum": ["client_secret_basic", "client_secret_post"] } } }
    }));
    configuration_properties.insert("networks".into(), serde_json::json!({
        "type": "array", "items": { "type": "object", "additionalProperties": false,
            "required": ["name", "owner", "kind", "addr", "tls", "nick", "realname", "autojoin", "buffer_cap", "sasl_account", "sasl_password"],
            "properties": { "name": { "type": "string" }, "owner": { "type": ["string", "null"] }, "kind": { "type": "string", "enum": ["irc", "local", "matrix", "discord", "slack"] }, "addr": { "type": "string" }, "tls": { "type": "boolean" }, "nick": { "type": "string" }, "realname": { "type": ["string", "null"] }, "autojoin": { "type": "array", "items": { "type": "string" } }, "buffer_cap": { "type": "integer", "minimum": 1 }, "sasl_account": { "type": ["string", "null"] }, "sasl_password": { "type": ["string", "null"] } } }
    }));
    configuration_properties.insert(
        "credentials_from_bootstrap".into(),
        serde_json::json!({
            "type": "boolean"
        }),
    );
    configuration_settings_schema["required"]
        .as_array_mut()
        .expect("configuration settings required fields are an array")
        .extend([
            serde_json::json!("opers"),
            serde_json::json!("oidc_providers"),
            serde_json::json!("networks"),
            serde_json::json!("credentials_from_bootstrap"),
        ]);
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
    let monitoring_response = json_response(
        "monitoring view",
        serde_json::json!({
            "type": "object", "additionalProperties": false,
            "required": ["core_ready", "database_ready", "active_connections", "registered_connections", "channels", "opened_total", "rejected_total", "traffic_in", "traffic_out", "upstream_in", "upstream_out", "inbound_rate", "outbound_rate", "upstream_inbound_rate", "upstream_outbound_rate", "http_requests", "database_requests", "bnc_connected", "bnc_networks", "upstreams_ready", "upstreams_degraded", "bnc_clients", "error_total", "sendq_kills", "core_p50", "core_p95", "core_p99", "database_p50", "database_p95", "database_p99", "http_p50", "http_p95", "http_p99", "traffic_bars", "upstream_traffic_bars", "connection_bars", "upstream_bars", "error_bars", "latency_bars", "queue_bars", "queues", "errors", "sampled_age", "history_samples", "window_label", "window_minutes", "window_links"],
            "properties": {
                "core_ready": { "type": "boolean" }, "database_ready": { "type": "boolean" }, "active_connections": { "type": "integer", "minimum": 0 }, "registered_connections": { "type": "integer", "minimum": 0 }, "channels": { "type": "integer", "minimum": 0 }, "opened_total": { "type": "integer", "minimum": 0 }, "rejected_total": { "type": "integer", "minimum": 0 },
                "traffic_in": { "type": "string" }, "traffic_out": { "type": "string" }, "upstream_in": { "type": "string" }, "upstream_out": { "type": "string" }, "inbound_rate": { "type": "string" }, "outbound_rate": { "type": "string" }, "upstream_inbound_rate": { "type": "string" }, "upstream_outbound_rate": { "type": "string" },
                "http_requests": { "type": "integer", "minimum": 0 }, "database_requests": { "type": "integer", "minimum": 0 }, "bnc_connected": { "type": "integer", "minimum": 0 }, "bnc_networks": { "type": "integer", "minimum": 0 }, "upstreams_ready": { "type": "boolean" }, "upstreams_degraded": { "type": "boolean" }, "bnc_clients": { "type": "integer", "minimum": 0 }, "error_total": { "type": "integer", "minimum": 0 }, "sendq_kills": { "type": "integer", "minimum": 0 },
                "core_p50": { "type": "string" }, "core_p95": { "type": "string" }, "core_p99": { "type": "string" }, "database_p50": { "type": "string" }, "database_p95": { "type": "string" }, "database_p99": { "type": "string" }, "http_p50": { "type": "string" }, "http_p95": { "type": "string" }, "http_p99": { "type": "string" },
                "traffic_bars": { "type": "array", "items": { "type": "object", "additionalProperties": false, "required": ["inbound_height", "outbound_height", "title"], "properties": { "inbound_height": { "type": "integer", "minimum": 0, "maximum": 100 }, "outbound_height": { "type": "integer", "minimum": 0, "maximum": 100 }, "title": { "type": "string" } } } },
                "upstream_traffic_bars": { "type": "array", "items": { "type": "object", "additionalProperties": false, "required": ["inbound_height", "outbound_height", "title"], "properties": { "inbound_height": { "type": "integer", "minimum": 0, "maximum": 100 }, "outbound_height": { "type": "integer", "minimum": 0, "maximum": 100 }, "title": { "type": "string" } } } },
                "connection_bars": { "type": "array", "items": { "type": "object", "additionalProperties": false, "required": ["irc_height", "bnc_height", "title"], "properties": { "irc_height": { "type": "integer", "minimum": 0, "maximum": 100 }, "bnc_height": { "type": "integer", "minimum": 0, "maximum": 100 }, "title": { "type": "string" } } } },
                "upstream_bars": { "type": "array", "items": { "type": "object", "additionalProperties": false, "required": ["height", "status_class", "title"], "properties": { "height": { "type": "integer", "minimum": 0, "maximum": 100 }, "status_class": { "type": "string", "enum": ["bar-off", "bar-ok", "bar-warn"] }, "title": { "type": "string" } } } },
                "error_bars": { "type": "array", "items": { "type": "object", "additionalProperties": false, "required": ["height", "title"], "properties": { "height": { "type": "integer", "minimum": 0, "maximum": 100 }, "title": { "type": "string" } } } },
                "latency_bars": { "type": "array", "items": { "type": "object", "additionalProperties": false, "required": ["core_height", "database_height", "http_height", "title"], "properties": { "core_height": { "type": "integer", "minimum": 0, "maximum": 100 }, "database_height": { "type": "integer", "minimum": 0, "maximum": 100 }, "http_height": { "type": "integer", "minimum": 0, "maximum": 100 }, "title": { "type": "string" } } } },
                "queue_bars": { "type": "array", "items": { "type": "object", "additionalProperties": false, "required": ["core_height", "database_height", "title"], "properties": { "core_height": { "type": "integer", "minimum": 0, "maximum": 100 }, "database_height": { "type": "integer", "minimum": 0, "maximum": 100 }, "title": { "type": "string" } } } },
                "queues": { "type": "array", "items": { "type": "object", "additionalProperties": false, "required": ["label", "depth", "capacity", "pressure", "mode", "mode_switches"], "properties": { "label": { "type": "string" }, "depth": { "type": "integer", "minimum": 0 }, "capacity": { "type": "integer", "minimum": 1 }, "pressure": { "type": "integer", "minimum": 0, "maximum": 100 }, "mode": { "type": "string" }, "mode_switches": { "type": "integer", "minimum": 0 } } } },
                "errors": { "type": "array", "items": { "type": "object", "additionalProperties": false, "required": ["kind", "count", "last_seen"], "properties": { "kind": { "type": "string" }, "count": { "type": "integer", "minimum": 1 }, "last_seen": { "type": "string" } } } },
                "sampled_age": { "type": "string" }, "history_samples": { "type": "integer", "minimum": 0 }, "window_label": { "type": "string" }, "window_minutes": { "type": "integer", "enum": [60, 360, 1440, 10080] }, "window_links": { "type": "array", "items": { "type": "object", "additionalProperties": false, "required": ["label", "minutes", "active"], "properties": { "label": { "type": "string" }, "minutes": { "type": "integer", "enum": [60, 360, 1440, 10080] }, "active": { "type": "boolean" } } } }
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
                    "responses": profile_response
                },
                "patch": {
                    "summary": "Replace or remove your private contact email",
                    "description": "The address is parsed and bounded before storage. JSON null removes it. The audit event records only replaced/removed, never the address.",
                    "security": authenticated,
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
                        "200": security_activity_response["200"],
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
                        "200": browser_sessions_response["200"],
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
                    "security": authenticated, "responses": identities_response }
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
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": {
                            "type": "object", "additionalProperties": false,
                            "required": ["device_code"],
                            "properties": { "device_code": { "type": "string", "minLength": 1 } }
                        }
                    } } },
                    "responses": { "200": { "description": "access_token once approved" },
                        "400": { "description": "authorization_pending / expired_token / invalid_grant" } } }
            },
            "/api/v1/auth/device/approve": {
                "post": {
                    "summary": "Approve a device grant from a browser session",
                    "description": "Requires the cookie-authenticated session and its X-E6IRC-CSRF header. Personal access tokens cannot mint a replacement bearer through device approval.",
                    "requestBody": { "required": true, "content": { "application/json": {
                        "schema": {
                            "type": "object", "additionalProperties": false,
                            "required": ["user_code"],
                            "properties": { "user_code": { "type": "string", "minLength": 1 } }
                        }
                    } } },
                    "responses": { "204": { "description": "approved" },
                        "401": { "description": "browser session required" },
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
                    "security": authenticated, "responses": read_markers_response }
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
                                "name": { "type": "string", "pattern": "^[#&+!]" }
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
                    "security": authenticated,
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
                    "responses": { "201": network_created_response["201"],
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
                    "responses": { "200": network_response["200"],
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
                    "responses": { "200": network_enabled_response["200"],
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
                    "parameters": [{ "name": "id", "in": "path", "required": true, "schema": { "type": "integer", "format": "int64" } }],
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
                "patch": { "summary": "Update revisioned scalar managed configuration", "description": "Updates typed scalar settings while retaining OIDC, operator, and network credential collections from the current revision. A live BNC listener change is applied before persistence and rolled back if persistence fails.", "security": authenticated,
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
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "additionalProperties": false, "required": ["revision", "name", "issuer_url", "client_id", "client_secret", "token_endpoint_auth_method"], "properties": { "revision": { "type": "integer" }, "name": { "type": "string" }, "issuer_url": { "type": "string" }, "client_id": { "type": "string" }, "client_secret": { "type": "string", "writeOnly": true }, "scopes": { "type": "array", "items": { "type": "string" } }, "allowed_email_domains": { "type": "array", "items": { "type": "string" } }, "end_session_endpoint": { "type": "string" }, "token_endpoint_auth_method": { "type": "string", "enum": ["client_secret_basic", "client_secret_post"] } } } } } },
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
                    "requestBody": { "required": true, "content": { "application/json": { "schema": { "type": "object", "additionalProperties": false, "required": ["revision", "name", "kind", "tls", "buffer_cap"], "properties": { "revision": { "type": "integer" }, "name": { "type": "string" }, "owner": { "type": "string" }, "kind": { "type": "string", "enum": ["irc", "local", "matrix", "discord", "slack"] }, "addr": { "type": "string" }, "tls": { "type": "boolean" }, "nick": { "type": "string" }, "realname": { "type": "string" }, "autojoin": { "type": "array", "items": { "type": "string" } }, "buffer_cap": { "type": "integer", "minimum": 1 }, "sasl_account": { "type": "string", "writeOnly": true }, "sasl_password": { "type": "string", "writeOnly": true } } } } } },
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
                    "responses": { "200": admin_network_enabled_response["200"], "403": { "description": "not an admin account" }, "404": { "description": "network or bouncer missing" }, "503": { "description": "database unavailable" } } }
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
                    "responses": { "200": monitoring_response["200"], "400": { "description": "unsupported monitoring window" }, "403": { "description": "not an admin account" } }
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
    const CONSOLE_READ_OPERATIONS: &[(&str, &str)] = &[
        ("/api/v1/admin/monitoring", "get"),
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
        ("/api/v1/me/networks/preflight", "post", "200"),
        ("/api/v1/me/networks/{name}", "patch", "200"),
        ("/api/v1/me/sessions", "delete", "200"),
        ("/api/v1/me/tokens", "post", "201"),
    ];
    const CHAT_READ_OPERATIONS: &[(&str, &str)] = &[
        ("/api/v1/me", "get"),
        ("/api/v1/me/networks", "get"),
        ("/api/v1/me/networks/{name}/buffer", "get"),
    ];

    #[test]
    fn openapi_covers_every_documented_router_operation_exactly() {
        let spec = super::document();
        assert_eq!(super::validate_documented_operations(&spec), Ok(()));
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
