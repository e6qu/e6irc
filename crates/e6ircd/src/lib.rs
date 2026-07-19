//! e6ircd library surface (consumed by the binary and by tests).

// The hand-authored OpenAPI spec is one large `serde_json::json!` literal
// whose nesting exceeds the default macro recursion limit.
#![recursion_limit = "256"]

pub mod bouncer;
pub mod config;
pub mod core;
pub mod db;
pub mod http;
pub mod net;
pub mod secret;
