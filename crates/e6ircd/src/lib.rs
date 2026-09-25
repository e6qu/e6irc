//! e6ircd library surface (consumed by the binary and by tests).

// The hand-authored OpenAPI spec is one large `serde_json::json!` literal
// whose nesting exceeds the default macro recursion limit.
#![recursion_limit = "512"]

pub mod bouncer;
pub(crate) mod certificate;
pub mod config;
pub mod core;
pub mod db;
pub mod egress;
pub mod environment_config;
pub mod http;
pub mod identity;
pub mod net;
pub(crate) mod observability;
pub(crate) mod peer_write;
pub(crate) mod recency;
pub(crate) mod sanitize;
pub mod secret;
