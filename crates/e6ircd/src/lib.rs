//! e6ircd library surface (consumed by the binary and by tests).

// The hand-authored OpenAPI spec is one large `serde_json::json!` literal
// whose nesting exceeds the default macro recursion limit.
#![recursion_limit = "512"]

pub(crate) mod account_authority;
pub(crate) mod account_deletion;
pub mod bouncer;
pub(crate) mod certificate;
pub mod config;
pub mod core;
pub mod db;
pub mod egress;
pub mod environment_config;
pub mod http;
pub mod identity;
pub(crate) mod lingering_close;
pub mod net;
pub(crate) mod observability;
pub(crate) mod peer_write;
pub(crate) mod recency;
pub(crate) mod sanitize;
pub mod secret;
pub(crate) mod settings_watch;

/// The commit this binary was built from: `E6IRC_BUILD_REVISION` at compile
/// time, which the container image and the native release archives set, or
/// the explicit `"unknown"` for a build that did not record one. Both
/// `e6ircd --version` and the `e6irc_build_info` metric report it.
pub const BUILD_REVISION: &str = match option_env!("E6IRC_BUILD_REVISION") {
    Some(revision) => revision,
    None => "unknown",
};
