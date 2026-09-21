//! e6irc-tui internals. The app state (terminal-independent) and the key
//! bindings are library code so they can be unit-tested; the binary wires
//! them to a terminal and a live connection.

pub mod app;
pub mod keys;
pub mod reconnect;
