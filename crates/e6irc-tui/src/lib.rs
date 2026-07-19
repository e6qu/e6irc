//! e6irc-tui internals. The app state (terminal-independent) is
//! library code so it can be unit-tested; the binary wires it to a
//! terminal and a live connection.

pub mod app;
