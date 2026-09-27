//! The edge: everything that holds a client connection and nothing that
//! interprets what it carries (DESIGN §19.1). Listening and accepting, TLS
//! termination and certificate reload, who a client is, line and WebSocket
//! framing, and every write to a client, bounded. It reaches the core only
//! through a [`connection::CorePort`], and never the database: this crate
//! depends on no sqlx, no e6ircd and no bridge client, which
//! `tools/check-edge-isolation.sh` holds (DESIGN §2).

#![deny(clippy::let_underscore_must_use)]

pub mod address;
pub mod certificate;
pub mod connection;
pub mod lingering_close;
pub mod peer_write;
pub mod websocket;
