//! The core link across a process boundary (DESIGN §19.2): mutual TLS
//! ([`tls`]), frames on a connection ([`io`]), and the edge's end of it
//! ([`remote`]). The frames themselves are the `e6irc-link` codec's; the
//! core's end is the core's.

pub mod io;
pub mod remote;
pub mod tls;
pub mod web;

/// The headers HTTP carries on a core link (DESIGN §19.1, "Plain HTTP"). The
/// edge sets the request headers on every request it forwards, replacing any
/// a client sent; the core reads them only from a link connection, which the
/// link's mutual TLS authenticates, and answers an upgrade it authorizes with
/// the grant headers, which the edge reads and never passes on.
pub mod headers {
    /// The address the client's connection came from (its socket peer, or
    /// the source a PROXY protocol header gave): the core resolves any
    /// forwarded address from it, as from its own socket's peer.
    pub const CLIENT: &str = "e6irc-edge-client";
    /// On a WebSocket upgrade the edge will complete: the connection
    /// identifier its session opens under.
    pub const UPGRADE: &str = "e6irc-edge-upgrade";
    /// The kind of listener the request came to, when it is a WebSocket IRC
    /// listener (`websocket-irc`), whose every path is `/ws/irc`.
    pub const LISTENER: &str = "e6irc-edge-listener";
    pub const WEBSOCKET_IRC_LISTENER: &str = "websocket-irc";
    /// The core authorized the upgrade: `irc` or `ui`.
    pub const GRANT: &str = "e6irc-edge-grant";
    /// The client's address as the session is shown under.
    pub const GRANT_ADDRESS: &str = "e6irc-edge-grant-address";
    /// `websocket`, or `wss` when a trusted proxy says its client reached it
    /// over HTTPS.
    pub const GRANT_TRANSPORT: &str = "e6irc-edge-grant-transport";
    /// The IRCv3 WebSocket subprotocol to answer with, when one was chosen.
    pub const GRANT_PROTOCOL: &str = "e6irc-edge-grant-protocol";
    /// A live chat socket's liveness interval, in milliseconds.
    pub const GRANT_LIVENESS_MS: &str = "e6irc-edge-grant-liveness-ms";

    /// Every header of this set, which the edge removes from what a client
    /// sends.
    pub const ALL: [&str; 8] = [
        CLIENT,
        UPGRADE,
        LISTENER,
        GRANT,
        GRANT_ADDRESS,
        GRANT_TRANSPORT,
        GRANT_PROTOCOL,
        GRANT_LIVENESS_MS,
    ];
}
