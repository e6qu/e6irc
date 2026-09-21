//! IRC protocol model shared by the server, the BNC upstream connector,
//! and the native clients, plus the few chat-provider constants the bridges
//! and their qualification campaigns must agree on (`provider`). No I/O in
//! this crate.

pub mod base64;
pub mod casemap;
pub mod framing;
pub mod isupport;
pub mod mask;
pub mod message;
pub mod numerics;
pub mod provider;
pub mod sasl;
pub mod time;
