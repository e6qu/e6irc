//! Shared SASL wire limits.

/// Maximum bytes in one `AUTHENTICATE` response parameter.
///
/// A response exactly this long is followed by another chunk; an empty
/// `AUTHENTICATE +` terminates a response whose final data chunk is exact.
pub const MAX_AUTHENTICATE_CHUNK_LEN: usize = 400;

/// Maximum bytes in one reassembled credential response.
///
/// This is an e6irc resource limit rather than an IRCv3 universal limit. Both
/// server listeners and the shared client use it so a locally generated
/// credential can never exceed what either listener is prepared to buffer.
pub const MAX_AUTHENTICATE_PAYLOAD_LEN: usize = 8192;
