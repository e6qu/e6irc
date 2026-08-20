//! Shared SASL wire limits and credential parsing.

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

/// A decoded SASL PLAIN credential whose optional authorization identity is
/// either absent or names the same RFC1459 account as the authentication
/// identity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlainCredentials {
    pub account: String,
    pub password: String,
}

/// Decode `base64(authzid NUL authcid NUL password)` at the one shared SASL
/// boundary. e6irc does not support authenticating as one account and
/// authorizing as another, so a non-empty `authzid` must name `authcid` under
/// the account casemap.
pub fn parse_plain_payload(payload: &str) -> Option<PlainCredentials> {
    let raw = crate::base64::decode(payload)?;
    let mut parts = raw.split(|&byte| byte == 0);
    let authzid = std::str::from_utf8(parts.next()?).ok()?;
    let account = std::str::from_utf8(parts.next()?).ok()?;
    let password = std::str::from_utf8(parts.next()?).ok()?;
    if parts.next().is_some()
        || account.is_empty()
        || password.is_empty()
        || (!authzid.is_empty() && !crate::casemap::CaseMapping::Rfc1459.eq(authzid, account))
    {
        return None;
    }
    Some(PlainCredentials {
        account: account.to_string(),
        password: password.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(raw: &[u8]) -> String {
        crate::base64::encode(raw)
    }

    #[test]
    fn plain_credentials_have_one_authorized_identity() {
        assert_eq!(
            parse_plain_payload(&payload(b"\0alice\0secret")),
            Some(PlainCredentials {
                account: "alice".into(),
                password: "secret".into(),
            })
        );
        assert_eq!(
            parse_plain_payload(&payload(b"ALICE\0alice\0secret")),
            Some(PlainCredentials {
                account: "alice".into(),
                password: "secret".into(),
            }),
            "the same RFC1459 identity is permitted in authzid"
        );
        for invalid in [
            b"bob\0alice\0secret".as_slice(),
            b"\0\0secret".as_slice(),
            b"\0alice\0".as_slice(),
            b"\0alice\0secret\0extra".as_slice(),
            b"\0\xff\0secret".as_slice(),
        ] {
            assert_eq!(parse_plain_payload(&payload(invalid)), None, "{invalid:?}");
        }
    }
}
