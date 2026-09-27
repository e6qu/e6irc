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

/// A decoded SASL OAUTHBEARER initial response (RFC 7628 §3.1): the bearer
/// token, and the account the GS2 header asked to act as, if it named one.
#[derive(Clone, PartialEq, Eq)]
pub struct OauthBearerCredentials {
    /// The GS2 `a=` authorization identity, unescaped; `None` when empty.
    /// e6irc does not let one account act as another, so whoever checks the
    /// token must refuse one that does not name the token's own account.
    pub authzid: Option<String>,
    pub token: String,
}

/// A bearer token is a secret: never printed, even in a debug dump.
impl std::fmt::Debug for OauthBearerCredentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OauthBearerCredentials")
            .field("authzid", &self.authzid)
            .finish_non_exhaustive()
    }
}

/// Decode `base64(gs2-header %x01 *(key "=" value %x01) %x01)` (RFC 7628 §3.1)
/// at the one shared SASL boundary. The GS2 header (RFC 5801 §4) is parsed,
/// not skipped: its channel-binding flag is `n` or `y` (OAUTHBEARER has no
/// channel binding to name with `p=`), and its authorization identity is
/// returned so the verifier can hold it to the token's account. Exactly one
/// `auth` pair must carry a non-empty `Bearer` token; other pairs (`host`,
/// `port`) are the client's to send.
pub fn parse_oauthbearer_payload(payload: &str) -> Option<OauthBearerCredentials> {
    let raw = crate::base64::decode(payload)?;
    let text = std::str::from_utf8(&raw).ok()?;
    let (gs2_header, pairs) = text.split_once('\x01')?;
    let (cbind_flag, rest) = gs2_header.split_once(',')?;
    if !matches!(cbind_flag, "n" | "y") {
        return None;
    }
    // `[ "a=" saslname ] ","` — the header ends with the comma.
    let authzid = rest.strip_suffix(',')?;
    let authzid = match authzid {
        "" => None,
        named => Some(unescape_saslname(named.strip_prefix("a=")?)?),
    };
    let mut token = None;
    let mut terminated = false;
    let mut fields = pairs.split('\x01');
    for field in fields.by_ref() {
        if field.is_empty() {
            terminated = true;
            break;
        }
        let (key, value) = field.split_once('=')?;
        if key == "auth" {
            let bearer = value
                .strip_prefix("Bearer ")
                .filter(|bearer| !bearer.is_empty())?;
            if token.replace(bearer).is_some() {
                return None;
            }
        }
    }
    // The message ends with the empty pair that terminated the loop; nothing
    // may follow it.
    if !terminated || fields.any(|trailing| !trailing.is_empty()) {
        return None;
    }
    Some(OauthBearerCredentials {
        authzid,
        token: token?.to_string(),
    })
}

/// A GS2 `saslname` (RFC 5801 §4): `,` and `=` travel as `=2C` and `=3D`, and
/// any other `=` is malformed.
fn unescape_saslname(escaped: &str) -> Option<String> {
    let mut name = String::with_capacity(escaped.len());
    let mut rest = escaped;
    while let Some(at) = rest.find('=') {
        name.push_str(&rest[..at]);
        let escape = rest.get(at..at + 3)?;
        name.push(match escape {
            "=2C" => ',',
            "=3D" => '=',
            _ => return None,
        });
        rest = &rest[at + 3..];
    }
    if rest.contains(',') {
        return None;
    }
    name.push_str(rest);
    (!name.is_empty()).then_some(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn payload(raw: &[u8]) -> String {
        crate::base64::encode(raw)
    }

    #[test]
    fn an_oauthbearer_response_carries_its_token_and_its_gs2_authorization_identity() {
        let parsed = |raw: &[u8]| parse_oauthbearer_payload(&payload(raw));
        assert_eq!(
            parsed(b"n,,\x01auth=Bearer tok\x01\x01"),
            Some(OauthBearerCredentials {
                authzid: None,
                token: "tok".into(),
            })
        );
        assert_eq!(
            parsed(b"n,a=bob,\x01host=irc.example\x01port=6697\x01auth=Bearer tok\x01\x01"),
            Some(OauthBearerCredentials {
                authzid: Some("bob".into()),
                token: "tok".into(),
            }),
            "the authorization identity is returned, not skipped"
        );
        assert_eq!(
            parsed(b"y,a=we=2Cird=3Dname,\x01auth=Bearer tok\x01\x01")
                .and_then(|credentials| credentials.authzid),
            Some("we,ird=name".into()),
            "a saslname is unescaped"
        );
        for invalid in [
            b"p=tls-unique,,\x01auth=Bearer tok\x01\x01".as_slice(),
            b"x,,\x01auth=Bearer tok\x01\x01".as_slice(),
            b"n,bob,\x01auth=Bearer tok\x01\x01".as_slice(),
            b"n,a=,\x01auth=Bearer tok\x01\x01".as_slice(),
            b"n,a=b=6Fb,\x01auth=Bearer tok\x01\x01".as_slice(),
            b"n,a=bob\x01auth=Bearer tok\x01\x01".as_slice(),
            b"n,,\x01auth=Bearer \x01\x01".as_slice(),
            b"n,,\x01auth=Basic tok\x01\x01".as_slice(),
            b"n,,\x01host=irc.example\x01\x01".as_slice(),
            b"n,,\x01auth=Bearer one\x01auth=Bearer two\x01\x01".as_slice(),
            b"n,,\x01auth=Bearer tok\x01\x01trailing".as_slice(),
            b"n,,\x01auth=Bearer tok".as_slice(),
            b"n,,\x01novalue\x01auth=Bearer tok\x01\x01".as_slice(),
            b"auth=Bearer tok".as_slice(),
            b"n,,\x01auth=Bearer \xff\x01\x01".as_slice(),
        ] {
            assert_eq!(parsed(invalid), None, "{invalid:?}");
        }
        assert_eq!(
            format!(
                "{:?}",
                parsed(b"n,,\x01auth=Bearer secret-token\x01\x01").expect("parses")
            ),
            "OauthBearerCredentials { authzid: None, .. }",
            "the token is never printed"
        );
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
