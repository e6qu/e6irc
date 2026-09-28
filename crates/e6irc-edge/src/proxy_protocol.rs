//! The PROXY protocol, version 2 (the HAProxy specification's binary header):
//! a load balancer that passes TCP through says who its client is in a header
//! it sends before the client's own bytes. An edge listener with
//! `proxy_protocol = true` reads that header from every connection before
//! anything else (DESIGN §19.1) and takes the client's address from it —
//! believed only from a peer in `trusted_proxies`, as a forwarded address is.
//!
//! The header is read exactly, byte for byte, so nothing of the client's own
//! stream (an IRC line, a TLS ClientHello, an HTTP request) is consumed with
//! it. A connection whose first bytes are not a well-formed header is refused:
//! a listener that expects the protocol never guesses.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt};

/// The twelve bytes every version-2 header starts with.
const SIGNATURE: [u8; 12] = [
    0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a,
];

/// The most bytes of addresses and type-length-value extensions one header
/// may carry: far past what a proxy sends (36 bytes of IPv6 addresses and a
/// few extensions), and a bound on what a peer can make the edge read.
pub const MAX_HEADER_BODY: usize = 1024;

/// How long a peer has to send its whole header.
pub const HEADER_DEADLINE: Duration = Duration::from_secs(10);

/// What a header says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyHeader {
    /// The proxy's own connection (a health check): the peer is the client.
    Local,
    /// A client's connection, relayed: its source address.
    Relayed { source: SocketAddr },
}

/// Why a connection's first bytes are not a header this edge accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyHeaderError {
    NotAHeader,
    Version(u8),
    Command(u8),
    /// An address family other than IPv4 or IPv6 over TCP.
    Family(u8),
    /// The addresses do not fit the length the header gives.
    Short,
    TooLong(usize),
    Read(String),
    TimedOut,
    /// The peer is not a trusted proxy: a listener that reads the protocol
    /// takes its clients only through one, so nothing it says is read.
    Untrusted,
}

impl std::fmt::Display for ProxyHeaderError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotAHeader => f.write_str("the connection does not start with a PROXY header"),
            Self::Version(version) => write!(f, "PROXY protocol version {version} is not 2"),
            Self::Command(command) => write!(f, "unknown PROXY command {command}"),
            Self::Family(family) => write!(
                f,
                "PROXY address family and protocol {family:#04x} is not TCP over IPv4 or IPv6"
            ),
            Self::Short => f.write_str("the PROXY header is shorter than its addresses"),
            Self::TooLong(length) => write!(
                f,
                "a PROXY header of {length} bytes is past the bound of {MAX_HEADER_BODY}"
            ),
            Self::Read(error) => write!(f, "reading the PROXY header failed: {error}"),
            Self::TimedOut => f.write_str("no PROXY header within the deadline"),
            Self::Untrusted => f.write_str(
                "the peer is not a trusted proxy, and this listener takes clients only through one",
            ),
        }
    }
}

impl std::error::Error for ProxyHeaderError {}

/// Parse the fixed first 16 bytes: the signature, version, command, family,
/// and the length of what follows.
fn parse_prefix(prefix: &[u8; 16]) -> Result<(u8, u8, usize), ProxyHeaderError> {
    if prefix[..12] != SIGNATURE {
        return Err(ProxyHeaderError::NotAHeader);
    }
    let version = prefix[12] >> 4;
    if version != 2 {
        return Err(ProxyHeaderError::Version(version));
    }
    let command = prefix[12] & 0x0f;
    if command > 1 {
        return Err(ProxyHeaderError::Command(command));
    }
    let length = usize::from(u16::from_be_bytes([prefix[14], prefix[15]]));
    if length > MAX_HEADER_BODY {
        return Err(ProxyHeaderError::TooLong(length));
    }
    Ok((command, prefix[13], length))
}

/// What a header of `command` and `family` with `body` says.
fn parse_body(command: u8, family: u8, body: &[u8]) -> Result<ProxyHeader, ProxyHeaderError> {
    if command == 0 {
        // A local connection (the proxy's own, such as a health check):
        // the addresses, if any, are not a client's.
        return Ok(ProxyHeader::Local);
    }
    let source = match family {
        // TCP over IPv4: source, destination, source port, destination port.
        0x11 => {
            let fields = body.get(..12).ok_or(ProxyHeaderError::Short)?;
            let ip = Ipv4Addr::new(fields[0], fields[1], fields[2], fields[3]);
            SocketAddr::new(IpAddr::V4(ip), u16::from_be_bytes([fields[8], fields[9]]))
        }
        // TCP over IPv6.
        0x21 => {
            let fields = body.get(..36).ok_or(ProxyHeaderError::Short)?;
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&fields[..16]);
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(octets)),
                u16::from_be_bytes([fields[32], fields[33]]),
            )
        }
        family => return Err(ProxyHeaderError::Family(family)),
    };
    Ok(ProxyHeader::Relayed { source })
}

/// Read one header from `stream`, and not a byte more, within
/// [`HEADER_DEADLINE`].
pub async fn read_header<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<ProxyHeader, ProxyHeaderError> {
    let read = async {
        let mut prefix = [0u8; 16];
        stream
            .read_exact(&mut prefix)
            .await
            .map_err(|error| ProxyHeaderError::Read(error.to_string()))?;
        let (command, family, length) = parse_prefix(&prefix)?;
        let mut body = vec![0u8; length];
        stream
            .read_exact(&mut body)
            .await
            .map_err(|error| ProxyHeaderError::Read(error.to_string()))?;
        parse_body(command, family, &body)
    };
    tokio::time::timeout(HEADER_DEADLINE, read)
        .await
        .unwrap_or(Err(ProxyHeaderError::TimedOut))
}

/// The client behind `peer` on a listener that reads the PROXY protocol:
/// what its header says, believed only from a trusted proxy.
pub async fn relayed_client<S: AsyncRead + Unpin>(
    stream: &mut S,
    peer: SocketAddr,
    trusted: &crate::address::TrustedProxies,
) -> Result<SocketAddr, ProxyHeaderError> {
    if !trusted.contains(peer.ip()) {
        return Err(ProxyHeaderError::Untrusted);
    }
    match read_header(stream).await? {
        ProxyHeader::Local => Ok(peer),
        ProxyHeader::Relayed { source } => Ok(source),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn header(command: u8, family: u8, body: &[u8]) -> Vec<u8> {
        let mut bytes = SIGNATURE.to_vec();
        bytes.push(0x20 | command);
        bytes.push(family);
        bytes.extend_from_slice(&u16::try_from(body.len()).expect("small").to_be_bytes());
        bytes.extend_from_slice(body);
        bytes
    }

    async fn read(bytes: &[u8]) -> Result<ProxyHeader, ProxyHeaderError> {
        read_header(&mut &bytes[..]).await
    }

    #[tokio::test]
    async fn a_relayed_ipv4_client_is_read_with_its_port() {
        let body = [192, 0, 2, 7, 10, 0, 0, 1, 0x1a, 0x0b, 0x1a, 0x0a];
        assert_eq!(
            read(&header(1, 0x11, &body)).await,
            Ok(ProxyHeader::Relayed {
                source: "192.0.2.7:6667".parse().expect("address")
            })
        );
    }

    #[tokio::test]
    async fn a_relayed_ipv6_client_is_read_and_extensions_are_skipped() {
        let mut body = vec![0u8; 36];
        body[..16].copy_from_slice(&"2001:db8::7".parse::<Ipv6Addr>().expect("v6").octets());
        body[32..34].copy_from_slice(&6697u16.to_be_bytes());
        // A type-length-value extension after the addresses.
        body.extend_from_slice(&[0x04, 0x00, 0x02, 0xab, 0xcd]);
        assert_eq!(
            read(&header(1, 0x21, &body)).await,
            Ok(ProxyHeader::Relayed {
                source: "[2001:db8::7]:6697".parse().expect("address")
            })
        );
    }

    #[tokio::test]
    async fn a_local_header_names_no_client() {
        assert_eq!(read(&header(0, 0x00, &[])).await, Ok(ProxyHeader::Local));
    }

    #[tokio::test]
    async fn anything_else_is_refused() {
        let mut not_a_header = b"NICK alice\r\nUSER a 0 * :A\r\n".to_vec();
        not_a_header.resize(32, b' ');
        assert_eq!(read(&not_a_header).await, Err(ProxyHeaderError::NotAHeader));
        let mut wrong_version = header(1, 0x11, &[0; 12]);
        wrong_version[12] = 0x11;
        assert_eq!(
            read(&wrong_version).await,
            Err(ProxyHeaderError::Version(1))
        );
        assert_eq!(
            read(&header(1, 0x31, &[0; 216])).await,
            Err(ProxyHeaderError::Family(0x31))
        );
        assert_eq!(
            read(&header(1, 0x11, &[0; 4])).await,
            Err(ProxyHeaderError::Short)
        );
        let whole = header(1, 0x11, &[0; 12]);
        assert!(matches!(
            read(&whole[..20]).await,
            Err(ProxyHeaderError::Read(_))
        ));
        let mut long = header(1, 0x11, &[]);
        long[14..16].copy_from_slice(
            &u16::try_from(MAX_HEADER_BODY + 1)
                .expect("small")
                .to_be_bytes(),
        );
        assert_eq!(
            read(&long).await,
            Err(ProxyHeaderError::TooLong(MAX_HEADER_BODY + 1))
        );
    }

    /// The header is read exactly: what the client sent after it is left in
    /// the stream for the connection to read; and only a trusted proxy's
    /// header is believed.
    #[tokio::test]
    async fn reading_a_header_leaves_the_client_s_bytes_in_the_stream() {
        let body = [198, 51, 100, 1, 10, 0, 0, 1, 0x30, 0x39, 0x1a, 0x0a];
        let mut bytes = header(1, 0x11, &body);
        bytes.extend_from_slice(b"NICK alice\r\n");
        let mut stream = &bytes[..];
        let trusted = crate::address::TrustedProxies::new(vec!["10.0.0.0/8".parse().expect("net")]);
        let client = relayed_client(
            &mut stream,
            "10.1.2.3:4000".parse().expect("peer"),
            &trusted,
        )
        .await
        .expect("relayed");
        assert_eq!(client, "198.51.100.1:12345".parse().expect("address"));
        assert_eq!(stream, b"NICK alice\r\n");
        let refused = relayed_client(
            &mut &bytes[..],
            "203.0.113.9:4000".parse().expect("peer"),
            &trusted,
        )
        .await;
        assert_eq!(
            refused,
            Err(ProxyHeaderError::Untrusted),
            "an untrusted peer's header is not believed"
        );
    }
}
