//! Standard base64 (RFC 4648, with padding) for SASL AUTHENTICATE
//! payloads. ~50 lines in-repo; a dependency is not warranted.

const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        let chars = [
            ALPHABET[(n >> 18) as usize & 63],
            ALPHABET[(n >> 12) as usize & 63],
            ALPHABET[(n >> 6) as usize & 63],
            ALPHABET[n as usize & 63],
        ];
        let keep = chunk.len() + 1;
        for (i, c) in chars.into_iter().enumerate() {
            out.push(if i < keep { c as char } else { '=' });
        }
    }
    out
}

/// Strict decode: rejects bad characters, bad length, and misplaced
/// padding. `None` on any violation — never a partial result.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let bytes = text.as_bytes();
    if !bytes.len().is_multiple_of(4) {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3);
    for (i, chunk) in bytes.chunks(4).enumerate() {
        let last = i == bytes.len() / 4 - 1;
        let pad = chunk.iter().filter(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return None;
        }
        let mut n: u32 = 0;
        for (j, &c) in chunk.iter().enumerate() {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                b'=' if j >= 4 - pad => 0,
                _ => return None,
            };
            n = (n << 6) | u32::from(v);
        }
        // The bits a padded group discards must be zero, or the input is
        // non-canonical: distinct strings would decode to identical bytes
        // (`"AB=="` and `"AA=="` both → [0]). On the untrusted SASL path that is
        // credential malleability, so reject it. (pad==1 discards the low 8
        // bits; pad==2 the low 16.)
        if (pad == 1 && n & 0xFF != 0) || (pad == 2 && n & 0xFFFF != 0) {
            return None;
        }
        out.push((n >> 16) as u8);
        if pad < 2 {
            out.push((n >> 8) as u8);
        }
        if pad < 1 {
            out.push(n as u8);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        for case in [
            &b""[..],
            b"f",
            b"fo",
            b"foo",
            b"foob",
            b"fooba",
            b"foobar",
            b"\x00alice\x00secretpass",
            &[0xFF, 0x00, 0xAB, 0xCD],
        ] {
            let enc = encode(case);
            assert_eq!(decode(&enc).as_deref(), Some(case), "{enc}");
        }
    }

    #[test]
    fn known_vectors() {
        // RFC 4648 test vectors
        assert_eq!(encode(b"foobar"), "Zm9vYmFy");
        assert_eq!(encode(b"foob"), "Zm9vYg==");
        assert_eq!(decode("Zm9vYmE=").as_deref(), Some(&b"fooba"[..]));
    }

    #[test]
    fn rejects_malformed() {
        for bad in ["A", "AB!D", "AB=D", "=ABC", "AAAA=AAA", "AA==AAAA"] {
            assert_eq!(decode(bad), None, "{bad:?}");
        }
    }

    #[test]
    fn rejects_non_canonical_padding() {
        // The bits discarded under padding must be zero, or two distinct
        // strings decode to the same bytes — credential malleability on the
        // SASL path. Each pair below shares a canonical decode with a
        // canonical sibling, so only the canonical form may decode.
        assert_eq!(decode("AA=="), Some(vec![0])); // canonical
        assert_eq!(decode("AB=="), None); // low 16 bits set → rejected
        assert_eq!(decode("Zm8="), Some(b"fo".to_vec())); // canonical
        assert_eq!(decode("Zm9="), None); // low 8 bits set → rejected
        // A genuine round-trip of every byte still decodes.
        for b in 0u8..=255 {
            let enc = encode(&[b]);
            assert_eq!(decode(&enc), Some(vec![b]), "{enc}");
        }
    }
}
