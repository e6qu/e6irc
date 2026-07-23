#![no_main]

//! The line framer, `LineBuffer::feed`, is the first thing that touches every
//! byte from every connection: it splits a TCP byte stream into IRC lines,
//! strips CRLF, and enforces the inbound length limit. Two properties matter
//! and are asserted here for arbitrary bytes fed in arbitrary chunks:
//!
//! 1. **Bounded output.** No emitted line exceeds the configured limit, and no
//!    emitted line contains a bare `\n`. This is the inbound half of the
//!    wire-length class the outbound sweeps (33–40) closed — a framer that
//!    emitted an over-long line would hand the core a line the rest of the
//!    system assumes cannot exist.
//! 2. **Chunk independence.** Framing a stream must not depend on how the
//!    kernel happened to split it into `read()` calls: the same bytes fed in
//!    one chunk and fed byte-by-byte must yield the identical sequence of
//!    `Line` events. A framer whose result shifts with the packet boundary is
//!    a heisenbug that a single-chunk unit test can never catch.

use e6irc_proto::framing::{LineBuffer, LineEvent};
use libfuzzer_sys::fuzz_target;

/// Frame `data` through a fresh `LineBuffer(limit)`, feeding it in the given
/// `chunk` size, and return only the completed lines (dropping `TooLong`
/// markers, whose positions legitimately depend on chunking).
fn lines(data: &[u8], limit: usize, chunk: usize) -> Vec<Vec<u8>> {
    let mut framer = LineBuffer::new(limit);
    let mut out = Vec::new();
    let mut events = Vec::new();
    for part in data.chunks(chunk.max(1)) {
        framer.feed(part, &mut events);
        for ev in events.drain(..) {
            if let LineEvent::Line(line) = ev {
                out.push(line);
            }
        }
    }
    out
}

fuzz_target!(|data: &[u8]| {
    // First byte picks a small limit so the boundary is exercised often; the
    // rest is the stream. `limit` must be > 0 (LineBuffer asserts it).
    let limit = (data.first().copied().unwrap_or(1) as usize % 64) + 1;
    let stream = data.get(1..).unwrap_or(&[]);

    // Property 1: every completed line fits the limit and holds no newline.
    let whole = lines(stream, limit, stream.len().max(1));
    for line in &whole {
        assert!(line.len() <= limit, "framed line of {} bytes over limit {limit}", line.len());
        assert!(!line.contains(&b'\n'), "framed line contains a bare newline");
        // A line may legitimately end in CR: the framer strips only the single
        // CR of the CRLF terminator, leaving any *embedded* CR for
        // `Message::parse` to reject (its documented single rejection point).
    }

    // Property 2: the line sequence is independent of chunk size. A second byte
    // picks the chunk width; feeding the same stream that way must agree.
    let chunk = (data.get(1).copied().unwrap_or(1) as usize % 17) + 1;
    let chunked = lines(stream, limit, chunk);
    assert_eq!(whole, chunked, "framing depends on chunk boundaries (chunk={chunk})");
});
