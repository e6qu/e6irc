#![no_main]

//! The core link's codec (`e6irc_link`) reads every byte an edge or a core
//! sends across the process boundary. For arbitrary bytes, in either
//! direction, fed whole and fed in arbitrary chunks:
//!
//! 1. **No panic.** A frame that does not decode is an error, never a crash:
//!    one bad frame from a peer must not take down the process that reads it.
//! 2. **Round trip.** A frame that decodes re-encodes to exactly the bytes it
//!    was read from, so the decoder admits nothing an encoder could not have
//!    written — no field past its bound (the encoder refuses those), no
//!    trailing byte, no second spelling of the same frame.
//! 3. **Chunk independence.** The frames read do not depend on how the stream
//!    was split into reads.

use bytes::BytesMut;
use e6irc_link::{CoreFrame, EdgeFrame, Frame};
use libfuzzer_sys::fuzz_target;

/// Every frame `data` holds, fed in `chunk`-byte reads, with each frame's
/// bytes, and whether a read failed; stops at the first error, as a link
/// reader does.
fn frames<F: Frame>(data: &[u8], chunk: usize) -> (Vec<(F, Vec<u8>)>, bool) {
    let mut buffer = BytesMut::new();
    let mut read = Vec::new();
    let mut consumed = 0usize;
    for part in data.chunks(chunk.max(1)) {
        buffer.extend_from_slice(part);
        loop {
            let before = buffer.len();
            match e6irc_link::decode::<F>(&mut buffer) {
                Ok(Some(frame)) => {
                    let used = before - buffer.len();
                    read.push((frame, data[consumed..consumed + used].to_vec()));
                    consumed += used;
                }
                Ok(None) => break,
                Err(_) => return (read, true),
            }
        }
    }
    (read, false)
}

fn check<F: Frame + PartialEq + std::fmt::Debug>(data: &[u8], chunk: usize) {
    let (whole, whole_failed) = frames::<F>(data, data.len().max(1));
    for (frame, bytes) in &whole {
        let again = e6irc_link::encoded(frame).expect("a decoded frame re-encodes");
        assert_eq!(&again[..], &bytes[..], "{frame:?} re-encodes differently");
    }
    let (chunked, chunked_failed) = frames::<F>(data, chunk);
    assert_eq!(whole_failed, chunked_failed, "an error depends on chunking");
    assert_eq!(
        whole.iter().map(|(frame, _)| frame).collect::<Vec<_>>(),
        chunked.iter().map(|(frame, _)| frame).collect::<Vec<_>>(),
        "the frames read depend on chunking (chunk={chunk})"
    );
}

fuzz_target!(|data: &[u8]| {
    let chunk = (data.first().copied().unwrap_or(1) as usize % 23) + 1;
    let stream = data.get(1..).unwrap_or(&[]);
    check::<EdgeFrame>(stream, chunk);
    check::<CoreFrame>(stream, chunk);
});
