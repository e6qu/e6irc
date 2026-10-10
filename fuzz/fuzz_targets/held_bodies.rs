#![no_main]

//! The bodies an edge holds for the core (`e6ircd::core::record`): a session's
//! record, a live chat socket's record, a channel's state, a member's entry and
//! the cut state. A core reads them back from an edge — another process — so
//! for arbitrary bytes:
//!
//! 1. **No panic.** A body that does not read is an error, never a crash: one
//!    bad record closes one session, never the core.
//! 2. **Round trip.** A body that reads, written again in its own format at
//!    its own clock origin, is exactly the bytes it was read from: the reader
//!    admits nothing a writer could not have written, and no second spelling
//!    of the same state.

use bytes::Bytes;
use e6irc_proto::time::{Millis, MonoMillis};
use e6ircd::core::record::{
    ChannelState, ClockOrigin, CutState, MemberEntry, RecordFormat, SessionRecord, UiRecord,
};
use libfuzzer_sys::fuzz_target;

/// The format and writer's clock origin a body starts with, when it has them.
fn header(data: &[u8]) -> Option<(RecordFormat, ClockOrigin)> {
    let format = RecordFormat::read(u16::from_be_bytes(data.get(..2)?.try_into().ok()?))?;
    let origin = i64::from_be_bytes(data.get(2..10)?.try_into().ok()?);
    // Reading on the writer's own clock moves no reading.
    let origin = if origin >= 0 {
        ClockOrigin::of(
            Millis::from_millis(origin.unsigned_abs()),
            MonoMillis::from_millis(0),
        )
    } else {
        ClockOrigin::of(
            Millis::from_millis(0),
            MonoMillis::from_millis(origin.unsigned_abs()),
        )
    };
    Some((format, origin))
}

fuzz_target!(|data: &[u8]| {
    let bytes = Bytes::copy_from_slice(data);
    let Some((format, origin)) = header(data) else {
        // Nothing reads without a format this release knows.
        assert!(
            SessionRecord::decode(
                bytes.clone(),
                ClockOrigin::of(Millis::from_millis(0), MonoMillis::from_millis(0))
            )
            .is_err()
        );
        return;
    };
    if let Ok(record) = SessionRecord::decode(bytes.clone(), origin) {
        let again = record.encode(format, origin).expect("a read record writes");
        assert_eq!(&again[..], data, "{record:?} writes differently");
    }
    if let Ok(state) = ChannelState::decode(bytes.clone(), origin) {
        let again = state.encode(format, origin).expect("a read channel writes");
        assert_eq!(&again[..], data, "{state:?} writes differently");
    }
    if let Ok(entry) = MemberEntry::decode(bytes.clone(), origin) {
        let again = entry.encode(format, origin).expect("a read entry writes");
        assert_eq!(&again[..], data, "{entry:?} writes differently");
    }
    if let Ok(record) = UiRecord::decode(bytes.clone(), origin) {
        let again = record.encode(format, origin).expect("a read socket record writes");
        assert_eq!(&again[..], data, "{record:?} writes differently");
    }
    if let Ok(state) = CutState::decode(bytes, origin) {
        let again = state
            .encode(format, origin)
            .expect("a read cut state writes");
        assert_eq!(&again[..], data, "{state:?} writes differently");
    }
});
