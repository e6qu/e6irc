//! The core link's wire codec (DESIGN §19.2): the frames an edge and the core
//! exchange across a process boundary, and nothing that does I/O.
//!
//! Every frame is `u32 length | u8 kind | u64 session | payload`, the length
//! counting everything after itself and bounded by [`MAX_FRAME_LEN`]. The
//! session is the connection identifier a frame concerns, or 0 for a frame
//! that concerns the link itself (`Hello`, `Welcome`, `Refused`, a stream's
//! `Credit`). The two directions are two types — [`EdgeFrame`] (edge to core)
//! and [`CoreFrame`] (core to edge) — so a frame read the wrong way round does
//! not decode. Every field has a bound, checked when it is written and when it
//! is read: [`encode`] refuses a frame past one ([`EncodeError`]) and [`decode`]
//! refuses bytes no encoder could have written ([`DecodeError`]), never
//! panicking on either side. The `link_frames` fuzz target holds all of it.
//!
//! [`negotiate`] is the version handshake: a core accepts its own link version
//! and the one before, so a core release never forces an edge restart, and
//! refuses anything else naming both sides' versions. Every frame names the
//! version that introduced it ([`EdgeFrame::since`], [`CoreFrame::since`]),
//! and each side refuses one newer than the version its link speaks. The two
//! frames that open a link, `Hello` and `Welcome`, carry the fields of a later
//! version after those of an earlier one, and which fields follow is read from
//! the frame itself (the `Hello`'s version range, the `Welcome`'s version), so
//! the codec needs no version to be told.
//!
//! Version 2 (DESIGN §19.3) adds what the edge holds for the core — session
//! records, channel replicas and the cut state ([`held`]) — the acknowledgement
//! of input, the frames of a graceful cut and a rebuild, the connection's TLS
//! facts on `Open` and the cut on `Hello`.

#![deny(clippy::let_underscore_must_use)]

mod core_frames;
mod edge_frames;
pub mod held;
pub mod wire;

use std::num::NonZeroU64;

use bytes::{Buf, BufMut, BytesMut};

pub use core_frames::{CloseFrame, CommandFloodTerms, CoreFrame, Credit, EdgeTerms, Welcome};
pub use edge_frames::{
    ClosedReason, EdgeFrame, Hello, ListenerKind, ListenerReport, MAX_CERTIFICATE_PATH_LEN,
    MAX_CLOSED_TEXT_LEN, Open, Role, SessionKind, Stream, Transport, UiMessage, WriteFailure,
};
pub use held::{
    Ack, Admission, Body, BodyPart, Cut, CutId, CutPart, RecordPart, Replica, ReplicaChange,
    TlsFacts, Upload,
};

/// This release's core-link version.
pub const LINK_VERSION: u16 = 2;

/// The oldest link version this release still speaks. A core accepts it as
/// well as [`LINK_VERSION`]; an edge offers every version from it up.
pub const OLDEST_SPOKEN: u16 = 1;

const _: () = assert!(OLDEST_SPOKEN <= LINK_VERSION && LINK_VERSION <= OLDEST_SPOKEN + 1);

/// The most bytes a frame's length word may count: its kind, session and
/// payload.
pub const MAX_FRAME_LEN: usize = 1 << 20;

/// The length word, the kind and the session.
const HEADER_LEN: usize = 4 + 1 + 8;

/// The kind and the session, counted in the length word.
const KIND_AND_SESSION_LEN: usize = 1 + 8;

/// The longest client line a `Line` frame carries: what the edge's framer
/// admits (the client tag budget and a 512-byte line without its CRLF).
pub const MAX_LINE_LEN: usize = e6irc_proto::message::MAX_CLIENT_FRAME_LEN;

/// The longest label an `OverlongLine` carries: the client tag budget, which
/// bounds the tag section it is read from.
pub const MAX_LABEL_LEN: usize = e6irc_proto::message::MAX_CLIENT_TAGS_LEN;

/// The largest `/ws/ui` message a client may send: JSON can escape one input
/// byte as six, so a wire-sized composer line fits with room for its
/// envelope. The edge reads no larger message, and a `Message` frame carries
/// none.
pub const MAX_UI_MESSAGE_LEN: usize = e6irc_proto::message::MAX_CLIENT_FRAME_LEN * 6 + 512;

/// The largest line or message the core sends one session in one `Output` or
/// `Kill`: whatever a frame can hold.
pub const MAX_OUTPUT_LEN: usize = MAX_FRAME_LEN - KIND_AND_SESSION_LEN - 4;

/// The most connection slots a deployment has: 14 bits, so a slot-prefixed
/// connection identifier keeps its top two bits clear (the HTTP boundary reads
/// identifiers as signed 64-bit integers).
pub const MAX_SLOT: u16 = (1 << 14) - 1;

/// The bit a slot starts at in a connection identifier: `slot << 48 | counter`.
pub const SLOT_SHIFT: u32 = 48;

/// The most session streams one edge opens: one per core shard.
pub const MAX_STREAMS: u16 = 256;

/// A range of link versions an edge speaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VersionRange {
    oldest: u16,
    newest: u16,
}

impl VersionRange {
    /// `None` when `oldest` is past `newest`.
    pub const fn new(oldest: u16, newest: u16) -> Option<Self> {
        if oldest > newest {
            return None;
        }
        Some(Self { oldest, newest })
    }

    /// The versions this release speaks.
    pub const fn spoken() -> Self {
        Self {
            oldest: OLDEST_SPOKEN,
            newest: LINK_VERSION,
        }
    }

    pub const fn oldest(self) -> u16 {
        self.oldest
    }

    pub const fn newest(self) -> u16 {
        self.newest
    }

    fn contains(self, version: u16) -> bool {
        (self.oldest..=self.newest).contains(&version)
    }
}

/// Why a core refused an edge's versions: the text names both sides' versions
/// and which side must be upgraded, and is what the edge logs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VersionRefused {
    pub offered: VersionRange,
}

impl std::fmt::Display for VersionRefused {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (edge_oldest, edge_newest) = (self.offered.oldest, self.offered.newest);
        let upgrade = if edge_newest < OLDEST_SPOKEN {
            "upgrade the edge"
        } else {
            "upgrade the core"
        };
        write!(
            f,
            "core-link version mismatch: this core speaks versions {OLDEST_SPOKEN} to \
             {LINK_VERSION} and the edge speaks {edge_oldest} to {edge_newest}; {upgrade} to a \
             release that speaks a version both do"
        )
    }
}

impl std::error::Error for VersionRefused {}

/// The version a core of this release speaks with an edge offering `offered`:
/// the newest both speak.
pub fn negotiate(offered: VersionRange) -> Result<u16, VersionRefused> {
    (OLDEST_SPOKEN..=LINK_VERSION)
        .rev()
        .find(|version| offered.contains(*version))
        .ok_or(VersionRefused { offered })
}

/// Whether an edge whose newest version is `edge_newest` must be upgraded
/// before the core release after this one, which will no longer speak the
/// version before [`LINK_VERSION`].
pub const fn edge_upgrade_needed(edge_newest: u16) -> bool {
    edge_newest < LINK_VERSION
}

/// The connection a frame concerns: never 0, which marks a frame about the
/// link itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct SessionId(NonZeroU64);

impl SessionId {
    pub const fn new(id: u64) -> Option<Self> {
        match NonZeroU64::new(id) {
            Some(id) => Some(Self(id)),
            None => None,
        }
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }

    fn from_wire(session: u64) -> Result<Self, DecodeError> {
        Self::new(session).ok_or(DecodeError::MissingSession)
    }
}

/// An edge's name: one DNS label (1 to 63 lowercase letters, digits and
/// hyphens, not starting or ending with a hyphen), the name its certificate
/// is issued for.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EdgeName(String);

/// The most bytes an [`EdgeName`] holds.
pub const MAX_EDGE_NAME_LEN: usize = 63;

impl EdgeName {
    pub fn new(name: &str) -> Result<Self, InvalidEdgeName> {
        let valid = !name.is_empty()
            && name.len() <= MAX_EDGE_NAME_LEN
            && !name.starts_with('-')
            && !name.ends_with('-')
            && name
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-');
        if valid {
            Ok(Self(name.to_owned()))
        } else {
            Err(InvalidEdgeName(name.to_owned()))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for EdgeName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidEdgeName(pub String);

impl std::fmt::Display for InvalidEdgeName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{:?} is not an edge name: one to {MAX_EDGE_NAME_LEN} lowercase letters, digits and \
             hyphens, not starting or ending with a hyphen",
            self.0
        )
    }
}

impl std::error::Error for InvalidEdgeName {}

/// The number the core assigns an edge, the top bits of every connection
/// identifier that edge allocates: 1 to [`MAX_SLOT`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Slot(u16);

impl Slot {
    pub const fn new(slot: u16) -> Option<Self> {
        if slot == 0 || slot > MAX_SLOT {
            return None;
        }
        Some(Self(slot))
    }

    pub const fn get(self) -> u16 {
        self.0
    }

    /// The first identifier of this slot's range; its last is
    /// `first + 2^48 - 1`.
    pub const fn first_id(self) -> u64 {
        (self.0 as u64) << SLOT_SHIFT
    }
}

/// A frame that could not be written: a field past its bound, or the whole
/// frame past [`MAX_FRAME_LEN`]. Nothing was written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EncodeError {
    OverBound {
        field: &'static str,
        length: usize,
        bound: usize,
    },
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::OverBound {
                field,
                length,
                bound,
            } => write!(
                f,
                "core-link frame field {field} holds {length}, past its bound of {bound}"
            ),
        }
    }
}

impl std::error::Error for EncodeError {}

/// Bytes that are not a frame an encoder of this version writes. The link is
/// broken past this point: the reader that meets one ends the link.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodeError {
    /// The length word counts less than a kind and a session.
    ShortFrame {
        length: usize,
    },
    /// The length word counts more than [`MAX_FRAME_LEN`].
    LongFrame {
        length: usize,
    },
    UnknownKind {
        kind: u8,
    },
    /// A frame about a session names none, or a frame about the link names
    /// one.
    MissingSession,
    UnexpectedSession {
        kind: u8,
    },
    Truncated {
        field: &'static str,
    },
    OverBound {
        field: &'static str,
        length: usize,
        bound: usize,
    },
    UnknownTag {
        field: &'static str,
        tag: u8,
    },
    NotUtf8 {
        field: &'static str,
    },
    Invalid {
        field: &'static str,
    },
    TrailingBytes {
        count: usize,
    },
}

impl std::fmt::Display for DecodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ShortFrame { length } => write!(f, "a frame of {length} bytes is too short"),
            Self::LongFrame { length } => write!(
                f,
                "a frame of {length} bytes is past the bound of {MAX_FRAME_LEN}"
            ),
            Self::UnknownKind { kind } => write!(f, "unknown frame kind {kind:#04x}"),
            Self::MissingSession => f.write_str("a session frame names no session"),
            Self::UnexpectedSession { kind } => {
                write!(f, "link frame kind {kind:#04x} names a session")
            }
            Self::Truncated { field } => write!(f, "the frame ends inside {field}"),
            Self::OverBound {
                field,
                length,
                bound,
            } => write!(f, "{field} holds {length}, past its bound of {bound}"),
            Self::UnknownTag { field, tag } => write!(f, "{field} has unknown tag {tag}"),
            Self::NotUtf8 { field } => write!(f, "{field} is not UTF-8"),
            Self::Invalid { field } => write!(f, "{field} holds a value no encoder writes"),
            Self::TrailingBytes { count } => {
                write!(f, "{count} bytes follow the frame's last field")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// One direction's frames: [`EdgeFrame`] or [`CoreFrame`].
pub trait Frame: sealed::Codec {}

impl Frame for EdgeFrame {}
impl Frame for CoreFrame {}

mod sealed {
    use super::{DecodeError, EncodeError, wire};

    /// How a direction's frames are written and read; only this crate's two
    /// frame types have it.
    pub trait Codec: Sized {
        /// The frame's kind byte and session (0 for a frame about the link).
        fn header(&self) -> (u8, u64);

        fn write_payload(&self, writer: &mut wire::Writer<'_>) -> Result<(), EncodeError>;

        fn read_payload(
            kind: u8,
            session: u64,
            reader: &mut wire::Reader,
        ) -> Result<Self, DecodeError>;
    }
}

/// Append `frame` to `out`. On an error `out` is left as it was.
pub fn encode<F: Frame>(frame: &F, out: &mut BytesMut) -> Result<(), EncodeError> {
    let start = out.len();
    let (kind, session) = sealed::Codec::header(frame);
    out.put_u32(0);
    out.put_u8(kind);
    out.put_u64(session);
    if let Err(error) = sealed::Codec::write_payload(frame, &mut wire::Writer(out)) {
        out.truncate(start);
        return Err(error);
    }
    let length = out.len() - start - 4;
    if length > MAX_FRAME_LEN {
        out.truncate(start);
        return Err(EncodeError::OverBound {
            field: "frame",
            length,
            bound: MAX_FRAME_LEN,
        });
    }
    let word = u32::try_from(length).expect("bounded by MAX_FRAME_LEN");
    out[start..start + 4].copy_from_slice(&word.to_be_bytes());
    Ok(())
}

/// Take the first whole frame off `buffer`: `Ok(None)` while it holds less
/// than one frame. A frame that does not decode is an error, and the link is
/// broken from there on.
pub fn decode<F: Frame>(buffer: &mut BytesMut) -> Result<Option<F>, DecodeError> {
    if buffer.len() < 4 {
        return Ok(None);
    }
    let length = u32::from_be_bytes(buffer[..4].try_into().expect("four bytes")) as usize;
    if length < KIND_AND_SESSION_LEN {
        return Err(DecodeError::ShortFrame { length });
    }
    if length > MAX_FRAME_LEN {
        return Err(DecodeError::LongFrame { length });
    }
    if buffer.len() < 4 + length {
        buffer.reserve(4 + length - buffer.len());
        return Ok(None);
    }
    buffer.advance(4);
    let mut frame = buffer.split_to(length).freeze();
    let kind = frame.get_u8();
    let session = frame.get_u64();
    let mut reader = wire::Reader(frame);
    let decoded = <F as sealed::Codec>::read_payload(kind, session, &mut reader)?;
    reader.finish()?;
    Ok(Some(decoded))
}

/// The frame bytes of `frame` alone, as [`encode`] writes them.
pub fn encoded<F: Frame>(frame: &F) -> Result<BytesMut, EncodeError> {
    let mut out = BytesMut::with_capacity(HEADER_LEN);
    encode(frame, &mut out)?;
    Ok(out)
}

/// A frame about the link must name no session.
fn link_frame(kind: u8, session: u64) -> Result<(), DecodeError> {
    if session != 0 {
        return Err(DecodeError::UnexpectedSession { kind });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
