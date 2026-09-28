//! What link version 2 adds (DESIGN §19.2, §19.3): the state an edge holds
//! for the core — each session's record, each channel's replica, the cut
//! state — and the frames that move it, pause input and resume it.
//!
//! Bodies are opaque here: the core writes them (in [`crate::wire`]'s
//! primitives) and reads them back at a rebuild; the edge stores and uploads
//! them whole, reading only the header a frame gives it. A body longer than
//! one frame travels as numbered parts ([`BodyPart`]).

use std::net::IpAddr;
use std::num::NonZeroU64;

use bytes::Bytes;

use crate::wire::{Reader, Writer};
use crate::{ClosedReason, DecodeError, EncodeError, SessionId, SessionKind, Transport};

/// The most bytes one part of a record, replica or cut-state body holds.
pub const MAX_BODY_PART: usize = 512 * 1024;

/// The most parts one body has: a body past `MAX_BODY_PART * MAX_BODY_PARTS`
/// bytes is refused by the core that writes it.
pub const MAX_BODY_PARTS: u32 = 1024;

/// The most bytes of a channel's key a replica names it by.
pub const MAX_REPLICA_KEY_LEN: usize = 512;

/// The most bytes of one member's entry in a replica.
pub const MAX_MEMBER_LEN: usize = 256;

/// The most input lines one acknowledgement marks retained for replay.
pub const MAX_RETAINED: usize = 4096;

/// The most bytes of a TLS server name an `Open` carries.
pub const MAX_SERVER_NAME_LEN: usize = 255;

/// The identifier of one graceful cut: the core that made it chose it, and
/// every edge that took part presents it when it links again.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct CutId(NonZeroU64);

impl CutId {
    pub const fn new(id: u64) -> Option<Self> {
        match NonZeroU64::new(id) {
            Some(id) => Some(Self(id)),
            None => None,
        }
    }

    pub const fn get(self) -> u64 {
        self.0.get()
    }

    pub(crate) fn write(self, w: &mut Writer<'_>) {
        w.u64(self.get());
    }

    pub(crate) fn read(r: &mut Reader) -> Result<Self, DecodeError> {
        Self::new(r.u64("cut")?).ok_or(DecodeError::Invalid { field: "cut" })
    }
}

/// What the edge knows of a TLS connection it terminated: the protocol
/// version and cipher suite (their IANA code points), the server name the
/// client asked for, and the SHA-256 fingerprint of the client certificate it
/// presented.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsFacts {
    pub version: u16,
    pub cipher_suite: u16,
    pub server_name: Option<String>,
    pub client_certificate: Option<[u8; 32]>,
}

impl TlsFacts {
    pub fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.u16(self.version);
        w.u16(self.cipher_suite);
        w.option(self.server_name.as_ref(), |w, name| {
            w.text("server name", name, MAX_SERVER_NAME_LEN)
        })?;
        w.option(self.client_certificate.as_ref(), |w, fingerprint| {
            w.bytes("client certificate", fingerprint, 32)
        })
    }

    pub fn read(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(Self {
            version: r.u16("TLS version")?,
            cipher_suite: r.u16("cipher suite")?,
            server_name: r.option("server name", |r| {
                r.text("server name", MAX_SERVER_NAME_LEN)
            })?,
            client_certificate: r.option("client certificate", |r| {
                let bytes = r.bytes("client certificate", 32)?;
                <[u8; 32]>::try_from(&bytes[..]).map_err(|_| DecodeError::Invalid {
                    field: "client certificate",
                })
            })?,
        })
    }
}

/// One part of a body: its place, whether it is the last, and its bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BodyPart {
    pub index: u32,
    pub last: bool,
    pub bytes: Bytes,
}

impl BodyPart {
    /// `body` cut into parts of at most [`MAX_BODY_PART`] bytes; one empty
    /// part for an empty body. `None` for a body of more than
    /// [`MAX_BODY_PARTS`] parts.
    pub fn split(body: &Bytes) -> Option<Vec<Self>> {
        let count = body.len().div_ceil(MAX_BODY_PART).max(1);
        if count > MAX_BODY_PARTS as usize {
            return None;
        }
        Some(
            (0..count)
                .map(|index| {
                    let start = index * MAX_BODY_PART;
                    let end = (start + MAX_BODY_PART).min(body.len());
                    Self {
                        index: u32::try_from(index).expect("bounded by MAX_BODY_PARTS"),
                        last: index + 1 == count,
                        bytes: body.slice(start..end),
                    }
                })
                .collect(),
        )
    }

    fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.u32(self.index);
        w.bool(self.last);
        w.bytes("body part", &self.bytes, MAX_BODY_PART)
    }

    fn read(r: &mut Reader) -> Result<Self, DecodeError> {
        let index = r.u32("part index")?;
        if index >= MAX_BODY_PARTS {
            return Err(DecodeError::Invalid {
                field: "part index",
            });
        }
        Ok(Self {
            index,
            last: r.bool("last part")?,
            bytes: r.bytes("body part", MAX_BODY_PART)?,
        })
    }
}

/// Parts of one body, gathered in order as they arrive.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Body {
    parts: Vec<Bytes>,
    whole: bool,
}

/// A part that does not follow the ones gathered.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OutOfOrder {
    pub expected: u32,
    pub got: u32,
}

impl std::fmt::Display for OutOfOrder {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "body part {} arrived where part {} was due",
            self.got, self.expected
        )
    }
}

impl Body {
    /// Add `part`: the first part starts the body over, any other must
    /// follow the last one gathered.
    pub fn gather(&mut self, part: BodyPart) -> Result<(), OutOfOrder> {
        if part.index == 0 {
            self.parts.clear();
            self.whole = false;
        }
        let expected = u32::try_from(self.parts.len()).unwrap_or(u32::MAX);
        if part.index != expected || self.whole {
            return Err(OutOfOrder {
                expected,
                got: part.index,
            });
        }
        self.parts.push(part.bytes);
        self.whole = part.last;
        Ok(())
    }

    /// Whether the last part has arrived.
    pub fn is_whole(&self) -> bool {
        self.whole
    }

    /// The parts, as they were given, to be sent on.
    pub fn parts(&self) -> Vec<BodyPart> {
        let count = self.parts.len();
        self.parts
            .iter()
            .enumerate()
            .map(|(index, bytes)| BodyPart {
                index: u32::try_from(index).expect("bounded by MAX_BODY_PARTS"),
                last: index + 1 == count && self.whole,
                bytes: bytes.clone(),
            })
            .collect()
    }

    /// The whole body in one piece, once it is whole.
    pub fn joined(&self) -> Option<Bytes> {
        if !self.whole {
            return None;
        }
        match self.parts.as_slice() {
            [only] => Some(only.clone()),
            parts => Some(Bytes::from(parts.concat())),
        }
    }

    /// The bytes held.
    pub fn len(&self) -> usize {
        self.parts.iter().map(Bytes::len).sum()
    }

    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }
}

/// One part of a session's record, at the record's revision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordPart {
    pub revision: u64,
    pub part: BodyPart,
}

impl RecordPart {
    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.u64(self.revision);
        self.part.write(w)
    }

    pub(crate) fn read(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(Self {
            revision: r.u64("record revision")?,
            part: BodyPart::read(r)?,
        })
    }
}

/// Which input lines of a session the core is done with: every line up to
/// `through` (the count of lines the session sent on this link), except the
/// `retained` ones, which only accumulated in the core's memory — an open
/// multiline batch, incomplete `AUTHENTICATE` chunks — and are replayed to
/// the next core if this one goes before they complete (DESIGN §2,
/// "acknowledge after effect").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Ack {
    pub through: u64,
    /// In ascending order, each at most `through`.
    pub retained: Vec<u64>,
}

impl Ack {
    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.u64(self.through);
        if self.retained.len() > MAX_RETAINED {
            return Err(EncodeError::OverBound {
                field: "retained lines",
                length: self.retained.len(),
                bound: MAX_RETAINED,
            });
        }
        w.u32(u32::try_from(self.retained.len()).expect("bounded above"));
        for line in &self.retained {
            w.u64(*line);
        }
        Ok(())
    }

    pub(crate) fn read(r: &mut Reader) -> Result<Self, DecodeError> {
        let through = r.u64("acknowledged through")?;
        let count = r.u32("retained lines")? as usize;
        if count > MAX_RETAINED {
            return Err(DecodeError::OverBound {
                field: "retained lines",
                length: count,
                bound: MAX_RETAINED,
            });
        }
        let mut retained = Vec::with_capacity(count);
        for _ in 0..count {
            let line = r.u64("retained line")?;
            let ordered = retained.last().is_none_or(|previous| *previous < line);
            if !ordered || line == 0 || line > through {
                return Err(DecodeError::Invalid {
                    field: "retained line",
                });
            }
            retained.push(line);
        }
        Ok(Self { through, retained })
    }
}

/// A change to the replica of one channel an edge holds: the channel's own
/// state, one of this edge's members, or the whole replica gone (the channel
/// ended, or this edge hosts no member of it any more).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replica {
    /// The channel's key, as the core names it; opaque to the edge.
    pub channel: Bytes,
    /// The channel's revision after this change.
    pub revision: u64,
    pub change: ReplicaChange,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplicaChange {
    /// The channel's state, whole.
    State(Bytes),
    /// A member on this edge joined or changed.
    Member(SessionId, Bytes),
    /// A member on this edge left.
    MemberGone(SessionId),
    /// The edge holds no replica of the channel any more.
    Gone,
}

impl Replica {
    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        w.bytes("replica channel", &self.channel, MAX_REPLICA_KEY_LEN)?;
        w.u64(self.revision);
        match &self.change {
            ReplicaChange::State(state) => {
                w.u8(0);
                w.bytes("replica state", state, MAX_BODY_PART)
            }
            ReplicaChange::Member(session, entry) => {
                w.u8(1);
                w.u64(session.get());
                w.bytes("replica member", entry, MAX_MEMBER_LEN)
            }
            ReplicaChange::MemberGone(session) => {
                w.u8(2);
                w.u64(session.get());
                Ok(())
            }
            ReplicaChange::Gone => {
                w.u8(3);
                Ok(())
            }
        }
    }

    pub(crate) fn read(r: &mut Reader) -> Result<Self, DecodeError> {
        let channel = r.bytes("replica channel", MAX_REPLICA_KEY_LEN)?;
        if channel.is_empty() {
            return Err(DecodeError::Invalid {
                field: "replica channel",
            });
        }
        let revision = r.u64("replica revision")?;
        let member = |r: &mut Reader| {
            SessionId::new(r.u64("replica member")?).ok_or(DecodeError::Invalid {
                field: "replica member",
            })
        };
        let change = match r.u8("replica change")? {
            0 => ReplicaChange::State(r.bytes("replica state", MAX_BODY_PART)?),
            1 => {
                let session = member(r)?;
                ReplicaChange::Member(session, r.bytes("replica member", MAX_MEMBER_LEN)?)
            }
            2 => ReplicaChange::MemberGone(member(r)?),
            3 => ReplicaChange::Gone,
            tag => {
                return Err(DecodeError::UnknownTag {
                    field: "replica change",
                    tag,
                });
            }
        };
        Ok(Self {
            channel,
            revision,
            change,
        })
    }
}

/// One part of the cut state (DESIGN §19.3: WHOWAS, the LUSERS maximum, the
/// registration buckets and the edges the cut was sent to).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CutPart {
    pub cut: CutId,
    pub part: BodyPart,
}

impl CutPart {
    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        self.cut.write(w);
        self.part.write(w)
    }

    pub(crate) fn read(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(Self {
            cut: CutId::read(r)?,
            part: BodyPart::read(r)?,
        })
    }
}

/// The last frame a stream carries from a core that stopped gracefully: every
/// record, replica and acknowledgement it wrote is before it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Cut {
    pub cut: CutId,
    /// The serving-lease epoch of the core that cut.
    pub epoch: u64,
}

/// A session an edge holds from a cut, as it uploads it to the next core: what
/// the edge knows of it itself. Its record follows in `RecordUpload` parts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Upload {
    pub kind: SessionKind,
    pub address: IpAddr,
    pub transport: Transport,
    pub tls: Option<TlsFacts>,
    /// Milliseconds since the client's last input line.
    pub since_input_ms: u64,
    /// Bytes the core sent that are not yet written to the client socket.
    pub unwritten: u64,
    /// Lines sent to the core it neither acknowledged nor retained: of
    /// unknown fate.
    pub unconfirmed: u32,
    /// The client's side ended during the gap, and why.
    pub closed: Option<ClosedReason>,
}

impl Upload {
    pub(crate) fn write(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        crate::edge_frames::write_kind(w, self.kind);
        w.ip(self.address);
        crate::edge_frames::write_transport(w, self.transport);
        w.option(self.tls.as_ref(), |w, tls| tls.write(w))?;
        w.u64(self.since_input_ms);
        w.u64(self.unwritten);
        w.u32(self.unconfirmed);
        w.option(self.closed.as_ref(), crate::edge_frames::write_closed)
    }

    pub(crate) fn read(r: &mut Reader) -> Result<Self, DecodeError> {
        Ok(Self {
            kind: crate::edge_frames::read_kind(r)?,
            address: r.ip("client address")?,
            transport: crate::edge_frames::read_transport(r)?,
            tls: r.option("TLS facts", TlsFacts::read)?,
            since_input_ms: r.u64("since input")?,
            unwritten: r.u64("unwritten")?,
            unconfirmed: r.u32("unconfirmed")?,
            closed: r.option("closed", crate::edge_frames::read_closed)?,
        })
    }
}

/// How the core admits an edge's link (link version 2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Admission {
    /// Serve now. An edge holding sessions from a cut closes them: this core
    /// will not rebuild them.
    Serve,
    /// Hold every session, a new one included, until `Resume`: the core is
    /// rebuilding from other edges. An edge holding sessions from a cut
    /// closes them.
    Hold,
    /// Upload the sessions held from the cut the `Hello` named, then hold
    /// until `Resume`.
    Upload,
}

impl Admission {
    pub(crate) fn write(self, w: &mut Writer<'_>) {
        w.u8(match self {
            Self::Serve => 0,
            Self::Hold => 1,
            Self::Upload => 2,
        });
    }

    pub(crate) fn read(r: &mut Reader) -> Result<Self, DecodeError> {
        match r.u8("admission")? {
            0 => Ok(Self::Serve),
            1 => Ok(Self::Hold),
            2 => Ok(Self::Upload),
            tag => Err(DecodeError::UnknownTag {
                field: "admission",
                tag,
            }),
        }
    }
}
