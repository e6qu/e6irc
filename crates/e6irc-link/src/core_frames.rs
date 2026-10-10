//! The frames the core sends an edge.

use std::net::IpAddr;

use bytes::Bytes;

use crate::held::{Ack, Admission, Cut, CutId, CutPart, RecordPart, Replica};
use crate::wire::{Reader, Writer};
use crate::{DecodeError, EncodeError, MAX_OUTPUT_LEN, MAX_STREAMS, SessionId, Slot, link_frame};

const WELCOME: u8 = 0x41;
const REFUSED: u8 = 0x42;
const OUTPUT: u8 = 0x43;
const KILL: u8 = 0x44;
const END: u8 = 0x45;
const FLOOD_EXEMPT: u8 = 0x46;
const STREAM_CREDIT: u8 = 0x47;
const SESSION_CREDIT: u8 = 0x48;
const PAUSE: u8 = 0x49;
const RESUME: u8 = 0x4a;
const ACK: u8 = 0x4b;
const RECORD: u8 = 0x4c;
const REPLICA: u8 = 0x4d;
const CUT_STATE: u8 = 0x4e;
const CUT: u8 = 0x4f;
const HOME: u8 = 0x50;

/// The most trusted-proxy ranges a `Welcome` carries.
pub const MAX_TRUSTED_PROXIES: usize = 1024;

/// The most bytes a refusal's text holds.
pub const MAX_REFUSAL_LEN: usize = 2048;

/// The most bytes a WebSocket close frame's reason holds (RFC 6455 §5.5: a
/// control frame's payload is at most 125 bytes, two of them the code).
pub const MAX_CLOSE_REASON_LEN: usize = 123;

/// A frame from the core to an edge.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoreFrame {
    /// The core accepts a link connection.
    Welcome(Welcome),
    /// The core refuses a link connection, saying why; it closes it next.
    Refused(String),
    /// One line (or `/ws/ui` text message) for a session's client.
    Output(SessionId, Bytes),
    /// Discard what the edge has not written of the session's output, write
    /// this one line, and close.
    Kill(SessionId, Bytes),
    /// Write what is buffered, then the close frame if any, and close.
    End(SessionId, Option<CloseFrame>),
    /// Whether the edge meters the session's lines.
    FloodExempt(SessionId, bool),
    Credit(Credit),
    /// Send no more input on this stream, holding what clients send, and
    /// answer `Paused`: the core is about to cut.
    Pause,
    /// Send input again: first the lines retained for replay, then what was
    /// held.
    Resume,
    /// Which of a session's input lines the core is done with.
    Ack(SessionId, Ack),
    /// One part of a session's record, which the edge holds for the next core.
    Record(SessionId, RecordPart),
    /// A change to a channel replica the edge holds.
    Replica(Replica),
    /// One part of the cut state, on the first session stream, before its
    /// `Cut`.
    CutState(CutPart),
    /// The stream's last frame: the core stopped gracefully, and the edge
    /// holds its sessions for the next.
    Cut(Cut),
    /// A session of the core's own — the `local` bouncer network's, which
    /// no client socket carries (decision D13) — homed on this edge at a cut:
    /// the edge holds the record that follows, and uploads it to the next
    /// core (`HomeUpload`). Numbered in slot 0.
    Home(SessionId),
}

impl CoreFrame {
    /// The link version that introduced this frame: a link of an older
    /// version never carries it.
    pub fn since(&self) -> u16 {
        match self {
            Self::Welcome(_)
            | Self::Refused(_)
            | Self::Output(..)
            | Self::Kill(..)
            | Self::End(..)
            | Self::FloodExempt(..)
            | Self::Credit(_) => 1,
            Self::Pause
            | Self::Resume
            | Self::Ack(..)
            | Self::Record(..)
            | Self::Replica(_)
            | Self::CutState(_)
            | Self::Cut(_)
            | Self::Home(_) => 2,
        }
    }
}

/// What the core grants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Credit {
    /// Lines the edge may send on this stream for sessions of the `Irc` kind.
    Stream(u32),
    /// Bytes of lines or messages the edge may send for one session of the
    /// `Attach` or `Ui` kind.
    Session(SessionId, u32),
}

/// A WebSocket close frame an `End` carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CloseFrame {
    pub code: u16,
    pub reason: String,
}

/// The core's answer to a `Hello` it accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Welcome {
    /// The link version both speak.
    pub version: u16,
    /// The core's serving-lease epoch (0 for a core without a database).
    pub epoch: u64,
    /// The edge's slot.
    pub slot: Slot,
    /// How many session streams the edge opens: one per core shard.
    pub streams: u16,
    pub terms: EdgeTerms,
    /// How the core admits the edge (link version 2; a version 1 link serves
    /// at once, as `Serve` does).
    pub admission: Admission,
}

/// The configuration an edge follows, as the core's is (DESIGN §19.2).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EdgeTerms {
    /// The proxies whose forwarded addresses are believed: `(network,
    /// prefix length)`.
    pub trusted_proxies: Vec<(IpAddr, u8)>,
    /// The per-address connection limit the edge pre-filters by.
    pub max_connections_per_ip: Option<u32>,
    /// Each session's send-queue bound, in bytes.
    pub sendq_bytes: u32,
    pub command_flood: Option<CommandFloodTerms>,
    /// Lines each session stream may send before its first `Credit`.
    pub line_credit: u32,
}

/// A command-flood bucket's shape: `burst` tokens, `rate` regained a second.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CommandFloodTerms {
    pub burst: u32,
    pub rate: u32,
}

impl crate::sealed::Codec for CoreFrame {
    fn header(&self) -> (u8, u64) {
        match self {
            Self::Welcome(_) => (WELCOME, 0),
            Self::Refused(_) => (REFUSED, 0),
            Self::Output(session, _) => (OUTPUT, session.get()),
            Self::Kill(session, _) => (KILL, session.get()),
            Self::End(session, _) => (END, session.get()),
            Self::FloodExempt(session, _) => (FLOOD_EXEMPT, session.get()),
            Self::Credit(Credit::Stream(_)) => (STREAM_CREDIT, 0),
            Self::Credit(Credit::Session(session, _)) => (SESSION_CREDIT, session.get()),
            Self::Pause => (PAUSE, 0),
            Self::Resume => (RESUME, 0),
            Self::Ack(session, _) => (ACK, session.get()),
            Self::Record(session, _) => (RECORD, session.get()),
            Self::Replica(_) => (REPLICA, 0),
            Self::CutState(_) => (CUT_STATE, 0),
            Self::Cut(_) => (CUT, 0),
            Self::Home(session) => (HOME, session.get()),
        }
    }

    fn write_payload(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        match self {
            Self::Welcome(welcome) => {
                w.u16(welcome.version);
                w.u64(welcome.epoch);
                w.u16(welcome.slot.get());
                w.u16(welcome.streams);
                let terms = &welcome.terms;
                w.list(
                    "trusted proxies",
                    &terms.trusted_proxies,
                    MAX_TRUSTED_PROXIES,
                    |w, (network, prefix)| {
                        w.ip(*network);
                        w.u8(*prefix);
                        Ok(())
                    },
                )?;
                w.option(terms.max_connections_per_ip.as_ref(), |w, limit| {
                    w.u32(*limit);
                    Ok(())
                })?;
                w.u32(terms.sendq_bytes);
                w.option(terms.command_flood.as_ref(), |w, flood| {
                    w.u32(flood.burst);
                    w.u32(flood.rate);
                    Ok(())
                })?;
                w.u32(terms.line_credit);
                // What link version 2 adds follows, in a Welcome of that
                // version: its fields follow from the version it names.
                if welcome.version >= 2 {
                    welcome.admission.write(w);
                } else if welcome.admission != Admission::Serve {
                    return Err(EncodeError::OverBound {
                        field: "admission in a version 1 Welcome",
                        length: 1,
                        bound: 0,
                    });
                }
                Ok(())
            }
            Self::Refused(text) => w.text("refusal", text, MAX_REFUSAL_LEN),
            Self::Output(_, line) => w.bytes("output", line, MAX_OUTPUT_LEN),
            Self::Kill(_, line) => w.bytes("final line", line, MAX_OUTPUT_LEN),
            Self::End(_, close) => w.option(close.as_ref(), |w, close| {
                w.u16(close.code);
                w.text("close reason", &close.reason, MAX_CLOSE_REASON_LEN)
            }),
            Self::FloodExempt(_, exempt) => {
                w.bool(*exempt);
                Ok(())
            }
            Self::Credit(Credit::Stream(amount) | Credit::Session(_, amount)) => {
                w.u32(*amount);
                Ok(())
            }
            Self::Pause | Self::Resume | Self::Home(_) => Ok(()),
            Self::Ack(_, ack) => ack.write(w),
            Self::Record(_, part) => part.write(w),
            Self::Replica(replica) => replica.write(w),
            Self::CutState(part) => part.write(w),
            Self::Cut(cut) => {
                cut.cut.write(w);
                w.u64(cut.epoch);
                Ok(())
            }
        }
    }

    fn read_payload(kind: u8, session: u64, r: &mut Reader) -> Result<Self, DecodeError> {
        let session_id = || SessionId::from_wire(session);
        Ok(match kind {
            WELCOME => {
                link_frame(kind, session)?;
                let version = r.u16("version")?;
                let epoch = r.u64("epoch")?;
                let slot =
                    Slot::new(r.u16("slot")?).ok_or(DecodeError::Invalid { field: "slot" })?;
                let streams = r.u16("streams")?;
                if streams == 0 || streams > MAX_STREAMS {
                    return Err(DecodeError::Invalid { field: "streams" });
                }
                let trusted_proxies = r.list("trusted proxies", MAX_TRUSTED_PROXIES, |r| {
                    let network = r.ip("trusted proxy")?;
                    let prefix = r.u8("trusted proxy prefix")?;
                    let widest = if network.is_ipv4() { 32 } else { 128 };
                    if prefix > widest {
                        return Err(DecodeError::Invalid {
                            field: "trusted proxy prefix",
                        });
                    }
                    Ok((network, prefix))
                })?;
                let max_connections_per_ip =
                    r.option("connection limit", |r| r.u32("connection limit"))?;
                let sendq_bytes = r.u32("send-queue bytes")?;
                let command_flood = r.option("command flood", |r| {
                    Ok(CommandFloodTerms {
                        burst: r.u32("flood burst")?,
                        rate: r.u32("flood rate")?,
                    })
                })?;
                let line_credit = r.u32("line credit")?;
                let admission = if version >= 2 {
                    Admission::read(r)?
                } else {
                    Admission::Serve
                };
                Self::Welcome(Welcome {
                    version,
                    epoch,
                    slot,
                    streams,
                    terms: EdgeTerms {
                        trusted_proxies,
                        max_connections_per_ip,
                        sendq_bytes,
                        command_flood,
                        line_credit,
                    },
                    admission,
                })
            }
            REFUSED => {
                link_frame(kind, session)?;
                Self::Refused(r.text("refusal", MAX_REFUSAL_LEN)?)
            }
            OUTPUT => Self::Output(session_id()?, r.bytes("output", MAX_OUTPUT_LEN)?),
            KILL => Self::Kill(session_id()?, r.bytes("final line", MAX_OUTPUT_LEN)?),
            END => {
                let session = session_id()?;
                let close = r.option("close frame", |r| {
                    Ok(CloseFrame {
                        code: r.u16("close code")?,
                        reason: r.text("close reason", MAX_CLOSE_REASON_LEN)?,
                    })
                })?;
                Self::End(session, close)
            }
            FLOOD_EXEMPT => Self::FloodExempt(session_id()?, r.bool("flood exemption")?),
            STREAM_CREDIT => {
                link_frame(kind, session)?;
                Self::Credit(Credit::Stream(r.u32("credit")?))
            }
            SESSION_CREDIT => Self::Credit(Credit::Session(session_id()?, r.u32("credit")?)),
            PAUSE => {
                link_frame(kind, session)?;
                Self::Pause
            }
            RESUME => {
                link_frame(kind, session)?;
                Self::Resume
            }
            ACK => Self::Ack(session_id()?, Ack::read(r)?),
            RECORD => Self::Record(session_id()?, RecordPart::read(r)?),
            REPLICA => {
                link_frame(kind, session)?;
                Self::Replica(Replica::read(r)?)
            }
            CUT_STATE => {
                link_frame(kind, session)?;
                Self::CutState(CutPart::read(r)?)
            }
            CUT => {
                link_frame(kind, session)?;
                Self::Cut(Cut {
                    cut: CutId::read(r)?,
                    epoch: r.u64("cut epoch")?,
                })
            }
            HOME => Self::Home(session_id()?),
            kind => return Err(DecodeError::UnknownKind { kind }),
        })
    }
}
