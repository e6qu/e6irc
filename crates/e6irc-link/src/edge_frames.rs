//! The frames an edge sends the core.

use std::net::{IpAddr, SocketAddr};

use bytes::Bytes;

use crate::held::{CutId, CutPart, RecordPart, Replica, TlsFacts, Upload};
use crate::wire::{Reader, Writer};
use crate::{
    DecodeError, EdgeName, EncodeError, MAX_EDGE_NAME_LEN, MAX_LABEL_LEN, MAX_LINE_LEN,
    MAX_STREAMS, MAX_UI_MESSAGE_LEN, SessionId, Slot, VersionRange, link_frame,
};

const HELLO: u8 = 0x01;
const OPEN: u8 = 0x02;
const LINE: u8 = 0x03;
const OVERLONG_LINE: u8 = 0x04;
const MESSAGE: u8 = 0x05;
const CLOSED: u8 = 0x06;
const DRAINED: u8 = 0x07;
const OPEN_TLS: u8 = 0x08;
const PAUSED: u8 = 0x09;
const UPLOAD: u8 = 0x0a;
const RECORD_UPLOAD: u8 = 0x0b;
const REPLICA_UPLOAD: u8 = 0x0c;
const CUT_UPLOAD: u8 = 0x0d;
const UPLOAD_DONE: u8 = 0x0e;
const HOME_UPLOAD: u8 = 0x0f;

/// The most listeners an edge reports in its `Hello`.
pub const MAX_LISTENERS: usize = 64;

/// The most bytes of a listener's certificate path an edge reports.
pub const MAX_CERTIFICATE_PATH_LEN: usize = 4096;

/// The most bytes of a failed read's description a `Closed` carries; the edge
/// shortens a longer one on a character boundary.
pub const MAX_CLOSED_TEXT_LEN: usize = 512;

/// A frame from an edge to the core.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EdgeFrame {
    /// The first frame on every link connection.
    Hello(Hello),
    /// A client session opens.
    Open(SessionId, Open),
    /// One framed client line, its terminator stripped.
    Line(SessionId, Bytes),
    /// A client line over the line bound, framing already dropped it; the
    /// label its tag section named, when that could be read.
    OverlongLine(SessionId, Option<String>),
    /// One message a `/ws/ui` client sent.
    Message(SessionId, UiMessage),
    /// The client's side of a session ended.
    Closed(SessionId, ClosedReason),
    /// Bytes of a session's output written to the client socket.
    Drained(SessionId, u64),
    /// The edge sends no more input on this stream until `Resume`: its answer
    /// to `Pause`.
    Paused,
    /// A session held from a cut, as the edge knows it; its record follows in
    /// `RecordUpload` parts.
    Upload(SessionId, Upload),
    /// One part of a held session's record.
    RecordUpload(SessionId, RecordPart),
    /// One change of a held channel replica.
    ReplicaUpload(Replica),
    /// One part of the held cut state.
    CutUpload(CutPart),
    /// Everything this stream held is uploaded.
    UploadDone,
    /// A session of the core's own it homed here at the cut
    /// ([`crate::CoreFrame::Home`]): no client is behind it, so the edge
    /// knows nothing of it but the record that follows in `RecordUpload`
    /// parts.
    HomeUpload(SessionId),
}

impl EdgeFrame {
    /// The link version that introduced this frame: a link of an older
    /// version never carries it.
    pub fn since(&self) -> u16 {
        match self {
            Self::Open(_, open) if open.tls.is_some() => 2,
            Self::Hello(_)
            | Self::Open(..)
            | Self::Line(..)
            | Self::OverlongLine(..)
            | Self::Message(..)
            | Self::Closed(..)
            | Self::Drained(..) => 1,
            Self::Paused
            | Self::Upload(..)
            | Self::RecordUpload(..)
            | Self::ReplicaUpload(_)
            | Self::CutUpload(_)
            | Self::UploadDone
            | Self::HomeUpload(_) => 2,
        }
    }
}

/// What an edge says when it opens a link connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// The link versions the edge speaks.
    pub versions: VersionRange,
    pub role: Role,
    /// The name the edge's certificate is issued for.
    pub edge: EdgeName,
    pub stream: Stream,
    /// The slot the core gave this edge before, if it has linked before.
    pub slot: Option<Slot>,
    /// The highest serving-lease epoch the edge has accepted (0 before any).
    pub highest_epoch: u64,
    /// The edge's listeners, as the console shows them; on the first session
    /// stream only.
    pub listeners: Vec<ListenerReport>,
    /// The cut whose sessions the edge holds, carried by an edge that speaks
    /// link version 2 (`None` from one holding none).
    pub cut: Option<CutId>,
}

/// What a link connection is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The edge's link to the core that serves its clients.
    Serving,
    /// A read-only link to a warm standby (DESIGN §19.8).
    Observer,
}

/// Which of an edge's link connections this is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Stream {
    /// The session stream of one core shard: every session whose identifier
    /// the shard owns travels on it.
    Sessions { index: u16 },
    /// A connection carrying HTTP/1.1 requests the edge forwards.
    Http,
}

/// One listener an edge accepts on, as its configuration names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ListenerReport {
    pub kind: ListenerKind,
    pub addr: SocketAddr,
    /// The certificate chain's path on the edge's host, for a listener that
    /// terminates TLS; `None` for a plaintext one.
    pub certificate: Option<String>,
    pub proxy_protocol: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerKind {
    /// IRC over TCP (or TLS).
    Irc,
    /// IRC over WebSocket at the root path.
    WebSocketIrc,
    /// The web port: the application, `/ws/irc` and `/ws/ui`.
    Http,
    /// Bouncer attach.
    Attach,
}

/// A session opening.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Open {
    pub kind: SessionKind,
    /// The client's canonical address.
    pub address: IpAddr,
    pub transport: Transport,
    /// What the edge knows of the TLS it terminated for the connection (link
    /// version 2); `None` for a plaintext connection.
    pub tls: Option<TlsFacts>,
}

/// Where a session's lines go in the core (DESIGN §19.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SessionKind {
    /// IRC lines to a core shard: TCP, TLS or `/ws/irc`.
    Irc,
    /// IRC lines to the bouncer's attach logic.
    Attach,
    /// WebSocket messages to the web client's live socket.
    Ui,
}

/// How a client reached the edge.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Transport {
    Tcp,
    Tls,
    WebSocket,
    SecureWebSocket,
}

/// A message a `/ws/ui` client sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UiMessage {
    Text(String),
    /// A binary message, refused by its kind alone; its bytes are not carried.
    Binary,
}

/// Why the client's side of a session ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ClosedReason {
    ByClient,
    ReadFailed(String),
    MessageTooBig,
    WriteFailed(WriteFailure),
    WriterPanicked,
    /// A session with no socket ended itself, for the reason given.
    Stopped(String),
}

/// How a write to a client failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WriteFailure {
    Transport,
    Stalled,
}

pub(crate) fn write_kind(w: &mut Writer<'_>, kind: SessionKind) {
    w.u8(match kind {
        SessionKind::Irc => 0,
        SessionKind::Attach => 1,
        SessionKind::Ui => 2,
    });
}

pub(crate) fn read_kind(r: &mut Reader) -> Result<SessionKind, DecodeError> {
    match r.u8("session kind")? {
        0 => Ok(SessionKind::Irc),
        1 => Ok(SessionKind::Attach),
        2 => Ok(SessionKind::Ui),
        tag => Err(DecodeError::UnknownTag {
            field: "session kind",
            tag,
        }),
    }
}

pub(crate) fn write_transport(w: &mut Writer<'_>, transport: Transport) {
    w.u8(match transport {
        Transport::Tcp => 0,
        Transport::Tls => 1,
        Transport::WebSocket => 2,
        Transport::SecureWebSocket => 3,
    });
}

pub(crate) fn read_transport(r: &mut Reader) -> Result<Transport, DecodeError> {
    match r.u8("transport")? {
        0 => Ok(Transport::Tcp),
        1 => Ok(Transport::Tls),
        2 => Ok(Transport::WebSocket),
        3 => Ok(Transport::SecureWebSocket),
        tag => Err(DecodeError::UnknownTag {
            field: "transport",
            tag,
        }),
    }
}

pub(crate) fn write_closed(w: &mut Writer<'_>, reason: &ClosedReason) -> Result<(), EncodeError> {
    match reason {
        ClosedReason::ByClient => {
            w.u8(0);
            Ok(())
        }
        ClosedReason::ReadFailed(text) => {
            w.u8(1);
            w.text("read failure", text, MAX_CLOSED_TEXT_LEN)
        }
        ClosedReason::MessageTooBig => {
            w.u8(2);
            Ok(())
        }
        ClosedReason::WriteFailed(failure) => {
            w.u8(3);
            w.u8(match failure {
                WriteFailure::Transport => 0,
                WriteFailure::Stalled => 1,
            });
            Ok(())
        }
        ClosedReason::WriterPanicked => {
            w.u8(4);
            Ok(())
        }
        ClosedReason::Stopped(text) => {
            w.u8(5);
            w.text("stop reason", text, MAX_CLOSED_TEXT_LEN)
        }
    }
}

pub(crate) fn read_closed(r: &mut Reader) -> Result<ClosedReason, DecodeError> {
    Ok(match r.u8("closed reason")? {
        0 => ClosedReason::ByClient,
        1 => ClosedReason::ReadFailed(r.text("read failure", MAX_CLOSED_TEXT_LEN)?),
        2 => ClosedReason::MessageTooBig,
        3 => ClosedReason::WriteFailed(match r.u8("write failure")? {
            0 => WriteFailure::Transport,
            1 => WriteFailure::Stalled,
            tag => {
                return Err(DecodeError::UnknownTag {
                    field: "write failure",
                    tag,
                });
            }
        }),
        4 => ClosedReason::WriterPanicked,
        5 => ClosedReason::Stopped(r.text("stop reason", MAX_CLOSED_TEXT_LEN)?),
        tag => {
            return Err(DecodeError::UnknownTag {
                field: "closed reason",
                tag,
            });
        }
    })
}

fn write_hello(w: &mut Writer<'_>, hello: &Hello) -> Result<(), EncodeError> {
    w.u16(hello.versions.oldest());
    w.u16(hello.versions.newest());
    w.u8(match hello.role {
        Role::Serving => 0,
        Role::Observer => 1,
    });
    w.text("edge name", hello.edge.as_str(), MAX_EDGE_NAME_LEN)?;
    match hello.stream {
        Stream::Sessions { index } => {
            w.u8(0);
            w.u16(index);
        }
        Stream::Http => w.u8(1),
    }
    w.u16(hello.slot.map_or(0, Slot::get));
    w.u64(hello.highest_epoch);
    w.list(
        "listeners",
        &hello.listeners,
        MAX_LISTENERS,
        |w, listener| {
            w.u8(match listener.kind {
                ListenerKind::Irc => 0,
                ListenerKind::WebSocketIrc => 1,
                ListenerKind::Http => 2,
                ListenerKind::Attach => 3,
            });
            w.socket(listener.addr);
            w.option(listener.certificate.as_ref(), |w, path| {
                w.text("listener certificate", path, MAX_CERTIFICATE_PATH_LEN)
            })?;
            w.bool(listener.proxy_protocol);
            Ok(())
        },
    )?;
    // What link version 2 adds follows what version 1 has, and only in the
    // Hello of an edge that speaks it: the fields a Hello holds follow from
    // the version range it opens with.
    if hello.versions.newest() >= 2 {
        w.option(hello.cut.as_ref(), |w, cut| {
            cut.write(w);
            Ok(())
        })
    } else if hello.cut.is_some() {
        Err(EncodeError::OverBound {
            field: "cut in a version 1 Hello",
            length: 1,
            bound: 0,
        })
    } else {
        Ok(())
    }
}

fn read_hello(r: &mut Reader) -> Result<Hello, DecodeError> {
    let oldest = r.u16("oldest version")?;
    let newest = r.u16("newest version")?;
    let versions = VersionRange::new(oldest, newest).ok_or(DecodeError::Invalid {
        field: "version range",
    })?;
    let role = match r.u8("role")? {
        0 => Role::Serving,
        1 => Role::Observer,
        tag => return Err(DecodeError::UnknownTag { field: "role", tag }),
    };
    let edge = EdgeName::new(&r.text("edge name", MAX_EDGE_NAME_LEN)?)
        .map_err(|_| DecodeError::Invalid { field: "edge name" })?;
    let stream = match r.u8("stream")? {
        0 => {
            let index = r.u16("stream index")?;
            if index >= MAX_STREAMS {
                return Err(DecodeError::Invalid {
                    field: "stream index",
                });
            }
            Stream::Sessions { index }
        }
        1 => Stream::Http,
        tag => {
            return Err(DecodeError::UnknownTag {
                field: "stream",
                tag,
            });
        }
    };
    let slot = match r.u16("slot")? {
        0 => None,
        slot => Some(Slot::new(slot).ok_or(DecodeError::Invalid { field: "slot" })?),
    };
    let highest_epoch = r.u64("highest epoch")?;
    let listeners = r.list("listeners", MAX_LISTENERS, |r| {
        let kind = match r.u8("listener kind")? {
            0 => ListenerKind::Irc,
            1 => ListenerKind::WebSocketIrc,
            2 => ListenerKind::Http,
            3 => ListenerKind::Attach,
            tag => {
                return Err(DecodeError::UnknownTag {
                    field: "listener kind",
                    tag,
                });
            }
        };
        Ok(ListenerReport {
            kind,
            addr: r.socket("listener address")?,
            certificate: r.option("listener certificate", |r| {
                r.text("listener certificate", MAX_CERTIFICATE_PATH_LEN)
            })?,
            proxy_protocol: r.bool("listener PROXY protocol")?,
        })
    })?;
    let cut = if versions.newest() >= 2 {
        r.option("cut", CutId::read)?
    } else {
        None
    };
    Ok(Hello {
        versions,
        role,
        edge,
        stream,
        slot,
        highest_epoch,
        listeners,
        cut,
    })
}

impl crate::sealed::Codec for EdgeFrame {
    fn header(&self) -> (u8, u64) {
        match self {
            Self::Hello(_) => (HELLO, 0),
            Self::Open(session, open) if open.tls.is_some() => (OPEN_TLS, session.get()),
            Self::Open(session, _) => (OPEN, session.get()),
            Self::Line(session, _) => (LINE, session.get()),
            Self::OverlongLine(session, _) => (OVERLONG_LINE, session.get()),
            Self::Message(session, _) => (MESSAGE, session.get()),
            Self::Closed(session, _) => (CLOSED, session.get()),
            Self::Drained(session, _) => (DRAINED, session.get()),
            Self::Paused => (PAUSED, 0),
            Self::Upload(session, _) => (UPLOAD, session.get()),
            Self::RecordUpload(session, _) => (RECORD_UPLOAD, session.get()),
            Self::ReplicaUpload(_) => (REPLICA_UPLOAD, 0),
            Self::CutUpload(_) => (CUT_UPLOAD, 0),
            Self::UploadDone => (UPLOAD_DONE, 0),
            Self::HomeUpload(session) => (HOME_UPLOAD, session.get()),
        }
    }

    fn write_payload(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        match self {
            Self::Hello(hello) => write_hello(w, hello),
            Self::Open(_, open) => {
                write_kind(w, open.kind);
                w.ip(open.address);
                write_transport(w, open.transport);
                match &open.tls {
                    Some(tls) => tls.write(w),
                    None => Ok(()),
                }
            }
            Self::Line(_, line) => w.bytes("line", line, MAX_LINE_LEN),
            Self::OverlongLine(_, label) => w.option(label.as_ref(), |w, label| {
                w.text("label", label, MAX_LABEL_LEN)
            }),
            Self::Message(_, message) => match message {
                UiMessage::Text(text) => {
                    w.u8(0);
                    w.text("message", text, MAX_UI_MESSAGE_LEN)
                }
                UiMessage::Binary => {
                    w.u8(1);
                    Ok(())
                }
            },
            Self::Closed(_, reason) => write_closed(w, reason),
            Self::Drained(_, bytes) => {
                w.u64(*bytes);
                Ok(())
            }
            Self::Paused | Self::UploadDone | Self::HomeUpload(_) => Ok(()),
            Self::Upload(_, upload) => upload.write(w),
            Self::RecordUpload(_, part) => part.write(w),
            Self::ReplicaUpload(replica) => replica.write(w),
            Self::CutUpload(part) => part.write(w),
        }
    }

    fn read_payload(kind: u8, session: u64, r: &mut Reader) -> Result<Self, DecodeError> {
        let session_id = || SessionId::from_wire(session);
        let link = || link_frame(kind, session);
        Ok(match kind {
            HELLO => {
                link()?;
                Self::Hello(read_hello(r)?)
            }
            OPEN | OPEN_TLS => {
                let session = session_id()?;
                let session_kind = read_kind(r)?;
                let address = r.ip("client address")?;
                let transport = read_transport(r)?;
                let tls = if kind == OPEN_TLS {
                    Some(TlsFacts::read(r)?)
                } else {
                    None
                };
                Self::Open(
                    session,
                    Open {
                        kind: session_kind,
                        address,
                        transport,
                        tls,
                    },
                )
            }
            LINE => Self::Line(session_id()?, r.bytes("line", MAX_LINE_LEN)?),
            OVERLONG_LINE => Self::OverlongLine(
                session_id()?,
                r.option("label", |r| r.text("label", MAX_LABEL_LEN))?,
            ),
            MESSAGE => {
                let session = session_id()?;
                let message = match r.u8("message kind")? {
                    0 => UiMessage::Text(r.text("message", MAX_UI_MESSAGE_LEN)?),
                    1 => UiMessage::Binary,
                    tag => {
                        return Err(DecodeError::UnknownTag {
                            field: "message kind",
                            tag,
                        });
                    }
                };
                Self::Message(session, message)
            }
            CLOSED => Self::Closed(session_id()?, read_closed(r)?),
            DRAINED => Self::Drained(session_id()?, r.u64("drained bytes")?),
            PAUSED => {
                link()?;
                Self::Paused
            }
            UPLOAD => Self::Upload(session_id()?, Upload::read(r)?),
            RECORD_UPLOAD => Self::RecordUpload(session_id()?, RecordPart::read(r)?),
            REPLICA_UPLOAD => {
                link()?;
                Self::ReplicaUpload(Replica::read(r)?)
            }
            CUT_UPLOAD => {
                link()?;
                Self::CutUpload(CutPart::read(r)?)
            }
            UPLOAD_DONE => {
                link()?;
                Self::UploadDone
            }
            HOME_UPLOAD => Self::HomeUpload(session_id()?),
            kind => return Err(DecodeError::UnknownKind { kind }),
        })
    }
}
