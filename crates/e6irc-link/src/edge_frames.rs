//! The frames an edge sends the core.

use std::net::{IpAddr, SocketAddr};

use bytes::Bytes;

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

/// The most listeners an edge reports in its `Hello`.
pub const MAX_LISTENERS: usize = 64;

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

/// One listener an edge accepts on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ListenerReport {
    pub kind: ListenerKind,
    pub addr: SocketAddr,
    pub tls: bool,
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
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Open {
    pub kind: SessionKind,
    /// The client's canonical address.
    pub address: IpAddr,
    pub transport: Transport,
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

impl crate::sealed::Codec for EdgeFrame {
    fn header(&self) -> (u8, u64) {
        match self {
            Self::Hello(_) => (HELLO, 0),
            Self::Open(session, _) => (OPEN, session.get()),
            Self::Line(session, _) => (LINE, session.get()),
            Self::OverlongLine(session, _) => (OVERLONG_LINE, session.get()),
            Self::Message(session, _) => (MESSAGE, session.get()),
            Self::Closed(session, _) => (CLOSED, session.get()),
            Self::Drained(session, _) => (DRAINED, session.get()),
        }
    }

    fn write_payload(&self, w: &mut Writer<'_>) -> Result<(), EncodeError> {
        match self {
            Self::Hello(hello) => {
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
                        w.bool(listener.tls);
                        w.bool(listener.proxy_protocol);
                        Ok(())
                    },
                )
            }
            Self::Open(_, open) => {
                w.u8(match open.kind {
                    SessionKind::Irc => 0,
                    SessionKind::Attach => 1,
                    SessionKind::Ui => 2,
                });
                w.ip(open.address);
                w.u8(match open.transport {
                    Transport::Tcp => 0,
                    Transport::Tls => 1,
                    Transport::WebSocket => 2,
                    Transport::SecureWebSocket => 3,
                });
                Ok(())
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
            Self::Closed(_, reason) => match reason {
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
            },
            Self::Drained(_, bytes) => {
                w.u64(*bytes);
                Ok(())
            }
        }
    }

    fn read_payload(kind: u8, session: u64, r: &mut Reader) -> Result<Self, DecodeError> {
        let session_id = || SessionId::from_wire(session);
        Ok(match kind {
            HELLO => {
                link_frame(kind, session)?;
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
                        tls: r.bool("listener TLS")?,
                        proxy_protocol: r.bool("listener PROXY protocol")?,
                    })
                })?;
                Self::Hello(Hello {
                    versions,
                    role,
                    edge,
                    stream,
                    slot,
                    highest_epoch,
                    listeners,
                })
            }
            OPEN => {
                let session = session_id()?;
                let kind = match r.u8("session kind")? {
                    0 => SessionKind::Irc,
                    1 => SessionKind::Attach,
                    2 => SessionKind::Ui,
                    tag => {
                        return Err(DecodeError::UnknownTag {
                            field: "session kind",
                            tag,
                        });
                    }
                };
                let address = r.ip("client address")?;
                let transport = match r.u8("transport")? {
                    0 => Transport::Tcp,
                    1 => Transport::Tls,
                    2 => Transport::WebSocket,
                    3 => Transport::SecureWebSocket,
                    tag => {
                        return Err(DecodeError::UnknownTag {
                            field: "transport",
                            tag,
                        });
                    }
                };
                Self::Open(
                    session,
                    Open {
                        kind,
                        address,
                        transport,
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
            CLOSED => {
                let session = session_id()?;
                let reason = match r.u8("closed reason")? {
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
                };
                Self::Closed(session, reason)
            }
            DRAINED => Self::Drained(session_id()?, r.u64("drained bytes")?),
            kind => return Err(DecodeError::UnknownKind { kind }),
        })
    }
}
