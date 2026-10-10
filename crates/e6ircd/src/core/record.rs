//! What the core writes for its edges to hold (DESIGN §19.2, §19.3): each
//! session's record, each channel's replica, and the cut state a graceful stop
//! leaves behind. The edge stores these bodies without reading them; the next
//! core reads them back to rebuild what the last one served.
//!
//! Every body starts with its format version, and a core reads the format of
//! its release and the one before (D11): a release that introduces a format
//! keeps writing the previous one until the operator runs `e6ircd records
//! advance`, so a one-release rollback never meets a body it cannot read. A
//! body in any other format is refused whole ([`RecordError`]), and the one
//! session it belonged to is closed loudly — never rebuilt from a guess.
//!
//! A monotonic clock reading means nothing to another process, so a body
//! carries its writer's [`ClockOrigin`] — where that process's monotonic clock
//! started, on the wall clock — and the reader moves each reading onto its own
//! monotonic clock by the difference between the two origins. The origin is
//! fixed for a process, so a session whose state has not changed writes the
//! same bytes, and a record is sent again only when something in it changed.

use bytes::{Bytes, BytesMut};
use e6irc_link::wire::{Reader, Writer};
use e6irc_link::{DecodeError, EncodeError, TlsFacts};
use e6irc_proto::time::{Millis, MonoMillis};

use super::{ConnectionTransport, HistoryKind, HistoryRow};

/// A body format this release reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RecordFormat {
    /// Everything but the connection's TLS facts.
    V1 = 1,
    /// Version 1 with the TLS facts the edge gave at `Open`.
    V2 = 2,
}

impl RecordFormat {
    /// The newest format this release writes once advanced to it.
    pub const NEWEST: Self = Self::V2;

    /// The format before [`Self::NEWEST`]: what this release writes until the
    /// operator advances it.
    pub const PREVIOUS: Self = Self::V1;

    pub fn number(self) -> u16 {
        self as u16
    }

    /// The format numbered `number`, when this release reads it.
    pub fn read(number: u16) -> Option<Self> {
        match number {
            1 => Some(Self::V1),
            2 => Some(Self::V2),
            _ => None,
        }
    }
}

/// Why a body could not be read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordError {
    /// A format this release does not read (one from a release more than one
    /// before, or a newer one).
    Format(u16),
    Malformed(DecodeError),
}

impl std::fmt::Display for RecordError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Format(number) => write!(
                f,
                "body format {number}, which this release does not read (it reads {} and {})",
                RecordFormat::PREVIOUS.number(),
                RecordFormat::NEWEST.number()
            ),
            Self::Malformed(error) => write!(f, "a malformed body: {error}"),
        }
    }
}

impl std::error::Error for RecordError {}

impl From<DecodeError> for RecordError {
    fn from(error: DecodeError) -> Self {
        Self::Malformed(error)
    }
}

/// Where a process's monotonic clock started, on the wall clock: the wall
/// clock less the monotonic clock, in milliseconds, read once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClockOrigin(i64);

impl ClockOrigin {
    /// The origin of the clocks `wall` and `mono` read together.
    pub fn of(wall: Millis, mono: MonoMillis) -> Self {
        let origin = i128::from(wall.as_millis()) - i128::from(mono.as_millis());
        Self(i64::try_from(origin).unwrap_or(if origin < 0 { i64::MIN } else { i64::MAX }))
    }
}

/// The most bytes of one text field of a body: every one the core holds is
/// bounded well below it (a line is 512 bytes, a history body a few KiB).
const MAX_TEXT: usize = 64 * 1024;

/// The most entries of one list in a body.
const MAX_ENTRIES: usize = 1 << 20;

fn over(field: &'static str, length: usize, bound: usize) -> EncodeError {
    EncodeError::OverBound {
        field,
        length,
        bound,
    }
}

/// Body writing: the link's primitives, plus what bodies need beyond frames.
struct BodyWriter<'a> {
    w: Writer<'a>,
}

impl BodyWriter<'_> {
    fn text(&mut self, field: &'static str, text: &str) -> Result<(), EncodeError> {
        self.w.text(field, text, MAX_TEXT)
    }

    fn opt_text(&mut self, field: &'static str, text: Option<&str>) -> Result<(), EncodeError> {
        self.w
            .option(text.as_ref(), |w, text| w.text(field, text, MAX_TEXT))
    }

    fn bool(&mut self, value: bool) {
        self.w.bool(value);
    }

    fn u64(&mut self, value: u64) {
        self.w.u64(value);
    }

    fn millis(&mut self, value: Millis) {
        self.w.u64(value.as_millis());
    }

    /// A monotonic reading, on the writer's clock.
    fn mono(&mut self, value: MonoMillis) {
        self.w.u64(value.as_millis());
    }

    fn opt_mono(&mut self, value: Option<MonoMillis>) {
        match value {
            None => self.w.u8(0),
            Some(value) => {
                self.w.u8(1);
                self.mono(value);
            }
        }
    }

    fn count(&mut self, field: &'static str, count: usize) -> Result<(), EncodeError> {
        if count > MAX_ENTRIES {
            return Err(over(field, count, MAX_ENTRIES));
        }
        self.w.u32(u32::try_from(count).expect("bounded above"));
        Ok(())
    }
}

/// Body reading: the link's primitives, plus what bodies need beyond frames.
pub(crate) struct BodyReader {
    r: Reader,
    /// What moves a monotonic reading of the writer's onto the reader's
    /// clock: the writer's origin less the reader's.
    offset: i128,
    format: RecordFormat,
}

impl BodyReader {
    fn new(bytes: Bytes, reader: ClockOrigin) -> Result<Self, RecordError> {
        let mut r = Reader::new(bytes);
        let number = r.u16("format")?;
        let format = RecordFormat::read(number).ok_or(RecordError::Format(number))?;
        let writer = r.u64("clock origin")?.cast_signed();
        Ok(Self {
            r,
            offset: i128::from(writer) - i128::from(reader.0),
            format,
        })
    }

    fn text(&mut self, field: &'static str) -> Result<String, DecodeError> {
        self.r.text(field, MAX_TEXT)
    }

    fn opt_text(&mut self, field: &'static str) -> Result<Option<String>, DecodeError> {
        self.r.option(field, |r| r.text(field, MAX_TEXT))
    }

    fn bool(&mut self, field: &'static str) -> Result<bool, DecodeError> {
        self.r.bool(field)
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, DecodeError> {
        self.r.u64(field)
    }

    fn millis(&mut self, field: &'static str) -> Result<Millis, DecodeError> {
        Ok(Millis::from_millis(self.r.u64(field)?))
    }

    fn mono(&mut self, field: &'static str) -> Result<MonoMillis, DecodeError> {
        let value = (i128::from(self.r.u64(field)?) + self.offset).clamp(0, i128::from(u64::MAX));
        Ok(MonoMillis::from_millis(
            u64::try_from(value).expect("clamped to the u64 range"),
        ))
    }

    fn opt_mono(&mut self, field: &'static str) -> Result<Option<MonoMillis>, DecodeError> {
        match self.r.u8(field)? {
            0 => Ok(None),
            1 => self.mono(field).map(Some),
            tag => Err(DecodeError::UnknownTag { field, tag }),
        }
    }

    fn count(&mut self, field: &'static str) -> Result<usize, DecodeError> {
        let count = self.r.u32(field)? as usize;
        if count > MAX_ENTRIES {
            return Err(DecodeError::OverBound {
                field,
                length: count,
                bound: MAX_ENTRIES,
            });
        }
        Ok(count)
    }

    fn finish(self) -> Result<(), RecordError> {
        Ok(self.r.finish()?)
    }
}

/// Write a body of `format` with `write`, starting with the format and the
/// writer's clock origin.
fn body(
    format: RecordFormat,
    clock: ClockOrigin,
    write: impl FnOnce(&mut BodyWriter<'_>) -> Result<(), EncodeError>,
) -> Result<Bytes, EncodeError> {
    let mut out = BytesMut::with_capacity(512);
    let mut writer = BodyWriter {
        w: Writer::new(&mut out),
    };
    writer.w.u16(format.number());
    writer.w.u64(clock.0.cast_unsigned());
    write(&mut writer)?;
    Ok(out.freeze())
}

/// The registration state a record holds, as the session's own sum type has
/// it: a registered session has its nick, user and real name.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordedRegistration {
    Registering {
        nick: Option<String>,
        user: Option<String>,
        realname: Option<String>,
        refused_nick: Option<String>,
    },
    Registered {
        nick: String,
        user: String,
        realname: String,
    },
}

/// A session's login.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedLogin {
    pub account: String,
    pub credential: crate::identity::CredentialId,
    pub expires_at: Option<MonoMillis>,
}

/// Where SASL stood: the mechanism line answered and its payload awaited, or
/// a verification dispatched (settled before a cut; after a crash the client
/// is told it was aborted).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordedSasl {
    Idle,
    PlainPending,
    BearerPending,
    Verifying,
}

/// A LIST or bare NAMES still answering: its question and the last channel
/// sent, from which a core of any shard count resumes exactly (rows go out in
/// global casemapped order).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedSweep {
    pub question: RecordedQuestion,
    pub batch: Option<String>,
    /// The folded key of the last channel sent, `None` before the first.
    pub sent_through: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecordedQuestion {
    /// LIST's parameter, and the Unix second its relative conditions were
    /// read against.
    List {
        parameter: Option<String>,
        parsed_at_secs: u64,
    },
    Names {
        multi_prefix: bool,
        userhost_in_names: bool,
    },
}

/// One WHO reply being paced out: the rows still to go.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedPacedReply {
    /// The labeled-response batch: its label, reference and whether it is
    /// open already.
    pub batch: Option<(String, String, bool)>,
    pub lines: Vec<Bytes>,
}

/// The hot history of one conversation with an unauthenticated party, which
/// is never stored and so lives in its participants' records (D6).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedRing {
    pub key: String,
    pub complete: bool,
    pub shed_through: Option<(Millis, String)>,
    pub entries: Vec<HistoryRow>,
}

/// One session, as its edge holds it for the next core. Built from a
/// session by destructuring it whole ([`crate::core::state`]), so a session
/// field that is neither recorded nor declared rebuilt from elsewhere does not
/// compile; and turned back into a session by a total conversion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub directory_key: u64,
    pub host: String,
    pub transport: ConnectionTransport,
    /// Format 2 onwards; a session read from format 1 has none.
    pub tls: Option<TlsFacts>,
    pub registration: RecordedRegistration,
    pub cap_negotiating: bool,
    pub cap_302: bool,
    pub caps: u32,
    pub login: Option<RecordedLogin>,
    pub sasl: RecordedSasl,
    /// A credential verification awaited, with the label of the command it
    /// answers.
    pub sasl_verify: Option<Option<String>>,
    pub credential_attempts: u8,
    pub pending_identify: Option<Option<String>>,
    pub pending_register: Option<Option<String>>,
    pub nick_held: Option<String>,
    pub nick_deadlines: Vec<(String, MonoMillis)>,
    pub drop_confirmation: Option<(String, String)>,
    pub away: Option<String>,
    pub oper: Option<String>,
    pub invisible: bool,
    pub wallops: bool,
    pub bot: bool,
    pub registered_only: bool,
    pub last_knock: Option<MonoMillis>,
    pub nick_changes: (u32, Option<MonoMillis>),
    /// Folded key and display form.
    pub monitoring: Vec<(String, String)>,
    pub channel_list: Option<RecordedSweep>,
    pub channel_names: Option<RecordedSweep>,
    pub paced_who: Vec<RecordedPacedReply>,
    pub anon_read_markers: Vec<(String, Millis)>,
    pub idle_since: MonoMillis,
    pub signon: Millis,
    pub opened_at: MonoMillis,
    pub awaiting_pong: bool,
    pub last_ping_sent: MonoMillis,
    pub conversations: Vec<RecordedRing>,
}

fn write_transport(w: &mut BodyWriter<'_>, transport: ConnectionTransport) {
    w.w.u8(match transport {
        ConnectionTransport::Tcp => 0,
        ConnectionTransport::Tls => 1,
        ConnectionTransport::WebSocket => 2,
        ConnectionTransport::SecureWebSocket => 3,
        ConnectionTransport::Local => 4,
    });
}

fn read_transport(r: &mut BodyReader) -> Result<ConnectionTransport, DecodeError> {
    Ok(match r.r.u8("transport")? {
        0 => ConnectionTransport::Tcp,
        1 => ConnectionTransport::Tls,
        2 => ConnectionTransport::WebSocket,
        3 => ConnectionTransport::SecureWebSocket,
        4 => ConnectionTransport::Local,
        tag => {
            return Err(DecodeError::UnknownTag {
                field: "transport",
                tag,
            });
        }
    })
}

fn write_label(
    w: &mut BodyWriter<'_>,
    pending: Option<&Option<String>>,
) -> Result<(), EncodeError> {
    match pending {
        None => {
            w.w.u8(0);
            Ok(())
        }
        Some(label) => {
            w.w.u8(1);
            w.opt_text("label", label.as_deref())
        }
    }
}

fn read_label(
    r: &mut BodyReader,
    field: &'static str,
) -> Result<Option<Option<String>>, DecodeError> {
    match r.r.u8(field)? {
        0 => Ok(None),
        1 => Ok(Some(r.opt_text(field)?)),
        tag => Err(DecodeError::UnknownTag { field, tag }),
    }
}

fn write_history_row(w: &mut BodyWriter<'_>, row: &HistoryRow) -> Result<(), EncodeError> {
    let HistoryRow {
        msgid,
        ts,
        sender_prefix,
        sender_account,
        kind,
        body,
        sender_is_bot,
        multiline,
        client_tags,
    } = row;
    w.text("msgid", msgid)?;
    w.millis(*ts);
    w.text("sender prefix", sender_prefix)?;
    w.opt_text("sender account", sender_account.as_deref())?;
    w.w.u8(match kind {
        HistoryKind::Privmsg => 0,
        HistoryKind::Notice => 1,
        HistoryKind::Tagmsg => 2,
    });
    w.text("body", body)?;
    w.bool(*sender_is_bot);
    w.opt_text("multiline", multiline.as_deref())?;
    w.text("client tags", client_tags)
}

fn read_history_row(r: &mut BodyReader) -> Result<HistoryRow, DecodeError> {
    Ok(HistoryRow {
        msgid: r.text("msgid")?,
        ts: r.millis("history time")?,
        sender_prefix: r.text("sender prefix")?,
        sender_account: r.opt_text("sender account")?,
        kind: match r.r.u8("history kind")? {
            0 => HistoryKind::Privmsg,
            1 => HistoryKind::Notice,
            2 => HistoryKind::Tagmsg,
            tag => {
                return Err(DecodeError::UnknownTag {
                    field: "history kind",
                    tag,
                });
            }
        },
        body: r.text("body")?,
        sender_is_bot: r.bool("sender is a bot")?,
        multiline: r.opt_text("multiline")?,
        client_tags: r.text("client tags")?,
    })
}

fn write_sweep(w: &mut BodyWriter<'_>, sweep: &RecordedSweep) -> Result<(), EncodeError> {
    match &sweep.question {
        RecordedQuestion::List {
            parameter,
            parsed_at_secs,
        } => {
            w.w.u8(0);
            w.opt_text("list parameter", parameter.as_deref())?;
            w.u64(*parsed_at_secs);
        }
        RecordedQuestion::Names {
            multi_prefix,
            userhost_in_names,
        } => {
            w.w.u8(1);
            w.bool(*multi_prefix);
            w.bool(*userhost_in_names);
        }
    }
    w.opt_text("sweep batch", sweep.batch.as_deref())?;
    w.opt_text("sent through", sweep.sent_through.as_deref())
}

fn read_sweep(r: &mut BodyReader) -> Result<RecordedSweep, DecodeError> {
    let question = match r.r.u8("sweep")? {
        0 => RecordedQuestion::List {
            parameter: r.opt_text("list parameter")?,
            parsed_at_secs: r.u64("list parsed at")?,
        },
        1 => RecordedQuestion::Names {
            multi_prefix: r.bool("multi-prefix")?,
            userhost_in_names: r.bool("userhost-in-names")?,
        },
        tag => {
            return Err(DecodeError::UnknownTag {
                field: "sweep",
                tag,
            });
        }
    };
    Ok(RecordedSweep {
        question,
        batch: r.opt_text("sweep batch")?,
        sent_through: r.opt_text("sent through")?,
    })
}

fn write_credential(w: &mut BodyWriter<'_>, credential: crate::identity::CredentialId) {
    use crate::identity::{CredentialId, IssuedCredential};
    match credential {
        CredentialId::AccountPassword => w.w.u8(0),
        CredentialId::Issued(IssuedCredential::AppPassword(id)) => {
            w.w.u8(1);
            w.u64(id.cast_unsigned());
        }
        CredentialId::Issued(IssuedCredential::ApiToken(id)) => {
            w.w.u8(2);
            w.u64(id.cast_unsigned());
        }
    }
}

fn read_credential(r: &mut BodyReader) -> Result<crate::identity::CredentialId, DecodeError> {
    use crate::identity::{CredentialId, IssuedCredential};
    Ok(match r.r.u8("credential")? {
        0 => CredentialId::AccountPassword,
        1 => CredentialId::Issued(IssuedCredential::AppPassword(
            r.u64("credential")?.cast_signed(),
        )),
        2 => CredentialId::Issued(IssuedCredential::ApiToken(
            r.u64("credential")?.cast_signed(),
        )),
        tag => {
            return Err(DecodeError::UnknownTag {
                field: "credential",
                tag,
            });
        }
    })
}

impl SessionRecord {
    /// The record's body, in `format`, at the writer's `clock`.
    pub fn encode(&self, format: RecordFormat, clock: ClockOrigin) -> Result<Bytes, EncodeError> {
        let Self {
            directory_key,
            host,
            transport,
            tls,
            registration,
            cap_negotiating,
            cap_302,
            caps,
            login,
            sasl,
            sasl_verify,
            credential_attempts,
            pending_identify,
            pending_register,
            nick_held,
            nick_deadlines,
            drop_confirmation,
            away,
            oper,
            invisible,
            wallops,
            bot,
            registered_only,
            last_knock,
            nick_changes,
            monitoring,
            channel_list,
            channel_names,
            paced_who,
            anon_read_markers,
            idle_since,
            signon,
            opened_at,
            awaiting_pong,
            last_ping_sent,
            conversations,
        } = self;
        body(format, clock, |w| {
            w.u64(*directory_key);
            w.text("host", host)?;
            write_transport(w, *transport);
            if format >= RecordFormat::V2 {
                w.w.option(tls.as_ref(), |w, tls| tls.write(w))?;
            }
            match registration {
                RecordedRegistration::Registering {
                    nick,
                    user,
                    realname,
                    refused_nick,
                } => {
                    w.w.u8(0);
                    w.opt_text("nick", nick.as_deref())?;
                    w.opt_text("user", user.as_deref())?;
                    w.opt_text("realname", realname.as_deref())?;
                    w.opt_text("refused nick", refused_nick.as_deref())?;
                }
                RecordedRegistration::Registered {
                    nick,
                    user,
                    realname,
                } => {
                    w.w.u8(1);
                    w.text("nick", nick)?;
                    w.text("user", user)?;
                    w.text("realname", realname)?;
                }
            }
            w.bool(*cap_negotiating);
            w.bool(*cap_302);
            w.w.u32(*caps);
            match login {
                None => w.w.u8(0),
                Some(login) => {
                    w.w.u8(1);
                    w.text("account", &login.account)?;
                    write_credential(w, login.credential);
                    w.opt_mono(login.expires_at);
                }
            }
            w.w.u8(match sasl {
                RecordedSasl::Idle => 0,
                RecordedSasl::PlainPending => 1,
                RecordedSasl::BearerPending => 2,
                RecordedSasl::Verifying => 3,
            });
            write_label(w, sasl_verify.as_ref())?;
            w.w.u8(*credential_attempts);
            write_label(w, pending_identify.as_ref())?;
            write_label(w, pending_register.as_ref())?;
            w.opt_text("held nick", nick_held.as_deref())?;
            w.count("nick deadlines", nick_deadlines.len())?;
            for (nick, deadline) in nick_deadlines {
                w.text("clocked nick", nick)?;
                w.mono(*deadline);
            }
            match drop_confirmation {
                None => w.w.u8(0),
                Some((account, key)) => {
                    w.w.u8(1);
                    w.text("drop account", account)?;
                    w.text("drop key", key)?;
                }
            }
            w.opt_text("away", away.as_deref())?;
            w.opt_text("oper", oper.as_deref())?;
            w.bool(*invisible);
            w.bool(*wallops);
            w.bool(*bot);
            w.bool(*registered_only);
            w.opt_mono(*last_knock);
            w.w.u32(nick_changes.0);
            w.opt_mono(nick_changes.1);
            w.count("monitoring", monitoring.len())?;
            for (key, display) in monitoring {
                w.text("monitored key", key)?;
                w.text("monitored nick", display)?;
            }
            for sweep in [channel_list, channel_names] {
                match sweep {
                    None => w.w.u8(0),
                    Some(sweep) => {
                        w.w.u8(1);
                        write_sweep(w, sweep)?;
                    }
                }
            }
            w.count("paced WHO replies", paced_who.len())?;
            for reply in paced_who {
                match &reply.batch {
                    None => w.w.u8(0),
                    Some((label, reference, opened)) => {
                        w.w.u8(1);
                        w.text("paced label", label)?;
                        w.text("paced batch", reference)?;
                        w.bool(*opened);
                    }
                }
                w.count("paced lines", reply.lines.len())?;
                for line in &reply.lines {
                    w.w.bytes("paced line", line, MAX_TEXT)?;
                }
            }
            w.count("read markers", anon_read_markers.len())?;
            for (target, at) in anon_read_markers {
                w.text("marker target", target)?;
                w.millis(*at);
            }
            w.mono(*idle_since);
            w.millis(*signon);
            w.mono(*opened_at);
            w.bool(*awaiting_pong);
            w.mono(*last_ping_sent);
            w.count("conversations", conversations.len())?;
            for ring in conversations {
                w.text("conversation", &ring.key)?;
                w.bool(ring.complete);
                match &ring.shed_through {
                    None => w.w.u8(0),
                    Some((ts, msgid)) => {
                        w.w.u8(1);
                        w.millis(*ts);
                        w.text("shed through", msgid)?;
                    }
                }
                w.count("conversation entries", ring.entries.len())?;
                for entry in &ring.entries {
                    write_history_row(w, entry)?;
                }
            }
            Ok(())
        })
    }

    /// A record read from `bytes` onto the reader's `clock`.
    pub fn decode(bytes: Bytes, clock: ClockOrigin) -> Result<Self, RecordError> {
        let mut r = BodyReader::new(bytes, clock)?;
        let directory_key = r.u64("directory key")?;
        let host = r.text("host")?;
        let transport = read_transport(&mut r)?;
        let tls = if r.format >= RecordFormat::V2 {
            r.r.option("TLS facts", TlsFacts::read)?
        } else {
            None
        };
        let registration = match r.r.u8("registration")? {
            0 => RecordedRegistration::Registering {
                nick: r.opt_text("nick")?,
                user: r.opt_text("user")?,
                realname: r.opt_text("realname")?,
                refused_nick: r.opt_text("refused nick")?,
            },
            1 => RecordedRegistration::Registered {
                nick: r.text("nick")?,
                user: r.text("user")?,
                realname: r.text("realname")?,
            },
            tag => {
                return Err(DecodeError::UnknownTag {
                    field: "registration",
                    tag,
                }
                .into());
            }
        };
        let cap_negotiating = r.bool("cap negotiating")?;
        let cap_302 = r.bool("cap 302")?;
        let caps = r.r.u32("caps")?;
        let login = match r.r.u8("login")? {
            0 => None,
            1 => Some(RecordedLogin {
                account: r.text("account")?,
                credential: read_credential(&mut r)?,
                expires_at: r.opt_mono("login expiry")?,
            }),
            tag => {
                return Err(DecodeError::UnknownTag {
                    field: "login",
                    tag,
                }
                .into());
            }
        };
        let sasl = match r.r.u8("sasl")? {
            0 => RecordedSasl::Idle,
            1 => RecordedSasl::PlainPending,
            2 => RecordedSasl::BearerPending,
            3 => RecordedSasl::Verifying,
            tag => return Err(DecodeError::UnknownTag { field: "sasl", tag }.into()),
        };
        let sasl_verify = read_label(&mut r, "sasl verification")?;
        let credential_attempts = r.r.u8("credential attempts")?;
        let pending_identify = read_label(&mut r, "pending identify")?;
        let pending_register = read_label(&mut r, "pending register")?;
        let nick_held = r.opt_text("held nick")?;
        let mut nick_deadlines = Vec::new();
        for _ in 0..r.count("nick deadlines")? {
            nick_deadlines.push((r.text("clocked nick")?, r.mono("nick deadline")?));
        }
        let drop_confirmation = match r.r.u8("drop confirmation")? {
            0 => None,
            1 => Some((r.text("drop account")?, r.text("drop key")?)),
            tag => {
                return Err(DecodeError::UnknownTag {
                    field: "drop confirmation",
                    tag,
                }
                .into());
            }
        };
        let away = r.opt_text("away")?;
        let oper = r.opt_text("oper")?;
        let invisible = r.bool("invisible")?;
        let wallops = r.bool("wallops")?;
        let bot = r.bool("bot")?;
        let registered_only = r.bool("registered only")?;
        let last_knock = r.opt_mono("last knock")?;
        let nick_changes = (r.r.u32("nick changes")?, r.opt_mono("last nick change")?);
        let mut monitoring = Vec::new();
        for _ in 0..r.count("monitoring")? {
            monitoring.push((r.text("monitored key")?, r.text("monitored nick")?));
        }
        let mut sweeps = [None, None];
        for sweep in &mut sweeps {
            *sweep = match r.r.u8("sweep present")? {
                0 => None,
                1 => Some(read_sweep(&mut r)?),
                tag => {
                    return Err(DecodeError::UnknownTag {
                        field: "sweep present",
                        tag,
                    }
                    .into());
                }
            };
        }
        let [channel_list, channel_names] = sweeps;
        let mut paced_who = Vec::new();
        for _ in 0..r.count("paced WHO replies")? {
            let batch = match r.r.u8("paced batch")? {
                0 => None,
                1 => Some((
                    r.text("paced label")?,
                    r.text("paced batch")?,
                    r.bool("paced batch opened")?,
                )),
                tag => {
                    return Err(DecodeError::UnknownTag {
                        field: "paced batch",
                        tag,
                    }
                    .into());
                }
            };
            let mut lines = Vec::new();
            for _ in 0..r.count("paced lines")? {
                lines.push(r.r.bytes("paced line", MAX_TEXT)?);
            }
            paced_who.push(RecordedPacedReply { batch, lines });
        }
        let mut anon_read_markers = Vec::new();
        for _ in 0..r.count("read markers")? {
            anon_read_markers.push((r.text("marker target")?, r.millis("marker")?));
        }
        let idle_since = r.mono("idle since")?;
        let signon = r.millis("signon")?;
        let opened_at = r.mono("opened at")?;
        let awaiting_pong = r.bool("awaiting pong")?;
        let last_ping_sent = r.mono("last ping sent")?;
        let mut conversations = Vec::new();
        for _ in 0..r.count("conversations")? {
            let key = r.text("conversation")?;
            let complete = r.bool("conversation complete")?;
            let shed_through = match r.r.u8("shed through")? {
                0 => None,
                1 => Some((r.millis("shed through")?, r.text("shed through")?)),
                tag => {
                    return Err(DecodeError::UnknownTag {
                        field: "shed through",
                        tag,
                    }
                    .into());
                }
            };
            let mut entries = Vec::new();
            for _ in 0..r.count("conversation entries")? {
                entries.push(read_history_row(&mut r)?);
            }
            conversations.push(RecordedRing {
                key,
                complete,
                shed_through,
                entries,
            });
        }
        r.finish()?;
        Ok(Self {
            directory_key,
            host,
            transport,
            tls,
            registration,
            cap_negotiating,
            cap_302,
            caps,
            login,
            sasl,
            sasl_verify,
            credential_attempts,
            pending_identify,
            pending_register,
            nick_held,
            nick_deadlines,
            drop_confirmation,
            away,
            oper,
            invisible,
            wallops,
            bot,
            registered_only,
            last_knock,
            nick_changes,
            monitoring,
            channel_list,
            channel_names,
            paced_who,
            anon_read_markers,
            idle_since,
            signon,
            opened_at,
            awaiting_pong,
            last_ping_sent,
            conversations,
        })
    }
}

/// One entry of a channel's ban, quiet or exception list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedListEntry {
    pub mask: String,
    pub set_by: String,
    pub set_at_secs: u64,
}

/// A channel's own state, as every edge hosting a member holds it: everything
/// but its members, each edge holding its own members' entries beside it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChannelState {
    pub name: String,
    pub created_at: Millis,
    /// Text, setter, Unix seconds.
    pub topic: Option<(String, String, u64)>,
    /// The flag modes set, as their mode letters.
    pub flags: String,
    pub key: Option<String>,
    pub limit: Option<u32>,
    pub bans: Vec<RecordedListEntry>,
    pub quiets: Vec<RecordedListEntry>,
    pub ban_exceptions: Vec<RecordedListEntry>,
    pub invite_exceptions: Vec<RecordedListEntry>,
    /// Connections invited in.
    pub invited: Vec<u64>,
    pub last_knock: Option<MonoMillis>,
}

fn write_list(w: &mut BodyWriter<'_>, list: &[RecordedListEntry]) -> Result<(), EncodeError> {
    w.count("channel list", list.len())?;
    for entry in list {
        w.text("mask", &entry.mask)?;
        w.text("set by", &entry.set_by)?;
        w.u64(entry.set_at_secs);
    }
    Ok(())
}

fn read_list(r: &mut BodyReader) -> Result<Vec<RecordedListEntry>, DecodeError> {
    let mut list = Vec::new();
    for _ in 0..r.count("channel list")? {
        list.push(RecordedListEntry {
            mask: r.text("mask")?,
            set_by: r.text("set by")?,
            set_at_secs: r.u64("set at")?,
        });
    }
    Ok(list)
}

impl ChannelState {
    pub fn encode(&self, format: RecordFormat, clock: ClockOrigin) -> Result<Bytes, EncodeError> {
        let Self {
            name,
            created_at,
            topic,
            flags,
            key,
            limit,
            bans,
            quiets,
            ban_exceptions,
            invite_exceptions,
            invited,
            last_knock,
        } = self;
        body(format, clock, |w| {
            w.text("channel name", name)?;
            w.millis(*created_at);
            match topic {
                None => w.w.u8(0),
                Some((text, set_by, set_at)) => {
                    w.w.u8(1);
                    w.text("topic", text)?;
                    w.text("topic setter", set_by)?;
                    w.u64(*set_at);
                }
            }
            w.text("flags", flags)?;
            w.opt_text("key", key.as_deref())?;
            w.w.option(limit.as_ref(), |w, limit| {
                w.u32(*limit);
                Ok(())
            })?;
            for list in [bans, quiets, ban_exceptions, invite_exceptions] {
                write_list(w, list)?;
            }
            w.count("invited", invited.len())?;
            for conn in invited {
                w.u64(*conn);
            }
            w.opt_mono(*last_knock);
            Ok(())
        })
    }

    pub fn decode(bytes: Bytes, clock: ClockOrigin) -> Result<Self, RecordError> {
        let mut r = BodyReader::new(bytes, clock)?;
        let name = r.text("channel name")?;
        let created_at = r.millis("created at")?;
        let topic = match r.r.u8("topic")? {
            0 => None,
            1 => Some((
                r.text("topic")?,
                r.text("topic setter")?,
                r.u64("topic set at")?,
            )),
            tag => {
                return Err(DecodeError::UnknownTag {
                    field: "topic",
                    tag,
                }
                .into());
            }
        };
        let flags = r.text("flags")?;
        let key = r.opt_text("key")?;
        let limit = r.r.option("limit", |r| r.u32("limit"))?;
        let bans = read_list(&mut r)?;
        let quiets = read_list(&mut r)?;
        let ban_exceptions = read_list(&mut r)?;
        let invite_exceptions = read_list(&mut r)?;
        let mut invited = Vec::new();
        for _ in 0..r.count("invited")? {
            invited.push(r.u64("invited")?);
        }
        let last_knock = r.opt_mono("channel knock")?;
        r.finish()?;
        Ok(Self {
            name,
            created_at,
            topic,
            flags,
            key,
            limit,
            bans,
            quiets,
            ban_exceptions,
            invite_exceptions,
            invited,
            last_knock,
        })
    }
}

/// One member's entry in a channel replica: its ranks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MemberEntry {
    pub op: bool,
    pub voice: bool,
}

impl MemberEntry {
    pub fn encode(self, format: RecordFormat, clock: ClockOrigin) -> Result<Bytes, EncodeError> {
        let Self { op, voice } = self;
        body(format, clock, |w| {
            w.bool(op);
            w.bool(voice);
            Ok(())
        })
    }

    pub fn decode(bytes: Bytes, clock: ClockOrigin) -> Result<Self, RecordError> {
        let mut r = BodyReader::new(bytes, clock)?;
        let entry = Self {
            op: r.bool("op")?,
            voice: r.bool("voice")?,
        };
        r.finish()?;
        Ok(entry)
    }
}

/// One WHOWAS record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordedWhowas {
    pub key: String,
    pub nick: String,
    pub user: String,
    pub host: String,
    pub realname: String,
    pub signoff: Millis,
}

/// The global state a graceful cut carries (D6): WHOWAS, the LUSERS maximum,
/// the account-creation buckets, and the edges the cut was sent to, which
/// the next core waits for.
#[derive(Debug, Clone, PartialEq)]
pub struct CutState {
    pub whowas: Vec<RecordedWhowas>,
    pub most_users: u64,
    /// The limit key (as the host text it was derived from), the tokens left,
    /// and when the refill was credited through.
    pub registration_buckets: Vec<(String, f64, MonoMillis)>,
    pub edges: Vec<String>,
}

impl CutState {
    pub fn encode(&self, format: RecordFormat, clock: ClockOrigin) -> Result<Bytes, EncodeError> {
        let Self {
            whowas,
            most_users,
            registration_buckets,
            edges,
        } = self;
        body(format, clock, |w| {
            w.count("whowas", whowas.len())?;
            for entry in whowas {
                w.text("whowas key", &entry.key)?;
                w.text("whowas nick", &entry.nick)?;
                w.text("whowas user", &entry.user)?;
                w.text("whowas host", &entry.host)?;
                w.text("whowas realname", &entry.realname)?;
                w.millis(entry.signoff);
            }
            w.u64(*most_users);
            w.count("registration buckets", registration_buckets.len())?;
            for (key, tokens, refilled) in registration_buckets {
                w.text("bucket key", key)?;
                w.u64(tokens.to_bits());
                w.mono(*refilled);
            }
            w.count("edges", edges.len())?;
            for edge in edges {
                w.text("edge", edge)?;
            }
            Ok(())
        })
    }

    pub fn decode(bytes: Bytes, clock: ClockOrigin) -> Result<Self, RecordError> {
        let mut r = BodyReader::new(bytes, clock)?;
        let mut whowas = Vec::new();
        for _ in 0..r.count("whowas")? {
            whowas.push(RecordedWhowas {
                key: r.text("whowas key")?,
                nick: r.text("whowas nick")?,
                user: r.text("whowas user")?,
                host: r.text("whowas host")?,
                realname: r.text("whowas realname")?,
                signoff: r.millis("whowas signoff")?,
            });
        }
        let most_users = r.u64("most users")?;
        let mut registration_buckets = Vec::new();
        for _ in 0..r.count("registration buckets")? {
            let key = r.text("bucket key")?;
            let tokens = f64::from_bits(r.u64("bucket tokens")?);
            if !tokens.is_finite() || tokens < 0.0 {
                return Err(DecodeError::Invalid {
                    field: "bucket tokens",
                }
                .into());
            }
            registration_buckets.push((key, tokens, r.mono("bucket refill")?));
        }
        let mut edges = Vec::new();
        for _ in 0..r.count("edges")? {
            edges.push(r.text("edge")?);
        }
        r.finish()?;
        Ok(Self {
            whowas,
            most_users,
            registration_buckets,
            edges,
        })
    }
}

/// The most bytes of a credential's digest a record holds: a SHA-256 digest
/// is 32.
const MAX_DIGEST: usize = 64;

/// A live chat socket (`/ws/ui`), as its edge holds it for the next core: whose
/// it is and on which of the account's networks, what its credential lets it
/// do and which credential that is (read again at the rebuild), and the ring
/// position its client has read through, where the next core's replay starts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UiRecord {
    pub account: String,
    pub network: String,
    /// The composer may send (the credential grants writing).
    pub may_send: bool,
    /// The credential's kind and digest ([`crate::db::RevocableCredential`]).
    pub credential: (u8, Bytes),
    /// The ring's epoch and position after the last line the client was
    /// sent; `None` before the replay was sent.
    pub cursor: Option<(u64, u64)>,
    pub liveness_ms: u64,
}

impl UiRecord {
    pub fn encode(&self, format: RecordFormat, clock: ClockOrigin) -> Result<Bytes, EncodeError> {
        let Self {
            account,
            network,
            may_send,
            credential: (kind, digest),
            cursor,
            liveness_ms,
        } = self;
        body(format, clock, |w| {
            w.text("account", account)?;
            w.text("network", network)?;
            w.bool(*may_send);
            w.w.u8(*kind);
            w.w.bytes("credential digest", digest, MAX_DIGEST)?;
            w.w.option(cursor.as_ref(), |w, (epoch, seq)| {
                w.u64(*epoch);
                w.u64(*seq);
                Ok(())
            })?;
            w.u64(*liveness_ms);
            Ok(())
        })
    }

    pub fn decode(bytes: Bytes, clock: ClockOrigin) -> Result<Self, RecordError> {
        let mut r = BodyReader::new(bytes, clock)?;
        let record = Self {
            account: r.text("account")?,
            network: r.text("network")?,
            may_send: r.bool("may send")?,
            credential: (
                r.r.u8("credential kind")?,
                r.r.bytes("credential digest", MAX_DIGEST)?,
            ),
            cursor: r
                .r
                .option("cursor", |r| Ok((r.u64("epoch")?, r.u64("seq")?)))?,
            liveness_ms: r.u64("liveness")?,
        };
        r.finish()?;
        Ok(record)
    }
}

/// A bouncer attachment, as its edge holds it for the next core: whose it is
/// and with which credential (both checked again at the rebuild), the network
/// it is attached to — the account's own, or the shared one of that name — and
/// the nick it registered with, its capabilities, the ring position it has
/// been sent everything through, and what it has been shown of the session:
/// its nick, its channels and the ISUPPORT it was told.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachRecord {
    pub account: String,
    pub credential: crate::identity::CredentialId,
    /// The shared (ownerless) network of that name, not the account's own.
    pub shared: bool,
    pub network: String,
    pub requested_nick: String,
    /// `AttachCaps`, as its bits.
    pub caps: u16,
    pub cursor: Option<(u64, u64)>,
    pub shown_nick: Option<String>,
    pub shown_channels: Vec<String>,
    pub shown_isupport: Vec<String>,
    /// The newest connection status the client was told.
    pub status_revision: u64,
}

impl AttachRecord {
    pub fn encode(&self, format: RecordFormat, clock: ClockOrigin) -> Result<Bytes, EncodeError> {
        let Self {
            account,
            credential,
            shared,
            network,
            requested_nick,
            caps,
            cursor,
            shown_nick,
            shown_channels,
            shown_isupport,
            status_revision,
        } = self;
        body(format, clock, |w| {
            w.text("account", account)?;
            write_credential(w, *credential);
            w.bool(*shared);
            w.text("network", network)?;
            w.text("requested nick", requested_nick)?;
            w.w.u16(*caps);
            w.w.option(cursor.as_ref(), |w, (epoch, seq)| {
                w.u64(*epoch);
                w.u64(*seq);
                Ok(())
            })?;
            w.opt_text("shown nick", shown_nick.as_deref())?;
            for (field, list) in [
                ("shown channels", shown_channels),
                ("shown ISUPPORT", shown_isupport),
            ] {
                w.count(field, list.len())?;
                for item in list {
                    w.text(field, item)?;
                }
            }
            w.u64(*status_revision);
            Ok(())
        })
    }

    pub fn decode(bytes: Bytes, clock: ClockOrigin) -> Result<Self, RecordError> {
        let mut r = BodyReader::new(bytes, clock)?;
        let account = r.text("account")?;
        let credential = read_credential(&mut r)?;
        let shared = r.bool("shared")?;
        let network = r.text("network")?;
        let requested_nick = r.text("requested nick")?;
        let caps = r.r.u16("capabilities")?;
        let cursor =
            r.r.option("cursor", |r| Ok((r.u64("epoch")?, r.u64("seq")?)))?;
        let shown_nick = r.opt_text("shown nick")?;
        let mut lists = [Vec::new(), Vec::new()];
        for (field, list) in ["shown channels", "shown ISUPPORT"]
            .into_iter()
            .zip(&mut lists)
        {
            for _ in 0..r.count(field)? {
                list.push(r.text(field)?);
            }
        }
        let [shown_channels, shown_isupport] = lists;
        let status_revision = r.u64("status revision")?;
        r.finish()?;
        Ok(Self {
            account,
            credential,
            shared,
            network,
            requested_nick,
            caps,
            cursor,
            shown_nick,
            shown_channels,
            shown_isupport,
            status_revision,
        })
    }
}

/// The most bytes of the session record a [`LocalRecord`] carries: as many
/// as one body holds.
const MAX_NESTED_BODY: usize =
    e6irc_link::held::MAX_BODY_PART * e6irc_link::held::MAX_BODY_PARTS as usize;

/// A session of the core's own homed on an edge across a cut (decision D13):
/// which `local` bouncer network it is — its owner, none for a shared one,
/// and its name, each folded — and the session's record as its shard wrote
/// it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalRecord {
    pub owner: Option<String>,
    pub network: String,
    /// A [`SessionRecord`] body.
    pub session: Bytes,
}

impl LocalRecord {
    pub fn encode(&self, format: RecordFormat, clock: ClockOrigin) -> Result<Bytes, EncodeError> {
        let Self {
            owner,
            network,
            session,
        } = self;
        body(format, clock, |w| {
            w.opt_text("owner", owner.as_deref())?;
            w.text("network", network)?;
            w.w.bytes("session record", session, MAX_NESTED_BODY)
        })
    }

    pub fn decode(bytes: Bytes, clock: ClockOrigin) -> Result<Self, RecordError> {
        let mut r = BodyReader::new(bytes, clock)?;
        let owner = r.opt_text("owner")?;
        let network = r.text("network")?;
        let session = r.r.bytes("session record", MAX_NESTED_BODY)?;
        r.finish()?;
        Ok(Self {
            owner,
            network,
            session,
        })
    }
}

#[cfg(test)]
mod tests;
