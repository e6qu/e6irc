//! Which attached client an upstream line answers.
//!
//! Every attached client shares one upstream connection, so the upstream
//! answers each client's `WHO`, `WHOIS`, `LIST` or refused `PRIVMSG` on the
//! same stream as the conversation. A reply belongs to the attachment whose
//! command asked for it — no other client asked, and none of it is history —
//! so [`ReplyRouter`] tells the two apart, the way soju and ZNC's
//! `route_replies` do:
//!
//! - With `labeled-response` (and `batch`) enabled upstream, every forwarded
//!   line carries a `label` naming its command, and the upstream labels
//!   everything it says in answer ([`Correlation::Labels`]).
//! - Otherwise ([`Correlation::Order`]) an upstream answers one connection's
//!   commands in the order it received them. Each forwarded command waits in
//!   a queue; a query's reply numerics go to the oldest query that expects
//!   them (the one naming the reply's subject, when one does) until its
//!   end-of-reply numeric, and an error numeric goes to the oldest command it
//!   can be about — the same command name, or one of its targets. A command
//!   that may end with no reply at all is closed by the upstream's answer to a
//!   `PING` sent after it (one in flight at a time, so a paste costs at most
//!   two), and anything left waiting is forgotten after
//!   [`PENDING_REPLY_WINDOW`].
//!
//! A line that answers no pending command is the session's own: a message,
//! a membership change, a numeric the upstream sent unasked. The numerics
//! that follow our own `JOIN` (topic, member list) are the channel's state
//! rather than a reply, and stay the session's, as they always were.
//! Upstream `BATCH` framing is consumed here: an attached client negotiated
//! its capabilities with the bouncer, not with the upstream, so the members
//! of an upstream batch reach it as ordinary lines.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant};

use e6irc_client::{NetworkNames, OwnedMessage};

/// How long a forwarded command waits for its replies before anything more
/// the upstream says is taken as unasked. A reply routed to nobody is still
/// delivered, to every attached client, so this bounds only how long a lost
/// end-of-reply numeric can misdirect later replies. ZNC waits as long.
pub(super) const PENDING_REPLY_WINDOW: Duration = Duration::from_secs(60);

/// Most forwarded commands awaiting their replies at once; the oldest is
/// forgotten past this. The upstream answers in order, so a queue this deep
/// means the upstream is not answering at all.
const MAX_PENDING: usize = 128;

/// The token of the `PING` that closes the commands forwarded before it.
const BARRIER_TOKEN: &str = "e6bnc-route-";

/// How the upstream's answers are told apart on this connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Correlation {
    /// `labeled-response`, `batch` and `message-tags` are enabled upstream.
    Labels,
    /// The upstream answers in order and labels nothing.
    Order,
}

/// What one upstream line is to the attached clients.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Upstream {
    /// The session's own line: tracked, retained and sent to every attached
    /// client. `origin` names the attachment whose command it answers, when a
    /// label says so (the upstream's echo of a message, the confirmation of a
    /// `JOIN`).
    Session { line: String, origin: Option<u64> },
    /// An answer to one attachment's command: for that attachment alone,
    /// live, and never history.
    Reply { line: String, origin: u64 },
    /// Upstream framing with nothing to show: a `BATCH`, an `ACK`, the
    /// answer to a correlation `PING`.
    Consumed,
}

/// The replies a query command is answered with.
struct Query {
    verb: &'static str,
    /// Numerics that answer it without ending the answer.
    replies: &'static [u16],
    /// Numerics that end the answer.
    ends: &'static [u16],
    /// Error numerics after which the end still follows (`401` in a `WHOIS`).
    continuing_errors: &'static [u16],
    /// Parameters past which the query is answered by another server, so its
    /// answer may follow the upstream's answers to later commands.
    local_params: Option<usize>,
}

const QUERIES: &[Query] = &[
    Query {
        verb: "WHO",
        replies: &[352, 354],
        ends: &[315],
        continuing_errors: &[],
        local_params: None,
    },
    Query {
        verb: "WHOIS",
        replies: &[
            276, 301, 307, 310, 311, 312, 313, 317, 319, 320, 330, 335, 338, 378, 379, 671,
        ],
        ends: &[318],
        continuing_errors: &[401, 402],
        local_params: Some(1),
    },
    Query {
        verb: "WHOWAS",
        replies: &[312, 314, 330, 338],
        ends: &[369],
        continuing_errors: &[406],
        local_params: None,
    },
    Query {
        verb: "LIST",
        replies: &[321, 322],
        ends: &[323],
        continuing_errors: &[],
        local_params: None,
    },
    Query {
        verb: "NAMES",
        replies: &[353],
        ends: &[366],
        continuing_errors: &[403],
        local_params: None,
    },
    Query {
        verb: "TOPIC",
        replies: &[332],
        ends: &[331, 333],
        continuing_errors: &[],
        local_params: None,
    },
    Query {
        verb: "MODE",
        replies: &[324, 346, 348, 367, 728],
        ends: &[221, 329, 347, 349, 368, 729],
        continuing_errors: &[],
        local_params: None,
    },
    Query {
        verb: "USERHOST",
        replies: &[],
        ends: &[302],
        continuing_errors: &[],
        local_params: None,
    },
    Query {
        verb: "ISON",
        replies: &[],
        ends: &[303],
        continuing_errors: &[],
        local_params: None,
    },
    Query {
        verb: "INVITE",
        replies: &[336],
        ends: &[337, 341],
        continuing_errors: &[],
        local_params: None,
    },
    Query {
        verb: "AWAY",
        replies: &[],
        ends: &[305, 306],
        continuing_errors: &[],
        local_params: None,
    },
    Query {
        verb: "LUSERS",
        replies: &[251, 252, 253, 254, 255, 265],
        ends: &[266],
        continuing_errors: &[],
        local_params: Some(1),
    },
    Query {
        verb: "MOTD",
        replies: &[372, 375],
        ends: &[376, 422],
        continuing_errors: &[],
        local_params: Some(0),
    },
    Query {
        verb: "TIME",
        replies: &[],
        ends: &[391],
        continuing_errors: &[],
        local_params: Some(0),
    },
    Query {
        verb: "ADMIN",
        replies: &[256, 257, 258],
        ends: &[259],
        continuing_errors: &[],
        local_params: Some(0),
    },
    Query {
        verb: "INFO",
        replies: &[371, 373],
        ends: &[374],
        continuing_errors: &[],
        local_params: Some(0),
    },
    Query {
        verb: "LINKS",
        replies: &[364],
        ends: &[365],
        continuing_errors: &[],
        local_params: Some(1),
    },
    Query {
        verb: "STATS",
        replies: &[
            211, 212, 213, 214, 215, 216, 217, 218, 240, 241, 242, 243, 244, 245, 246, 247, 248,
            249, 250,
        ],
        ends: &[219],
        continuing_errors: &[],
        local_params: Some(1),
    },
];

/// `RPL_AWAY`: part of a `WHOIS`, and the answer to a message sent to someone
/// who is away.
const RPL_AWAY: u16 = 301;

/// Numerics that follow our own `JOIN` of a channel: its state, told to every
/// attached client, not a reply to whoever asked to join.
const JOIN_BURST: &[u16] = &[324, 328, 329, 332, 333, 353, 366];

/// The query a command line is, when it is one. `MODE` is a query only when it
/// changes nothing: a bare `MODE <target>`, or a list mode named with no mask.
fn query_of(verb: &str, params: &[String]) -> Option<&'static Query> {
    let query = QUERIES.iter().find(|query| query.verb == verb)?;
    match verb {
        "MODE" => match params {
            [_] => Some(query),
            [_, modes] => {
                let modes = modes.trim_start_matches('+');
                (modes.len() == 1 && "beIq".contains(modes)).then_some(query)
            }
            _ => None,
        },
        "TOPIC" => (params.len() == 1).then_some(query),
        // `INVITE <nick> <channel>` is answered with 341; bare `INVITE` lists.
        "INVITE" => (params.len() == 2 || params.is_empty()).then_some(query),
        _ => Some(query),
    }
}

/// One forwarded command awaiting its answer, in [`Correlation::Order`].
struct Pending {
    /// Position in the order commands were forwarded.
    id: u64,
    origin: u64,
    verb: String,
    /// Every name the command is about, folded: its channels and nicks.
    targets: Vec<String>,
    query: Option<&'static Query>,
    /// Answered by another server, so possibly after later commands.
    remote: bool,
    since: Instant,
}

/// One labelled command awaiting its answer, in [`Correlation::Labels`].
struct Labelled {
    origin: u64,
    since: Instant,
}

/// See the module documentation.
#[derive(Default)]
pub(super) struct ReplyRouter {
    pending: VecDeque<Pending>,
    labels: HashMap<String, Labelled>,
    /// Open upstream batches, each with the label that opened it (or the one
    /// its enclosing batch carries); `None` for a batch nobody asked for.
    batches: HashMap<String, Option<String>>,
    /// Folded channels whose join burst is still arriving.
    joining: HashSet<String>,
    next_id: u64,
    /// The newest forwarded command a correlation `PING` has been sent after,
    /// while its answer is outstanding.
    barrier_sent: Option<u64>,
}

impl ReplyRouter {
    /// Take one client line about to be forwarded upstream and return the line
    /// to write: labelled under [`Correlation::Labels`], and otherwise the
    /// line itself, queued to await its answer. Origin 0 is no attachment
    /// (the REST API), whose replies are the session's as they always were.
    pub(super) fn forward(
        &mut self,
        origin: u64,
        line: &str,
        correlation: Correlation,
        names: &NetworkNames,
        now: Instant,
    ) -> String {
        self.expire(now);
        let Ok(message) = e6irc_proto::message::Message::parse(line) else {
            return line.to_string();
        };
        if origin == 0 {
            return line.to_string();
        }
        self.next_id += 1;
        let id = self.next_id;
        match correlation {
            Correlation::Labels => {
                let label = format!("e6b{id}");
                let Some(labelled) = with_label(line, &message, &label) else {
                    // A tag section already at its budget cannot take one
                    // more tag; the line goes as it is, and its answer is the
                    // session's.
                    return line.to_string();
                };
                if self.labels.len() >= MAX_PENDING
                    && let Some(oldest) = self
                        .labels
                        .iter()
                        .min_by_key(|(_, labelled)| labelled.since)
                        .map(|(label, _)| label.clone())
                {
                    self.labels.remove(&oldest);
                }
                self.labels.insert(label, Labelled { origin, since: now });
                labelled
            }
            Correlation::Order => {
                let verb = message.command.to_ascii_uppercase();
                let params: Vec<String> = message.params.iter().map(ToString::to_string).collect();
                let query = query_of(&verb, &params);
                let remote = query
                    .and_then(|query| query.local_params)
                    .is_some_and(|local| params.len() > local);
                if self.pending.len() >= MAX_PENDING {
                    self.pending.pop_front();
                }
                self.pending.push_back(Pending {
                    id,
                    origin,
                    targets: command_targets(&verb, &params, names),
                    verb,
                    query,
                    remote,
                    since: now,
                });
                line.to_string()
            }
        }
    }

    /// The correlation `PING` to write now, when a command that may end
    /// without any reply has been forwarded since the last one was answered.
    pub(super) fn barrier_due(&mut self) -> Option<String> {
        if self.barrier_sent.is_some() {
            return None;
        }
        let newest = self
            .pending
            .iter()
            .filter(|pending| pending.query.is_none())
            .map(|pending| pending.id)
            .max()?;
        self.barrier_sent = Some(newest);
        Some(format!("PING :{BARRIER_TOKEN}{newest}"))
    }

    /// Classify one upstream line. `own_nick` is the session's nick, whose
    /// `JOIN` begins a channel's join burst.
    pub(super) fn classify(
        &mut self,
        message: &OwnedMessage,
        raw: String,
        names: &NetworkNames,
        own_nick: &str,
        now: Instant,
    ) -> Upstream {
        self.expire(now);
        if message.command == "BATCH" {
            self.frame_batch(message);
            return Upstream::Consumed;
        }
        if message.command == "PONG"
            && let Some(covered) = message
                .params
                .last()
                .and_then(|token| token.strip_prefix(BARRIER_TOKEN))
                .and_then(|id| id.parse::<u64>().ok())
        {
            self.pending
                .retain(|pending| pending.query.is_some() || pending.id > covered);
            if self.barrier_sent == Some(covered) {
                self.barrier_sent = None;
            }
            return Upstream::Consumed;
        }
        let (label, direct) = match message.tag("label") {
            Some(label) => (Some(label.to_string()), true),
            None => (
                message
                    .tag("batch")
                    .and_then(|batch| self.batches.get(batch).cloned().flatten()),
                false,
            ),
        };
        let line = without_framing_tags(raw);
        if message.command == "ACK" {
            if let Some(label) = label {
                self.labels.remove(&label);
            }
            return Upstream::Consumed;
        }
        self.track_join_burst(message, names, own_nick);
        let numeric = message
            .command
            .parse::<u16>()
            .ok()
            .filter(|_| message.command.len() == 3);
        let join_state = numeric.is_some_and(|code| self.in_join_burst(code, message, names));
        if let Some(label) = label {
            let origin = self.labels.get(&label).map(|labelled| labelled.origin);
            if direct {
                self.labels.remove(&label);
            }
            if let Some(origin) = origin {
                return if (numeric.is_some() && !join_state) || is_standard_reply(message) {
                    Upstream::Reply { line, origin }
                } else {
                    Upstream::Session {
                        line,
                        origin: Some(origin),
                    }
                };
            }
            return Upstream::Session { line, origin: None };
        }
        if join_state {
            return Upstream::Session { line, origin: None };
        }
        let origin = match numeric {
            Some(code) => self.answer_to_numeric(code, message, names),
            None if is_standard_reply(message) => self.answer_to_standard_reply(message),
            None => None,
        };
        match origin {
            Some(origin) => Upstream::Reply { line, origin },
            None => Upstream::Session { line, origin: None },
        }
    }

    /// Forget commands whose answer is overdue.
    fn expire(&mut self, now: Instant) {
        let fresh = |since: Instant| now.duration_since(since) < PENDING_REPLY_WINDOW;
        self.pending.retain(|pending| fresh(pending.since));
        self.labels.retain(|_, labelled| fresh(labelled.since));
    }

    fn frame_batch(&mut self, message: &OwnedMessage) {
        let Some(reference) = message.params.first() else {
            return;
        };
        if let Some(id) = reference.strip_prefix('+') {
            let label = message.tag("label").map(str::to_string).or_else(|| {
                message
                    .tag("batch")
                    .and_then(|outer| self.batches.get(outer).cloned().flatten())
            });
            if self.batches.len() < MAX_PENDING {
                self.batches.insert(id.to_string(), label);
            }
        } else if let Some(id) = reference.strip_prefix('-')
            && let Some(Some(label)) = self.batches.remove(id)
            && !self
                .batches
                .values()
                .any(|open| open.as_ref() == Some(&label))
        {
            self.labels.remove(&label);
        }
    }

    fn track_join_burst(&mut self, message: &OwnedMessage, names: &NetworkNames, own_nick: &str) {
        let ours = message
            .source
            .as_deref()
            .map(|source| source.split_once('!').map_or(source, |(nick, _)| nick))
            .is_some_and(|nick| names.eq(nick, own_nick));
        if ours
            && message.command.eq_ignore_ascii_case("JOIN")
            && let Some(channels) = message.params.first()
        {
            for channel in channels.split(',').filter(|channel| !channel.is_empty()) {
                if self.joining.len() < MAX_PENDING {
                    self.joining.insert(names.fold(channel));
                }
            }
        }
    }

    /// Whether numeric `code` is part of a join burst still arriving; the
    /// burst's end-of-names ends it.
    fn in_join_burst(&mut self, code: u16, message: &OwnedMessage, names: &NetworkNames) -> bool {
        if !JOIN_BURST.contains(&code) {
            return false;
        }
        let Some(channel) = e6irc_client::numeric_subject(message) else {
            return false;
        };
        let key = names.fold(channel);
        if !self.joining.contains(&key) {
            return false;
        }
        if code == 366 {
            self.joining.remove(&key);
        }
        true
    }

    /// The attachment a numeric answers, in [`Correlation::Order`]: a reply
    /// of a pending query (the one about its subject when one is), or an
    /// error about a pending command.
    fn answer_to_numeric(
        &mut self,
        code: u16,
        message: &OwnedMessage,
        names: &NetworkNames,
    ) -> Option<u64> {
        let subject = e6irc_client::numeric_subject(message).map(|subject| names.fold(subject));
        let about = |pending: &Pending| {
            subject
                .as_ref()
                .is_some_and(|subject| pending.targets.contains(subject))
        };
        let answers = |pending: &Pending| {
            pending.query.is_some_and(|query| {
                query.replies.contains(&code)
                    || query.ends.contains(&code)
                    || query.continuing_errors.contains(&code)
            })
        };
        let index = self
            .pending
            .iter()
            .position(|pending| answers(pending) && about(pending))
            .or_else(|| {
                // An away notice also answers a message to that nick.
                (code == RPL_AWAY)
                    .then(|| self.pending.iter().position(about))
                    .flatten()
            })
            .or_else(|| self.pending.iter().position(answers))
            .or_else(|| {
                if !is_error(code) {
                    return None;
                }
                // 421, 461 and 263 name the command they refuse.
                if matches!(code, 263 | 421 | 461) {
                    let verb = message.params.get(1)?.to_ascii_uppercase();
                    return self.pending.iter().position(|pending| pending.verb == verb);
                }
                self.pending.iter().position(about)
            })?;
        let pending = &self.pending[index];
        let origin = pending.origin;
        let ended = match pending.query {
            Some(query) => {
                query.ends.contains(&code)
                    || (is_error(code) && !query.continuing_errors.contains(&code))
            }
            None => false,
        };
        let answered = pending.id;
        if ended {
            self.pending.remove(index);
        }
        // The upstream answers in order: a local query older than the one
        // answering now has had its whole answer.
        self.pending
            .retain(|pending| pending.id >= answered || pending.remote || pending.query.is_none());
        Some(origin)
    }

    /// The attachment an IRCv3 standard reply (`FAIL`/`WARN`/`NOTE`) answers,
    /// in [`Correlation::Order`]: the oldest pending command it names.
    fn answer_to_standard_reply(&mut self, message: &OwnedMessage) -> Option<u64> {
        let verb = message.params.first()?.to_ascii_uppercase();
        let index = self
            .pending
            .iter()
            .position(|pending| pending.verb == verb)?;
        let pending = &self.pending[index];
        let origin = pending.origin;
        if message.command == "FAIL" && pending.query.is_some() {
            self.pending.remove(index);
        }
        Some(origin)
    }
}

fn is_error(code: u16) -> bool {
    (400..600).contains(&code) || code == 263
}

fn is_standard_reply(message: &OwnedMessage) -> bool {
    matches!(message.command.as_str(), "FAIL" | "WARN" | "NOTE")
}

/// The names a command is about, folded — every parameter but a free-text
/// trailing one, split on commas — so an error about one of them can be
/// traced back to it.
fn command_targets(verb: &str, params: &[String], names: &NetworkNames) -> Vec<String> {
    let text_last = matches!(
        verb,
        "PRIVMSG" | "NOTICE" | "PART" | "KICK" | "TOPIC" | "QUIT" | "AWAY" | "KNOCK"
    );
    let named = if text_last && params.len() > 1 {
        &params[..params.len() - 1]
    } else {
        params
    };
    named
        .iter()
        .flat_map(|param| param.split(','))
        .filter(|name| !name.is_empty())
        .map(|name| names.fold(names.conversation(name)))
        .collect()
}

/// `line` with its own `label` replaced by `label`, when the tag section can
/// take it.
fn with_label(
    line: &str,
    message: &e6irc_proto::message::Message<'_>,
    label: &str,
) -> Option<String> {
    let body = match line.strip_prefix('@') {
        Some(rest) => rest.split_once(' ').map_or("", |(_, body)| body),
        None => line,
    };
    let mut tags: Vec<String> = message
        .tags
        .iter()
        .filter(|tag| tag.key != "label")
        .map(|tag| match &tag.value {
            Some(value) => format!(
                "{}={}",
                tag.key,
                e6irc_proto::message::escape_tag_value(value)
            ),
            None => tag.key.to_string(),
        })
        .collect();
    tags.push(format!("label={label}"));
    let labelled = format!("@{} {body}", tags.join(";"));
    e6irc_proto::message::client_frame_fits(labelled.as_bytes()).then_some(labelled)
}

/// `raw` without the `label` and `batch` tags: the attached client did not
/// negotiate labels or batches with the upstream, and the batch it would
/// name is consumed here.
fn without_framing_tags(raw: String) -> String {
    let Some(rest) = raw.strip_prefix('@') else {
        return raw;
    };
    let Some((tags, body)) = rest.split_once(' ') else {
        return raw;
    };
    let kept: Vec<&str> = tags
        .split(';')
        .filter(|tag| !matches!(tag.split('=').next(), Some("label" | "batch")))
        .collect();
    if kept.len() == tags.split(';').count() {
        return raw;
    }
    if kept.is_empty() {
        body.to_string()
    } else {
        format!("@{} {body}", kept.join(";"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(line: &str) -> OwnedMessage {
        OwnedMessage::from(&e6irc_proto::message::Message::parse(line).expect("test line"))
    }

    fn classify(router: &mut ReplyRouter, line: &str, now: Instant) -> Upstream {
        router.classify(
            &message(line),
            line.to_string(),
            &NetworkNames::default(),
            "me",
            now,
        )
    }

    fn reply(line: &str, origin: u64) -> Upstream {
        Upstream::Reply {
            line: line.to_string(),
            origin,
        }
    }

    fn session(line: &str) -> Upstream {
        Upstream::Session {
            line: line.to_string(),
            origin: None,
        }
    }

    fn forward(router: &mut ReplyRouter, origin: u64, line: &str, now: Instant) -> String {
        router.forward(
            origin,
            line,
            Correlation::Order,
            &NetworkNames::default(),
            now,
        )
    }

    /// Two clients' queries are answered in order: each reply reaches the one
    /// that asked, and the end-of-reply numeric ends it.
    #[test]
    fn replies_go_to_the_query_that_asked_in_order() {
        let now = Instant::now();
        let mut router = ReplyRouter::default();
        forward(&mut router, 1, "WHO #a", now);
        forward(&mut router, 2, "LIST", now);
        for (line, origin) in [
            (":s 352 me #a u h s nick H :0 real", 1),
            (":s 315 me #a :End of WHO", 1),
            (":s 321 me Channel :Users Name", 2),
            (":s 322 me #big 50000 :topic", 2),
            (":s 323 me :End of LIST", 2),
        ] {
            assert_eq!(classify(&mut router, line, now), reply(line, origin));
        }
        let after = ":s 322 me #late 1 :unasked";
        assert_eq!(classify(&mut router, after, now), session(after));
    }

    /// A reply names its subject: the `WHOIS` it answers is that nick's, even
    /// when another `WHOIS` was sent first (a remote one, answered later).
    #[test]
    fn a_reply_about_one_target_reaches_the_query_about_it() {
        let now = Instant::now();
        let mut router = ReplyRouter::default();
        forward(&mut router, 1, "WHOIS far far", now);
        forward(&mut router, 2, "WHOIS near", now);
        let line = ":s 311 me near u h * :Near";
        assert_eq!(classify(&mut router, line, now), reply(line, 2));
        let end = ":s 318 me near :End of WHOIS";
        assert_eq!(classify(&mut router, end, now), reply(end, 2));
        let remote = ":s 311 me far u h * :Far";
        assert_eq!(
            classify(&mut router, remote, now),
            reply(remote, 1),
            "the remote query still waits"
        );
    }

    /// An error numeric goes to the command it is about; one that names no
    /// pending command is the session's, as before.
    #[test]
    fn errors_reach_the_command_they_refuse() {
        let now = Instant::now();
        let mut router = ReplyRouter::default();
        forward(&mut router, 1, "PRIVMSG #a :hi", now);
        forward(&mut router, 2, "PRIVMSG #b :hi", now);
        forward(&mut router, 3, "TAGMSG #c", now);
        let refused = ":s 404 me #B :Cannot send to channel";
        assert_eq!(classify(&mut router, refused, now), reply(refused, 2));
        let unknown = ":s 421 me TAGMSG :Unknown command";
        assert_eq!(classify(&mut router, unknown, now), reply(unknown, 3));
        let unasked = ":s 404 me #elsewhere :Cannot send to channel";
        assert_eq!(classify(&mut router, unasked, now), session(unasked));
    }

    /// An away notice answers whichever command is about that nick: a message
    /// to it as much as a WHOIS of it.
    #[test]
    fn an_away_notice_reaches_the_message_it_answers() {
        let now = Instant::now();
        let mut router = ReplyRouter::default();
        forward(&mut router, 1, "WHOIS someone", now);
        forward(&mut router, 2, "PRIVMSG Sleeper :are you there", now);
        let whois_away = ":s 301 me someone :back soon";
        assert_eq!(classify(&mut router, whois_away, now), reply(whois_away, 1));
        let away = ":s 301 me sleeper :gone fishing";
        assert_eq!(classify(&mut router, away, now), reply(away, 2));
    }

    /// A command that can end with no reply at all is closed by the answer to
    /// a `PING` sent after it, one at a time, so a later error about the same
    /// channel is not taken for its answer.
    #[test]
    fn a_barrier_closes_the_commands_sent_before_it() {
        let now = Instant::now();
        let mut router = ReplyRouter::default();
        forward(&mut router, 1, "PRIVMSG #a :accepted", now);
        let barrier = router.barrier_due().expect("a barrier is due");
        assert_eq!(barrier, "PING :e6bnc-route-1");
        forward(&mut router, 1, "PRIVMSG #a :also accepted", now);
        assert_eq!(router.barrier_due(), None, "one in flight at a time");
        let pong = ":s PONG s :e6bnc-route-1";
        assert_eq!(classify(&mut router, pong, now), Upstream::Consumed);
        assert_eq!(router.barrier_due().as_deref(), Some("PING :e6bnc-route-2"));
        assert_eq!(
            classify(&mut router, ":s PONG s :e6bnc-route-2", now),
            Upstream::Consumed
        );
        forward(&mut router, 2, "PRIVMSG #a :refused", now);
        let refused = ":s 404 me #a :Cannot send to channel";
        assert_eq!(classify(&mut router, refused, now), reply(refused, 2));
    }

    /// The numerics after our own JOIN are the channel's state for everyone;
    /// the same numerics asked for with NAMES are a reply.
    #[test]
    fn a_join_burst_is_the_session_and_a_names_query_is_a_reply() {
        let now = Instant::now();
        let mut router = ReplyRouter::default();
        forward(&mut router, 1, "JOIN #a", now);
        forward(&mut router, 1, "NAMES #a", now);
        for line in [
            ":me!u@h JOIN #a",
            ":s 332 me #a :topic",
            ":s 353 me = #a :me other",
            ":s 366 me #a :End of NAMES",
        ] {
            assert_eq!(classify(&mut router, line, now), session(line));
        }
        let names = ":s 353 me = #a :me other";
        assert_eq!(classify(&mut router, names, now), reply(names, 1));
    }

    #[test]
    fn a_pending_command_is_forgotten_after_its_window() {
        let now = Instant::now();
        let mut router = ReplyRouter::default();
        forward(&mut router, 1, "LIST", now);
        let late = ":s 322 me #a 1 :t";
        assert_eq!(
            classify(&mut router, late, now + PENDING_REPLY_WINDOW),
            session(late)
        );
    }

    /// With labels, what the upstream labels is the labelled command's: its
    /// numerics a reply, its echo the session's with the origin named, and
    /// the framing consumed.
    #[test]
    fn labels_name_the_attachment_and_batches_are_unwrapped() {
        let now = Instant::now();
        let names = NetworkNames::default();
        let mut router = ReplyRouter::default();
        let who = router.forward(1, "@+typing=x WHO #a", Correlation::Labels, &names, now);
        assert_eq!(who, "@+typing=x;label=e6b1 WHO #a");
        let message_line = router.forward(2, "PRIVMSG #a :hi", Correlation::Labels, &names, now);
        assert_eq!(message_line, "@label=e6b2 PRIVMSG #a :hi");
        let mut run =
            |line: &str| router.classify(&message(line), line.to_string(), &names, "me", now);
        assert_eq!(
            run("@label=e6b1 :s BATCH +x labeled-response"),
            Upstream::Consumed
        );
        assert_eq!(
            run("@batch=x :s 352 me #a u h s nick H :0 real"),
            reply(":s 352 me #a u h s nick H :0 real", 1)
        );
        assert_eq!(run(":s BATCH -x"), Upstream::Consumed);
        assert_eq!(
            run("@label=e6b2;time=t :me!u@h PRIVMSG #a :hi"),
            Upstream::Session {
                line: "@time=t :me!u@h PRIVMSG #a :hi".to_string(),
                origin: Some(2)
            }
        );
        assert_eq!(
            run("@label=e6b1 :s 352 me #a u h s x H :0 r"),
            session(":s 352 me #a u h s x H :0 r"),
            "the label was answered"
        );
        assert_eq!(run(":s BATCH +n netsplit a b"), Upstream::Consumed);
        assert_eq!(
            run("@batch=n :x!u@h QUIT :a b"),
            session(":x!u@h QUIT :a b"),
            "an unasked batch's members reach everyone, unwrapped"
        );
    }
}
