//! Terminal-independent TUI state. All message-handling and input
//! logic lives here so it can be unit-tested without a terminal.
//!
//! The UI is multi-buffer: one buffer per joined channel or open query,
//! switchable independently (each keeps its own scrollback). Cross-
//! network multiplexing is the BNC's job server-side — a client attaches
//! to one network and opens buffers within it.

use e6irc_client::{OwnedMessage, TerminalSafe};

/// One rendered line in a buffer's scrollback. Both fields are
/// [`TerminalSafe`], so a line can only ever hold server text with its terminal
/// control bytes already neutralized — a render path cannot be handed a raw
/// escape sequence, and the client's terminal safety is a project guarantee
/// rather than a reliance on the TUI framework's internal filtering. Build one
/// only via [`LogLine::new`], which sanitizes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogLine {
    pub from: TerminalSafe,
    pub text: TerminalSafe,
}

impl LogLine {
    /// Neutralize control bytes in the (untrusted) sender and text, and drop
    /// the text's IRC formatting codes, which this client does not render.
    fn new(from: &str, text: &str) -> Self {
        Self {
            from: TerminalSafe::from_untrusted(from),
            text: TerminalSafe::from_irc_text(text),
        }
    }

    /// A message body as the sender meant it to be shown: a CTCP `ACTION`
    /// (`/me waves`) is `* nick waves`, any other CTCP request is named as
    /// one rather than shown with its delimiters, and ordinary text is itself.
    fn message(sender: &str, text: &str) -> Self {
        let Some(ctcp) = text.strip_prefix('\x01') else {
            return Self::new(sender, text);
        };
        let ctcp = ctcp.strip_suffix('\x01').unwrap_or(ctcp);
        match ctcp.split_once(' ') {
            Some((verb, action)) if verb.eq_ignore_ascii_case("ACTION") => {
                Self::new(&format!("* {sender}"), action)
            }
            _ if ctcp.eq_ignore_ascii_case("ACTION") => Self::new(&format!("* {sender}"), ""),
            _ => Self::new(sender, &format!("[CTCP {ctcp}]")),
        }
    }
}

/// What a buffer holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BufferKind {
    /// A channel or a query: text typed here is sent to it.
    Conversation,
    /// The server's own lines — the welcome burst, replies to `/raw`, modes
    /// and notices that belong to no conversation. Nothing is sent to it.
    Server,
}

/// How far a buffer's read marker may advance.
#[derive(Debug, Clone, PartialEq, Eq)]
enum ReadHold {
    /// To the latest line shown.
    Free,
    /// No further than this time: the last line loaded before a gap.
    At(String),
    /// Not at all: a gap follows lines whose times are unknown.
    Nowhere,
}

/// The server buffer's name: not a legal channel or nickname, so no
/// conversation can share it.
pub const SERVER_BUFFER: &str = "*server*";

/// One conversation: a channel or a query (PM) with its own scrollback.
#[derive(Debug, Clone)]
pub struct Buffer {
    pub name: String,
    pub kind: BufferKind,
    pub log: Vec<LogLine>,
    seen_msgids: std::collections::HashSet<String>,
    msgid_order: std::collections::VecDeque<String>,
    latest_time: Option<String>,
    read_marker: Option<String>,
    /// How far the read marker may advance. Held at the last line loaded
    /// contiguously from history when unread lines remain beyond it: the lines
    /// between it and the live stream were never shown, and marking them read
    /// would do so on every device.
    read_hold: ReadHold,
    unread: usize,
    /// Scrollback offset in lines from the bottom (0 = following live).
    scroll: usize,
}

impl Buffer {
    fn new(name: String, kind: BufferKind) -> Self {
        Self {
            name,
            kind,
            log: Vec::new(),
            seen_msgids: std::collections::HashSet::new(),
            msgid_order: std::collections::VecDeque::new(),
            latest_time: None,
            read_marker: None,
            read_hold: ReadHold::Free,
            unread: 0,
            scroll: 0,
        }
    }

    fn push(&mut self, line: LogLine) {
        self.log.push(line);
        // Scrollback is bounded: every line here came from the server, so an
        // unbounded log is a remote party deciding how much memory this client
        // uses. Oldest lines go first, which is what a scrollback is.
        if self.log.len() > SCROLLBACK_LINES {
            let excess = self.log.len() - SCROLLBACK_LINES;
            self.log.drain(..excess);
            // `scroll` is an offset from the *end*, so dropping lines off the
            // front does not move the view and must not adjust it. Only the
            // push below did, and that is what the fixup accounts for.
        }
        // Keep a scrolled-back view stable when a live line arrives. Once the
        // log is at its cap this eventually clamps: the lines being read have
        // been dropped, so the view holds at the oldest one still kept.
        if self.scroll > 0 {
            self.scroll = (self.scroll + 1).min(self.log.len().saturating_sub(1));
        }
    }

    fn accept_msgid(&mut self, msgid: Option<&str>) -> bool {
        let Some(msgid) = msgid else {
            return true;
        };
        if !self.seen_msgids.insert(msgid.to_owned()) {
            return false;
        }
        self.msgid_order.push_back(msgid.to_owned());
        if self.msgid_order.len() > SCROLLBACK_LINES
            && let Some(expired) = self.msgid_order.pop_front()
        {
            self.seen_msgids.remove(&expired);
        }
        true
    }

    pub fn scroll_up(&mut self, n: usize) {
        self.scroll = (self.scroll + n).min(self.log.len().saturating_sub(1));
    }

    pub fn scroll_down(&mut self, n: usize) {
        self.scroll = self.scroll.saturating_sub(n);
    }

    pub fn scrolled_back(&self) -> bool {
        self.scroll > 0
    }

    pub fn lines_behind_latest(&self) -> usize {
        self.scroll
    }

    pub fn unread(&self) -> usize {
        self.unread
    }

    /// The window of lines to render for a pane `height` rows tall, when
    /// each line takes one row.
    pub fn visible(&self, height: usize) -> &[LogLine] {
        self.visible_rows(height, |_| 1)
    }

    /// The window of lines to render for a pane `height` rows tall, when a
    /// line takes `rows(line)` rows (a long line wraps): the lines ending at
    /// the scroll position whose rows fill the pane. The first may be taller
    /// than what is left of the pane; the renderer shows its end.
    pub fn visible_rows(&self, height: usize, rows: impl Fn(&LogLine) -> usize) -> &[LogLine] {
        let end = self.log.len().saturating_sub(self.scroll);
        let mut start = end;
        let mut filled = 0;
        while start > 0 && filled < height {
            start -= 1;
            filled += rows(&self.log[start]).max(1);
        }
        &self.log[start..end]
    }
}

/// Lines of scrollback kept per buffer. Older lines are dropped.
pub const SCROLLBACK_LINES: usize = 5_000;

/// Buffers a client will open. Names arrive from the server, so this bounds
/// what a remote party can make the client allocate.
const MAX_BUFFERS: usize = 256;

/// The composer admits the full client message-tag plus traditional-body
/// allowance. The derived line is then checked against each independent wire
/// budget, so `/raw @tags ...` works without letting an untagged body borrow
/// the tag allowance.
const MAX_COMPOSER_BYTES: usize = e6irc_proto::message::MAX_CLIENT_FRAME_LEN;

pub struct App {
    pub nick: String,
    pub buffers: Vec<Buffer>,
    pub current: usize,
    input: String,
    input_cursor: usize,
    pub should_quit: bool,
    connected: bool,
    /// The network task stopped reconnecting; nothing typed will ever be sent.
    gave_up: bool,
    pending_read_marker: Option<String>,
    invalid_time_reported: bool,
    /// The buffer cap has been reported to the user; say it once, not per line.
    buffer_limit_reported: bool,
    input_limit_reported: bool,
    outbound_limit_reported: bool,
    /// The STATUSMSG sigils the server declared in `005` (`@#chan` addresses
    /// the channel's operators, but is still said in `#chan`).
    statusmsg_sigils: String,
}

/// The STATUSMSG sigils assumed until the server's `005` says otherwise: the
/// two every network that supports STATUSMSG at all offers.
const DEFAULT_STATUSMSG_SIGILS: &str = "@+";

/// A command the UI wants the network layer to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Send(Outbound),
    Quit,
    None,
}

/// One line awaiting admission to the bounded socket-writer queue. A local
/// echo is data attached to the request, not a mutation performed in advance:
/// the UI adds it only after the queue accepts the line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outbound {
    line: String,
    input: String,
    local_echo: Option<LocalEcho>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct LocalEcho {
    target: String,
    text: String,
}

impl Outbound {
    pub fn line(&self) -> &str {
        &self.line
    }
}

impl App {
    pub fn new(channel: String, nick: String) -> Self {
        Self {
            nick,
            buffers: vec![Buffer::new(channel, BufferKind::Conversation)],
            current: 0,
            input: String::new(),
            input_cursor: 0,
            should_quit: false,
            connected: true,
            gave_up: false,
            pending_read_marker: None,
            invalid_time_reported: false,
            buffer_limit_reported: false,
            input_limit_reported: false,
            outbound_limit_reported: false,
            statusmsg_sigils: DEFAULT_STATUSMSG_SIGILS.to_owned(),
        }
    }

    /// The channel a message target is said in: the target itself, or the
    /// channel a STATUSMSG target (`@#chan`, `+#chan`) addresses a subset of.
    fn channel_of<'a>(&self, target: &'a str) -> Option<&'a str> {
        let bare = target.trim_start_matches(|sigil| self.statusmsg_sigils.contains(sigil));
        [bare, target]
            .into_iter()
            .find(|candidate| e6irc_client::is_channel_target(candidate))
    }

    /// Adopt the nickname the server confirmed at registration. It is the
    /// server's to choose, and the only name under which this client's own
    /// messages and joins come back.
    pub fn set_nick(&mut self, nick: &str) {
        self.nick = nick.to_owned();
    }

    /// Update whether sends can reach the server. The network task reconnects
    /// independently; the model refuses input while it is down so a line is
    /// never rendered as sent and queued for surprise delivery later.
    pub fn set_connected(&mut self, connected: bool) {
        self.connected = connected;
    }

    /// The network task will not reconnect: say so instead of "reconnecting".
    pub fn stop_reconnecting(&mut self) {
        self.connected = false;
        self.gave_up = true;
    }

    pub fn gave_up(&self) -> bool {
        self.gave_up
    }

    pub fn connected(&self) -> bool {
        self.connected
    }

    pub fn total_unread(&self) -> usize {
        self.buffers.iter().map(Buffer::unread).sum()
    }

    pub fn input(&self) -> &str {
        &self.input
    }

    pub fn input_cursor(&self) -> usize {
        self.input_cursor
    }

    pub fn current(&self) -> &Buffer {
        &self.buffers[self.current]
    }

    fn current_mut(&mut self) -> &mut Buffer {
        &mut self.buffers[self.current]
    }

    /// Index of the buffer named `name`, if open.
    fn buffer_index(&self, name: &str) -> Option<usize> {
        self.buffers
            .iter()
            .position(|buffer| e6irc_proto::casemap::CaseMapping::Rfc1459.eq(&buffer.name, name))
    }

    /// Open a buffer (or focus it if already open) and return its index.
    /// The buffer for `name`, opening one if this is the first we have seen of
    /// it. `None` once [`MAX_BUFFERS`] are open.
    ///
    /// Bounded for the same reason as the scrollback: the names come from the
    /// server, so without a cap a remote party can make this client allocate a
    /// buffer per message. Hitting the cap is reported once in the current
    /// buffer rather than dropping the message without a word.
    fn open_buffer(&mut self, name: String) -> Option<usize> {
        if let Some(i) = self.buffer_index(&name) {
            return Some(i);
        }
        if self.buffers.len() >= MAX_BUFFERS {
            return None;
        }
        self.buffers
            .push(Buffer::new(name, BufferKind::Conversation));
        Some(self.buffers.len() - 1)
    }

    /// The server buffer, opened the first time the server says something
    /// that belongs to no conversation. At the buffer cap its lines go where
    /// the user is looking — never nowhere.
    fn server_buffer(&mut self) -> usize {
        if let Some(index) = self
            .buffers
            .iter()
            .position(|buffer| buffer.kind == BufferKind::Server)
        {
            return index;
        }
        if self.buffers.len() >= MAX_BUFFERS {
            self.note_buffer_limit();
            return self.current;
        }
        self.buffers
            .push(Buffer::new(SERVER_BUFFER.to_owned(), BufferKind::Server));
        self.buffers.len() - 1
    }

    /// Say `text` in the server buffer.
    fn note_server(&mut self, text: &str) {
        let index = self.server_buffer();
        self.buffers[index].push(LogLine::new("*", text));
    }

    /// Say `text` in the conversation named `name` when one is open, else in
    /// the server buffer: a reply about something this client is showing
    /// belongs beside it.
    fn note_about(&mut self, name: &str, text: &str) {
        match self.conversation_index(name) {
            Some(index) => self.buffers[index].push(LogLine::new("*", text)),
            None => self.note_server(text),
        }
    }

    /// Index of the open conversation (not the server buffer) named `name`.
    fn conversation_index(&self, name: &str) -> Option<usize> {
        self.buffer_index(name)
            .filter(|index| self.buffers[*index].kind == BufferKind::Conversation)
    }

    /// Let the read marker of `channel` advance freely again: its history
    /// loaded every unread line, so no gap remains.
    pub fn release_read_marker(&mut self, channel: &str) {
        if let Some(index) = self.conversation_index(channel) {
            self.buffers[index].read_hold = ReadHold::Free;
        }
    }

    /// Hold the read marker of `channel` at its last loaded line: history
    /// stopped paging with unread lines still beyond it, and those lines were
    /// never shown.
    pub fn hold_read_marker(&mut self, channel: &str) {
        let Some(index) = self.conversation_index(channel) else {
            return;
        };
        let buffer = &mut self.buffers[index];
        buffer.read_hold = match buffer
            .latest_time
            .clone()
            .or_else(|| buffer.read_marker.clone())
        {
            Some(time) => ReadHold::At(time),
            None => ReadHold::Nowhere,
        };
        buffer.push(LogLine::new(
            "*",
            "more unread lines were not loaded; the read marker stays at the last line \
             loaded here",
        ));
    }

    pub fn next_buffer(&mut self) {
        if !self.buffers.is_empty() {
            self.current = (self.current + 1) % self.buffers.len();
            self.focus_current();
        }
    }

    pub fn prev_buffer(&mut self) {
        if !self.buffers.is_empty() {
            self.current = (self.current + self.buffers.len() - 1) % self.buffers.len();
            self.focus_current();
        }
    }

    pub fn scroll_up(&mut self, n: usize) {
        self.current_mut().scroll_up(n);
    }

    pub fn scroll_down(&mut self, n: usize) {
        let was_scrolled_back = self.current().scrolled_back();
        self.current_mut().scroll_down(n);
        if was_scrolled_back && !self.current().scrolled_back() {
            self.focus_current();
        }
    }

    pub fn jump_latest(&mut self) {
        self.scroll_down(usize::MAX);
    }

    /// Fold an incoming server message into the right buffer.
    pub fn on_message(&mut self, msg: &OwnedMessage) {
        let sender = msg
            .source
            .as_deref()
            .and_then(|s| s.split('!').next())
            .unwrap_or("?")
            .to_string();
        let casemap = e6irc_proto::casemap::CaseMapping::Rfc1459;
        match msg.command.as_str() {
            "PRIVMSG" | "NOTICE" => {
                let Some(target) = msg.params.first().cloned() else {
                    return;
                };
                let text = msg.params.get(1).cloned().unwrap_or_default();
                let from_a_user = msg
                    .source
                    .as_deref()
                    .is_some_and(|source| source.contains('!'));
                // A channel message lands in that channel's buffer; a PM to
                // us opens/uses a query buffer named after the sender. What a
                // server says to us, or to no one in particular (`NOTICE *`,
                // a bouncer's status), belongs to no conversation.
                let buffer = if let Some(channel) = self.channel_of(&target) {
                    channel.to_owned()
                } else if casemap.eq(&target, &self.nick) && from_a_user {
                    sender.clone()
                } else if casemap.eq(&sender, &self.nick) {
                    // Our own message, sent from another client attached to
                    // the same bouncer network: it belongs to its recipient.
                    target
                } else {
                    self.note_server(&format!("{sender}: {text}"));
                    return;
                };
                let Some(idx) = self.open_buffer(buffer) else {
                    self.note_buffer_limit();
                    return;
                };
                if !self.buffers[idx].accept_msgid(msg.tag("msgid")) {
                    return;
                }
                self.buffers[idx].push(LogLine::message(&sender, &text));
                if let Some(raw_time) = msg.tag("time") {
                    if let Some(millis) = e6irc_proto::time::parse_server_time_millis(raw_time) {
                        self.buffers[idx].latest_time =
                            Some(e6irc_proto::time::server_time(millis));
                    } else if !self.invalid_time_reported {
                        self.invalid_time_reported = true;
                        self.status(
                            "server sent an invalid time tag; read position was not advanced",
                        );
                    }
                }
                if idx == self.current && !self.buffers[idx].scrolled_back() {
                    self.buffers[idx].unread = 0;
                    self.queue_current_marker();
                } else {
                    self.buffers[idx].unread = self.buffers[idx].unread.saturating_add(1);
                }
            }
            "JOIN" => {
                if let Some(chan) = msg.params.first().cloned() {
                    let Some(idx) = self.open_buffer(chan) else {
                        self.note_buffer_limit();
                        return;
                    };
                    self.buffers[idx].push(LogLine::new("*", &format!("{sender} joined")));
                }
            }
            "PART" => {
                if let Some(chan) = msg.params.first()
                    && let Some(idx) = self.buffer_index(chan)
                {
                    self.buffers[idx].push(LogLine::new("*", &format!("{sender} left")));
                }
            }
            "QUIT" => {
                self.note_about_user(&sender, &format!("{sender} quit"));
            }
            "NICK" => {
                let Some(new_nick) = msg.params.first() else {
                    return;
                };
                if casemap.eq(&sender, &self.nick) {
                    self.nick = new_nick.clone();
                    self.status(format!("you are now known as {new_nick}"));
                } else {
                    self.note_about_user(&sender, &format!("{sender} is now known as {new_nick}"));
                }
            }
            "KICK" => {
                let (Some(channel), Some(kicked)) = (msg.params.first(), msg.params.get(1)) else {
                    return;
                };
                let reason = msg.params.get(2).map(String::as_str).unwrap_or("");
                let who = if casemap.eq(kicked, &self.nick) {
                    "you were"
                } else {
                    &format!("{kicked} was")
                };
                self.note_in(channel, &format!("{who} kicked by {sender}: {reason}"));
            }
            "TOPIC" => {
                let (Some(channel), Some(topic)) = (msg.params.first(), msg.params.get(1)) else {
                    return;
                };
                self.note_about(channel, &format!("{sender} set the topic: {topic}"));
            }
            "MODE" => {
                let Some(target) = msg.params.first() else {
                    return;
                };
                let change = msg.params.get(1..).unwrap_or_default().join(" ");
                self.note_about(target, &format!("{sender} sets mode {change} on {target}"));
            }
            "INVITE" => {
                let (Some(invited), Some(channel)) = (msg.params.first(), msg.params.get(1)) else {
                    return;
                };
                if casemap.eq(invited, &self.nick) {
                    self.status(format!(
                        "{sender} invited you to {channel} — /join {channel} to accept"
                    ));
                } else {
                    self.note_about(channel, &format!("{sender} invited {invited} to {channel}"));
                }
            }
            "MARKREAD" => {
                let Some(target) = msg.params.first() else {
                    return;
                };
                let Some(index) = self.buffer_index(target) else {
                    return;
                };
                let marker = msg
                    .params
                    .get(1)
                    .and_then(|value| value.strip_prefix("timestamp="))
                    .and_then(e6irc_proto::time::parse_server_time_millis)
                    .map(e6irc_proto::time::server_time);
                let reaches_latest = marker.as_ref().is_some_and(|marker| {
                    self.buffers[index]
                        .latest_time
                        .as_ref()
                        .is_none_or(|latest| marker >= latest)
                });
                self.buffers[index].read_marker = marker;
                if reaches_latest {
                    self.buffers[index].unread = 0;
                }
            }
            // Liveness traffic: the network task answers the server's PING,
            // and a PONG answers a PING of this client's own.
            "PING" | "PONG" => {}
            // The server closing the link, or answering a command with a
            // standard reply, is the only account the user gets of it.
            "ERROR" => self.status(format!("server error: {}", msg.params.join(" "))),
            command @ ("FAIL" | "WARN" | "NOTE") => {
                self.status(format!("{command} {}", msg.params.join(" ")));
            }
            // 400–599 are the error replies. The local echo shows a message as
            // sent the moment it is queued, so a refusal that is not shown
            // leaves the user believing it was delivered. `params[0]` is our
            // own nick; what follows names the subject, then says why.
            numeric if e6irc_client::is_refusal(msg) => {
                let subject = msg.params.get(1).map(String::as_str).unwrap_or("");
                let detail = msg.params.get(1..).unwrap_or_default().join(" ");
                self.note_in(subject, &format!("{detail} ({numeric})"));
            }
            // Every other numeric — the welcome burst, a WHOIS answer to
            // `/raw`, NAMES, a topic on join — is shown beside the
            // conversation it names, else in the server buffer. `params[0]` is
            // our own nick.
            numeric if numeric.len() == 3 && numeric.bytes().all(|byte| byte.is_ascii_digit()) => {
                if numeric == "005" {
                    self.adopt_isupport(msg);
                }
                let subject = msg.params.get(1).map(String::as_str).unwrap_or("");
                let detail = msg.params.get(1..).unwrap_or_default().join(" ");
                self.note_about(subject, &detail);
            }
            // A command this client does not model (AWAY, ACCOUNT, CHGHOST,
            // WALLOPS, CAP NEW, …) is still something the server said.
            command => {
                let detail = msg.params.join(" ");
                self.note_server(&format!("{sender} {command} {detail}"));
            }
        }
    }

    /// Adopt what a `005` line declares that routing depends on. Tokens sit
    /// between the nick and the trailing "are supported by this server".
    fn adopt_isupport(&mut self, msg: &OwnedMessage) {
        let tokens = msg
            .params
            .get(1..msg.params.len().saturating_sub(1))
            .unwrap_or_default();
        for token in tokens {
            if let Some(sigils) = token.strip_prefix("STATUSMSG=") {
                sigils.clone_into(&mut self.statusmsg_sigils);
            } else if token == "-STATUSMSG" {
                self.statusmsg_sigils.clear();
            }
        }
    }

    /// Say `text` in the buffer named `buffer`, or where the user is looking
    /// when there is no such buffer — never nowhere.
    fn note_in(&mut self, buffer: &str, text: &str) {
        let index = self.buffer_index(buffer).unwrap_or(self.current);
        self.buffers[index].push(LogLine::new("*", text));
    }

    /// Say `text` wherever `nick` may be present. This client tracks no
    /// per-channel membership, so channel buffers are the closest honest scope
    /// — but a query buffer with an *unrelated* user must not report it: that
    /// would attribute an event to a conversation it never touched.
    fn note_about_user(&mut self, nick: &str, text: &str) {
        for buffer in &mut self.buffers {
            if e6irc_client::is_channel_target(&buffer.name)
                || e6irc_proto::casemap::CaseMapping::Rfc1459.eq(&buffer.name, nick)
            {
                buffer.push(LogLine::new("*", text));
            }
        }
    }

    fn focus_current(&mut self) {
        if self.buffers[self.current].scrolled_back() {
            return;
        }
        self.buffers[self.current].unread = 0;
        self.queue_current_marker();
    }

    fn queue_current_marker(&mut self) {
        let buffer = &mut self.buffers[self.current];
        let Some(latest) = buffer.latest_time.clone() else {
            return;
        };
        // Times are the server's fixed-width UTC form, so they order as text.
        let latest = match &buffer.read_hold {
            ReadHold::Free => latest,
            ReadHold::At(ceiling) => latest.min(ceiling.clone()),
            ReadHold::Nowhere => return,
        };
        // Read positions only move forward: a marker at or past this one (set
        // here, or by another device) needs no update.
        if buffer
            .read_marker
            .as_deref()
            .is_some_and(|marker| marker >= latest.as_str())
        {
            return;
        }
        self.pending_read_marker = Some(format!("MARKREAD {} timestamp={latest}", buffer.name));
    }

    /// Take the latest coalesced marker update. Multiple messages between UI
    /// polls become one durable MARKREAD write.
    pub fn take_read_marker_command(&mut self) -> Option<String> {
        self.pending_read_marker.take()
    }

    /// Put back a coalesced marker that could not enter the bounded outbound
    /// queue. A newer marker already waiting wins because read positions are
    /// monotonic.
    pub fn requeue_read_marker_command(&mut self, command: String) {
        if self.pending_read_marker.is_none() {
            self.pending_read_marker = Some(command);
        }
    }

    /// Commit the local presentation of a message only after its wire line has
    /// entered the bounded writer queue.
    pub fn outbound_accepted(&mut self, outbound: &Outbound) {
        self.outbound_limit_reported = false;
        let Some(echo) = &outbound.local_echo else {
            return;
        };
        let Some(index) = self.buffer_index(&echo.target) else {
            return;
        };
        let from = self.nick.clone();
        self.buffers[index].push(LogLine::new(&from, &echo.text));
    }

    /// Restore editor text when the bounded writer refuses admission. The
    /// request owns the exact original input so queue pressure cannot turn a
    /// visible refusal into data loss.
    pub fn outbound_refused(&mut self, outbound: &Outbound) {
        if self.input.is_empty() {
            self.restore_input(outbound.input.clone());
        }
    }

    /// Say once that the local writer queue is saturated. Repeated read-marker
    /// retries must not flood the buffer with the same notice.
    pub fn note_outbound_full(&mut self) {
        if self.outbound_limit_reported {
            return;
        }
        self.outbound_limit_reported = true;
        self.status("outbound queue is full — input retained; try again");
    }

    /// Say once that the buffer limit stopped a new buffer from opening. Said
    /// once rather than per message, because the condition that triggers it is
    /// exactly the one that would flood the notice.
    fn note_buffer_limit(&mut self) {
        if self.buffer_limit_reported {
            return;
        }
        self.buffer_limit_reported = true;
        self.status(format!(
            "not opening more than {MAX_BUFFERS} buffers; further new targets are ignored"
        ));
    }

    /// Note a local status line in the current buffer.
    pub fn status(&mut self, text: impl Into<String>) {
        self.current_mut().push(LogLine::new("*", &text.into()));
    }

    pub fn on_char(&mut self, c: char) {
        if c.is_control() {
            return;
        }
        if self.input.len() + c.len_utf8() > MAX_COMPOSER_BYTES {
            if !self.input_limit_reported {
                self.input_limit_reported = true;
                self.status(format!(
                    "input is limited to {MAX_COMPOSER_BYTES} bytes by the IRC wire limit"
                ));
            }
            return;
        }
        self.input.insert(self.input_cursor, c);
        self.input_cursor += c.len_utf8();
    }

    /// Insert pasted text at the cursor. A paste holding a line break is
    /// refused whole: typed into the composer it would be one message with
    /// the breaks lost, and sent line by line it would be several messages
    /// the user never saw separately.
    pub fn on_paste(&mut self, text: &str) {
        if text.contains(['\r', '\n']) {
            let lines = text
                .split(['\r', '\n'])
                .filter(|line| !line.is_empty())
                .count();
            self.status(format!(
                "a paste of {lines} lines was not inserted: paste one line at a time"
            ));
            return;
        }
        for character in text.chars() {
            self.on_char(character);
        }
    }

    pub fn on_backspace(&mut self) {
        let Some((previous, _)) = self.input[..self.input_cursor].char_indices().next_back() else {
            return;
        };
        self.input.drain(previous..self.input_cursor);
        self.input_cursor = previous;
        self.input_limit_reported = false;
    }

    pub fn on_delete(&mut self) {
        let Some(next) = self.input[self.input_cursor..]
            .chars()
            .next()
            .map(char::len_utf8)
        else {
            return;
        };
        self.input
            .drain(self.input_cursor..self.input_cursor + next);
        self.input_limit_reported = false;
    }

    pub fn move_input_left(&mut self) {
        if let Some((previous, _)) = self.input[..self.input_cursor].char_indices().next_back() {
            self.input_cursor = previous;
        }
    }

    pub fn move_input_right(&mut self) {
        if let Some(next) = self.input[self.input_cursor..]
            .chars()
            .next()
            .map(char::len_utf8)
        {
            self.input_cursor += next;
        }
    }

    pub fn move_input_home(&mut self) {
        self.input_cursor = 0;
    }

    pub fn move_input_end(&mut self) {
        self.input_cursor = self.input.len();
    }

    pub fn clear_input(&mut self) {
        self.input.clear();
        self.input_cursor = 0;
        self.input_limit_reported = false;
    }

    /// Handle Enter: produce an action and clear accepted input. Commands are
    /// closed and explicit; a misspelled command is retained for correction
    /// instead of leaking into the active conversation as message text.
    pub fn on_enter(&mut self) -> Action {
        let line = std::mem::take(&mut self.input);
        self.input_cursor = 0;
        self.input_limit_reported = false;
        if line.is_empty() {
            return Action::None;
        }

        if let Some(text) = line.strip_prefix("//") {
            return self.message_outbound(line.clone(), format!("/{text}"));
        }

        if let Some(command_line) = line.strip_prefix('/') {
            let (command, arguments) = command_line
                .split_once(' ')
                .map_or((command_line, ""), |(command, arguments)| {
                    (command, arguments.trim())
                });
            let command = command.to_ascii_lowercase();
            let arguments = arguments.to_owned();
            return match command.as_str() {
                "help" if arguments.is_empty() => {
                    self.status(
                        "commands: /join #channel · /msg nick text · /win name|number · /raw LINE · /quit · //text sends /text",
                    );
                    Action::None
                }
                "quit" if arguments.is_empty() => {
                    self.should_quit = true;
                    Action::Quit
                }
                "join" => self.join_command(line, &arguments),
                "win" => self.window_command(line, &arguments),
                "msg" => self.direct_message_command(line, &arguments),
                "raw" => self.raw_command(line, &arguments),
                "help" => self.refuse_command(line, "usage: /help"),
                "quit" => self.refuse_command(line, "usage: /quit"),
                "" => self.refuse_command(line, "enter /help to list commands"),
                _ => self.refuse_command(
                    line,
                    format!(
                        "unknown command /{command} — use /help; use // to send a literal slash"
                    ),
                ),
            };
        }

        self.message_outbound(line.clone(), line)
    }

    fn join_command(&mut self, input: String, channel: &str) -> Action {
        if channel.is_empty() || channel.contains(char::is_whitespace) {
            return self.refuse_command(input, "usage: /join #channel");
        }
        if !self.connected {
            return self.refuse_command(input, "not connected — JOIN not sent");
        }
        let wire = format!("JOIN {channel}");
        if !e6irc_proto::message::client_frame_fits(wire.as_bytes()) {
            return self.refuse_command(
                input,
                format!("message exceeds an IRC wire budget ({} bytes)", wire.len()),
            );
        }
        let Some(index) = self.open_buffer(channel.to_owned()) else {
            self.restore_input(input);
            self.note_buffer_limit();
            return Action::None;
        };
        self.current = index;
        self.focus_current();
        Action::Send(Outbound {
            line: wire,
            input,
            local_echo: None,
        })
    }

    fn window_command(&mut self, input: String, target: &str) -> Action {
        if target.is_empty() || target.contains(char::is_whitespace) {
            return self.refuse_command(input, "usage: /win name|number");
        }
        let index = target
            .parse::<usize>()
            .ok()
            .and_then(|number| number.checked_sub(1))
            .filter(|index| *index < self.buffers.len())
            .or_else(|| self.buffer_index(target));
        if let Some(index) = index {
            self.current = index;
            self.focus_current();
        } else {
            self.restore_input(input);
            self.status(format!("no buffer named or numbered {target}"));
        }
        Action::None
    }

    fn direct_message_command(&mut self, input: String, arguments: &str) -> Action {
        let Some((target, text)) = arguments.split_once(' ') else {
            return self.refuse_command(input, "usage: /msg nick text");
        };
        let text = text.trim_start();
        if target.is_empty() || text.is_empty() {
            return self.refuse_command(input, "usage: /msg nick text");
        }
        if !self.connected {
            return self.refuse_command(input, "not connected — message not sent");
        }
        let wire = format!("PRIVMSG {target} :{text}");
        if !e6irc_proto::message::client_frame_fits(wire.as_bytes()) {
            return self.refuse_command(
                input,
                format!("message exceeds an IRC wire budget ({} bytes)", wire.len()),
            );
        }
        let Some(index) = self.open_buffer(target.to_owned()) else {
            self.restore_input(input);
            self.note_buffer_limit();
            return Action::None;
        };
        self.current = index;
        self.focus_current();
        self.outbound_or_restore(
            input,
            wire,
            Some(LocalEcho {
                target: target.to_owned(),
                text: text.to_owned(),
            }),
        )
    }

    fn raw_command(&mut self, input: String, line: &str) -> Action {
        if line.is_empty() {
            return self.refuse_command(input, "usage: /raw LINE");
        }
        if !self.connected {
            return self.refuse_command(input, "not connected — raw line not sent");
        }
        self.outbound_or_restore(input, line.to_owned(), None)
    }

    fn refuse_command(&mut self, input: String, message: impl Into<String>) -> Action {
        self.restore_input(input);
        self.status(message);
        Action::None
    }

    fn message_outbound(&mut self, input: String, text: String) -> Action {
        if self.current().kind == BufferKind::Server {
            return self.refuse_command(
                input,
                "the server buffer is not a conversation — /msg nick text, /join #channel, or /raw LINE",
            );
        }
        if !self.connected {
            return self.refuse_command(input, "not connected — message not sent");
        }
        let target = self.current().name.clone();
        let wire = format!("PRIVMSG {target} :{text}");
        self.outbound_or_restore(input, wire, Some(LocalEcho { target, text }))
    }

    fn outbound_or_restore(
        &mut self,
        input: String,
        line: String,
        local_echo: Option<LocalEcho>,
    ) -> Action {
        if !e6irc_proto::message::client_frame_fits(line.as_bytes()) {
            self.restore_input(input);
            self.status(format!(
                "message exceeds an IRC wire budget ({} bytes)",
                line.len()
            ));
            return Action::None;
        }
        Action::Send(Outbound {
            line,
            input,
            local_echo,
        })
    }

    fn restore_input(&mut self, input: String) {
        self.input_cursor = input.len();
        self.input = input;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn msg(raw: &str) -> OwnedMessage {
        OwnedMessage::from(&e6irc_proto::message::Message::parse(raw).expect("valid line"))
    }

    /// Every line below arrives from the server, so the memory the client
    /// spends on them must not be the server's decision.
    #[test]
    fn scrollback_is_bounded() {
        let mut app = App::new("#home".into(), "me".into());
        for i in 0..SCROLLBACK_LINES + 500 {
            app.on_message(&msg(&format!(":a!u@h PRIVMSG #c :line {i}")));
        }
        let buf = &app.buffers[app.buffer_index("#c").expect("channel buffer")];
        assert_eq!(buf.log.len(), SCROLLBACK_LINES);
        // The oldest lines went, not the newest: a scrollback that dropped the
        // live tail would be worse than one that grew.
        assert!(
            buf.log
                .last()
                .expect("a line")
                .text
                .as_str()
                .ends_with("line 5499")
        );
        assert!(
            buf.log
                .first()
                .expect("a line")
                .text
                .as_str()
                .ends_with("line 500")
        );
    }

    #[test]
    fn scrolled_view_survives_the_drop() {
        // Scrolled back into history while the log is trimmed from the front:
        // `scroll` counts from the end, so it must shrink with the drain or it
        // would silently walk off into lines that no longer exist.
        let mut app = App::new("#home".into(), "me".into());
        for i in 0..SCROLLBACK_LINES {
            app.on_message(&msg(&format!(":a!u@h PRIVMSG #c :line {i}")));
        }
        let idx = app.buffer_index("#c").expect("channel buffer");
        app.current = idx;
        app.scroll_up(10);
        let before: Vec<String> = app.buffers[idx]
            .visible(5)
            .iter()
            .map(|l| l.text.as_str().to_string())
            .collect();
        // Now push past the cap, so every new line drains one from the front.
        for i in 0..50 {
            app.on_message(&msg(&format!(":a!u@h PRIVMSG #c :more {i}")));
        }
        let buf = &app.buffers[idx];
        let after: Vec<String> = buf
            .visible(5)
            .iter()
            .map(|l| l.text.as_str().to_string())
            .collect();
        // The user is looking at the same lines. Without the `scroll` fixup the
        // drain would slide the viewport forward by one line per arrival.
        assert_eq!(before, after);
        // And a legal window at every height, including past the end.
        for h in [0usize, 1, 10, 100_000] {
            let _ = buf.visible(h);
        }
    }

    #[test]
    fn buffer_count_is_bounded_and_says_so() {
        let mut app = App::new("#home".into(), "me".into());
        for i in 0..MAX_BUFFERS + 100 {
            app.on_message(&msg(&format!(":a!u@h PRIVMSG #c{i} :hi")));
        }
        assert_eq!(app.buffers.len(), MAX_BUFFERS);
        // Refused, not silently: the user is told once that targets are being
        // dropped. A silent cap would look like the network went quiet.
        let said = app.buffers[0]
            .log
            .iter()
            .filter(|l| l.text.as_str().contains("not opening more than"))
            .count();
        assert_eq!(said, 1, "the limit is reported exactly once");
    }

    #[test]
    fn channel_messages_land_in_their_buffer() {
        let mut app = App::new("#c".into(), "me".into());
        app.on_message(&msg(":bob!b@h PRIVMSG #c :hello"));
        app.on_message(&msg(":bob!b@h PRIVMSG #other :elsewhere"));
        assert_eq!(app.buffers.len(), 2);
        assert_eq!(app.buffers[0].log[0].text, "hello");
        assert_eq!(
            app.buffer_index("#other")
                .map(|i| app.buffers[i].log[0].text.as_str().to_string()),
            Some("elsewhere".into())
        );
    }

    fn last_line(app: &App, buffer: &str) -> String {
        let index = app.buffer_index(buffer).expect("buffer");
        app.buffers[index]
            .log
            .last()
            .map(|line| line.text.to_string())
            .unwrap_or_default()
    }

    /// The local echo appears as soon as a line is queued, so the server's
    /// refusal is the only thing that tells the user it was not delivered.
    #[test]
    fn a_refused_message_is_said_in_the_buffer_it_was_sent_from() {
        let mut app = App::new("#home".into(), "me".into());
        app.on_message(&msg(":me!u@h JOIN #moderated"));
        app.on_message(&msg(":srv 404 me #moderated :Cannot send to channel"));
        assert_eq!(
            last_line(&app, "#moderated"),
            "#moderated Cannot send to channel (404)"
        );
        // A refusal about something with no buffer is said where the user is.
        app.on_message(&msg(":srv 401 me nosuchnick :No such nick/channel"));
        assert_eq!(
            last_line(&app, "#home"),
            "nosuchnick No such nick/channel (401)"
        );
        app.on_message(&msg(":srv 473 me #inviteonly :Cannot join channel (+i)"));
        assert_eq!(
            last_line(&app, "#home"),
            "#inviteonly Cannot join channel (+i) (473)"
        );
    }

    #[test]
    fn kicks_standard_replies_and_server_errors_are_never_dropped() {
        let mut app = App::new("#home".into(), "me".into());
        app.on_message(&msg(":op!u@h KICK #home me :enough"));
        assert_eq!(last_line(&app, "#home"), "you were kicked by op: enough");
        app.on_message(&msg(":op!u@h KICK #home troll :bye"));
        assert_eq!(last_line(&app, "#home"), "troll was kicked by op: bye");
        app.on_message(&msg(
            ":srv FAIL CHATHISTORY INVALID_TARGET #x :no such target",
        ));
        assert_eq!(
            last_line(&app, "#home"),
            "FAIL CHATHISTORY INVALID_TARGET #x no such target"
        );
        app.on_message(&msg("ERROR :Closing Link: me (Ping timeout)"));
        assert_eq!(
            last_line(&app, "#home"),
            "server error: Closing Link: me (Ping timeout)"
        );
        // An ordinary informational numeric is still not conversation.
        let before = app.buffers[0].log.len();
        app.on_message(&msg(":srv 372 me :- message of the day"));
        assert_eq!(app.buffers[0].log.len(), before);
    }

    /// The server confirms the nickname; a bouncer's is the upstream's. A
    /// direct message is recognised by the confirmed name, and it follows every
    /// NICK whose source is that name.
    #[test]
    fn direct_messages_are_recognised_by_the_nick_the_server_confirmed() {
        let mut app = App::new("#home".into(), "requested".into());
        app.set_nick("Upstream");
        app.on_message(&msg(":alice!u@h PRIVMSG upstream :hello"));
        assert!(app.buffer_index("alice").is_some());
        assert!(
            app.buffer_index("upstream").is_none(),
            "a message to us opened a buffer where replies would go to ourselves"
        );

        app.on_message(&msg(":UPSTREAM!u@h NICK renamed"));
        assert_eq!(app.nick, "renamed");
        assert_eq!(last_line(&app, "#home"), "you are now known as renamed");
        app.on_message(&msg(":bob!u@h PRIVMSG renamed :hi"));
        assert!(app.buffer_index("bob").is_some());
        assert!(app.buffer_index("renamed").is_none());

        app.on_message(&msg(":alice!u@h NICK alicia"));
        assert_eq!(app.nick, "renamed");
        assert_eq!(last_line(&app, "alice"), "alice is now known as alicia");
    }

    /// A STATUSMSG line (`@#c`: to the channel's operators) is part of that
    /// channel's conversation, not a query with a nick named `@#c`.
    #[test]
    fn statusmsg_targets_are_said_in_their_channel() {
        let mut app = App::new("#c".into(), "me".into());
        app.on_message(&msg(":op!o@h NOTICE @#c :ops only"));
        app.on_message(&msg(":op!o@h PRIVMSG +#C :voiced"));
        assert_eq!(app.buffers.len(), 1, "no buffer named for a sigil");
        assert_eq!(app.buffers[0].log[0].text, "ops only");
        assert_eq!(app.buffers[0].log[1].text, "voiced");
        // The server's own declaration governs which sigils those are.
        app.on_message(&msg(
            ":srv 005 me STATUSMSG=~@ CHANTYPES=# :are supported by this server",
        ));
        app.on_message(&msg(":op!o@h PRIVMSG ~#c :owners"));
        assert_eq!(last_line(&app, "#c"), "owners");
        // A server-local `&channel` stays itself even when `&` is a sigil.
        app.on_message(&msg(
            ":srv 005 me STATUSMSG=&@ :are supported by this server",
        ));
        app.on_message(&msg(":op!o@h PRIVMSG &local :here"));
        assert_eq!(last_line(&app, "&local"), "here");
    }

    /// A QUIT is reported in the query with that user whatever case the
    /// server spells the nick in: nicknames compare under RFC 1459.
    #[test]
    fn user_events_reach_their_query_under_any_case() {
        let mut app = App::new("#c".into(), "me".into());
        app.on_message(&msg(":Al[ex]!a@h PRIVMSG me :psst"));
        app.on_message(&msg(":al{EX}!a@h QUIT :bye"));
        assert_eq!(last_line(&app, "Al[ex]"), "al{EX} quit");
    }

    #[test]
    fn private_message_opens_a_query_named_for_the_sender() {
        let mut app = App::new("#c".into(), "me".into());
        app.on_message(&msg(":al!a@h PRIVMSG ME :psst"));
        let i = app.buffer_index("al").expect("query buffer");
        assert_eq!(app.buffers[i].log[0].text, "psst");
    }

    #[test]
    fn rfc1459_equivalent_names_share_one_buffer() {
        let mut app = App::new("#[room]".into(), "me".into());
        app.on_message(&msg(":a!a@h PRIVMSG #{ROOM} :same channel"));
        assert_eq!(app.buffers.len(), 1);
        assert_eq!(app.current().log[0].text, "same channel");
    }

    #[test]
    fn typing_and_send_targets_the_current_buffer() {
        let mut app = App::new("#c".into(), "me".into());
        for ch in "ho".chars() {
            app.on_char(ch);
        }
        let Action::Send(outbound) = app.on_enter() else {
            panic!("message should be queued");
        };
        assert_eq!(outbound.line(), "PRIVMSG #c :ho");
        assert!(app.current().log.is_empty(), "no echo before admission");
        app.outbound_accepted(&outbound);
        assert_eq!(app.current().log.last().unwrap().text, "ho");
    }

    #[test]
    fn disconnected_input_is_not_echoed_or_queued() {
        let mut app = App::new("#c".into(), "me".into());
        app.set_connected(false);
        for character in "unsent".chars() {
            app.on_char(character);
        }
        assert_eq!(app.on_enter(), Action::None);
        assert_eq!(app.current().log.len(), 1);
        assert_eq!(
            app.current().log[0].text,
            "not connected — message not sent"
        );
        assert_eq!(app.input, "unsent");

        app.clear_input();
        for character in "/join #lost".chars() {
            app.on_char(character);
        }
        assert_eq!(app.on_enter(), Action::None);
        assert_eq!(app.buffers.len(), 1);
        assert_eq!(app.current().log[1].text, "not connected — JOIN not sent");
        assert_eq!(app.input, "/join #lost");
    }

    #[test]
    fn slash_join_opens_and_focuses_a_channel() {
        let mut app = App::new("#c".into(), "me".into());
        for ch in "/join #rust".chars() {
            app.on_char(ch);
        }
        let Action::Send(outbound) = app.on_enter() else {
            panic!("JOIN should be queued");
        };
        assert_eq!(outbound.line(), "JOIN #rust");
        assert_eq!(app.current().name, "#rust");
        assert_eq!(app.buffers.len(), 2);
    }

    #[test]
    fn slash_commands_are_explicit_and_mistakes_are_retained() {
        for input in [
            "/join",
            "/win",
            "/msg alice",
            "/raw",
            "/quit later",
            "/bogus",
        ] {
            let mut app = App::new("#c".into(), "me".into());
            app.input = input.into();
            assert_eq!(app.on_enter(), Action::None, "{input}");
            assert_eq!(app.input, input, "{input}");
            assert_eq!(app.current().log.len(), 1, "{input}");
        }
    }

    #[test]
    fn help_literal_slash_direct_message_and_raw_are_first_class() {
        let mut app = App::new("#c".into(), "me".into());
        app.input = "/help".into();
        assert_eq!(app.on_enter(), Action::None);
        assert!(app.input.is_empty());
        assert!(
            app.current()
                .log
                .last()
                .is_some_and(|line| line.text.as_str().contains("/msg nick text"))
        );

        app.input = "//join is message text".into();
        let Action::Send(literal) = app.on_enter() else {
            panic!("escaped slash should be queued as message text");
        };
        assert_eq!(literal.line(), "PRIVMSG #c :/join is message text");
        app.outbound_accepted(&literal);
        assert_eq!(
            app.current().log.last().unwrap().text,
            "/join is message text"
        );

        app.input = "/msg Alice hello there".into();
        let Action::Send(direct) = app.on_enter() else {
            panic!("direct message should be queued");
        };
        assert_eq!(direct.line(), "PRIVMSG Alice :hello there");
        assert_eq!(app.current().name, "Alice");
        app.outbound_accepted(&direct);
        assert_eq!(app.current().log.last().unwrap().text, "hello there");

        app.input = "/raw WHOIS Alice".into();
        let Action::Send(raw) = app.on_enter() else {
            panic!("raw line should be queued");
        };
        assert_eq!(raw.line(), "WHOIS Alice");

        app.input = format!("/raw @example={} PING", "a".repeat(600));
        let Action::Send(tagged) = app.on_enter() else {
            panic!("the client tag allowance should be usable by raw commands");
        };
        assert!(tagged.line().starts_with("@example="));
    }

    #[test]
    fn composer_and_wire_line_are_bounded_without_truncating() {
        let mut app = App::new("#channel".into(), "me".into());
        for _ in 0..MAX_COMPOSER_BYTES + 20 {
            app.on_char('x');
        }
        assert_eq!(app.input.len(), MAX_COMPOSER_BYTES);
        assert_eq!(
            app.current()
                .log
                .iter()
                .filter(|line| line.text.as_str().contains("input is limited"))
                .count(),
            1
        );

        assert_eq!(app.on_enter(), Action::None);
        assert_eq!(app.input.len(), MAX_COMPOSER_BYTES);
        assert!(
            app.current()
                .log
                .last()
                .is_some_and(|line| line.text.as_str().contains("exceeds an IRC wire budget"))
        );

        let mut direct = App::new("#channel".into(), "me".into());
        direct.input = format!("/msg Alice {}", "x".repeat(MAX_COMPOSER_BYTES - 11));
        let retained = direct.input.clone();
        assert_eq!(direct.on_enter(), Action::None);
        assert_eq!(direct.input, retained);
        assert_eq!(direct.buffers.len(), 1);
    }

    #[test]
    fn composer_cursor_edits_on_character_boundaries() {
        let mut app = App::new("#channel".into(), "me".into());
        for character in "a界c".chars() {
            app.on_char(character);
        }
        assert_eq!(app.input_cursor(), app.input().len());

        app.move_input_left();
        app.move_input_left();
        app.on_char('b');
        assert_eq!(app.input(), "ab界c");
        assert_eq!(app.input_cursor(), 2);

        app.on_delete();
        assert_eq!(app.input(), "abc");
        app.move_input_end();
        app.on_backspace();
        app.move_input_home();
        app.on_delete();
        app.on_backspace();
        assert_eq!(app.input(), "b");
        assert_eq!(app.input_cursor(), 0);
    }

    #[test]
    fn outbound_refusal_never_creates_a_false_echo_and_is_reported_once() {
        let mut app = App::new("#c".into(), "me".into());
        app.input = "unsent".into();
        let Action::Send(outbound) = app.on_enter() else {
            panic!("message should reach queue admission");
        };
        assert_eq!(outbound.line(), "PRIVMSG #c :unsent");
        app.outbound_refused(&outbound);
        app.note_outbound_full();
        app.note_outbound_full();
        assert_eq!(app.input, "unsent");
        assert_eq!(
            app.current()
                .log
                .iter()
                .filter(|line| line.text.as_str().contains("outbound queue is full"))
                .count(),
            1
        );
        assert!(
            app.current()
                .log
                .iter()
                .all(|line| line.text.as_str() != "unsent")
        );
    }

    #[test]
    fn buffer_switching_wraps() {
        let mut app = App::new("#a".into(), "me".into());
        app.on_message(&msg(":x!x@h PRIVMSG #b :hi"));
        assert_eq!(app.buffers.len(), 2);
        assert_eq!(app.current, 0);
        app.next_buffer();
        assert_eq!(app.current().name, "#b");
        app.next_buffer();
        assert_eq!(app.current().name, "#a"); // wrapped
        app.prev_buffer();
        assert_eq!(app.current().name, "#b");
    }

    #[test]
    fn slash_win_uses_displayed_one_based_number_or_name() {
        let mut app = App::new("#a".into(), "me".into());
        app.on_message(&msg(":x!x@h PRIVMSG #b :hi"));
        app.input = "/win 2".into();
        assert_eq!(app.on_enter(), Action::None);
        assert_eq!(app.current().name, "#b");
        app.input = "/win #A".into();
        assert_eq!(app.on_enter(), Action::None);
        assert_eq!(app.current().name, "#a");
        app.input = "/win 0".into();
        assert_eq!(app.on_enter(), Action::None);
        assert!(
            app.current()
                .log
                .last()
                .unwrap()
                .text
                .as_str()
                .contains("no buffer named or numbered")
        );
    }

    #[test]
    fn slash_quit_exits() {
        let mut app = App::new("#c".into(), "me".into());
        for ch in "/quit".chars() {
            app.on_char(ch);
        }
        assert_eq!(app.on_enter(), Action::Quit);
        assert!(app.should_quit);
    }

    #[test]
    fn scrollback_windows_and_stays_stable() {
        let mut app = App::new("#c".into(), "me".into());
        for i in 0..10 {
            app.on_message(&msg(&format!(":u!u@h PRIVMSG #c :line{i}")));
        }
        assert_eq!(app.current().visible(3).last().unwrap().text, "line9");
        assert!(!app.current().scrolled_back());
        app.scroll_up(2);
        assert!(app.current().scrolled_back());
        assert_eq!(app.current().visible(3).last().unwrap().text, "line7");
        // a live line doesn't yank the scrolled view
        app.on_message(&msg(":u!u@h PRIVMSG #c :fresh"));
        assert_eq!(app.current().visible(3).last().unwrap().text, "line7");
        app.scroll_down(1000);
        assert_eq!(app.current().visible(3).last().unwrap().text, "fresh");
    }

    #[test]
    fn messages_seen_only_after_scrollback_do_not_advance_the_read_marker() {
        let mut app = App::new("#a".into(), "me".into());
        app.on_message(&msg(
            "@time=2026-07-30T12:00:00.000Z :alice!u@h PRIVMSG #a :one",
        ));
        app.on_message(&msg(
            "@time=2026-07-30T12:00:01.000Z :alice!u@h PRIVMSG #a :two",
        ));
        assert_eq!(
            app.take_read_marker_command().as_deref(),
            Some("MARKREAD #a timestamp=2026-07-30T12:00:01.000Z")
        );

        app.scroll_up(1);
        app.on_message(&msg(
            "@time=2026-07-30T12:00:02.000Z :alice!u@h PRIVMSG #a :unseen",
        ));
        assert!(app.current().scrolled_back());
        assert_eq!(app.current().unread(), 1);
        assert!(app.take_read_marker_command().is_none());

        app.jump_latest();
        assert!(!app.current().scrolled_back());
        assert_eq!(app.current().unread(), 0);
        assert_eq!(
            app.take_read_marker_command().as_deref(),
            Some("MARKREAD #a timestamp=2026-07-30T12:00:02.000Z")
        );
        app.jump_latest();
        assert!(app.take_read_marker_command().is_none());
    }

    #[test]
    fn read_markers_coalesce_and_unread_clears_only_when_reached() {
        let mut app = App::new("#a".into(), "me".into());
        app.on_message(&msg(
            "@time=2026-07-30T12:00:00.000Z :alice!u@h PRIVMSG #a :one",
        ));
        app.on_message(&msg(
            "@time=2026-07-30T12:00:01.000Z :alice!u@h PRIVMSG #a :two",
        ));
        assert_eq!(
            app.take_read_marker_command().as_deref(),
            Some("MARKREAD #a timestamp=2026-07-30T12:00:01.000Z")
        );
        assert!(app.take_read_marker_command().is_none());

        app.on_message(&msg(
            "@time=2026-07-30T12:00:02.000Z :alice!u@h PRIVMSG #b :unread",
        ));
        let b = app.buffer_index("#b").unwrap();
        assert_eq!(app.buffers[b].unread(), 1);
        app.on_message(&msg(
            ":irc.example MARKREAD #b timestamp=2026-07-30T12:00:01.000Z",
        ));
        assert_eq!(app.buffers[b].unread(), 1, "an older marker is not read");
        app.on_message(&msg(
            ":irc.example MARKREAD #b timestamp=2026-07-30T12:00:02.000Z",
        ));
        assert_eq!(app.buffers[b].unread(), 0);

        app.on_message(&msg(
            "@time=2026-07-30T12:00:03.000Z :alice!u@h PRIVMSG #c :focus me",
        ));
        app.next_buffer();
        assert!(app.take_read_marker_command().is_none());
        app.next_buffer();
        assert_eq!(
            app.take_read_marker_command().as_deref(),
            Some("MARKREAD #c timestamp=2026-07-30T12:00:03.000Z")
        );
    }

    #[test]
    fn invalid_server_time_is_reported_once_and_never_replayed() {
        let mut app = App::new("#a".into(), "me".into());
        app.on_message(&msg("@time=bad :alice!u@h PRIVMSG #a :one"));
        app.on_message(&msg("@time=also-bad :alice!u@h PRIVMSG #a :two"));
        assert!(app.take_read_marker_command().is_none());
        assert_eq!(
            app.current()
                .log
                .iter()
                .filter(|line| line.text.as_str().contains("invalid time tag"))
                .count(),
            1
        );
    }

    #[test]
    fn live_history_overlap_is_deduplicated_by_msgid() {
        let mut app = App::new("#a".into(), "me".into());
        let line = "@msgid=same;time=2026-07-30T12:00:00.000Z :alice!u@h PRIVMSG #a :once";
        app.on_message(&msg(line));
        app.on_message(&msg(&format!("@batch=history;{}", &line[1..])));
        assert_eq!(
            app.current()
                .log
                .iter()
                .filter(|entry| entry.text.as_str() == "once")
                .count(),
            1
        );
    }

    /// A line this client does not model is still something the server said:
    /// shown beside the conversation it names, else in the server buffer.
    #[test]
    fn unmodelled_replies_and_commands_are_shown_not_dropped() {
        let mut app = App::new("#home".into(), "me".into());
        app.on_message(&msg(":srv 001 me :Welcome to the network"));
        app.on_message(&msg(":srv 311 me alice ~a host.example * :Alice Liddell"));
        let server = app.buffer_index(SERVER_BUFFER).expect("a server buffer");
        assert_eq!(app.buffers[server].kind, BufferKind::Server);
        assert_eq!(
            last_line(&app, SERVER_BUFFER),
            "alice ~a host.example * Alice Liddell"
        );
        assert!(
            app.buffers[server]
                .log
                .iter()
                .any(|line| line.text.as_str() == "Welcome to the network")
        );
        // A reply about an open conversation is shown beside it.
        app.on_message(&msg(":alice!u@h PRIVMSG me :hi"));
        app.on_message(&msg(":srv 301 me alice :gone fishing"));
        assert_eq!(last_line(&app, "alice"), "alice gone fishing");

        app.on_message(&msg(":bob!u@h INVITE me #secret"));
        assert_eq!(
            last_line(&app, "#home"),
            "bob invited you to #secret — /join #secret to accept"
        );
        app.on_message(&msg(":op!u@h TOPIC #home :new topic"));
        assert_eq!(last_line(&app, "#home"), "op set the topic: new topic");
        app.on_message(&msg(":op!u@h MODE #home +o me"));
        assert_eq!(last_line(&app, "#home"), "op sets mode +o me on #home");
        app.on_message(&msg(":srv NOTICE * :*** Looking up your hostname"));
        assert_eq!(
            last_line(&app, SERVER_BUFFER),
            "srv: *** Looking up your hostname"
        );
        app.on_message(&msg(":alice!u@h AWAY :lunch"));
        assert_eq!(last_line(&app, SERVER_BUFFER), "alice AWAY lunch");
        // Keepalive traffic is not.
        let before = app.buffers[server].log.len();
        app.on_message(&msg("PING :x"));
        app.on_message(&msg(":srv PONG srv :x"));
        assert_eq!(app.buffers[server].log.len(), before);

        // The server buffer is not a conversation to type into.
        app.input = "/win *server*".into();
        app.on_enter();
        assert_eq!(app.current().kind, BufferKind::Server);
        app.input = "hello".into();
        assert_eq!(app.on_enter(), Action::None);
        assert_eq!(app.input, "hello");
    }

    #[test]
    fn actions_and_formatting_render_as_meant() {
        let mut app = App::new("#home".into(), "me".into());
        app.on_message(&msg(":alice!u@h PRIVMSG #home :\x01ACTION waves\x01"));
        let line = app.current().log.last().expect("a line").clone();
        assert_eq!(line.from, "* alice");
        assert_eq!(line.text, "waves");
        app.on_message(&msg(
            ":alice!u@h PRIVMSG #home :\x02bold\x02 and \x0304,01red\x03 \x1ditalic\x1d",
        ));
        assert_eq!(last_line(&app, "#home"), "bold and red italic");
        app.on_message(&msg(":alice!u@h PRIVMSG me :\x01VERSION\x01"));
        assert_eq!(last_line(&app, "alice"), "[CTCP VERSION]");
    }

    /// Unread history that did not all load leaves a gap between the last
    /// loaded line and the live stream. A live line must not move the read
    /// marker over it — that would mark the unloaded lines read everywhere.
    #[test]
    fn the_read_marker_never_passes_the_last_contiguously_loaded_line() {
        let mut app = App::new("#a".into(), "me".into());
        app.on_message(&msg(":srv MARKREAD #a timestamp=2026-07-30T12:00:00.000Z"));
        app.on_message(&msg(
            "@batch=h;time=2026-07-30T12:00:01.000Z :alice!u@h PRIVMSG #a :oldest unread",
        ));
        app.on_message(&msg(
            "@batch=h;time=2026-07-30T12:00:02.000Z :alice!u@h PRIVMSG #a :last loaded",
        ));
        app.hold_read_marker("#a");
        assert!(
            app.current()
                .log
                .last()
                .is_some_and(|line| line.text.as_str().contains("more unread lines"))
        );
        assert_eq!(
            app.take_read_marker_command().as_deref(),
            Some("MARKREAD #a timestamp=2026-07-30T12:00:02.000Z")
        );
        app.on_message(&msg(":srv MARKREAD #a timestamp=2026-07-30T12:00:02.000Z"));
        app.on_message(&msg(
            "@time=2026-07-30T13:00:00.000Z :alice!u@h PRIVMSG #a :live, after the gap",
        ));
        assert_eq!(app.take_read_marker_command(), None);

        // A later session that loads every unread line closes the gap.
        app.release_read_marker("#a");
        assert_eq!(
            app.take_read_marker_command().as_deref(),
            None,
            "releasing queues nothing by itself"
        );
        app.on_message(&msg(
            "@time=2026-07-30T13:00:01.000Z :alice!u@h PRIVMSG #a :caught up",
        ));
        assert_eq!(
            app.take_read_marker_command().as_deref(),
            Some("MARKREAD #a timestamp=2026-07-30T13:00:01.000Z")
        );

        // With no time known at all, the marker does not move.
        let mut app = App::new("#b".into(), "me".into());
        app.hold_read_marker("#b");
        app.on_message(&msg(
            "@time=2026-07-30T13:00:00.000Z :alice!u@h PRIVMSG #b :live",
        ));
        assert_eq!(app.take_read_marker_command(), None);
    }

    #[test]
    fn a_multi_line_paste_is_refused_and_a_single_line_is_inserted() {
        let mut app = App::new("#c".into(), "me".into());
        app.on_paste("a\rb");
        assert_eq!(app.input(), "");
        assert!(
            app.current()
                .log
                .last()
                .is_some_and(|line| line.text.as_str().contains("paste of 2 lines"))
        );
        app.on_char('x');
        app.on_paste(" pasted");
        assert_eq!(app.input(), "x pasted");
        assert_eq!(app.input_cursor(), app.input().len());
    }
}
