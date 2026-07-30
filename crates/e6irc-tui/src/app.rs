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
    /// Neutralize control bytes in the (untrusted) sender and text.
    fn new(from: &str, text: &str) -> Self {
        Self {
            from: TerminalSafe::from_untrusted(from),
            text: TerminalSafe::from_untrusted(text),
        }
    }
}

/// One conversation: a channel or a query (PM) with its own scrollback.
#[derive(Debug, Clone)]
pub struct Buffer {
    pub name: String,
    pub log: Vec<LogLine>,
    seen_msgids: std::collections::HashSet<String>,
    msgid_order: std::collections::VecDeque<String>,
    latest_time: Option<String>,
    read_marker: Option<String>,
    unread: usize,
    /// Scrollback offset in lines from the bottom (0 = following live).
    scroll: usize,
}

impl Buffer {
    fn new(name: String) -> Self {
        Self {
            name,
            log: Vec::new(),
            seen_msgids: std::collections::HashSet::new(),
            msgid_order: std::collections::VecDeque::new(),
            latest_time: None,
            read_marker: None,
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

    pub fn unread(&self) -> usize {
        self.unread
    }

    /// The window of lines to render for a pane `height` rows tall.
    pub fn visible(&self, height: usize) -> &[LogLine] {
        let end = self.log.len().saturating_sub(self.scroll);
        let start = end.saturating_sub(height);
        &self.log[start..end]
    }
}

/// Lines of scrollback kept per buffer. Older lines are dropped.
const SCROLLBACK_LINES: usize = 5_000;

/// Buffers a client will open. Names arrive from the server, so this bounds
/// what a remote party can make the client allocate.
const MAX_BUFFERS: usize = 256;

pub struct App {
    pub nick: String,
    pub buffers: Vec<Buffer>,
    pub current: usize,
    pub input: String,
    pub should_quit: bool,
    connected: bool,
    pending_read_marker: Option<String>,
    invalid_time_reported: bool,
    /// The buffer cap has been reported to the user; say it once, not per line.
    buffer_limit_reported: bool,
}

/// A command the UI wants the network layer to perform.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    Send(String),
    Quit,
    None,
}

impl App {
    pub fn new(channel: String, nick: String) -> Self {
        Self {
            nick,
            buffers: vec![Buffer::new(channel)],
            current: 0,
            input: String::new(),
            should_quit: false,
            connected: true,
            pending_read_marker: None,
            invalid_time_reported: false,
            buffer_limit_reported: false,
        }
    }

    /// Update whether sends can reach the server. The network task reconnects
    /// independently; the model refuses input while it is down so a line is
    /// never rendered as sent and queued for surprise delivery later.
    pub fn set_connected(&mut self, connected: bool) {
        self.connected = connected;
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
        self.buffers.push(Buffer::new(name));
        Some(self.buffers.len() - 1)
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
        self.current_mut().scroll_down(n);
    }

    /// Fold an incoming server message into the right buffer.
    pub fn on_message(&mut self, msg: &OwnedMessage) {
        let sender = msg
            .source
            .as_deref()
            .and_then(|s| s.split('!').next())
            .unwrap_or("?")
            .to_string();
        match msg.command.as_str() {
            "PRIVMSG" | "NOTICE" => {
                let Some(target) = msg.params.first().cloned() else {
                    return;
                };
                let text = msg.params.get(1).cloned().unwrap_or_default();
                // A channel message lands in that channel's buffer; a PM to
                // us opens/uses a query buffer named after the sender.
                let buffer = if e6irc_proto::casemap::CaseMapping::Rfc1459.eq(&target, &self.nick) {
                    sender.clone()
                } else {
                    target
                };
                let Some(idx) = self.open_buffer(buffer) else {
                    self.note_buffer_limit();
                    return;
                };
                if !self.buffers[idx].accept_msgid(msg.tag("msgid")) {
                    return;
                }
                self.buffers[idx].push(LogLine::new(&sender, &text));
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
                if idx == self.current {
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
                // A quit affects the channels we share and any open query with
                // the quitter. This client tracks no per-channel membership, so
                // channel buffers are the closest honest scope — but a query
                // buffer with an *unrelated* user must not report it: that
                // would attribute an event to a conversation it never touched.
                for b in &mut self.buffers {
                    if b.name.starts_with('#') || b.name.starts_with('&') || b.name == sender {
                        b.push(LogLine::new("*", &format!("{sender} quit")));
                    }
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
            _ => {}
        }
    }

    fn focus_current(&mut self) {
        self.buffers[self.current].unread = 0;
        self.queue_current_marker();
    }

    fn queue_current_marker(&mut self) {
        let buffer = &mut self.buffers[self.current];
        let Some(latest) = buffer.latest_time.clone() else {
            return;
        };
        if buffer.read_marker.as_deref() == Some(latest.as_str()) {
            return;
        }
        self.pending_read_marker = Some(format!("MARKREAD {} timestamp={latest}", buffer.name));
    }

    /// Take the latest coalesced marker update. Multiple messages between UI
    /// polls become one durable MARKREAD write.
    pub fn take_read_marker_command(&mut self) -> Option<String> {
        self.pending_read_marker.take()
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
        self.input.push(c);
    }

    pub fn on_backspace(&mut self) {
        self.input.pop();
    }

    /// Handle Enter: produce an Action and clear the input.
    /// `/quit` exits; `/join #c` opens+joins a channel; `/win N` (or a
    /// buffer name) switches; anything else is sent to the current buffer.
    pub fn on_enter(&mut self) -> Action {
        let line = std::mem::take(&mut self.input);
        if line.is_empty() {
            return Action::None;
        }
        if line == "/quit" {
            self.should_quit = true;
            return Action::Quit;
        }
        if let Some(chan) = line.strip_prefix("/join ").map(str::trim) {
            if !chan.is_empty() {
                if !self.connected {
                    self.status("not connected — JOIN not sent");
                    return Action::None;
                }
                // The user's own /join is refused the same way as a
                // server-driven one, but it is worth saying so: silently not
                // switching would look like the command did nothing.
                let Some(idx) = self.open_buffer(chan.to_string()) else {
                    self.note_buffer_limit();
                    return Action::None;
                };
                self.current = idx;
                self.focus_current();
                return Action::Send(format!("JOIN {chan}"));
            }
            return Action::None;
        }
        if let Some(rest) = line.strip_prefix("/win ").map(str::trim) {
            let target = rest
                .parse::<usize>()
                .ok()
                .and_then(|number| number.checked_sub(1))
                .filter(|index| *index < self.buffers.len())
                .or_else(|| self.buffer_index(rest));
            if let Some(index) = target {
                self.current = index;
                self.focus_current();
            } else {
                self.status(format!("no buffer named or numbered {rest}"));
            }
            return Action::None;
        }
        if !self.connected {
            self.status("not connected — message not sent");
            return Action::None;
        }
        let target = self.current().name.clone();
        let from = self.nick.clone();
        self.current_mut().push(LogLine::new(&from, &line));
        Action::Send(format!("PRIVMSG {target} :{line}"))
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
        assert_eq!(app.on_enter(), Action::Send("PRIVMSG #c :ho".into()));
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

        for character in "/join #lost".chars() {
            app.on_char(character);
        }
        assert_eq!(app.on_enter(), Action::None);
        assert_eq!(app.buffers.len(), 1);
        assert_eq!(app.current().log[1].text, "not connected — JOIN not sent");
    }

    #[test]
    fn slash_join_opens_and_focuses_a_channel() {
        let mut app = App::new("#c".into(), "me".into());
        for ch in "/join #rust".chars() {
            app.on_char(ch);
        }
        assert_eq!(app.on_enter(), Action::Send("JOIN #rust".into()));
        assert_eq!(app.current().name, "#rust");
        assert_eq!(app.buffers.len(), 2);
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
}
