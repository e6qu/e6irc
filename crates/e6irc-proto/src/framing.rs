//! Byte-stream → line framing.
//!
//! IRC lines end in CRLF; lenient implementations also accept bare LF
//! (Solanum does), so we do too. A line longer than the limit is
//! reported as [`LineEvent::TooLong`], carrying the `label` its retained
//! prefix names (when that prefix holds a complete, well-formed tag section)
//! so the caller can answer `ERR_INPUTTOOLONG` under the label the client is
//! waiting on — never silently truncate — and the rest of that over-long line
//! is discarded up to its terminator.

/// Accumulates raw socket bytes and yields complete lines.
#[derive(Debug)]
pub struct LineBuffer {
    buf: Vec<u8>,
    limit: usize,
    /// Set while discarding the tail of an over-long line.
    discarding: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LineEvent {
    /// A complete line, terminator stripped, non-empty. An embedded NUL is
    /// **not** stripped here — it is passed through for `Message::parse` to
    /// reject, so the framing layer never silently alters line content.
    Line(Vec<u8>),
    /// A line exceeded the limit; its content is dropped (this event fires
    /// once per over-long line, at detection time). `label` is the unescaped
    /// value of its `label` tag, when the retained prefix holds the whole tag
    /// section (see [`LineEvent::too_long`]).
    TooLong { label: Option<String> },
}

impl LineEvent {
    /// The event for an over-long line of which `prefix` was received: its
    /// label, read from the tag section exactly as for a line refused after
    /// framing (the last occurrence wins). None when the tag section is
    /// malformed, or does not end within the client tag budget
    /// ([`MAX_CLIENT_TAGS_LEN`](crate::message::MAX_CLIENT_TAGS_LEN)) — so the
    /// label a reply echoes is bounded by that budget, however long the
    /// prefix (a WebSocket message is one whole line).
    pub fn too_long(prefix: &[u8]) -> Self {
        let window = &prefix[..prefix.len().min(crate::message::MAX_CLIENT_TAGS_LEN)];
        Self::TooLong {
            label: crate::message::tag_section_value(window, "label"),
        }
    }
}

impl LineBuffer {
    /// `limit` is the maximum line length *excluding* the CRLF.
    pub fn new(limit: usize) -> Self {
        assert!(limit > 0, "line limit must be > 0");
        Self {
            buf: Vec::with_capacity(limit.min(4096)),
            limit,
            discarding: false,
        }
    }

    /// Feed received bytes; push resulting events. Empty lines are
    /// swallowed (bare CRLF is legal no-op filler on the wire). Illegal
    /// bytes such as NUL are *not* filtered here: the line is yielded
    /// as-is and `Message::parse` is the single loud rejection point.
    pub fn feed(&mut self, data: &[u8], out: &mut Vec<LineEvent>) {
        for &b in data {
            if self.discarding {
                if b == b'\n' {
                    self.discarding = false;
                }
                continue;
            }
            if b == b'\n' {
                let mut line = std::mem::take(&mut self.buf);
                if line.last() == Some(&b'\r') {
                    line.pop();
                }
                if !line.is_empty() {
                    out.push(LineEvent::Line(line));
                }
                continue;
            }
            self.buf.push(b);
            // A single trailing CR is (probably) half a terminator and
            // doesn't count against the limit; if it wasn't, the line
            // will overflow on its next byte anyway.
            let effective = self.buf.len() - usize::from(self.buf.last() == Some(&b'\r'));
            if effective > self.limit {
                out.push(LineEvent::too_long(&self.buf));
                self.buf.clear();
                self.discarding = true;
            }
        }
    }

    /// Bytes currently buffered awaiting a terminator.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn feed_all(lb: &mut LineBuffer, chunks: &[&[u8]]) -> Vec<LineEvent> {
        let mut out = Vec::new();
        for c in chunks {
            lb.feed(c, &mut out);
        }
        out
    }

    fn line(s: &str) -> LineEvent {
        LineEvent::Line(s.as_bytes().to_vec())
    }

    #[test]
    fn splits_crlf_lines() {
        let mut lb = LineBuffer::new(512);
        let got = feed_all(&mut lb, &[b"NICK alice\r\nUSER a 0 * :A\r\n"]);
        assert_eq!(got, vec![line("NICK alice"), line("USER a 0 * :A")]);
        assert_eq!(lb.pending(), 0);
    }

    #[test]
    fn accepts_bare_lf() {
        let mut lb = LineBuffer::new(512);
        let got = feed_all(&mut lb, &[b"PING x\nPONG y\n"]);
        assert_eq!(got, vec![line("PING x"), line("PONG y")]);
    }

    #[test]
    fn reassembles_across_chunks() {
        let mut lb = LineBuffer::new(512);
        let got = feed_all(&mut lb, &[b"PRIV", b"MSG #c ", b":hel", b"lo\r", b"\n"]);
        assert_eq!(got, vec![line("PRIVMSG #c :hello")]);
    }

    #[test]
    fn swallows_empty_lines() {
        let mut lb = LineBuffer::new(512);
        let got = feed_all(&mut lb, &[b"\r\n\r\nPING x\r\n\n"]);
        assert_eq!(got, vec![line("PING x")]);
    }

    #[test]
    fn overlong_line_reports_once_and_discards_to_terminator() {
        let mut lb = LineBuffer::new(8);
        let got = feed_all(&mut lb, &[b"0123456789ABCDEF\r\nPING x\r\n"]);
        assert_eq!(
            got,
            vec![LineEvent::TooLong { label: None }, line("PING x")]
        );
    }

    #[test]
    fn overlong_detection_spans_chunks() {
        let mut lb = LineBuffer::new(8);
        // 6 bytes, then 6 more: crosses the limit mid-second-chunk.
        let got = feed_all(&mut lb, &[b"AAAAAA", b"BBBBBB", b"CC\r\nPING y\r\n"]);
        assert_eq!(
            got,
            vec![LineEvent::TooLong { label: None }, line("PING y")]
        );
    }

    /// The client is waiting on the over-long line's label, so the event
    /// carries it whenever the retained prefix holds the whole tag section —
    /// wherever the chunk boundaries fall.
    #[test]
    fn overlong_line_carries_the_label_its_tag_section_names() {
        let wire = b"@label=a\\sb;x=y PRIVMSG #c :0123456789012345678901234567890\r\nPING z\r\n";
        for chunk in [1, 7, wire.len()] {
            let mut lb = LineBuffer::new(32);
            let chunks: Vec<&[u8]> = wire.chunks(chunk).collect();
            assert_eq!(
                feed_all(&mut lb, &chunks),
                vec![
                    LineEvent::TooLong {
                        label: Some("a b".into())
                    },
                    line("PING z")
                ],
                "chunk {chunk}"
            );
        }
        // A tag section cut off by the limit, or malformed, names no label.
        for wire in [
            &b"@label=abc;padding=0123456789012345678901234567 PING\r\n"[..],
            b"@label=abc;;=x PRIVMSG #c :0123456789012345678901234567890\r\n",
        ] {
            let mut lb = LineBuffer::new(32);
            assert_eq!(
                feed_all(&mut lb, &[wire]),
                vec![LineEvent::TooLong { label: None }]
            );
        }
    }

    /// A reply echoes the recovered label, so it is recovered only from a tag
    /// section within the client tag budget — a WebSocket message hands over
    /// the whole over-long line, not a framer-bounded prefix.
    #[test]
    fn a_label_is_recovered_only_within_the_client_tag_budget() {
        let budget = crate::message::MAX_CLIENT_TAGS_LEN;
        // `@label=` + value + ` ` is exactly the budget: recovered.
        let fits = format!("@label={} PRIVMSG #c :x", "v".repeat(budget - 8));
        assert!(matches!(
            LineEvent::too_long(fits.as_bytes()),
            LineEvent::TooLong { label: Some(label) } if label.len() == budget - 8
        ));
        let over = format!("@label={} PRIVMSG #c :x", "v".repeat(budget - 7));
        assert_eq!(
            LineEvent::too_long(over.as_bytes()),
            LineEvent::TooLong { label: None }
        );
    }

    #[test]
    fn exactly_at_limit_is_fine() {
        let mut lb = LineBuffer::new(8);
        let got = feed_all(&mut lb, &[b"01234567\r\n"]);
        assert_eq!(got, vec![line("01234567")]);
    }

    #[test]
    fn nul_bytes_pass_through_for_parser_rejection() {
        // Framing yields the line; Message::parse is the single loud
        // rejection point for illegal bytes.
        let mut lb = LineBuffer::new(512);
        let got = feed_all(&mut lb, &[b"PI\0NG\r\n"]);
        assert_eq!(got, vec![LineEvent::Line(b"PI\0NG".to_vec())]);
    }

    #[test]
    fn crlf_split_across_chunks_is_not_two_lines() {
        let mut lb = LineBuffer::new(512);
        let got = feed_all(&mut lb, &[b"PING a\r", b"\nPING b\r\n"]);
        assert_eq!(got, vec![line("PING a"), line("PING b")]);
    }
    #[test]
    fn strips_only_the_terminator_cr_not_embedded_ones() {
        // The framer removes the single CR of the CRLF terminator; an *embedded*
        // CR is left in the line for `Message::parse` to reject as an illegal
        // byte. So a wire line `a\r\r\n` yields the two-byte content `a\r`,
        // not `a`. (Pinned because a fuzzer flagged a test that wrongly assumed
        // no line could end in CR.)
        let mut fr = LineBuffer::new(64);
        let mut out = Vec::new();
        fr.feed(b"a\r\r\n", &mut out);
        assert_eq!(out, vec![LineEvent::Line(b"a\r".to_vec())]);
    }
}
