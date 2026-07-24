//! Byte-stream → line framing.
//!
//! IRC lines end in CRLF; lenient implementations also accept bare LF
//! (Solanum does), so we do too. A line longer than the limit is
//! reported as an error carrying the truncated prefix — the caller must
//! answer `ERR_INPUTTOOLONG`/`FAIL`, never silently truncate — and the
//! remainder of that over-long line is discarded up to its terminator.

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
    /// A line exceeded the limit; the overflowing content is dropped
    /// (this event fires once per over-long line, at detection time).
    TooLong,
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
                self.buf.clear();
                self.discarding = true;
                out.push(LineEvent::TooLong);
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
        assert_eq!(got, vec![LineEvent::TooLong, line("PING x")]);
    }

    #[test]
    fn overlong_detection_spans_chunks() {
        let mut lb = LineBuffer::new(8);
        // 6 bytes, then 6 more: crosses the limit mid-second-chunk.
        let got = feed_all(&mut lb, &[b"AAAAAA", b"BBBBBB", b"CC\r\nPING y\r\n"]);
        assert_eq!(got, vec![LineEvent::TooLong, line("PING y")]);
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
