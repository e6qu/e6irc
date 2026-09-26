//! WHO replies too long to queue at once.
//!
//! A `WHO *` answers with a row per visible user and a WHO of a large channel
//! with a row per member: more than a client's send queue holds, which would
//! kill the client that asked ("SendQ exceeded"). Such a reply is paced like
//! LIST's (`SAFELIST`): its lines go out only while the client's send queue is
//! under half full (in bytes, the unit the queue is bounded in), and the rest
//! follow as it drains. A connection's paced WHO
//! replies go out whole and in the order they were asked; other traffic keeps
//! flowing beside them.

use std::collections::VecDeque;

use bytes::Bytes;

/// A WHO's reply, formatted for its requester: its rows, then its closing
/// `RPL_ENDOFWHO`. Kept apart so a reply too long to queue at once can be
/// paced out, or refused and still closed.
#[derive(Debug)]
pub struct WhoReply<Line> {
    pub(crate) rows: Vec<Line>,
    pub(crate) end: Line,
}

/// One WHO reply being paced out: its rows, then its `RPL_ENDOFWHO`.
pub(crate) struct PacedReply {
    /// The labeled-response batch the reply goes out in, and whether its
    /// opening line is sent yet (it is when the reply reaches the front).
    pub batch: Option<PacedBatch>,
    pub lines: VecDeque<Bytes>,
}

pub(crate) struct PacedBatch {
    pub label: String,
    pub reference: String,
    pub opened: bool,
}

/// A connection's paced WHO replies, oldest first.
#[derive(Default)]
pub(crate) struct PacedReplies {
    pub replies: VecDeque<PacedReply>,
    /// Bytes still to go across `replies`, for the admission bound.
    pub bytes: usize,
}

impl PacedReplies {
    /// Whether a reply of `bytes` bytes may queue behind these. The first is
    /// always taken — it is bounded by the users the server has — and later
    /// ones while everything queued stays within one send queue
    /// (`sendq_bytes`): a client pipelining WHOs holds at most that much here,
    /// as it could in its queue.
    pub(crate) fn admits(&self, bytes: usize, sendq_bytes: usize) -> bool {
        self.replies.is_empty() || self.bytes + bytes <= sendq_bytes
    }

    pub(crate) fn push(&mut self, reply: PacedReply) {
        self.bytes += reply.lines.iter().map(Bytes::len).sum::<usize>();
        self.replies.push_back(reply);
    }

    /// The next line of the oldest reply, no longer counted as to go.
    pub(crate) fn take_line(&mut self) -> Option<Bytes> {
        let line = self.replies.front_mut()?.lines.pop_front()?;
        self.bytes -= line.len();
        Some(line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reply of `lines` three-byte lines.
    fn reply(lines: usize) -> PacedReply {
        PacedReply {
            batch: None,
            lines: (0..lines).map(|_| Bytes::from_static(b"x\r\n")).collect(),
        }
    }

    #[test]
    fn the_first_reply_is_always_taken_and_later_ones_within_a_send_queue() {
        let mut paced = PacedReplies::default();
        assert!(paced.admits(15_000, 768));
        paced.push(reply(5_000));
        assert!(!paced.admits(1, 768), "already past the bound");
        let mut paced = PacedReplies::default();
        paced.push(reply(200));
        assert!(paced.admits(168, 768));
        assert!(!paced.admits(169, 768));
    }

    /// What is still to go is counted in bytes, and a line taken is no longer.
    #[test]
    fn taking_a_line_releases_its_bytes() {
        let mut paced = PacedReplies::default();
        paced.push(reply(2));
        assert_eq!(paced.bytes, 6);
        assert_eq!(paced.take_line().as_deref(), Some(&b"x\r\n"[..]));
        assert_eq!(paced.bytes, 3);
    }
}
