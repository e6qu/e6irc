//! Writes to a peer that may stop reading.
//!
//! A peer that keeps its connection open but advertises a zero receive window
//! parks a bare write forever. Whatever task owns that write then never sees
//! anything else — its session closed by the core, its network removed, a
//! shutdown — and holds its socket, its per-IP slot and whatever else it owns
//! for as long as the peer likes. Every write to a peer therefore goes through
//! one of the two bounds here: [`DeadlineWriter`] for byte streams, and
//! [`within_send_deadline`] for framed sinks.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite};

/// How long one write to a peer may wait for the peer to take it.
pub(crate) const PEER_WRITE_DEADLINE: Duration = Duration::from_secs(30);

/// Why an outbound frame was not delivered. Either way the connection is over.
#[derive(Debug)]
pub(crate) enum SendFailure {
    Transport,
    Stalled,
}

/// Run one framed send, giving up on a peer that has not taken it by
/// `deadline`.
pub(crate) async fn within_send_deadline<T, E>(
    deadline: Duration,
    send: impl Future<Output = Result<T, E>>,
) -> Result<T, SendFailure> {
    match tokio::time::timeout(deadline, send).await {
        Ok(Ok(value)) => Ok(value),
        Ok(Err(_)) => Err(SendFailure::Transport),
        Err(_) => Err(SendFailure::Stalled),
    }
}

/// The error a [`DeadlineWriter`] reports for a peer that stopped reading,
/// recognisable with [`is_stalled`].
#[derive(Debug)]
struct WriteStalled(Duration);

impl std::fmt::Display for WriteStalled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "the peer took no output for {}s; it has stopped reading",
            self.0.as_secs_f32()
        )
    }
}

impl std::error::Error for WriteStalled {}

/// Whether `error` is a [`DeadlineWriter`] giving up on a peer that stopped
/// reading, as opposed to the transport failing.
pub(crate) fn is_stalled(error: &io::Error) -> bool {
    error
        .get_ref()
        .is_some_and(|inner| inner.is::<WriteStalled>())
}

/// A byte-stream writer whose every write, flush and shutdown fails with
/// [`io::ErrorKind::TimedOut`] once it has made no progress for its deadline.
///
/// The deadline runs from the first poll that could not make progress to the
/// next one that does, so a peer that reads slowly but steadily is never cut
/// off, however long a whole burst takes.
pub(crate) struct DeadlineWriter<W> {
    inner: W,
    deadline: Duration,
    stalled_since: Option<Pin<Box<tokio::time::Sleep>>>,
}

impl<W> DeadlineWriter<W> {
    pub(crate) fn new(inner: W, deadline: Duration) -> Self {
        Self {
            inner,
            deadline,
            stalled_since: None,
        }
    }

    pub(crate) fn into_inner(self) -> W {
        self.inner
    }

    fn bound<T>(&mut self, cx: &mut Context<'_>, poll: Poll<io::Result<T>>) -> Poll<io::Result<T>> {
        if poll.is_ready() {
            self.stalled_since = None;
            return poll;
        }
        let deadline = self.deadline;
        let timer = self
            .stalled_since
            .get_or_insert_with(|| Box::pin(tokio::time::sleep(deadline)));
        match timer.as_mut().poll(cx) {
            Poll::Ready(()) => {
                self.stalled_since = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    WriteStalled(deadline),
                )))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Reads pass straight through: only a peer's silence toward what it is sent
/// is bounded here, so a whole duplex stream can be wrapped once.
impl<S: AsyncRead + Unpin> AsyncRead for DeadlineWriter<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<W: AsyncWrite + Unpin> AsyncWrite for DeadlineWriter<W> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.bound(cx, poll)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        this.bound(cx, poll)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_flush(cx);
        this.bound(cx, poll)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let poll = Pin::new(&mut this.inner).poll_shutdown(cx);
        this.bound(cx, poll)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn a_peer_that_never_takes_the_frame_ends_the_send() {
        let deadline = Duration::from_millis(20);
        let stalled =
            within_send_deadline(deadline, std::future::pending::<Result<(), ()>>()).await;
        assert!(matches!(stalled, Err(SendFailure::Stalled)));
        let delivered = within_send_deadline(deadline, async { Ok::<(), ()>(()) }).await;
        assert!(delivered.is_ok());
        let failed = within_send_deadline(deadline, async { Err::<(), ()>(()) }).await;
        assert!(matches!(failed, Err(SendFailure::Transport)));
    }

    /// A peer whose window is shut: the write is refused as stalled once the
    /// deadline passes, rather than parked for as long as the peer likes.
    #[tokio::test(start_paused = true)]
    async fn a_peer_that_stops_reading_fails_the_write_at_the_deadline() {
        let (near, _far) = tokio::io::duplex(16);
        let mut writer = DeadlineWriter::new(near, Duration::from_secs(30));
        let error = writer
            .write_all(&[b'x'; 64])
            .await
            .expect_err("a write nobody reads must not complete");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(is_stalled(&error));
    }

    /// Progress resets the deadline: a peer that reads slowly but steadily is
    /// never cut off, even when the whole write takes far longer than the bound.
    #[tokio::test(start_paused = true)]
    async fn a_slow_but_steady_reader_is_never_cut_off() {
        let (near, mut far) = tokio::io::duplex(8);
        let reader = tokio::spawn(async move {
            use tokio::io::AsyncReadExt;
            let mut taken = Vec::new();
            let mut byte = [0u8; 8];
            loop {
                tokio::time::sleep(Duration::from_secs(20)).await;
                match far.read(&mut byte).await.expect("read") {
                    0 => return taken,
                    n => taken.extend_from_slice(&byte[..n]),
                }
            }
        });
        let mut writer = DeadlineWriter::new(near, Duration::from_secs(30));
        writer
            .write_all(&[b'y'; 64])
            .await
            .expect("each chunk is taken within the deadline");
        writer.shutdown().await.expect("shutdown");
        drop(writer);
        assert_eq!(reader.await.expect("reader").len(), 64);
    }

    #[test]
    fn a_transport_error_is_not_a_stall() {
        assert!(!is_stalled(&io::Error::new(
            io::ErrorKind::TimedOut,
            "some other timeout"
        )));
    }
}
