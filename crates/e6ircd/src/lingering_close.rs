//! Closing an HTTP connection without destroying the answer on it.
//!
//! A server that refuses a request before reading all of it — a body over the
//! limit, a deadline — answers and closes while the client is still sending.
//! Closing a socket that holds unread input makes the kernel send a reset
//! instead of an orderly close, and a reset lets the client's stack discard
//! the answer it has not read yet (macOS and Windows do): the client sees
//! "connection reset" in place of the `413` it was sent. Like nginx's
//! lingering close, [`LingeringClose`] shuts its write half first, then reads
//! and discards what the client is still sending until it closes too — within
//! a bound of time and bytes, so a client that never stops costs no more.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// How long a closing connection keeps reading what its client still sends.
pub(crate) const LINGER_TIME: Duration = Duration::from_secs(2);

/// How much a closing connection reads and discards before it gives up.
pub(crate) const LINGER_BYTES: usize = 8 * 1024 * 1024;

/// A stream whose shutdown lingers: see the module documentation.
pub(crate) struct LingeringClose<S> {
    inner: S,
    state: Linger,
}

enum Linger {
    Open,
    /// The write half is shut; draining input until EOF or the bound.
    Draining {
        deadline: Pin<Box<tokio::time::Sleep>>,
        discarded: usize,
    },
    Done,
}

impl<S> LingeringClose<S> {
    pub(crate) fn new(inner: S) -> Self {
        Self {
            inner,
            state: Linger::Open,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for LingeringClose<S> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<S: AsyncRead + AsyncWrite + Unpin> AsyncWrite for LingeringClose<S> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            match &mut this.state {
                Linger::Open => {
                    std::task::ready!(Pin::new(&mut this.inner).poll_shutdown(cx))?;
                    this.state = Linger::Draining {
                        deadline: Box::pin(tokio::time::sleep(LINGER_TIME)),
                        discarded: 0,
                    };
                }
                Linger::Draining {
                    deadline,
                    discarded,
                } => {
                    if deadline.as_mut().poll(cx).is_ready() || *discarded >= LINGER_BYTES {
                        this.state = Linger::Done;
                        continue;
                    }
                    let mut scratch = [0u8; 8192];
                    let mut buf = ReadBuf::new(&mut scratch);
                    match Pin::new(&mut this.inner).poll_read(cx, &mut buf) {
                        Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                            this.state = Linger::Done;
                        }
                        Poll::Ready(Ok(())) => *discarded += buf.filled().len(),
                        // The client reset or the socket failed: nothing is
                        // left to protect, and the write half is already shut.
                        Poll::Ready(Err(_)) => this.state = Linger::Done,
                        Poll::Pending => return Poll::Pending,
                    }
                }
                Linger::Done => return Poll::Ready(Ok(())),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A client still sending when the server closes: the server's shutdown
    /// reads what it sends to the end, and the client still reads the whole
    /// answer and an orderly end of stream.
    #[tokio::test]
    async fn shutdown_drains_what_the_client_is_still_sending() {
        let (near, far) = tokio::io::duplex(1024);
        let mut server = LingeringClose::new(near);
        let (mut far_read, mut far_write) = tokio::io::split(far);
        let sender = tokio::spawn(async move {
            far_write
                .write_all(&vec![b'x'; 64 * 1024])
                .await
                .expect("send");
            far_write.shutdown().await.expect("close");
        });
        server
            .write_all(b"HTTP/1.1 413\r\n\r\n")
            .await
            .expect("answer");
        server.shutdown().await.expect("lingering shutdown");
        sender
            .await
            .expect("the client finished sending, never refused");
        let mut answer = Vec::new();
        far_read.read_to_end(&mut answer).await.expect("read");
        assert_eq!(answer, b"HTTP/1.1 413\r\n\r\n");
    }

    /// A client that never stops sending costs the bound, not forever.
    #[tokio::test(start_paused = true)]
    async fn a_client_that_never_stops_is_dropped_at_the_bound() {
        let (near, far) = tokio::io::duplex(1024);
        let mut server = LingeringClose::new(near);
        let (_far_read, mut far_write) = tokio::io::split(far);
        tokio::spawn(async move {
            while far_write.write_all(&[b'x'; 512]).await.is_ok() {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        });
        let started = tokio::time::Instant::now();
        server.shutdown().await.expect("lingering shutdown");
        assert!(started.elapsed() >= LINGER_TIME);
        assert!(started.elapsed() < LINGER_TIME + Duration::from_secs(1));
    }
}
