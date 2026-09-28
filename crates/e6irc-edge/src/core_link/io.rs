//! Frames on a link connection: read one at a time, and written in batches by
//! the one task that owns the connection's writing half.

use std::io;
use std::time::Duration;

use bytes::BytesMut;
use e6irc_link::Frame;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// How long one write on a link may wait for its peer to read: a peer that
/// has taken nothing for this long has stopped reading, and the link is reset
/// (DESIGN §19.2, "Flow control").
pub const LINK_WRITE_DEADLINE: Duration = Duration::from_secs(30);

/// How long each side of a link connection waits for the other's first frame
/// (`Hello`, then `Welcome`) before giving up on it.
pub const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(10);

/// Reads frames from one link connection.
pub struct FrameReader<R> {
    inner: R,
    buffer: BytesMut,
}

fn broken(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, format!("core link: {error}"))
}

impl<R: AsyncRead + Unpin> FrameReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            buffer: BytesMut::with_capacity(16 * 1024),
        }
    }

    /// The next frame; `None` when the peer closed between frames. A frame
    /// that does not decode, or a close inside one, is an error: the link is
    /// broken.
    pub async fn next<F: Frame>(&mut self) -> io::Result<Option<F>> {
        loop {
            if let Some(frame) = e6irc_link::decode::<F>(&mut self.buffer).map_err(broken)? {
                return Ok(Some(frame));
            }
            if self.buffer.capacity() - self.buffer.len() < 4096 {
                self.buffer.reserve(16 * 1024);
            }
            if self.inner.read_buf(&mut self.buffer).await? == 0 {
                if self.buffer.is_empty() {
                    return Ok(None);
                }
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "core link: the peer closed inside a frame",
                ));
            }
        }
    }

    /// The first frame, within [`HANDSHAKE_DEADLINE`]; a close before it is an
    /// error.
    pub async fn first<F: Frame>(&mut self) -> io::Result<F> {
        match tokio::time::timeout(HANDSHAKE_DEADLINE, self.next::<F>()).await {
            Ok(Ok(Some(frame))) => Ok(frame),
            Ok(Ok(None)) => Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "core link: the peer closed before its first frame",
            )),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "core link: no first frame within the handshake deadline",
            )),
        }
    }

    /// The stream, once the frames on it are over (an HTTP link connection
    /// after its handshake): nothing may have been read past the last frame.
    pub fn into_inner(self) -> io::Result<R> {
        if !self.buffer.is_empty() {
            return Err(broken("bytes arrived past the handshake"));
        }
        Ok(self.inner)
    }
}

/// Write `frame` and flush, within [`LINK_WRITE_DEADLINE`].
pub async fn write_frame<W, F>(writer: &mut W, frame: &F) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    F: Frame,
{
    let bytes = e6irc_link::encoded(frame).map_err(broken)?;
    within_deadline(async {
        writer.write_all(&bytes).await?;
        writer.flush().await
    })
    .await
}

async fn within_deadline(write: impl Future<Output = io::Result<()>>) -> io::Result<()> {
    tokio::time::timeout(LINK_WRITE_DEADLINE, write)
        .await
        .unwrap_or_else(|_| {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "core link: the peer read nothing for the write deadline",
            ))
        })
}

/// Write every frame `frames` yields until it ends, each batch — everything
/// queued when the writer woke — in one write, each within
/// [`LINK_WRITE_DEADLINE`], and then close the writing side (TLS's
/// `close_notify`), so the peer reads the end as an end. A frame that cannot
/// be encoded is a bug in its sender, and breaks the link loudly.
pub async fn write_frames<W, F>(
    mut writer: W,
    frames: &mut tokio::sync::mpsc::Receiver<F>,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
    F: Frame,
{
    let mut batch = BytesMut::with_capacity(16 * 1024);
    while let Some(frame) = frames.recv().await {
        batch.clear();
        e6irc_link::encode(&frame, &mut batch).map_err(broken)?;
        while batch.len() < 256 * 1024 {
            let Ok(frame) = frames.try_recv() else { break };
            e6irc_link::encode(&frame, &mut batch).map_err(broken)?;
        }
        within_deadline(async {
            writer.write_all(&batch).await?;
            writer.flush().await
        })
        .await?;
    }
    within_deadline(writer.shutdown()).await
}

/// Keep a link's TCP connection probed while it is idle, so a peer whose host
/// went away without a word is noticed within about a minute rather than at
/// the next write.
pub fn keep_alive(stream: &tokio::net::TcpStream) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let keepalive = socket2::TcpKeepalive::new()
        .with_time(Duration::from_secs(30))
        .with_interval(Duration::from_secs(10));
    socket2::SockRef::from(stream).set_tcp_keepalive(&keepalive)
}
