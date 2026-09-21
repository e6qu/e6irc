//! Whether the server is still there.
//!
//! A half-open connection — the server's host gone, a NAT mapping expired, a
//! link that drops packets without a reset — reads as nothing forever. A client
//! that only waits sits "connected" on one for as long as it is left open: the
//! TUI with every message typed into it accepted and lost, `e6irc tail` never
//! exiting for its supervisor to notice. The steady-state read of every native
//! client is bounded instead: after one window of silence the client asks
//! (`PING`), and after a second it declares the server gone.
//!
//! The deadline lives outside the read loop's turns on purpose: a loop that
//! `select!`s the read against local input abandons the read on every turn, so
//! a timeout started by the read would be restarted by each outbound line, and
//! a silent server would look alive for as long as the user kept typing.

use std::io;
use std::time::Duration;

use crate::{Connection, OwnedMessage, RelayEvent};

/// How long the server may say nothing before the client asks whether it is
/// there. A live server PINGs an idle client well inside this, so a quiet
/// connection never trips it; a half-open one is caught within two windows.
pub const LIVENESS_WINDOW: Duration = Duration::from_secs(180);

/// The token the client's own keepalive `PING` carries, so its `PONG` can be
/// told from conversation and kept out of what the client shows.
pub const KEEPALIVE_TOKEN: &str = "e6irc-keepalive";

/// The reason a session ends when the probe went unanswered too.
pub const SERVER_STOPPED_RESPONDING: &str = "server stopped responding";

/// What a full window of silence means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Silence {
    /// The first silent window: ask the server to speak.
    Probe,
    /// A second silent window, with the probe unanswered: the server is gone.
    Dead,
}

/// What one bounded read produced, once keepalive traffic is dealt with.
#[derive(Debug)]
pub enum Heard {
    /// A line for the caller: neither a server `PING` (answered here) nor the
    /// answer to this client's own probe.
    Event(RelayEvent),
    /// Keepalive traffic, or a probe sent after a silent window: read again.
    Nothing,
    /// The server closed the connection.
    Closed,
}

/// The moment by which the server must next be heard from.
#[derive(Debug)]
pub struct Liveness {
    window: Duration,
    deadline: tokio::time::Instant,
    /// A probe was sent when the previous window passed in silence.
    probed: bool,
}

impl Liveness {
    pub fn new(window: Duration) -> Self {
        Self {
            window,
            deadline: tokio::time::Instant::now() + window,
            probed: false,
        }
    }

    /// The server was heard from: a full window starts now, and any probe is
    /// answered.
    pub fn heard(&mut self) {
        self.deadline = tokio::time::Instant::now() + self.window;
        self.probed = false;
    }

    /// `read`'s output, or `None` once the whole window has passed in silence.
    pub async fn bound<T>(&self, read: impl Future<Output = T>) -> Option<T> {
        tokio::time::timeout_at(self.deadline, read).await.ok()
    }

    /// The window passed in silence. The first time that is a [`Silence::Probe`]
    /// and a new window starts for the answer; a second time in a row is
    /// [`Silence::Dead`].
    pub fn silent(&mut self) -> Silence {
        if self.probed {
            Silence::Dead
        } else {
            self.probed = true;
            self.deadline = tokio::time::Instant::now() + self.window;
            Silence::Probe
        }
    }

    /// Settle one [`Liveness::bound`] read of
    /// [`Connection::next_line_relayable`]: answer a server `PING`, swallow
    /// the answer to this client's own probe, send the probe after a first
    /// silent window, and fail with [`SERVER_STOPPED_RESPONDING`] (as
    /// [`io::ErrorKind::TimedOut`]) after a second.
    ///
    /// Kept apart from the read so that a caller `select!`ing the read against
    /// local input only ever abandons the read — never a half-written `PONG`.
    pub async fn settle(
        &mut self,
        connection: &mut Connection,
        read: Option<io::Result<Option<RelayEvent>>>,
    ) -> io::Result<Heard> {
        let event = match read {
            None => {
                return match self.silent() {
                    Silence::Probe => {
                        connection
                            .send_line(&format!("PING :{KEEPALIVE_TOKEN}"))
                            .await
                            .map_err(|error| {
                                io::Error::new(
                                    error.kind(),
                                    format!("keepalive PING failed: {error}"),
                                )
                            })?;
                        Ok(Heard::Nothing)
                    }
                    Silence::Dead => Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        SERVER_STOPPED_RESPONDING,
                    )),
                };
            }
            Some(Err(error)) => return Err(error),
            Some(Ok(None)) => return Ok(Heard::Closed),
            Some(Ok(Some(event))) => event,
        };
        self.heard();
        if let RelayEvent::Line {
            message: Some(message),
            ..
        } = &event
        {
            if message.command == "PING" {
                let token = message.params.first().cloned().unwrap_or_default();
                connection
                    .send_line(&format!("PONG :{token}"))
                    .await
                    .map_err(|error| {
                        io::Error::new(error.kind(), format!("PING response failed: {error}"))
                    })?;
                return Ok(Heard::Nothing);
            }
            if is_keepalive_answer(message) {
                return Ok(Heard::Nothing);
            }
        }
        Ok(Heard::Event(event))
    }

    /// The next line for the caller, with keepalive handled: a read bounded by
    /// the window and settled by [`Liveness::settle`]. `Ok(None)` is the server
    /// closing the connection.
    pub async fn next(&mut self, connection: &mut Connection) -> io::Result<Option<RelayEvent>> {
        loop {
            let read = self.bound(connection.next_line_relayable()).await;
            match self.settle(connection, read).await? {
                Heard::Event(event) => return Ok(Some(event)),
                Heard::Nothing => {}
                Heard::Closed => return Ok(None),
            }
        }
    }
}

/// Whether `message` is the server's answer to this client's own probe:
/// bookkeeping that proved the server is there, not conversation.
fn is_keepalive_answer(message: &OwnedMessage) -> bool {
    message.command == "PONG" && message.params.last().map(String::as_str) == Some(KEEPALIVE_TOKEN)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(start_paused = true)]
    async fn two_silent_windows_in_a_row_are_a_dead_server() {
        let mut liveness = Liveness::new(Duration::from_secs(10));
        assert!(liveness.bound(std::future::pending::<()>()).await.is_none());
        assert_eq!(liveness.silent(), Silence::Probe);
        assert!(liveness.bound(std::future::pending::<()>()).await.is_none());
        assert_eq!(liveness.silent(), Silence::Dead);
    }

    #[tokio::test(start_paused = true)]
    async fn an_answer_to_the_probe_starts_the_count_over() {
        let mut liveness = Liveness::new(Duration::from_secs(10));
        assert!(liveness.bound(std::future::pending::<()>()).await.is_none());
        assert_eq!(liveness.silent(), Silence::Probe);
        liveness.heard();
        assert!(liveness.bound(std::future::pending::<()>()).await.is_none());
        assert_eq!(liveness.silent(), Silence::Probe);
    }

    #[tokio::test(start_paused = true)]
    async fn a_read_that_completes_inside_the_window_is_returned() {
        let liveness = Liveness::new(Duration::from_secs(10));
        assert_eq!(liveness.bound(async { 7 }).await, Some(7));
    }

    /// A server that registers the client and then says nothing, without
    /// closing: the client probes after one window and gives up after two,
    /// and a server `PING` on the way is answered, not handed to the caller.
    #[tokio::test]
    async fn a_silent_server_is_probed_then_declared_gone() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let (reader, mut writer) = socket.into_split();
            writer.write_all(b"PING :from-server\r\n").await.unwrap();
            let mut lines = tokio::io::BufReader::new(reader).lines();
            let mut seen = Vec::new();
            while let Ok(Some(line)) = lines.next_line().await {
                seen.push(line);
            }
            seen
        });
        let mut connection = Connection::connect(&address).await.unwrap();
        let window = Duration::from_millis(150);
        let mut liveness = Liveness::new(window);
        let started = std::time::Instant::now();
        let error = tokio::time::timeout(Duration::from_secs(5), liveness.next(&mut connection))
            .await
            .expect("a silent server ends the read")
            .expect_err("a silent server is not a line");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert_eq!(error.to_string(), SERVER_STOPPED_RESPONDING);
        assert!(started.elapsed() >= window * 2, "{:?}", started.elapsed());
        drop(connection);
        assert_eq!(
            server.await.unwrap(),
            ["PONG :from-server", &format!("PING :{KEEPALIVE_TOKEN}")]
        );
    }
}
