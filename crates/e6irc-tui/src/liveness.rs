//! Whether the server is still there.
//!
//! A half-open connection — the server's host gone, a NAT mapping expired, a
//! link that drops packets without a reset — reads as nothing forever. The
//! client sat CONNECTED on one for as long as it was left open, with every
//! message typed into it accepted and lost. The steady-state read is bounded
//! instead: after one window of silence the client asks (`PING`), and after a
//! second it declares the server gone and lets the reconnect path run.
//!
//! The deadline lives outside the read loop's turns on purpose: the loop is a
//! `select!` whose every turn abandons the read it was waiting on, so a timeout
//! started by the read would be restarted by each outbound line, and a silent
//! server would look alive for as long as the user kept typing.

use std::time::Duration;

/// How long the server may say nothing before the client asks whether it is
/// there. A live server PINGs an idle client well inside this, so a quiet
/// connection never trips it; a half-open one is caught within two windows.
pub const LIVENESS_WINDOW: Duration = Duration::from_secs(180);

/// The token the client's own keepalive `PING` carries, so its `PONG` can be
/// told from conversation and kept out of the log.
pub const KEEPALIVE_TOKEN: &str = "e6irc-tui";

/// What a full window of silence means.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Silence {
    /// The first silent window: ask the server to speak.
    Probe,
    /// A second silent window, with the probe unanswered: the server is gone.
    Dead,
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
}
