//! The stop control (DESIGN §19.3, D16): `e6ircd stop --handover|--final`
//! asks a running server to stop, the same way on every operating system —
//! Windows has no SIGTERM to send, and a signal cannot say which stop it
//! means.
//!
//! Each serving process listens on its own local endpoint, named by its
//! process identifier: on Unix a socket in a directory only its user can
//! enter (`e6ircd-<user id>` under `$XDG_RUNTIME_DIR`, or the temporary
//! directory), on Windows a named pipe that refuses remote clients. A stop
//! command sends one line — `stop handover` or `stop final` — and the server
//! answers `stopping <mode>` or `refused: <why>`; an accepted stop keeps the
//! connection until the stop is over, and says `stopped` last, so the command
//! returns when the server has stopped and says whether it stopped cleanly.

use std::io;
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};

use crate::net::StopMode;

/// How long a connection to the control has to say what it asks.
const ASK_WAIT: Duration = Duration::from_secs(5);

/// The longest line a stop command sends.
const MAX_ASK: u64 = 64;

/// A connection to the control, whatever the platform's kind.
trait Duplex: AsyncRead + AsyncWrite + Send + Unpin {}
impl<S: AsyncRead + AsyncWrite + Send + Unpin> Duplex for S {}

impl StopMode {
    fn word(self) -> &'static str {
        match self {
            Self::Handover => "handover",
            Self::Final => "final",
        }
    }

    fn from_word(word: &str) -> Option<Self> {
        match word {
            "handover" => Some(Self::Handover),
            "final" => Some(Self::Final),
            _ => None,
        }
    }
}

/// A stop command's request, not yet answered.
pub struct StopAsk {
    pub mode: StopMode,
    connection: Box<dyn Duplex>,
}

impl StopAsk {
    /// Refuse the stop, saying why; the server runs on.
    pub async fn refuse(mut self, why: &str) {
        drop(
            self.connection
                .write_all(format!("refused: {why}\n").as_bytes())
                .await,
        );
        drop(self.connection.shutdown().await);
    }

    /// Accept the stop: the command hears `stopping`, and waits for the rest.
    pub async fn accept(mut self) -> Stopping {
        drop(
            self.connection
                .write_all(format!("stopping {}\n", self.mode.word()).as_bytes())
                .await,
        );
        Stopping(self.connection)
    }
}

/// An accepted stop's connection, held until the stop is over.
pub struct Stopping(Box<dyn Duplex>);

impl Stopping {
    /// Tell the command how the stop ended, and let it go.
    pub async fn stopped(mut self, cleanly: bool) {
        let last: &[u8] = if cleanly {
            b"stopped\n"
        } else {
            b"stopped with errors: see the server's log\n"
        };
        drop(self.0.write_all(last).await);
        drop(self.0.shutdown().await);
    }
}

/// This process's control endpoint.
pub struct Control {
    listener: platform::Listener,
}

impl Control {
    /// Listen for stop commands.
    pub fn open() -> io::Result<Self> {
        Ok(Self {
            listener: platform::Listener::bind(std::process::id())?,
        })
    }

    /// Where a stop command reaches this process.
    pub fn location(&self) -> String {
        self.listener.location()
    }

    /// The next stop command's request. A connection that says nothing, or
    /// something else, within [`ASK_WAIT`] is told so and dropped.
    pub async fn asked(&mut self) -> StopAsk {
        loop {
            let connection = match self.listener.accept().await {
                Ok(connection) => connection,
                Err(error) => {
                    eprintln!("e6ircd: the stop control could not take a connection: {error}");
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    continue;
                }
            };
            match tokio::time::timeout(ASK_WAIT, read_ask(connection)).await {
                Ok(Ok(ask)) => return ask,
                Ok(Err(error)) => {
                    eprintln!("e6ircd: the stop control was sent what it does not read: {error}");
                }
                Err(_) => eprintln!(
                    "e6ircd: a stop command said nothing within {}s",
                    ASK_WAIT.as_secs()
                ),
            }
        }
    }
}

async fn read_ask(mut connection: Box<dyn Duplex>) -> io::Result<StopAsk> {
    let mut line = String::new();
    BufReader::new(tokio::io::AsyncReadExt::take(&mut connection, MAX_ASK))
        .read_line(&mut line)
        .await?;
    let mode = line
        .trim_end()
        .strip_prefix("stop ")
        .and_then(StopMode::from_word);
    match mode {
        Some(mode) => Ok(StopAsk { mode, connection }),
        None => {
            drop(connection.write_all(b"refused: not a stop request\n").await);
            Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "not a stop request",
            ))
        }
    }
}

/// Ask the server with process identifier `pid` — or, without one, the only
/// server of this user running here — to stop with `mode`, and wait until it
/// has. Each line the server says is given to `heard`. `Ok` when it stopped
/// cleanly.
pub async fn ask(
    pid: Option<u32>,
    mode: StopMode,
    mut heard: impl FnMut(&str),
) -> Result<(), String> {
    let pid = match pid {
        Some(pid) => pid,
        None => {
            let running = platform::running()?;
            match running.as_slice() {
                [only] => *only,
                [] => return Err("no e6ircd server of this user runs here".into()),
                several => {
                    return Err(format!(
                        "several e6ircd servers run here (processes {}); name one with --pid",
                        several
                            .iter()
                            .map(u32::to_string)
                            .collect::<Vec<_>>()
                            .join(", ")
                    ));
                }
            }
        }
    };
    let mut connection = platform::connect(pid)
        .await
        .map_err(|error| format!("cannot reach process {pid}'s stop control: {error}"))?;
    connection
        .write_all(format!("stop {}\n", mode.word()).as_bytes())
        .await
        .map_err(|error| format!("cannot ask process {pid} to stop: {error}"))?;
    let mut lines = BufReader::new(connection).lines();
    let mut accepted = false;
    let mut last = String::new();
    while let Some(line) = lines
        .next_line()
        .await
        .map_err(|error| format!("process {pid}'s answer: {error}"))?
    {
        heard(&line);
        if let Some(why) = line.strip_prefix("refused: ") {
            return Err(format!("process {pid} refused to stop: {why}"));
        }
        accepted |= line.starts_with("stopping ");
        last = line;
    }
    match (accepted, last.as_str()) {
        (true, "stopped") => Ok(()),
        (true, _) => Err(format!(
            "process {pid} stopped without saying it stopped cleanly ({last:?})"
        )),
        (false, _) => Err(format!(
            "process {pid} closed the stop control without answering"
        )),
    }
}

#[cfg(unix)]
mod platform {
    use std::io;
    use std::os::unix::fs::{DirBuilderExt, MetadataExt, PermissionsExt};
    use std::path::PathBuf;

    use super::Duplex;

    /// The directory holding this user's control sockets.
    fn directory() -> io::Result<PathBuf> {
        let runtime = crate::environment_config::optional(
            &crate::environment_config::process_environment,
            "XDG_RUNTIME_DIR",
        )
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error.to_string()))?;
        // The base directory specification: a relative path is ignored, as
        // an unset one is.
        let base = runtime
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .unwrap_or_else(std::env::temp_dir);
        // SAFETY: getuid takes no arguments, touches no memory and cannot
        // fail.
        let uid = unsafe { libc::getuid() };
        Ok(base.join(format!("e6ircd-{uid}")))
    }

    /// The directory, made if missing: this user's own and nobody else's,
    /// or it is not used.
    fn private_directory() -> io::Result<PathBuf> {
        let directory = directory()?;
        match std::fs::DirBuilder::new().mode(0o700).create(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
        let metadata = std::fs::symlink_metadata(&directory)?;
        // SAFETY: as in `directory`.
        let uid = unsafe { libc::getuid() };
        if !metadata.is_dir() || metadata.uid() != uid || metadata.permissions().mode() & 0o077 != 0
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!(
                    "{} is not a directory private to this user",
                    directory.display()
                ),
            ));
        }
        Ok(directory)
    }

    pub(super) struct Listener {
        listener: tokio::net::UnixListener,
        path: PathBuf,
    }

    impl Listener {
        pub(super) fn bind(pid: u32) -> io::Result<Self> {
            let path = private_directory()?.join(format!("{pid}.sock"));
            // A socket of this identifier is one a process gone before left.
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            let listener = tokio::net::UnixListener::bind(&path)?;
            Ok(Self { listener, path })
        }

        pub(super) fn location(&self) -> String {
            self.path.display().to_string()
        }

        pub(super) async fn accept(&mut self) -> io::Result<Box<dyn Duplex>> {
            let (stream, _) = self.listener.accept().await?;
            Ok(Box::new(stream))
        }
    }

    impl Drop for Listener {
        fn drop(&mut self) {
            drop(std::fs::remove_file(&self.path));
        }
    }

    /// The processes with a control socket here.
    pub(super) fn running() -> Result<Vec<u32>, String> {
        let directory =
            directory().map_err(|error| format!("the stop control directory: {error}"))?;
        let entries = match std::fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(format!("cannot read {}: {error}", directory.display())),
        };
        let mut running: Vec<u32> = entries
            .filter_map(Result::ok)
            .filter_map(|entry| {
                let name = entry.file_name();
                let pid = name.to_str()?.strip_suffix(".sock")?.parse().ok()?;
                // A socket nobody listens on is a process gone.
                std::os::unix::net::UnixStream::connect(entry.path())
                    .ok()
                    .map(|_| pid)
            })
            .collect();
        running.sort_unstable();
        Ok(running)
    }

    pub(super) async fn connect(pid: u32) -> io::Result<Box<dyn Duplex>> {
        let stream =
            tokio::net::UnixStream::connect(directory()?.join(format!("{pid}.sock"))).await?;
        Ok(Box::new(stream))
    }
}

#[cfg(windows)]
mod platform {
    use std::io;

    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions};

    use super::Duplex;

    const PREFIX: &str = "e6ircd-control-";

    fn name(pid: u32) -> String {
        format!(r"\\.\pipe\{PREFIX}{pid}")
    }

    pub(super) struct Listener {
        name: String,
        next: NamedPipeServer,
    }

    impl Listener {
        pub(super) fn bind(pid: u32) -> io::Result<Self> {
            let name = name(pid);
            let next = ServerOptions::new()
                .first_pipe_instance(true)
                .reject_remote_clients(true)
                .create(&name)?;
            Ok(Self { name, next })
        }

        pub(super) fn location(&self) -> String {
            self.name.clone()
        }

        pub(super) async fn accept(&mut self) -> io::Result<Box<dyn Duplex>> {
            self.next.connect().await?;
            let fresh = ServerOptions::new()
                .reject_remote_clients(true)
                .create(&self.name)?;
            let connected = std::mem::replace(&mut self.next, fresh);
            Ok(Box::new(connected))
        }
    }

    /// The processes with a control pipe.
    pub(super) fn running() -> Result<Vec<u32>, String> {
        let entries = std::fs::read_dir(r"\\.\pipe\")
            .map_err(|error| format!("cannot list the named pipes: {error}"))?;
        let mut running: Vec<u32> = entries
            .filter_map(Result::ok)
            .filter_map(|entry| {
                entry
                    .file_name()
                    .to_str()?
                    .strip_prefix(PREFIX)?
                    .parse()
                    .ok()
            })
            .collect();
        running.sort_unstable();
        Ok(running)
    }

    pub(super) async fn connect(pid: u32) -> io::Result<Box<dyn Duplex>> {
        let name = name(pid);
        // A pipe busy with another command frees within moments.
        let mut attempts = 0;
        loop {
            match ClientOptions::new().open(&name) {
                Ok(client) => return Ok(Box::new(client)),
                Err(error) if error.raw_os_error() == Some(ERROR_PIPE_BUSY) && attempts < 50 => {
                    attempts += 1;
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
                Err(error) => return Err(error),
            }
        }
    }

    /// `ERROR_PIPE_BUSY` (winerror.h): every instance of the pipe is taken.
    const ERROR_PIPE_BUSY: i32 = 231;
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    /// A stop command reaches the process by its identifier, is answered, and
    /// hears the stop end; one asking something else is refused and the
    /// control keeps listening.
    #[tokio::test]
    async fn a_stop_is_asked_answered_and_seen_through() {
        let mut control = Control::open().expect("the control");
        let pid = std::process::id();
        let garbage = tokio::spawn(async move {
            let mut connection = platform::connect(pid).await.expect("connect");
            connection.write_all(b"reboot\n").await.expect("write");
            let mut answer = String::new();
            BufReader::new(connection)
                .read_line(&mut answer)
                .await
                .expect("read");
            answer
        });
        let command = tokio::spawn(async move {
            // After the garbage has been refused.
            tokio::time::sleep(Duration::from_millis(200)).await;
            let mut heard = Vec::new();
            let result = ask(Some(pid), StopMode::Final, |line| {
                heard.push(line.to_owned())
            })
            .await;
            (result, heard)
        });
        let request = tokio::time::timeout(Duration::from_secs(60), control.asked())
            .await
            .expect("a stop request");
        assert_eq!(request.mode, StopMode::Final);
        request.accept().await.stopped(true).await;
        let (result, heard) = command.await.expect("the command");
        assert_eq!(result, Ok(()));
        assert_eq!(heard, ["stopping final", "stopped"]);
        assert_eq!(
            garbage.await.expect("the garbage"),
            "refused: not a stop request\n"
        );

        // A refusal is the command's failure, with the server's reason. (One
        // test: the process has one control.)
        let command = tokio::spawn(async move { ask(Some(pid), StopMode::Handover, |_| {}).await });
        let request = tokio::time::timeout(Duration::from_secs(60), control.asked())
            .await
            .expect("a stop request");
        assert_eq!(request.mode, StopMode::Handover);
        request.refuse("nothing to hand over").await;
        let result = command.await.expect("the command");
        assert_eq!(
            result,
            Err(format!(
                "process {pid} refused to stop: nothing to hand over"
            ))
        );
    }
}
