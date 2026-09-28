//! The zero-drop suite's first scenarios (DESIGN §19.11): real `e6ircd`
//! processes — a core in edge mode and `e6ircd edge` processes in front of it,
//! linked over mutual TLS with credentials `e6ircd edge-credentials` issued —
//! and clients over TCP, TLS and `/ws/irc`, and HTTP, through the edge.
//!
//! What a client may see is what this release promises: every line through
//! the edge exactly once and in order, and a core that goes — stopped,
//! killed, or cut off by a link reset — closing every session loudly with an
//! `ERROR`, never silently. A later release keeps the sessions instead; these
//! scenarios then change their expectation, not their shape.
//!
//! None needs a database, so the suite runs wherever the workspace's tests
//! run: Linux, macOS and Windows, on both architectures.

#[path = "support/deadline.rs"]
mod deadline;

use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use tokio::io::{
    AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader as AsyncBufReader,
};
use tokio_tungstenite::tungstenite::Message as Frame;

/// A running `e6ircd` process and every line it writes.
struct Process {
    name: &'static str,
    child: Child,
    lines: Arc<Mutex<Vec<String>>>,
}

impl Process {
    fn spawn(name: &'static str, args: &[&std::ffi::OsStr], dir: &Path) -> Self {
        Self::spawn_with(name, args, dir, &[])
    }

    /// [`Process::spawn`], with `environment` set for it (and nothing else of
    /// e6irc's own inherited).
    fn spawn_with(
        name: &'static str,
        args: &[&std::ffi::OsStr],
        dir: &Path,
        environment: &[(&str, &str)],
    ) -> Self {
        let mut command = Command::new(env!("CARGO_BIN_EXE_e6ircd"));
        for variable in e6ircd::db::LIBPQ_ENVIRONMENT {
            command.env_remove(variable);
        }
        command.env_remove("E6IRC_MONITORING_TOKEN");
        command.envs(environment.iter().copied());
        let mut child = command
            .args(args)
            .current_dir(dir)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("start e6ircd");
        let lines = Arc::new(Mutex::new(Vec::new()));
        for output in [
            Box::new(child.stdout.take().expect("stdout")) as Box<dyn std::io::Read + Send>,
            Box::new(child.stderr.take().expect("stderr")),
        ] {
            let lines = lines.clone();
            std::thread::spawn(move || {
                for line in BufReader::new(output).lines() {
                    let Ok(line) = line else { break };
                    lines.lock().expect("lines").push(line);
                }
            });
        }
        Self { name, child, lines }
    }

    fn said(&self) -> String {
        self.lines.lock().expect("lines").join("\n")
    }

    /// Wait until `count` lines contain `needle`; the last of them.
    async fn until(&mut self, needle: &str, count: usize) -> String {
        let deadline = Instant::now() + deadline::HANG;
        loop {
            let found: Vec<String> = self
                .lines
                .lock()
                .expect("lines")
                .iter()
                .filter(|line| line.contains(needle))
                .cloned()
                .collect();
            if found.len() >= count {
                return found[count - 1].clone();
            }
            let exited = self.child.try_wait().expect("poll the process");
            assert!(
                exited.is_none() && Instant::now() < deadline,
                "{} never said {needle:?} {count} times (exited: {exited:?}):\n{}",
                self.name,
                self.said()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    /// The addresses of every line saying `prefix` then an address, in order.
    async fn address(&mut self, prefix: &str) -> SocketAddr {
        let line = self.until(prefix, 1).await;
        line.split(prefix)
            .nth(1)
            .and_then(|rest| rest.split_whitespace().next())
            .and_then(|address| address.parse().ok())
            .unwrap_or_else(|| panic!("{} said no address after {prefix:?}: {line}", self.name))
    }

    /// Stop the process as a crash does.
    fn kill(&mut self) {
        self.child.kill().expect("kill");
        self.child.wait().expect("reap");
    }

    #[cfg(unix)]
    fn terminate(&self) {
        let sent = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .expect("run kill");
        assert!(sent.success(), "kill -TERM: {sent}");
    }

    #[cfg(unix)]
    async fn exited(&mut self) -> std::process::ExitStatus {
        let deadline = Instant::now() + deadline::HANG;
        loop {
            if let Some(status) = self.child.try_wait().expect("poll the process") {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "{} did not exit:\n{}",
                self.name,
                self.said()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            drop(self.child.kill());
            drop(self.child.wait());
        }
    }
}

/// A scratch directory holding one deployment's credentials and
/// configurations, removed when the test ends.
struct Deployment {
    dir: PathBuf,
}

impl Deployment {
    /// A deployment with its link credentials: `e6ircd edge-credentials`
    /// writes the authority and the core's certificate, and one per edge.
    fn new(test: &str, edges: &[&str]) -> Self {
        let dir =
            std::env::temp_dir().join(format!("e6irc-zero-drop-{test}-{}", std::process::id()));
        drop(std::fs::remove_dir_all(&dir));
        std::fs::create_dir_all(&dir).expect("scratch directory");
        let credentials = |args: &[&str]| {
            let output = Command::new(env!("CARGO_BIN_EXE_e6ircd"))
                .arg("edge-credentials")
                .args(args)
                .current_dir(&dir)
                .output()
                .expect("run e6ircd edge-credentials");
            assert!(
                output.status.success(),
                "e6ircd edge-credentials {args:?}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        };
        credentials(&["init", "--dir", "credentials"]);
        for edge in edges {
            credentials(&["issue", "--dir", "credentials", "--edge", edge]);
        }
        Self { dir }
    }

    fn path(&self, file: &str) -> PathBuf {
        self.dir.join(file)
    }

    fn write(&self, file: &str, text: &str) -> PathBuf {
        let path = self.path(file);
        std::fs::write(&path, text).expect("write a configuration");
        path
    }

    /// A self-signed certificate for `localhost`, for an edge's TLS listener;
    /// its DER form for a client to trust.
    fn tls_certificate(&self) -> rustls_pki_types::CertificateDer<'static> {
        let generated =
            rcgen::generate_simple_self_signed(vec!["localhost".into()]).expect("certificate");
        std::fs::write(self.path("irc.pem"), generated.cert.pem()).expect("certificate file");
        std::fs::write(
            self.path("irc-key.pem"),
            generated.signing_key.serialize_pem(),
        )
        .expect("key file");
        generated.cert.der().clone()
    }

    /// Start a core in edge mode, its link on `link` (port 0: any) and HTTP on
    /// any port, with `extra` added to its configuration.
    async fn core(&self, file: &str, link: &str, extra: &str) -> Core {
        let config = self.write(
            file,
            &format!(
                "server_name = \"irc.zero.test\"\n\
                 network_name = \"ZeroNet\"\n\
                 {extra}\n\
                 [edge_link]\n\
                 addr = \"{link}\"\n\
                 ca = 'credentials/ca.pem'\n\
                 cert = 'credentials/core.pem'\n\
                 key = 'credentials/core-key.pem'\n\
                 [http]\n\
                 addr = \"127.0.0.1:0\"\n"
            ),
        );
        let mut process = Process::spawn(
            "the core",
            &["--config".as_ref(), config.as_os_str()],
            &self.dir,
        );
        let link = process.address("edge mode: edges link at ").await;
        Core { process, link }
    }

    /// Start edge `name` linking to `core`, with `listeners` in its
    /// configuration.
    async fn edge(&self, name: &'static str, core: SocketAddr, listeners: &str) -> Process {
        let mut process = self.edge_process(name, core, listeners, &[]);
        process.until("accepting clients", 1).await;
        process
    }

    /// Spawn edge `name` without waiting for it, with `environment`.
    fn edge_process(
        &self,
        name: &'static str,
        core: SocketAddr,
        listeners: &str,
        environment: &[(&str, &str)],
    ) -> Process {
        let config = self.write(
            &format!("{name}.toml"),
            &format!(
                "[edge]\n\
                 name = \"{name}\"\n\
                 core = [\"{core}\"]\n\
                 ca = 'credentials/ca.pem'\n\
                 cert = 'credentials/edge-{name}.pem'\n\
                 key = 'credentials/edge-{name}-key.pem'\n\
                 {listeners}"
            ),
        );
        Process::spawn_with(
            name,
            &["edge".as_ref(), "--config".as_ref(), config.as_os_str()],
            &self.dir,
            environment,
        )
    }
}

impl Drop for Deployment {
    fn drop(&mut self) {
        drop(std::fs::remove_dir_all(&self.dir));
    }
}

struct Core {
    process: Process,
    link: SocketAddr,
}

/// An IRC client on any byte stream: it sends lines, and reads them one at a
/// time, each within the suite's bound.
struct Client {
    name: String,
    reader: AsyncBufReader<tokio::io::ReadHalf<Box<dyn Stream>>>,
    writer: tokio::io::WriteHalf<Box<dyn Stream>>,
}

trait Stream: AsyncRead + AsyncWrite + Send + Unpin {}
impl<S: AsyncRead + AsyncWrite + Send + Unpin> Stream for S {}

impl Client {
    fn over(name: &str, stream: Box<dyn Stream>) -> Self {
        let (reader, writer) = tokio::io::split(stream);
        Self {
            name: name.to_owned(),
            reader: AsyncBufReader::new(reader),
            writer,
        }
    }

    async fn tcp(name: &str, address: SocketAddr) -> Self {
        let stream = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect to the edge");
        Self::over(name, Box::new(stream))
    }

    async fn tls(
        name: &str,
        address: SocketAddr,
        trusted: rustls_pki_types::CertificateDer<'static>,
    ) -> Self {
        e6irc_edge::certificate::install_crypto_provider();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(trusted).expect("trust the edge's certificate");
        let connector = tokio_rustls::TlsConnector::from(Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        ));
        let tcp = tokio::net::TcpStream::connect(address)
            .await
            .expect("connect to the edge");
        let tls = connector
            .connect("localhost".try_into().expect("name"), tcp)
            .await
            .expect("TLS to the edge");
        Self::over(name, Box::new(tls))
    }

    async fn send(&mut self, line: &str) {
        self.writer
            .write_all(format!("{line}\r\n").as_bytes())
            .await
            .expect("send a line");
    }

    /// The next line; `None` at the end of the stream.
    async fn line(&mut self) -> Option<String> {
        let mut line = String::new();
        let read = tokio::time::timeout(deadline::HANG, self.reader.read_line(&mut line))
            .await
            .unwrap_or_else(|_| panic!("{} waited in vain for a line", self.name));
        match read {
            Ok(0) | Err(_) => None,
            Ok(_) => Some(line.trim_end_matches(['\r', '\n']).to_owned()),
        }
    }

    /// Read until a line contains `needle`; that line.
    async fn until(&mut self, needle: &str) -> String {
        loop {
            match self.line().await {
                Some(line) if line.contains(needle) => return line,
                Some(_) => {}
                None => panic!("{} reached the end before {needle:?}", self.name),
            }
        }
    }

    async fn register(&mut self) {
        let nick = self.name.clone();
        self.send(&format!("NICK {nick}")).await;
        self.send(&format!("USER {nick} 0 * :{nick}")).await;
        self.until(" 001 ").await;
    }

    async fn join(&mut self, channel: &str) {
        self.send(&format!("JOIN {channel}")).await;
        self.until(" 366 ").await;
    }

    /// Everything until the end of the stream; the last line is what the
    /// client was told as it was closed.
    async fn until_closed(&mut self) -> Vec<String> {
        let mut lines = Vec::new();
        while let Some(line) = self.line().await {
            lines.push(line);
        }
        lines
    }
}

/// An IRC client over `/ws/irc` on an edge's web port.
struct WebSocketClient {
    name: String,
    socket: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
}

impl WebSocketClient {
    async fn connect(name: &str, web: SocketAddr) -> Self {
        let (socket, _) = tokio_tungstenite::connect_async(format!("ws://{web}/ws/irc"))
            .await
            .expect("a WebSocket to the edge");
        Self {
            name: name.to_owned(),
            socket,
        }
    }

    async fn send(&mut self, line: &str) {
        self.socket
            .send(Frame::text(line.to_owned()))
            .await
            .expect("send a message");
    }

    /// The next line; `None` once the socket is closed.
    async fn line(&mut self) -> Option<String> {
        loop {
            let frame = tokio::time::timeout(deadline::HANG, self.socket.next())
                .await
                .unwrap_or_else(|_| panic!("{} waited in vain for a message", self.name));
            match frame {
                Some(Ok(Frame::Text(text))) => return Some(text.to_string()),
                Some(Ok(Frame::Binary(bytes))) => {
                    return Some(String::from_utf8_lossy(&bytes).into_owned());
                }
                Some(Ok(Frame::Close(_))) | Some(Err(_)) | None => return None,
                Some(Ok(_)) => {}
            }
        }
    }

    async fn until(&mut self, needle: &str) -> String {
        loop {
            match self.line().await {
                Some(line) if line.contains(needle) => return line,
                Some(_) => {}
                None => panic!("{} was closed before {needle:?}", self.name),
            }
        }
    }

    async fn register(&mut self) {
        let nick = self.name.clone();
        self.send(&format!("NICK {nick}")).await;
        self.send(&format!("USER {nick} 0 * :{nick}")).await;
        self.until(" 001 ").await;
    }

    async fn until_closed(&mut self) -> Vec<String> {
        let mut lines = Vec::new();
        while let Some(line) = self.line().await {
            lines.push(line);
        }
        lines
    }
}

/// One HTTP/1.1 request: the status, the headers' text and the body.
async fn http(address: SocketAddr, request: &str) -> (u16, String, String) {
    let mut stream = tokio::net::TcpStream::connect(address)
        .await
        .expect("connect for HTTP");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("send the request");
    let mut response = Vec::new();
    tokio::time::timeout(
        deadline::HANG,
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut response),
    )
    .await
    .expect("an answer")
    .expect("read the answer");
    let text = String::from_utf8_lossy(&response).into_owned();
    let status = text
        .get(9..12)
        .and_then(|status| status.parse().ok())
        .unwrap_or_else(|| panic!("not HTTP: {text:?}"));
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    (status, head.to_owned(), body.to_owned())
}

fn get(path: &str) -> String {
    format!("GET {path} HTTP/1.1\r\nHost: irc.zero.test\r\nConnection: close\r\n\r\n")
}

/// Listeners every scenario's edge has: plain IRC, TLS IRC and the web port.
fn listeners() -> &'static str {
    "[[listeners]]\n\
     addr = \"127.0.0.1:0\"\n\
     [[listeners]]\n\
     addr = \"127.0.0.1:0\"\n\
     tls = { cert_path = 'irc.pem', key_path = 'irc-key.pem' }\n\
     [http]\n\
     addr = \"127.0.0.1:0\"\n"
}

/// An edge's addresses: plain IRC, TLS IRC, the web port.
async fn addresses(edge: &mut Process) -> (SocketAddr, SocketAddr, SocketAddr) {
    let plain = edge.until("listening on ", 1).await;
    let tls = edge.until("listening on ", 2).await;
    let parse = |line: &str| -> SocketAddr {
        line.rsplit(' ')
            .next()
            .and_then(|address| address.parse().ok())
            .unwrap_or_else(|| panic!("no address in {line:?}"))
    };
    let web = edge.address("http listening on ").await;
    (parse(&plain), parse(&tls), web)
}

/// Clients on TCP, TLS and `/ws/irc` exchange a numbered stream of messages
/// through an edge in its own process, and each is delivered exactly once, in
/// order — past a shard queue of eight lines, so the edge runs on the core's
/// credits all the way. The web port forwards the application to the core and
/// answers its own `/healthz`, and the core's `/readyz` names the edge linked
/// and its link version.
#[tokio::test(flavor = "multi_thread")]
async fn clients_of_every_transport_are_served_through_an_edge_process() {
    let deployment = Deployment::new("transports", &["edge-a"]);
    let trusted = deployment.tls_certificate();
    let mut core = deployment
        .core("core.toml", "127.0.0.1:0", "core_queue = 8")
        .await;
    let mut edge = deployment.edge("edge-a", core.link, listeners()).await;
    let (plain, tls, web) = addresses(&mut edge).await;

    let mut alice = Client::tcp("alice", plain).await;
    let mut bob = Client::tls("bob", tls, trusted).await;
    let mut carol = WebSocketClient::connect("carol", web).await;
    alice.register().await;
    bob.register().await;
    carol.register().await;
    alice.join("#zero").await;
    bob.join("#zero").await;
    carol.send("JOIN #zero").await;
    carol.until(" 366 ").await;
    // Everyone has joined once alice sees carol's JOIN.
    alice.until("carol!carol@").await;

    const MESSAGES: usize = 300;
    for number in 1..=MESSAGES {
        alice
            .send(&format!("PRIVMSG #zero :message {number}"))
            .await;
    }
    for number in 1..=MESSAGES {
        let expected = format!("PRIVMSG #zero :message {number}");
        let over_tls = bob.until("PRIVMSG #zero").await;
        assert!(
            over_tls.ends_with(&expected),
            "bob: {over_tls} for {expected}"
        );
        let over_websocket = carol.until("PRIVMSG #zero").await;
        assert!(
            over_websocket.ends_with(&expected),
            "carol: {over_websocket} for {expected}"
        );
    }
    // Nothing more: the next thing either sees is the PONG to its own PING.
    bob.send("PING :after").await;
    assert!(bob.until("PONG").await.ends_with(":after"));
    carol.send("PING :after").await;
    assert!(carol.until("PONG").await.ends_with(":after"));

    // The edge shows its clients under their own address.
    alice.send("WHOIS bob").await;
    let whois = alice.until(" 311 ").await;
    assert!(whois.contains(" 127.0.0.1 "), "{whois}");
    // The TLS the edge terminated is named to the user itself, from the
    // facts its `Open` carried (link version 2), and not to anyone else.
    let secure = alice.until(" 671 ").await;
    assert!(
        secure.ends_with(":is using a secure connection"),
        "{secure}"
    );
    bob.send("WHOIS bob").await;
    let secure = bob.until(" 671 ").await;
    assert!(
        secure.contains(":is using a secure connection [TLSv1.3, TLS13_"),
        "{secure}"
    );

    let (status, _, body) = http(web, &get("/api/v1/server")).await;
    assert_eq!(status, 200, "{body}");
    assert!(body.contains("\"server_name\":\"irc.zero.test\""), "{body}");
    let (status, _, body) = http(web, &get("/healthz")).await;
    assert_eq!((status, body.as_str()), (200, "ok"));

    let core_web = core.process.address("http listening on ").await;
    let (status, _, body) = http(core_web, &get("/readyz")).await;
    assert_eq!(status, 200, "{body}");
    let readiness: serde_json::Value = serde_json::from_str(&body).expect("readiness JSON");
    assert_eq!(readiness["edges"]["link_version"], e6irc_link::LINK_VERSION);
    assert_eq!(readiness["edges"]["linked"][0]["name"], "edge-a");
    assert_eq!(readiness["edges"]["linked"][0]["upgrade_needed"], false);
}

/// A killed core: every client of every transport is told the server is
/// restarting and is closed, by the edge, which keeps its listeners. A
/// request that finds no core is answered `503` with `Retry-After` once its
/// wait is over. A new core on the same address serves new clients at once:
/// the edge links again by itself.
#[tokio::test(flavor = "multi_thread")]
async fn a_killed_core_closes_every_session_loudly_and_the_next_core_serves() {
    let deployment = Deployment::new("killed", &["edge-a"]);
    let trusted = deployment.tls_certificate();
    let mut core = deployment.core("core.toml", "127.0.0.1:0", "").await;
    let link = core.link;
    let mut edge = deployment.edge("edge-a", link, listeners()).await;
    let (plain, tls, web) = addresses(&mut edge).await;

    let mut alice = Client::tcp("alice", plain).await;
    let mut bob = Client::tls("bob", tls, trusted).await;
    let mut carol = WebSocketClient::connect("carol", web).await;
    alice.register().await;
    bob.register().await;
    carol.register().await;

    core.process.kill();
    for (name, closing) in [
        ("alice", alice.until_closed().await),
        ("bob", bob.until_closed().await),
        ("carol", carol.until_closed().await),
    ] {
        assert_eq!(
            closing.last().map(String::as_str),
            Some("ERROR :Closing Link: 127.0.0.1 (server restarting)"),
            "{name} was not told: {closing:?}"
        );
    }
    edge.until("sessions were closed as the server restarting", 1)
        .await;

    let (status, head, body) = http(web, &get("/api/v1/server")).await;
    assert_eq!(status, 503, "{body}");
    assert!(
        head.to_ascii_lowercase().contains("retry-after: "),
        "{head}"
    );

    let _next = deployment.core("next.toml", &link.to_string(), "").await;
    edge.until("linked to the core", 2).await;
    let mut dave = Client::tcp("dave", plain).await;
    dave.register().await;
    let (status, _, body) = http(web, &get("/api/v1/server")).await;
    assert_eq!(status, 200, "{body}");
}

/// A core that stops gracefully closes its sessions itself, each with its
/// own closing `ERROR`, which the edge delivers before closing: the edge has
/// nothing left to close as restarting.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_stopped_core_closes_every_session_with_its_own_error() {
    let deployment = Deployment::new("stopped", &["edge-a"]);
    let _trusted = deployment.tls_certificate();
    let mut core = deployment.core("core.toml", "127.0.0.1:0", "").await;
    let mut edge = deployment.edge("edge-a", core.link, listeners()).await;
    let (plain, _, web) = addresses(&mut edge).await;
    let mut alice = Client::tcp("alice", plain).await;
    let mut carol = WebSocketClient::connect("carol", web).await;
    alice.register().await;
    carol.register().await;

    core.process.terminate();
    assert!(
        core.process.exited().await.success(),
        "{}",
        core.process.said()
    );
    for (name, closing) in [
        ("alice", alice.until_closed().await),
        ("carol", carol.until_closed().await),
    ] {
        assert_eq!(
            closing.last().map(String::as_str),
            Some("ERROR :Closing Link: 127.0.0.1 (Server shutting down)"),
            "{name}: {closing:?}"
        );
    }
    edge.until("0 sessions were closed as the server restarting", 1)
        .await;
}

/// A relay between an edge and its core that forwards every link
/// connection until it is told to cut them all.
struct Relay {
    address: SocketAddr,
    cut: tokio::sync::watch::Sender<u64>,
}

impl Relay {
    async fn to(core: SocketAddr) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind the relay");
        let address = listener.local_addr().expect("relay address");
        let (cut, cuts) = tokio::sync::watch::channel(0u64);
        tokio::spawn(async move {
            loop {
                let Ok((mut inbound, _)) = listener.accept().await else {
                    return;
                };
                let mut cuts = cuts.clone();
                let seen = *cuts.borrow_and_update();
                tokio::spawn(async move {
                    let Ok(mut outbound) = tokio::net::TcpStream::connect(core).await else {
                        return;
                    };
                    tokio::select! {
                        _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound) => {}
                        _ = cuts.wait_for(|now| *now != seen) => {}
                    }
                });
            }
        });
        Self { address, cut }
    }

    fn cut(&self) {
        self.cut.send_modify(|cuts| *cuts += 1);
    }
}

/// A link reset — the link's connections cut while the core runs on — closes
/// the sessions it carried as loudly as a core that went, on both sides: the
/// clients are told the server is restarting, and the core ends their
/// sessions (their channel sees them quit). The edge links again at once.
#[tokio::test(flavor = "multi_thread")]
async fn a_link_reset_closes_its_sessions_loudly_on_both_sides() {
    let deployment = Deployment::new("reset", &["edge-a", "edge-b"]);
    let _trusted = deployment.tls_certificate();
    let core = deployment.core("core.toml", "127.0.0.1:0", "").await;
    let relay = Relay::to(core.link).await;
    let mut cut_off = deployment.edge("edge-a", relay.address, listeners()).await;
    let mut direct = deployment.edge("edge-b", core.link, listeners()).await;
    let (cut_plain, ..) = addresses(&mut cut_off).await;
    let (direct_plain, ..) = addresses(&mut direct).await;

    let mut alice = Client::tcp("alice", cut_plain).await;
    let mut bob = Client::tcp("bob", direct_plain).await;
    alice.register().await;
    bob.register().await;
    alice.join("#reset").await;
    bob.join("#reset").await;
    alice.until("bob!bob@").await;

    relay.cut();
    let closing = alice.until_closed().await;
    assert_eq!(
        closing.last().map(String::as_str),
        Some("ERROR :Closing Link: 127.0.0.1 (server restarting)"),
        "{closing:?}"
    );
    let quit = bob.until("QUIT").await;
    assert!(quit.starts_with(":alice!alice@"), "{quit}");
    assert!(quit.ends_with("Edge link lost"), "{quit}");
    cut_off.until("linked to the core", 2).await;
    let mut carol = Client::tcp("carol", cut_plain).await;
    carol.register().await;
}

/// The per-address connection limit is the core's across edges, with each
/// edge pre-filtering by it: two connections from one address through two
/// edges are one too many for a limit of one, and the core refuses the second
/// with an `ERROR` saying why.
#[tokio::test(flavor = "multi_thread")]
async fn the_per_address_limit_holds_across_edges() {
    let deployment = Deployment::new("limit", &["edge-a", "edge-b"]);
    let _trusted = deployment.tls_certificate();
    let core = deployment
        .core(
            "core.toml",
            "127.0.0.1:0",
            "[limits]\nmax_connections_per_ip = 1",
        )
        .await;
    let mut first = deployment.edge("edge-a", core.link, listeners()).await;
    let mut second = deployment.edge("edge-b", core.link, listeners()).await;
    let (first_plain, ..) = addresses(&mut first).await;
    let (second_plain, ..) = addresses(&mut second).await;

    let mut alice = Client::tcp("alice", first_plain).await;
    alice.register().await;
    // The same edge refuses a second one itself, before the core hears of it.
    let mut refused_here = Client::tcp("refused", first_plain).await;
    assert_eq!(refused_here.until_closed().await, Vec::<String>::new());
    // Another edge does not know of the first: the core refuses it.
    let mut refused_there = Client::tcp("bob", second_plain).await;
    let closing = refused_there.until_closed().await;
    assert_eq!(
        closing.last().map(String::as_str),
        Some("ERROR :Closing Link: 127.0.0.1 (Too many connections from your address)"),
        "{closing:?}"
    );
    // alice is untouched.
    alice.send("PING :still").await;
    assert!(alice.until("PONG").await.ends_with(":still"));
}

/// The PROXY protocol: a listener behind a load balancer that passes TCP
/// through takes each client's address from the header the balancer sends,
/// from a trusted proxy only; the core shows the client under it.
#[tokio::test(flavor = "multi_thread")]
async fn a_proxy_protocol_listener_shows_the_relayed_client() {
    let deployment = Deployment::new("proxy", &["edge-a"]);
    let core = deployment
        .core(
            "core.toml",
            "127.0.0.1:0",
            "[limits]\ntrusted_proxies = [\"127.0.0.1/32\"]",
        )
        .await;
    let mut edge = deployment
        .edge(
            "edge-a",
            core.link,
            "[[listeners]]\naddr = \"127.0.0.1:0\"\nproxy_protocol = true\n\
             [http]\naddr = \"127.0.0.1:0\"\nproxy_protocol = true\n",
        )
        .await;
    let plain = edge.address("listening on ").await;
    let web = edge.address("http listening on ").await;

    // A version 2 header: PROXY over TCP and IPv4, from 198.51.100.7:40000.
    let mut header = vec![
        0x0d, 0x0a, 0x0d, 0x0a, 0x00, 0x0d, 0x0a, 0x51, 0x55, 0x49, 0x54, 0x0a, 0x21, 0x11, 0x00,
        0x0c,
    ];
    header.extend_from_slice(&[198, 51, 100, 7, 127, 0, 0, 1]);
    header.extend_from_slice(&40000u16.to_be_bytes());
    header.extend_from_slice(&6667u16.to_be_bytes());

    let mut stream = tokio::net::TcpStream::connect(plain)
        .await
        .expect("connect");
    stream.write_all(&header).await.expect("PROXY header");
    let mut relayed = Client::over("relayed", Box::new(stream));
    relayed.register().await;
    relayed.send("WHOIS relayed").await;
    let whois = relayed.until(" 311 ").await;
    assert!(whois.contains(" 198.51.100.7 "), "{whois}");

    let mut stream = tokio::net::TcpStream::connect(web).await.expect("connect");
    stream.write_all(&header).await.expect("PROXY header");
    stream
        .write_all(get("/api/v1/server").as_bytes())
        .await
        .expect("request");
    let mut answer = Vec::new();
    tokio::time::timeout(
        deadline::HANG,
        tokio::io::AsyncReadExt::read_to_end(&mut stream, &mut answer),
    )
    .await
    .expect("an answer")
    .expect("read");
    assert!(
        String::from_utf8_lossy(&answer).starts_with("HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&answer)
    );

    // A connection without the header is refused: nothing is guessed.
    let mut unannounced = Client::tcp("unannounced", plain).await;
    unannounced.send("NICK unannounced").await;
    assert_eq!(unannounced.until_closed().await, Vec::<String>::new());
}

/// A client cannot forge what only the edge and the core say to each other:
/// a request naming its own upgrade identifier, client address or grant is
/// forwarded without them, so the core does not authorize an upgrade the
/// client never made and the answer carries no grant; and nothing of the
/// link's namespace reaches a client in any answer.
#[tokio::test(flavor = "multi_thread")]
async fn a_client_cannot_forge_the_link_s_headers() {
    let deployment = Deployment::new("forged", &["edge-a"]);
    let _trusted = deployment.tls_certificate();
    let core = deployment.core("core.toml", "127.0.0.1:0", "").await;
    let mut edge = deployment.edge("edge-a", core.link, listeners()).await;
    let (_, _, web) = addresses(&mut edge).await;

    let forged = |path: &str| {
        format!(
            "GET {path} HTTP/1.1\r\nHost: irc.zero.test\r\nConnection: close\r\n\
             e6irc-edge-upgrade: 4611686018427387905\r\n\
             e6irc-edge-client: 203.0.113.9\r\n\
             e6irc-edge-grant: irc\r\n\
             e6irc-edge-grant-address: 203.0.113.9\r\n\
             e6irc-edge-grant-transport: wss\r\n\r\n"
        )
    };
    // Unforged, the core would take an upgrade identifier as the edge asking
    // it to authorize `/ws/irc`, and answer 200 with a grant.
    let (status, head, body) = http(web, &forged("/ws/irc")).await;
    assert_ne!(
        status, 200,
        "a forged upgrade was authorized: {head}\n{body}"
    );
    assert!(
        !head.to_ascii_lowercase().contains("e6irc-edge-"),
        "a link header reached the client: {head}"
    );
    let (status, head, body) = http(web, &forged("/api/v1/server")).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        !head.to_ascii_lowercase().contains("e6irc-edge-"),
        "a link header reached the client: {head}"
    );
}

/// An edge serves its own metrics on `[metrics]`, in the core's format, to a
/// scraper holding the monitoring token, linked or not; one configured
/// without the token refuses to start rather than serve what no scraper can
/// read.
#[tokio::test(flavor = "multi_thread")]
async fn an_edge_serves_its_metrics_to_the_monitoring_token() {
    const TOKEN: &str = "zero-drop-monitoring-token-0123456789";
    let deployment = Deployment::new("metrics", &["edge-a", "edge-b"]);
    let _trusted = deployment.tls_certificate();
    let mut core = deployment.core("core.toml", "127.0.0.1:0", "").await;
    let metrics = "[metrics]\naddr = \"127.0.0.1:0\"\n";

    let mut refused = deployment.edge_process(
        "edge-b",
        core.link,
        &format!("{}{metrics}", listeners()),
        &[],
    );
    refused.until("E6IRC_MONITORING_TOKEN", 1).await;

    let mut edge = deployment.edge_process(
        "edge-a",
        core.link,
        &format!("{}{metrics}", listeners()),
        &[("E6IRC_MONITORING_TOKEN", TOKEN)],
    );
    edge.until("accepting clients", 1).await;
    let (plain, _, _) = addresses(&mut edge).await;
    let scrape_at = edge.address("metrics listening on ").await;
    let scrape = |token: Option<&str>| {
        let authorization = token
            .map(|token| format!("Authorization: Bearer {token}\r\n"))
            .unwrap_or_default();
        format!("GET /metrics HTTP/1.1\r\nHost: edge\r\nConnection: close\r\n{authorization}\r\n")
    };

    let (status, head, _) = http(scrape_at, &scrape(None)).await;
    assert_eq!(status, 401, "{head}");
    let (status, _, _) = http(
        scrape_at,
        &scrape(Some("not-the-token-0123456789abcdef0123")),
    )
    .await;
    assert_eq!(status, 401);

    let mut alice = Client::tcp("alice", plain).await;
    alice.register().await;
    let (status, head, body) = http(scrape_at, &scrape(Some(TOKEN))).await;
    assert_eq!(status, 200, "{body}");
    assert!(
        head.contains("text/plain; version=0.0.4"),
        "the core's exposition format: {head}"
    );
    for series in [
        "e6irc_edge_linked{edge=\"edge-a\"} 1",
        "e6irc_edge_links_total{edge=\"edge-a\"} 1",
        "e6irc_edge_connections{edge=\"edge-a\"} 1",
        "e6irc_edge_core_epoch{edge=\"edge-a\"} 0",
        "e6irc_connections_rejected_total{edge=\"edge-a\"} 0",
        "e6irc_errors_total{edge=\"edge-a\",kind=\"tls_handshake\"} 0",
        "# TYPE e6irc_edge_link_version gauge",
    ] {
        assert!(body.contains(series), "{series} missing from:\n{body}");
    }

    core.process.kill();
    drop(alice.until_closed().await);
    edge.until("sessions were closed as the server restarting", 1)
        .await;
    let (status, _, body) = http(scrape_at, &scrape(Some(TOKEN))).await;
    assert_eq!(status, 200, "a scrape is answered while no core is linked");
    assert!(
        body.contains("e6irc_edge_linked{edge=\"edge-a\"} 0"),
        "{body}"
    );
}
