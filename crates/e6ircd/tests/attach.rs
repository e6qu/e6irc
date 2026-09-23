//! Attach-layer e2e: a downstream client attaches to a BNC network
//! (driver connected to an e6ircd-as-upstream), receives buffered +
//! live traffic, and its sent lines reach the upstream.

#[path = "support/deadline.rs"]
mod deadline;

use e6ircd::bouncer::{IrcNetwork, NetworkConfig, NetworkHandle, attach};
use e6ircd::config::{Config, ListenerConfig};
use e6ircd::egress::InternalUpstreams;
use e6ircd::net;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

async fn upstream() -> std::net::SocketAddr {
    let config = Config {
        server_name: "irc.up.example".into(),
        network_name: "Up".into(),
        listeners: vec![ListenerConfig {
            addr: "127.0.0.1:0".parse().unwrap(),
            tls: None,
            websocket: false,
        }],
        ..Config::default()
    };
    net::start(config).await.expect("start").addrs[0]
}

/// Wait for the driver's sticky connected state without losing the one-shot
/// broadcast between `start` and `subscribe`. Subscribing first and then
/// checking the authoritative state closes both sides of that race.
async fn wait_connected(handle: &NetworkHandle) {
    let mut events = handle.subscribe();
    if handle.runtime_snapshot().lifecycle == e6ircd::bouncer::NetworkLifecycle::Connected {
        return;
    }
    tokio::time::timeout(deadline::HANG, async {
        loop {
            match events.recv().await {
                Ok(e6ircd::bouncer::DriverEvent::Status {
                    status: e6ircd::bouncer::DriverConnectionStatus::Connected,
                    ..
                }) => return,
                Ok(_) | Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    panic!("driver event stream closed before connecting");
                }
            }
        }
    })
    .await
    .expect("driver did not connect");
}

#[tokio::test(flavor = "multi_thread")]
async fn attached_client_gets_playback_and_live_and_can_send() {
    let addr = upstream().await;

    // driver joins #room on the upstream
    let handle = IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "bnc".parse().expect("test nickname"),
        autojoin: vec!["#room".parse().expect("test channel")],
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    });
    wait_connected(&handle).await;

    // a peer posts a message BEFORE the client attaches -> goes to buffer
    let mut peer = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .unwrap();
    peer.register(&e6irc_client::Identity {
        nick: "peer",
        username: "peer",
        realname: "peer",
        server_password: None,
    })
    .await
    .unwrap();
    peer.send_line("JOIN #room").await.unwrap();
    loop {
        if peer.next_message().await.unwrap().unwrap().command == "366" {
            break;
        }
    }
    peer.send_line("PRIVMSG #room :buffered before attach")
        .await
        .unwrap();

    // let the driver receive & buffer it (attach replays the buffer, so
    // we don't need to drain live events — a fresh subscription won't
    // see pre-attach messages anyway)
    tokio::time::sleep(std::time::Duration::from_millis(300)).await;

    // attach a downstream client over an in-memory duplex
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let handle = std::sync::Arc::new(handle);
    let attach_handle = handle.clone();
    let attach_task = tokio::spawn(async move {
        let _ = attach(
            server_side,
            &attach_handle,
            Default::default(),
            "attacher",
            "attacher",
            e6ircd::bouncer::ATTACH_LIVENESS_INTERVAL,
        )
        .await;
    });

    let (cr, mut cw) = tokio::io::split(client_side);
    let mut client = BufReader::new(cr);

    // playback: the buffered message arrives first
    let playback = tokio::time::timeout(deadline::HANG, async {
        loop {
            let mut line = String::new();
            client.read_line(&mut line).await.unwrap();
            if line.contains("buffered before attach") {
                return line;
            }
        }
    })
    .await
    .expect("playback timeout");
    assert!(playback.contains("PRIVMSG #room"), "{playback}");

    // live: a new peer message reaches the attached client
    peer.send_line("PRIVMSG #room :live after attach")
        .await
        .unwrap();
    let live = tokio::time::timeout(deadline::HANG, async {
        loop {
            let mut line = String::new();
            client.read_line(&mut line).await.unwrap();
            if line.contains("live after attach") {
                return line;
            }
        }
    })
    .await
    .expect("live timeout");
    assert!(live.contains("PRIVMSG #room"), "{live}");

    // client -> upstream: the attached client sends, the peer receives
    cw.write_all(b"PRIVMSG #room :from attached client\r\n")
        .await
        .unwrap();
    let echoed = tokio::time::timeout(deadline::HANG, async {
        loop {
            let m = peer.next_message().await.unwrap().unwrap();
            if m.command == "PRIVMSG"
                && m.params.get(1).map(String::as_str) == Some("from attached client")
            {
                return m;
            }
        }
    })
    .await
    .expect("upstream timeout");
    assert!(
        echoed.source.as_deref().unwrap_or("").starts_with("bnc!"),
        "{echoed:?}"
    );

    drop(cw);
    drop(client);
    tokio::time::timeout(deadline::HANG, attach_task)
        .await
        .expect("attach did not stop after its client closed")
        .expect("attach task panicked");
}

#[tokio::test(flavor = "multi_thread")]
async fn two_clients_attach_to_one_always_on_network() {
    let addr = upstream().await;
    let handle = std::sync::Arc::new(IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "shared".parse().expect("test nickname"),
        autojoin: vec!["#multi".parse().expect("test channel")],
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    }));
    wait_connected(&handle).await;

    // two clients attach
    let (c1, s1) = tokio::io::duplex(64 * 1024);
    let (c2, s2) = tokio::io::duplex(64 * 1024);
    for (h, s) in [(handle.clone(), s1), (handle.clone(), s2)] {
        tokio::spawn(async move {
            let _ = attach(
                s,
                &h,
                Default::default(),
                "attacher",
                "attacher",
                e6ircd::bouncer::ATTACH_LIVENESS_INTERVAL,
            )
            .await;
        });
    }
    // small delay so both attaches subscribe before the live message
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // a peer posts; BOTH attached clients receive it
    let mut peer = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .unwrap();
    peer.register(&e6irc_client::Identity {
        nick: "mpeer",
        username: "mpeer",
        realname: "mpeer",
        server_password: None,
    })
    .await
    .unwrap();
    peer.send_line("JOIN #multi").await.unwrap();
    loop {
        if peer.next_message().await.unwrap().unwrap().command == "366" {
            break;
        }
    }
    peer.send_line("PRIVMSG #multi :broadcast to all clients")
        .await
        .unwrap();

    for client in [c1, c2] {
        let (r, _w) = tokio::io::split(client);
        let mut br = BufReader::new(r);
        let got = tokio::time::timeout(deadline::HANG, async {
            loop {
                let mut line = String::new();
                br.read_line(&mut line).await.unwrap();
                if line.contains("broadcast to all clients") {
                    return line;
                }
            }
        })
        .await
        .expect("a client missed the broadcast");
        assert!(got.contains("PRIVMSG #multi"), "{got}");
    }
}

/// Once a downstream falls behind the bounded broadcast, continuing would
/// leave its nick/channel model dependent on whichever state-changing lines
/// happened to be dropped. The BNC surfaces the gap and closes so reconnect
/// starts from an authoritative replay instead.
#[tokio::test(flavor = "multi_thread")]
async fn lagged_attach_is_not_left_open_with_stale_session_state() {
    let (handle, ends) = NetworkHandle::channels(8);
    let handle = std::sync::Arc::new(handle);
    let (client, server) = tokio::io::duplex(64);
    let attach_handle = handle.clone();
    let task = tokio::spawn(async move {
        attach(
            server,
            &attach_handle,
            Default::default(),
            "attacher",
            "attacher",
            e6ircd::bouncer::ATTACH_LIVENESS_INTERVAL,
        )
        .await
    });

    tokio::time::timeout(deadline::HANG, async {
        while handle.runtime_snapshot().attached_clients == 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("attach did not establish its replay boundary");

    // The tiny duplex blocks the attach writer while this burst overruns its
    // 1024-event receiver. A PART is included so silently continuing would be
    // observably unsafe, not merely a missing chat line.
    for sequence in 0..1_500 {
        ends.emit_line(format!(":peer PRIVMSG #room :burst {sequence}"));
    }
    ends.emit_line(":attacher!u@h PART #room :gone".into());

    let mut reader = BufReader::new(client);
    let output = tokio::time::timeout(deadline::HANG, async {
        let mut output = String::new();
        reader.read_to_string(&mut output).await.unwrap();
        output
    })
    .await
    .expect("lagged attach did not close");
    assert!(output.contains("client too slow"), "{output}");
    task.await
        .expect("attach task panicked")
        .expect("attach returned an I/O error");
}

/// Attach one downstream client over an in-memory duplex; returns the read
/// half (buffered), the write half, and the join handle of the attach task.
fn attach_client(
    handle: &std::sync::Arc<NetworkHandle>,
    caps: e6ircd::bouncer::AttachCaps,
) -> (
    BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
    tokio::io::WriteHalf<tokio::io::DuplexStream>,
    tokio::task::JoinHandle<()>,
) {
    let (client_side, server_side) = tokio::io::duplex(64 * 1024);
    let attach_handle = handle.clone();
    let task = tokio::spawn(async move {
        let _ = attach(
            server_side,
            &attach_handle,
            caps,
            "attacher",
            "attacher",
            e6ircd::bouncer::ATTACH_LIVENESS_INTERVAL,
        )
        .await;
    });
    let (cr, cw) = tokio::io::split(client_side);
    (BufReader::new(cr), cw, task)
}

/// Read until a line containing `needle` arrives.
async fn read_until(
    br: &mut BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
    needle: &str,
) -> String {
    tokio::time::timeout(deadline::HANG, async {
        loop {
            let mut line = String::new();
            br.read_line(&mut line).await.unwrap();
            if line.contains(needle) {
                return line;
            }
        }
    })
    .await
    .expect("read_until timeout")
}

/// A client that sends a message must not receive its own echo unless it
/// negotiated echo-message — but the account's *other* sessions and the
/// detached buffer must (they would otherwise see one-sided conversations).
#[tokio::test(flavor = "multi_thread")]
async fn self_echo_excluded_for_originator_but_reaches_others_and_buffer() {
    let addr = upstream().await;
    let handle = std::sync::Arc::new(IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "echobot".parse().expect("test nickname"),
        username: "echoident".parse().expect("test user name"),
        autojoin: vec!["#echo".parse().expect("test channel")],
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    }));
    wait_connected(&handle).await;

    // originator: no echo-message; observer: none either (it still gets the
    // echo — only the originator is ever excluded).
    let (mut a_reader, mut a_writer, _a) = attach_client(&handle, Default::default());
    let (mut b_reader, _b_writer, _b) = attach_client(&handle, Default::default());
    // Attach status notices, then the upstream's confirmation of the
    // autojoin: our own JOIN echo, which shows the identity the upstream
    // presents for us (this upstream adds no `~`).
    read_until(&mut a_reader, "upstream connected").await;
    read_until(&mut a_reader, "JOIN #echo").await;
    read_until(&mut b_reader, "upstream connected").await;

    a_writer
        .write_all(b"PRIVMSG #echo :both sides now\r\n")
        .await
        .unwrap();

    // The observer receives the synthesized echo, prefixed as the upstream
    // shows the driver: the configured user name and the shown host, never
    // the nickname as user.
    let echoed = read_until(&mut b_reader, "both sides now").await;
    assert!(
        echoed.contains(":echobot!echoident@127.0.0.1 PRIVMSG"),
        "echo carries the upstream identity: {echoed}"
    );
    assert!(echoed.contains("PRIVMSG #echo"), "{echoed}");

    // The originator does not receive its own line back. Give the stream a
    // moment: any such line would arrive promptly.
    let own = tokio::time::timeout(std::time::Duration::from_millis(400), async {
        loop {
            let mut line = String::new();
            a_reader.read_line(&mut line).await.unwrap();
            if line.contains("both sides now") {
                return line;
            }
        }
    })
    .await;
    assert!(own.is_err(), "originator must not be echoed: {own:?}");

    // The detached buffer records it (playback holds both sides).
    let buffered = tokio::time::timeout(deadline::HANG, async {
        loop {
            let snapshot = handle.buffer_snapshot();
            if let Some(line) = snapshot.iter().find(|l| l.contains("both sides now")) {
                return line.clone();
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("echo not buffered");
    assert!(
        buffered.contains(":echobot!echoident@127.0.0.1 PRIVMSG"),
        "{buffered}"
    );
}

/// With echo-message negotiated on attach, the originator receives exactly
/// one copy of its own message (synthesized — the upstream is never asked
/// for echo-message, so no second echo can arrive).
#[tokio::test(flavor = "multi_thread")]
async fn self_echo_delivered_once_when_negotiated() {
    let addr = upstream().await;
    let handle = std::sync::Arc::new(IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "echobot".parse().expect("test nickname"),
        username: "echoident".parse().expect("test user name"),
        autojoin: vec!["#echo".parse().expect("test channel")],
        internal_upstreams: InternalUpstreams::Allow,
        ..NetworkConfig::default()
    }));
    wait_connected(&handle).await;

    let caps = e6ircd::bouncer::AttachCaps {
        echo_message: true,
        ..Default::default()
    };
    let (mut reader, mut writer, _task) = attach_client(&handle, caps);
    read_until(&mut reader, "upstream connected").await;
    read_until(&mut reader, "JOIN #echo").await;

    writer
        .write_all(b"PRIVMSG #echo :my own words\r\n")
        .await
        .unwrap();
    let first = read_until(&mut reader, "my own words").await;
    assert!(
        first.contains(":echobot!echoident@127.0.0.1 PRIVMSG"),
        "{first}"
    );
    // No second copy follows.
    let second = tokio::time::timeout(std::time::Duration::from_millis(400), async {
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            if line.contains("my own words") {
                return line;
            }
        }
    })
    .await;
    assert!(second.is_err(), "exactly one echo: {second:?}");
}

/// Wait for the next command the driver receives.
async fn next_driver_command(ends: &mut e6ircd::bouncer::DriverEnds) -> String {
    tokio::time::timeout(deadline::HANG, ends.next_command())
        .await
        .expect("driver command timeout")
        .expect("driver command queue closed")
        .line
}

/// Every IRC client sends `QUIT` when it exits. The upstream session is the
/// account's always-on presence, shared by every other attachment, so one
/// client leaving ends that client's attachment and nothing else.
#[tokio::test(flavor = "multi_thread")]
async fn attached_client_quit_ends_the_attachment_and_never_reaches_the_driver() {
    let (handle, mut ends) = NetworkHandle::channels(8);
    let handle = std::sync::Arc::new(handle);
    let (mut reader, mut writer, task) = attach_client(&handle, Default::default());
    read_until(&mut reader, "upstream disconnected").await;

    writer.write_all(b"QUIT :leaving\r\n").await.unwrap();
    tokio::time::timeout(deadline::HANG, task)
        .await
        .expect("QUIT did not end the attachment")
        .expect("attach task panicked");

    let mut rest = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        reader.read_to_string(&mut rest),
    )
    .await
    .expect("the attach stream stayed open after QUIT")
    .unwrap();
    assert!(rest.contains("ERROR :"), "{rest}");

    // The first command the driver ever sees is this marker: the QUIT was not
    // queued ahead of it.
    assert_eq!(
        handle.send("PRIVMSG #room :marker"),
        e6ircd::bouncer::SendOutcome::Sent
    );
    assert_eq!(
        next_driver_command(&mut ends).await,
        "PRIVMSG #room :marker"
    );
}

/// A client's lag-check `PING` is answered by the bouncer itself: the upstream
/// may be reconnecting or parked, and its `PONG` would otherwise be buffered and
/// broadcast to the account's other clients.
#[tokio::test(flavor = "multi_thread")]
async fn attached_client_ping_is_answered_locally_and_pong_is_consumed() {
    let (handle, mut ends) = NetworkHandle::channels(8);
    let handle = std::sync::Arc::new(handle);
    let (mut reader, mut writer, _task) = attach_client(&handle, Default::default());
    read_until(&mut reader, "upstream disconnected").await;

    writer
        .write_all(b"PING :lag 1234\r\nPONG :unsolicited\r\nPRIVMSG #room :marker\r\n")
        .await
        .unwrap();
    let pong = read_until(&mut reader, "PONG").await;
    assert_eq!(pong, ":*bnc* PONG *bnc* :lag 1234\r\n");
    assert_eq!(
        next_driver_command(&mut ends).await,
        "PRIVMSG #room :marker"
    );
}

/// A quiet or parked network writes nothing to its clients, so a half-open
/// client was never written to, never errored, and held its task, its socket
/// and its place in `attached_clients` until the next broadcast line. The
/// bouncer asks; a client that answers stays, and one that does not is let go.
#[tokio::test(flavor = "multi_thread")]
async fn a_silent_client_is_pinged_and_then_let_go_while_an_answering_one_stays() {
    let interval = std::time::Duration::from_millis(100);
    let (handle, _ends) = NetworkHandle::channels(8);
    let handle = std::sync::Arc::new(handle);
    let attach_with_liveness = |handle: &std::sync::Arc<NetworkHandle>| {
        let (client_side, server_side) = tokio::io::duplex(64 * 1024);
        let handle = handle.clone();
        let task = tokio::spawn(async move {
            attach(
                server_side,
                &handle,
                Default::default(),
                "attacher",
                "attacher",
                interval,
            )
            .await
        });
        let (reader, writer) = tokio::io::split(client_side);
        (BufReader::new(reader), writer, task)
    };

    // The half-open client: the socket stays open and says nothing.
    let (mut silent_reader, _silent_writer, silent) = attach_with_liveness(&handle);
    // The live client answers every PING it is sent.
    let (mut live_reader, mut live_writer, live) = attach_with_liveness(&handle);
    let answering = tokio::spawn(async move {
        loop {
            let ping = read_until(&mut live_reader, "PING").await;
            let token = ping.trim_end().rsplit(':').next().unwrap_or_default();
            if live_writer
                .write_all(format!("PONG :{token}\r\n").as_bytes())
                .await
                .is_err()
            {
                return;
            }
        }
    });

    let ping = read_until(&mut silent_reader, "PING").await;
    assert!(ping.starts_with(":*bnc* PING "), "{ping}");
    let end = tokio::time::timeout(deadline::HANG, silent)
        .await
        .expect("a client that answers nothing stayed attached")
        .expect("attach task panicked")
        .expect("attach returned an I/O error");
    assert_eq!(end, e6ircd::bouncer::AttachEnd::ClientUnresponsive);

    // Many intervals later the answering client is still there, and it is the
    // only one counted.
    tokio::time::sleep(interval * 6).await;
    assert!(!live.is_finished(), "a client that answers was let go");
    assert_eq!(handle.runtime_snapshot().attached_clients, 1);
    answering.abort();
}
