//! Attach-layer e2e: a downstream client attaches to a BNC network
//! (driver connected to an e6ircd-as-upstream), receives buffered +
//! live traffic, and its sent lines reach the upstream.

use e6ircd::bouncer::{IrcNetwork, NetworkConfig, NetworkHandle, attach};
use e6ircd::config::{Config, ListenerConfig};
use e6ircd::net;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

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
    if handle.is_connected() {
        return;
    }
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            match events.recv().await {
                Ok(e6ircd::bouncer::DriverEvent::Connected) => return,
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
        nick: "bnc".into(),
        autojoin: vec!["#room".into()],
        ..NetworkConfig::default()
    });
    wait_connected(&handle).await;

    // a peer posts a message BEFORE the client attaches -> goes to buffer
    let mut peer = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .unwrap();
    peer.register("peer", "peer").await.unwrap();
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
        let _ = attach(server_side, &attach_handle, Default::default(), "attacher").await;
    });

    let (cr, mut cw) = tokio::io::split(client_side);
    let mut client = BufReader::new(cr);

    // playback: the buffered message arrives first
    let playback = tokio::time::timeout(std::time::Duration::from_secs(5), async {
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
    let live = tokio::time::timeout(std::time::Duration::from_secs(5), async {
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
    let echoed = tokio::time::timeout(std::time::Duration::from_secs(5), async {
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
    tokio::time::timeout(std::time::Duration::from_secs(5), attach_task)
        .await
        .expect("attach did not stop after its client closed")
        .expect("attach task panicked");
}

#[tokio::test(flavor = "multi_thread")]
async fn two_clients_attach_to_one_always_on_network() {
    let addr = upstream().await;
    let handle = std::sync::Arc::new(IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "shared".into(),
        autojoin: vec!["#multi".into()],
        ..NetworkConfig::default()
    }));
    wait_connected(&handle).await;

    // two clients attach
    let (c1, s1) = tokio::io::duplex(64 * 1024);
    let (c2, s2) = tokio::io::duplex(64 * 1024);
    for (h, s) in [(handle.clone(), s1), (handle.clone(), s2)] {
        tokio::spawn(async move {
            let _ = attach(s, &h, Default::default(), "attacher").await;
        });
    }
    // small delay so both attaches subscribe before the live message
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // a peer posts; BOTH attached clients receive it
    let mut peer = e6irc_client::Connection::connect(&addr.to_string())
        .await
        .unwrap();
    peer.register("mpeer", "mpeer").await.unwrap();
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
        let got = tokio::time::timeout(std::time::Duration::from_secs(5), async {
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
        let _ = attach(server_side, &attach_handle, caps, "attacher").await;
    });
    let (cr, cw) = tokio::io::split(client_side);
    (BufReader::new(cr), cw, task)
}

/// Read until a line containing `needle` arrives.
async fn read_until(
    br: &mut BufReader<tokio::io::ReadHalf<tokio::io::DuplexStream>>,
    needle: &str,
) -> String {
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
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
        nick: "echobot".into(),
        autojoin: vec!["#echo".into()],
        ..NetworkConfig::default()
    }));
    wait_connected(&handle).await;

    // originator: no echo-message; observer: none either (it still gets the
    // echo — only the originator is ever excluded).
    let (mut a_reader, mut a_writer, _a) = attach_client(&handle, Default::default());
    let (mut b_reader, _b_writer, _b) = attach_client(&handle, Default::default());
    // Attach status notices.
    read_until(&mut a_reader, "upstream connected").await;
    read_until(&mut b_reader, "upstream connected").await;

    a_writer
        .write_all(b"PRIVMSG #echo :both sides now\r\n")
        .await
        .unwrap();

    // The observer receives the synthesized echo, prefixed as the driver's
    // upstream identity.
    let echoed = read_until(&mut b_reader, "both sides now").await;
    assert!(
        echoed.contains(":echobot!~echobot@"),
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
    let buffered = tokio::time::timeout(std::time::Duration::from_secs(5), async {
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
    assert!(buffered.contains(":echobot!~echobot@"), "{buffered}");
}

/// With echo-message negotiated on attach, the originator receives exactly
/// one copy of its own message (synthesized — the upstream is never asked
/// for echo-message, so no second echo can arrive).
#[tokio::test(flavor = "multi_thread")]
async fn self_echo_delivered_once_when_negotiated() {
    let addr = upstream().await;
    let handle = std::sync::Arc::new(IrcNetwork::start(NetworkConfig {
        addr: addr.to_string(),
        nick: "echobot".into(),
        autojoin: vec!["#echo".into()],
        ..NetworkConfig::default()
    }));
    wait_connected(&handle).await;

    let caps = e6ircd::bouncer::AttachCaps {
        echo_message: true,
        ..Default::default()
    };
    let (mut reader, mut writer, _task) = attach_client(&handle, caps);
    read_until(&mut reader, "upstream connected").await;

    writer
        .write_all(b"PRIVMSG #echo :my own words\r\n")
        .await
        .unwrap();
    let first = read_until(&mut reader, "my own words").await;
    assert!(first.contains(":echobot!~echobot@"), "{first}");
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
