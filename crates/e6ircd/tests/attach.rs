//! Attach-layer e2e: a downstream client attaches to a BNC network
//! (driver connected to an e6ircd-as-upstream), receives buffered +
//! live traffic, and its sent lines reach the upstream.

use e6ircd::bouncer::{IrcNetwork, NetworkConfig, attach};
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
        }],
        ..Config::default()
    };
    net::start(config).await.expect("start").addrs[0]
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
    let mut ev = handle.subscribe();
    // wait for connect
    while ev.recv().await != Ok(e6ircd::bouncer::DriverEvent::Connected) {}

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
        let _ = attach(server_side, &attach_handle, Default::default()).await;
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
    let _ = attach_task.await;
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
    let mut ev = handle.subscribe();
    while ev.recv().await != Ok(e6ircd::bouncer::DriverEvent::Connected) {}

    // two clients attach
    let (c1, s1) = tokio::io::duplex(64 * 1024);
    let (c2, s2) = tokio::io::duplex(64 * 1024);
    for (h, s) in [(handle.clone(), s1), (handle.clone(), s2)] {
        tokio::spawn(async move {
            let _ = attach(s, &h, Default::default()).await;
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
