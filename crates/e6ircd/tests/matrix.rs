//! Live integration for the `matrix` bridge against a Conduit homeserver
//! (vendor/tests/external-oracles/conduit/). Opt-in: needs the `matrix`
//! feature and a running Conduit whose URL is in E6IRC_TEST_MATRIX_URL.
//!
//!   docker compose -f vendor/tests/external-oracles/conduit/docker-compose.yml up -d
//!   E6IRC_TEST_MATRIX_URL=http://127.0.0.1:16167 \
//!     cargo test -p e6ircd --features matrix --test matrix -- --ignored --nocapture

#![cfg(feature = "matrix")]

use std::time::Duration;

use e6ircd::bouncer::{DriverEvent, MatrixConfig, MatrixDriver, NetworkDriver};

fn base() -> String {
    std::env::var("E6IRC_TEST_MATRIX_URL").expect("E6IRC_TEST_MATRIX_URL (a Conduit homeserver)")
}

async fn register(http: &reqwest::Client, base: &str, user: &str, pass: &str) -> String {
    let resp: serde_json::Value = http
        .post(format!("{base}/_matrix/client/v3/register"))
        .json(&serde_json::json!({
            "username": user, "password": pass, "auth": { "type": "m.login.dummy" }
        }))
        .send()
        .await
        .expect("register")
        .json()
        .await
        .expect("register json");
    resp["access_token"]
        .as_str()
        .unwrap_or_else(|| panic!("no token for {user}: {resp}"))
        .to_string()
}

fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (b as char).to_string()
            }
            _ => format!("%{b:02X}"),
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs a Conduit homeserver; set E6IRC_TEST_MATRIX_URL"]
async fn matrix_bridge_relays_both_ways() {
    let base = base();
    let http = reqwest::Client::new();
    // Conduit persists across runs; unique names avoid collisions.
    let sfx = std::process::id();
    let bot = format!("e6bot{sfx}");
    let alice = format!("alice{sfx}");
    let bot_token = register(&http, &base, &bot, "botpass").await;
    let alice_token = register(&http, &base, &alice, "alicepass").await;

    // Bot creates a room; alice joins.
    let room_local = format!("e6room{sfx}");
    let room: serde_json::Value = http
        .post(format!("{base}/_matrix/client/v3/createRoom"))
        .bearer_auth(&bot_token)
        .json(&serde_json::json!({ "room_alias_name": room_local, "preset": "public_chat" }))
        .send()
        .await
        .expect("createRoom")
        .json()
        .await
        .expect("room json");
    let room_id = room["room_id"].as_str().expect("room_id").to_string();
    let alias = format!("#{room_local}:localhost");
    http.post(format!("{base}/_matrix/client/v3/join/{}", enc(&alias)))
        .bearer_auth(&alice_token)
        .json(&serde_json::json!({}))
        .send()
        .await
        .expect("alice join");

    // Start the bridge as the bot, bridging the room.
    let handle = Box::new(MatrixDriver::new(MatrixConfig {
        homeserver: base.clone(),
        user: bot.clone(),
        password: "botpass".into(),
        rooms: vec![alias.clone()],
        buffer_cap: 100,
    }))
    .start();
    let mut events = handle.subscribe();
    let connected = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await {
                Ok(DriverEvent::Connected) => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    })
    .await
    .expect("timeout");
    assert!(connected, "bridge never connected/logged in");
    tokio::time::sleep(Duration::from_millis(500)).await; // sync loop running

    // Matrix -> IRC: alice sends; the bridge emits a PRIVMSG line.
    http.put(format!(
        "{base}/_matrix/client/v3/rooms/{}/send/m.room.message/t1",
        enc(&room_id)
    ))
    .bearer_auth(&alice_token)
    .json(&serde_json::json!({ "msgtype": "m.text", "body": "hello from matrix" }))
    .send()
    .await
    .expect("alice send");

    let line = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match events.recv().await {
                Ok(DriverEvent::Line(l)) if l.contains("hello from matrix") => return Some(l),
                Ok(_) => {}
                Err(_) => return None,
            }
        }
    })
    .await
    .expect("timeout")
    .expect("no bridged line");
    assert!(line.contains(&format!("PRIVMSG #{room_local}")), "{line}");
    assert!(
        line.starts_with(&format!(":{alice}!")),
        "sender nick: {line}"
    );

    // IRC -> Matrix: a downstream command reaches the room; alice sees it.
    assert!(handle.send(&format!("PRIVMSG #{room_local} :from the bridge")));
    let seen = tokio::time::timeout(Duration::from_secs(10), async {
        let mut since = String::new();
        loop {
            let mut req = http
                .get(format!("{base}/_matrix/client/v3/sync"))
                .bearer_auth(&alice_token)
                .query(&[("timeout", "3000")]);
            if !since.is_empty() {
                req = req.query(&[("since", since.as_str())]);
            }
            let body: serde_json::Value = req.send().await.unwrap().json().await.unwrap();
            since = body["next_batch"].as_str().unwrap_or("").to_string();
            if let Some(join) = body["rooms"]["join"].as_object() {
                for room in join.values() {
                    if let Some(evs) = room["timeline"]["events"].as_array() {
                        for ev in evs {
                            if ev["content"]["body"] == "from the bridge" {
                                return true;
                            }
                        }
                    }
                }
            }
        }
    })
    .await
    .unwrap_or(false);
    assert!(seen, "bridge's message did not reach the Matrix room");
}
