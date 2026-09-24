//! Waiting on IRC membership instead of sleeping: a test that needs a BNC
//! driver registered upstream and joined to its autojoin channel asks the IRC
//! server, rather than guessing how long that takes.

use super::deadline;

/// What WHOIS says about a nickname: absent (401), or present and on these
/// channels (status prefixes stripped).
pub type Whois = Option<Vec<String>>;

/// Ask `server` about `nick` with WHOIS until `done` accepts the answer.
/// Asked from a separate connection that joins nothing, so no channel and no
/// driver buffer sees a trace of the check.
pub async fn whois_until(
    server: std::net::SocketAddr,
    nick: &str,
    what: &str,
    done: impl Fn(&Whois) -> bool,
) {
    static OBSERVERS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
    let observer = format!(
        "whoiswatch{}",
        OBSERVERS.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    );
    let mut conn = e6irc_client::Connection::connect(&server.to_string())
        .await
        .expect("observer connects");
    conn.register(&e6irc_client::Identity {
        nick: &observer,
        username: "watch",
        realname: "whois watch",
        server_password: None,
    })
    .await
    .expect("observer registers");
    let mut last: Whois = None;
    let settled = tokio::time::timeout(deadline::HANG, async {
        loop {
            conn.send_line(&format!("WHOIS {nick}")).await.unwrap();
            let mut answer: Whois = Some(Vec::new());
            loop {
                let m = conn.next_message().await.unwrap().expect("observer open");
                match m.command.as_str() {
                    // ERR_NOSUCHNICK.
                    "401" => answer = None,
                    // RPL_WHOISCHANNELS, each channel with its status prefix.
                    "319" => {
                        if let (Some(channels), Some(list)) = (answer.as_mut(), m.params.last()) {
                            channels.extend(list.split(' ').filter(|c| !c.is_empty()).map(|c| {
                                c.trim_start_matches(['@', '%', '+', '~', '&']).to_string()
                            }));
                        }
                    }
                    // RPL_ENDOFWHOIS, which follows a 401 too.
                    "318" => break,
                    _ => {}
                }
            }
            if done(&answer) {
                return;
            }
            last = answer;
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
    })
    .await;
    assert!(
        settled.is_ok(),
        "{nick} never {what} on {server}; last WHOIS: {last:?}"
    );
    let _ = conn.send_line("QUIT").await;
}

/// Wait until `nick` is on `channel` at `server` — for a BNC network, until its
/// driver has registered upstream and finished its autojoin.
pub async fn wait_joined(server: std::net::SocketAddr, nick: &str, channel: &str) {
    whois_until(server, nick, &format!("joined {channel}"), |whois| {
        whois
            .as_ref()
            .is_some_and(|channels| channels.iter().any(|c| c == channel))
    })
    .await;
}
