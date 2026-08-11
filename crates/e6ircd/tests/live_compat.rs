//! Opt-in interoperability checks against public TLS IRC servers.
//! They register and read the greeting and ISUPPORT.
//!
//! They do not run in normal CI. Each test opens two brief sessions and QUITs.
//! Run manually:
//!
//!   cargo test -p e6ircd --test live_compat -- --ignored --nocapture

use std::collections::HashMap;
use std::time::Duration;

use e6irc_client::{Connection, webpki_root_store};

/// Register, collect ISUPPORT, then quit.
async fn probe(addr: &str, server_name: &str) -> std::io::Result<(bool, HashMap<String, String>)> {
    let mut conn = Connection::connect_tls(addr, server_name, webpki_root_store()).await?;
    // Use a brief unique nick.
    let nick = format!("e6c{:05}", std::process::id() % 100000);
    conn.send_line("CAP LS 302").await?;
    conn.send_line(&format!("NICK {nick}")).await?;
    conn.send_line(&format!("USER {nick} 0 * :e6irc interop probe"))
        .await?;

    let mut welcomed = false;
    let mut isupport: HashMap<String, String> = HashMap::new();

    let outcome = tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(msg) = conn.next_message().await? {
            match msg.command.as_str() {
                "PING" => {
                    let token = msg.params.first().cloned().unwrap_or_default();
                    conn.send_line(&format!("PONG :{token}")).await?;
                }
                // Complete CAP negotiation.
                "CAP" if msg.params.get(1).map(String::as_str) == Some("LS") => {
                    conn.send_line("CAP END").await?;
                }
                "001" => welcomed = true,
                // RPL_ISUPPORT.
                "005" => {
                    for tok in msg.params.iter().skip(1) {
                        if tok.contains(' ') {
                            break;
                        }
                        let (n, v) = tok.split_once('=').unwrap_or((tok.as_str(), ""));
                        isupport.insert(n.to_string(), v.to_string());
                    }
                }
                // End of greeting.
                "376" | "422" => break,
                _ => {}
            }
        }
        Ok::<(), std::io::Error>(())
    })
    .await;
    // Accept timeout after registration.
    if let Ok(res) = outcome {
        res?;
    }
    let _ = conn.send_line("QUIT :interop probe done").await;
    Ok((welcomed, isupport))
}

/// Check two registrations and required ISUPPORT tokens.
async fn assert_interop(addr: &str, server_name: &str) {
    assert_single_interop(addr, server_name).await;
    assert_single_interop(addr, server_name).await;
}

async fn assert_single_interop(addr: &str, server_name: &str) {
    let (welcomed, isupport) = probe(addr, server_name)
        .await
        .unwrap_or_else(|e| panic!("{addr}: connection/registration failed: {e}"));
    assert!(welcomed, "{addr}: never received RPL_WELCOME (001)");
    assert!(
        isupport.len() >= 8,
        "{addr}: only {} ISUPPORT tokens parsed",
        isupport.len()
    );
    // Required IRC support tokens.
    for key in ["CASEMAPPING", "CHANTYPES", "NICKLEN"] {
        assert!(
            isupport.contains_key(key),
            "{addr}: missing ISUPPORT {key} (have: {:?})",
            isupport.keys().collect::<Vec<_>>()
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live network: connects to Libera.Chat; run with --ignored"]
async fn interoperates_with_libera() {
    assert_interop("irc.libera.chat:6697", "irc.libera.chat").await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live network: connects to OFTC; run with --ignored"]
async fn interoperates_with_oftc() {
    assert_interop("irc.oftc.net:6697", "irc.oftc.net").await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "live network: connects to the Ergo test network; run with --ignored"]
async fn interoperates_with_ergo() {
    assert_interop("testnet.ergo.chat:6697", "testnet.ergo.chat").await;
}
