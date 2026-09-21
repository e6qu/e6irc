//! The shipped binary's startup failures, as a person at a terminal sees them.

use std::process::{Command, Stdio};

/// A server that offers SASL PLAIN and rejects every password.
async fn rejecting_server() -> String {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap().to_string();
    tokio::spawn(async move {
        let (socket, _) = listener.accept().await.unwrap();
        let (reader, mut writer) = socket.into_split();
        let mut lines = tokio::io::BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            let reply = match line.as_str() {
                "CAP LS 302" => ":srv CAP * LS :sasl=PLAIN",
                "CAP REQ :sasl" => ":srv CAP * ACK :sasl",
                "AUTHENTICATE PLAIN" => "AUTHENTICATE +",
                other if other.starts_with("AUTHENTICATE ") => {
                    ":srv 904 * :Invalid password for account alice"
                }
                _ => continue,
            };
            writer
                .write_all(format!("{reply}\r\n").as_bytes())
                .await
                .unwrap();
        }
    });
    address
}

/// A startup failure is one line, prefixed with the program's name, in the
/// same form as the CLI's — not a Rust `Debug` dump of the error value.
#[tokio::test(flavor = "multi_thread")]
async fn a_rejected_password_is_reported_as_one_readable_line() {
    let address = rejecting_server().await;
    let bin = env!("CARGO_BIN_EXE_e6irc-tui");
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(20),
        tokio::task::spawn_blocking(move || {
            Command::new(bin)
                .args([
                    "--server",
                    &address,
                    "--nick",
                    "alice",
                    "--channel",
                    "#c",
                    "--account",
                    "alice",
                    "--password",
                    "wrong",
                    "--response-timeout",
                    "5",
                ])
                .stdin(Stdio::null())
                .output()
                .expect("run the TUI")
        }),
    )
    .await
    .expect("the TUI neither started nor failed")
    .unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "{stderr}");
    assert!(stderr.starts_with("e6irc-tui: "), "{stderr}");
    assert!(
        stderr.contains("Invalid password for account alice"),
        "{stderr}"
    );
    assert!(
        !stderr.contains("Custom {") && !stderr.contains("kind:"),
        "a Debug dump reached the user: {stderr}"
    );
    assert_eq!(stderr.trim_end().lines().count(), 1, "{stderr}");
}
