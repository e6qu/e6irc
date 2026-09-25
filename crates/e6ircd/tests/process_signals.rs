//! How the daemon process answers signals before it is serving.
#![cfg(unix)]

use std::io::{BufRead, BufReader};
use std::process::{Command, Stdio};
use std::time::Duration;

/// `SIGHUP` asks for a certificate reload. One that arrives while the process
/// still waits for PostgreSQL used to find the default action — terminate — in
/// place, and a service manager does not restart a unit that died of it. The
/// handler is now taken over first thing, so the process keeps waiting.
#[test]
fn a_hangup_during_the_database_wait_does_not_end_the_process() {
    let mut daemon = Command::new(env!("CARGO_BIN_EXE_e6ircd"))
        .arg("--config-from-environment")
        .env_clear()
        .envs([
            ("E6IRC_SERVER_NAME", "irc.example.test"),
            ("E6IRC_PUBLIC_URL", "https://irc.example.test"),
            // Nothing listens on port 1: every attempt is refused at once, and
            // the daemon keeps retrying for its startup wait.
            ("E6IRC_DATABASE_URL", "postgres://e6irc@127.0.0.1:1/e6irc"),
            (
                "APPLICATION_RELEASE_REVISION",
                "0123456789abcdef0123456789abcdef01234567",
            ),
            ("E6IRC_HTTP_ADDR", "127.0.0.1:0"),
            ("E6IRC_IRC_ADDR", "127.0.0.1:0"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .spawn()
        .expect("start e6ircd");
    let stderr = daemon.stderr.take().expect("piped standard error");
    let (said, lines) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        for line in BufReader::new(stderr).lines() {
            let Ok(line) = line else { break };
            if said.send(line).is_err() {
                break;
            }
        }
    });
    // In the database wait: an attempt has failed and another is scheduled.
    loop {
        let line = lines
            .recv_timeout(Duration::from_secs(30))
            .expect("the daemon reports its first database attempt");
        if line.contains("database connection attempt 1 failed") {
            assert!(line.contains("retrying"), "{line}");
            break;
        }
    }
    let sent = Command::new("kill")
        .args(["-HUP", &daemon.id().to_string()])
        .status()
        .expect("run kill");
    assert!(sent.success(), "send SIGHUP: {sent}");
    std::thread::sleep(Duration::from_millis(500));
    let status = daemon.try_wait().expect("poll the daemon");
    daemon.kill().expect("stop the daemon");
    daemon.wait().expect("reap the daemon");
    assert!(
        status.is_none(),
        "SIGHUP during the database wait ended the process: {status:?}"
    );
}
