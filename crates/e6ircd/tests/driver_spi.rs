//! Bridge SPI conformance (DESIGN §10.5). Any `NetworkDriver` must, once
//! started, expose a usable `NetworkHandle`: it comes up, records lines
//! to the detached buffer, broadcasts them live, and relays downstream
//! commands. The kit runs that contract against the loopback reference
//! driver (which echoes each command back as a line) and exercises the
//! shared `attach` path against it — no external service required.

use std::time::Duration;

use e6ircd::bouncer::{DriverEvent, LoopbackDriver, NetworkDriver, NetworkHandle, attach};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::broadcast::Receiver;

async fn wait_for(events: &mut Receiver<DriverEvent>, pred: impl Fn(&DriverEvent) -> bool) -> bool {
    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match events.recv().await {
                Ok(ev) if pred(&ev) => return true,
                Ok(_) => {}
                Err(_) => return false,
            }
        }
    })
    .await
    .unwrap_or(false)
}

/// The universal driver contract, run against any driver whose commands
/// are expected to surface as lines (the loopback reference does exactly
/// this; a real bridge would surface upstream traffic instead).
async fn assert_echo_driver_contract(driver: Box<dyn NetworkDriver>) {
    let kind = driver.kind();
    let handle: NetworkHandle = driver.start();
    let mut events = handle.subscribe();

    // Connection state is read from the sticky flag, not the live event:
    // the `Connected` event may fire before this task subscribes (a
    // broadcast receiver never sees a message sent before it existed),
    // which is exactly the race that made this test flaky on loaded CI.
    let connected = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if handle.is_connected() {
                return true;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or(false);
    assert!(connected, "{kind}: never reported Connected");

    assert!(handle.send("hello world"), "{kind}: send failed");
    assert!(
        wait_for(
            &mut events,
            |e| matches!(e, DriverEvent::Line(l) if l == "hello world")
        )
        .await,
        "{kind}: command was not surfaced as a line"
    );

    // The line is also recorded to the detached buffer for playback.
    let buffered = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if handle.buffer_snapshot().iter().any(|l| l == "hello world") {
                return true;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or(false);
    assert!(buffered, "{kind}: line missing from the detached buffer");
}

#[tokio::test(flavor = "multi_thread")]
async fn loopback_reference_driver_meets_the_spi_contract() {
    assert_echo_driver_contract(Box::new(LoopbackDriver::new(100))).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn attach_relays_over_the_loopback_driver() {
    let handle = Box::new(LoopbackDriver::new(100)).start();

    // Pre-attach line lands in the buffer and must replay on attach.
    // Poll for it rather than sleeping a fixed interval (a fixed sleep is
    // a latent flake on a slow runner).
    handle.send("earlier");
    let buffered = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if handle.buffer_snapshot().iter().any(|l| l == "earlier") {
                return true;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap_or(false);
    assert!(buffered, "pre-attach line never reached the buffer");

    let (client, server) = tokio::io::duplex(4096);
    let handle = std::sync::Arc::new(handle);
    let attach_handle = handle.clone();
    tokio::spawn(async move { attach(server, &attach_handle, Default::default()).await });

    let (r, mut w) = tokio::io::split(client);
    let mut lines = BufReader::new(r).lines();

    // Playback of the buffered line.
    let replayed = tokio::time::timeout(Duration::from_secs(2), lines.next_line())
        .await
        .expect("timeout")
        .expect("io")
        .expect("line");
    assert_eq!(replayed, "earlier");

    // Live: a client line is echoed by the loopback driver back to us.
    w.write_all(b"live ping\r\n").await.unwrap();
    let echoed = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let line = lines.next_line().await.unwrap().unwrap();
            if line == "live ping" {
                return true;
            }
        }
    })
    .await
    .expect("timeout");
    assert!(echoed, "client line not relayed back through attach");
}
