#![no_main]

//! Feed the TUI arbitrary server output.
//!
//! The core targets fuzz what a hostile *client* can send a server. This one
//! is the other direction: a client is fed by whatever server it connected to,
//! and that server is not necessarily e6ircd — it may be hostile, buggy, or a
//! bridge relaying somebody else's text. The application state a client keeps
//! (buffers, scroll positions, the nick it thinks it has) is derived entirely
//! from those lines, and a panic there takes the user's client down.
//!
//! Each input line is parsed the way the real client parses it, then handed to
//! the same `App::on_message` the binary uses. The render path is exercised too
//! — `visible` slices the log against a caller-supplied height, which is where
//! an off-by-one becomes a panic rather than a wrong pixel.

use e6irc_client::OwnedMessage;
use e6irc_proto::message::Message;
use e6irc_tui::app::App;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut app = App::new("#chan".to_string(), "nick".to_string());
    for line in text.split('\n').take(256) {
        let Ok(parsed) = Message::parse(line) else {
            continue;
        };
        app.on_message(&OwnedMessage::from(&parsed));
        // Scroll and render at several heights, including the degenerate ones:
        // an empty log, a height past the end, and zero.
        for height in [0usize, 1, 3, 80] {
            let _ = app.current().visible(height);
        }
    }
    app.scroll_up(3);
    let _ = app.current().visible(10);
    app.scroll_down(1);
    let _ = app.current().visible(10);
    app.next_buffer();
    let _ = app.current().visible(0);
    app.prev_buffer();
    let _ = app.current().visible(1);
});
