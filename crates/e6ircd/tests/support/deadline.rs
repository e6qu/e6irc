//! How long an integration test waits for something that must happen.
//!
//! These deadlines exist to turn a hang into a readable failure — "the lagged
//! attach did not close" instead of a job killed with no message. They are not
//! assertions about latency: nothing here is measuring how fast the server is,
//! and a loaded machine is not a regression. Written as a few seconds they
//! became one, and the suite failed for being run beside a browser suite or on
//! a busy CI runner.
//!
//! So: generous on purpose. A real hang still fails, with its own sentence,
//! just a minute later. A test that genuinely asserts *when* something happens
//! keeps its own bound — the short `from_millis` windows that assert nothing
//! arrived are deliberately untouched.

/// The bound on a positive wait: the thing being waited for must happen.
pub const HANG: std::time::Duration = std::time::Duration::from_secs(60);
