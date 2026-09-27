//! A scripted peer (a fake upstream server, a stand-in client) running beside
//! a test's body in its own task.
//!
//! Such a script asserts on what the code under test sent it. In a detached
//! `tokio::spawn` whose handle is dropped, a failed assertion only ends that
//! task: the panic vanishes, and the test passes or fails on whatever the code
//! did next. A `ScriptedTask` keeps the handle, so the script's failure is the
//! test's: `finish` awaits the script and re-raises its panic, and dropping the
//! value (at the end of the test, unless the test is already failing) re-raises
//! a panic the script already hit, then stops a script still waiting for input.
//! A script that must report what it saw for the test body to judge sends it
//! over a channel instead.

use std::future::Future;
use std::task::{Context, Poll, Waker};

use tokio::task::JoinHandle;

pub struct ScriptedTask<T> {
    task: Option<JoinHandle<T>>,
}

impl<T: Send + 'static> ScriptedTask<T> {
    /// Run `script` beside the test. Bind the result to a named variable
    /// (`let _upstream = …`): `let _ = …` drops it at once, which stops the
    /// script before it has run.
    #[must_use = "a dropped ScriptedTask stops its script at once"]
    pub fn spawn(script: impl Future<Output = T> + Send + 'static) -> Self {
        Self {
            task: Some(tokio::spawn(script)),
        }
    }
}

impl<T> ScriptedTask<T> {
    /// Wait for the script to end and return its result; its panic is the
    /// test's.
    pub async fn finish(mut self) -> T {
        let task = self.task.take().expect("a ScriptedTask is finished once");
        match task.await {
            Ok(value) => value,
            Err(error) => reraise(error),
        }
    }
}

fn reraise(error: tokio::task::JoinError) -> ! {
    match error.try_into_panic() {
        Ok(panic) => std::panic::resume_unwind(panic),
        Err(error) => panic!("the scripted task did not run to its end: {error}"),
    }
}

impl<T> Drop for ScriptedTask<T> {
    fn drop(&mut self) {
        let Some(mut task) = self.task.take() else {
            return;
        };
        if !task.is_finished() {
            task.abort();
            return;
        }
        // A test that is already failing reports its own panic; a second one
        // raised while unwinding would abort the whole test binary.
        if std::thread::panicking() {
            return;
        }
        // The task has finished, so its result is ready; `unconstrained` keeps
        // tokio's cooperative budget from answering "not yet" regardless.
        let mut context = Context::from_waker(Waker::noop());
        match std::pin::pin!(tokio::task::unconstrained(&mut task)).poll(&mut context) {
            Poll::Ready(Ok(_)) => {}
            Poll::Ready(Err(error)) => reraise(error),
            Poll::Pending => panic!("a finished scripted task did not yield its result"),
        }
    }
}
