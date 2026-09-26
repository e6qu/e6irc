//! What each key does. Kept out of the render loop so every binding is a
//! unit-tested function of the key and the application state.

use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

use crate::app::{Action, App, Outbound};

/// What the render loop must do after a key.
#[derive(Debug, PartialEq, Eq)]
pub enum KeyOutcome {
    /// The key only changed local state (or nothing).
    Handled,
    /// A line to offer to the socket writer.
    Send(Outbound),
    /// Leave the client.
    Quit,
}

/// The key bindings, shown in the hint bar. Buffer switching has three
/// spellings because terminals disagree about modifiers: macOS Terminal sends
/// Option-Left as `ESC b` (Alt-b), and some terminals send no Alt at all.
pub const HINT: &str = " switch: Alt-←/→ Alt-b/f Ctrl-P/N · scroll: PgUp/PgDn · latest: Ctrl-End · clear: Esc · help: /help · quit: /quit Ctrl-C";

/// Apply one key to `app`.
pub fn dispatch(app: &mut App, key: KeyEvent) -> KeyOutcome {
    if key.kind != KeyEventKind::Press {
        return KeyOutcome::Handled;
    }
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    let control = key.modifiers.contains(KeyModifiers::CONTROL);
    // The Alt Graph key arrives as Control+Alt on some platforms: the
    // character it produces is text, not a binding.
    let alt_graph = alt && control;
    match key.code {
        KeyCode::Left if alt => app.prev_buffer(),
        KeyCode::Right if alt => app.next_buffer(),
        KeyCode::Char('b' | 'B') if alt && !alt_graph => app.prev_buffer(),
        KeyCode::Char('f' | 'F') if alt && !alt_graph => app.next_buffer(),
        KeyCode::Char('p' | 'P') if control && !alt_graph => app.prev_buffer(),
        KeyCode::Char('n' | 'N') if control && !alt_graph => app.next_buffer(),
        KeyCode::Char('c' | 'C') if control && !alt_graph => {
            app.should_quit = true;
            return KeyOutcome::Quit;
        }
        KeyCode::Char('u' | 'U') if control && !alt_graph => app.clear_input(),
        // Any other Alt- or Control-modified letter is an unbound shortcut;
        // typing its letter would put text in the composer nobody typed.
        KeyCode::Char(_) if (alt || control) && !alt_graph => {}
        KeyCode::Char(c) => app.on_char(c),
        KeyCode::Left => app.move_input_left(),
        KeyCode::Right => app.move_input_right(),
        KeyCode::Home => app.move_input_home(),
        KeyCode::PageUp => app.scroll_up(10),
        KeyCode::PageDown => app.scroll_down(10),
        KeyCode::End if control => app.jump_latest(),
        KeyCode::End => app.move_input_end(),
        KeyCode::Backspace => app.on_backspace(),
        KeyCode::Delete => app.on_delete(),
        // Esc is the key people press to back out of what they were typing;
        // quitting on it threw away a session on a stray keypress.
        KeyCode::Esc => app.clear_input(),
        KeyCode::Enter => {
            return match app.on_enter() {
                Action::Send(outbound) => KeyOutcome::Send(outbound),
                Action::Quit => KeyOutcome::Quit,
                Action::None => KeyOutcome::Handled,
            };
        }
        _ => {}
    }
    KeyOutcome::Handled
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::app::test_app;

    fn key(code: KeyCode, modifiers: KeyModifiers) -> KeyEvent {
        KeyEvent::new(code, modifiers)
    }

    fn app_with_two_buffers() -> App {
        let mut app = test_app("#a", "me");
        app.on_message(&e6irc_client::OwnedMessage::from(
            &e6irc_proto::message::Message::parse(":x!x@h PRIVMSG #b :hi").unwrap(),
        ));
        app
    }

    /// Option-Left in macOS Terminal is `ESC b`: Alt-b. It switches buffers
    /// instead of typing a "b", as do Alt-f and Ctrl-P/N.
    #[test]
    fn alt_letters_switch_buffers_and_never_type() {
        let mut app = app_with_two_buffers();
        for (code, modifiers, expected) in [
            (KeyCode::Char('f'), KeyModifiers::ALT, "#b"),
            (KeyCode::Char('b'), KeyModifiers::ALT, "#a"),
            (KeyCode::Char('n'), KeyModifiers::CONTROL, "#b"),
            (KeyCode::Char('p'), KeyModifiers::CONTROL, "#a"),
            (KeyCode::Right, KeyModifiers::ALT, "#b"),
            (KeyCode::Left, KeyModifiers::ALT, "#a"),
        ] {
            assert_eq!(
                dispatch(&mut app, key(code, modifiers)),
                KeyOutcome::Handled
            );
            assert_eq!(app.current().name, expected, "{code:?} {modifiers:?}");
        }
        assert_eq!(app.input(), "");
        dispatch(&mut app, key(KeyCode::Char('x'), KeyModifiers::ALT));
        dispatch(&mut app, key(KeyCode::Char('x'), KeyModifiers::CONTROL));
        assert_eq!(app.input(), "", "an unbound shortcut typed its letter");
        // Alt Graph (Control+Alt) produces text.
        dispatch(
            &mut app,
            key(
                KeyCode::Char('@'),
                KeyModifiers::CONTROL | KeyModifiers::ALT,
            ),
        );
        dispatch(&mut app, key(KeyCode::Char('A'), KeyModifiers::SHIFT));
        assert_eq!(app.input(), "@A");
    }

    #[test]
    fn escape_clears_the_composer_and_only_quit_or_control_c_leaves() {
        let mut app = test_app("#a", "me");
        for c in "draft".chars() {
            dispatch(&mut app, key(KeyCode::Char(c), KeyModifiers::NONE));
        }
        assert_eq!(
            dispatch(&mut app, key(KeyCode::Esc, KeyModifiers::NONE)),
            KeyOutcome::Handled
        );
        assert_eq!(app.input(), "");
        assert!(!app.should_quit);
        assert_eq!(
            dispatch(&mut app, key(KeyCode::Char('c'), KeyModifiers::CONTROL)),
            KeyOutcome::Quit
        );
        assert!(app.should_quit);

        let mut app = test_app("#a", "me");
        for c in "/quit".chars() {
            dispatch(&mut app, key(KeyCode::Char(c), KeyModifiers::NONE));
        }
        assert_eq!(
            dispatch(&mut app, key(KeyCode::Enter, KeyModifiers::NONE)),
            KeyOutcome::Quit
        );
    }

    #[test]
    fn enter_offers_the_line_to_the_writer() {
        let mut app = test_app("#a", "me");
        for c in "hi".chars() {
            dispatch(&mut app, key(KeyCode::Char(c), KeyModifiers::NONE));
        }
        let KeyOutcome::Send(outbound) =
            dispatch(&mut app, key(KeyCode::Enter, KeyModifiers::NONE))
        else {
            panic!("a message is offered to the writer");
        };
        assert_eq!(outbound.line(), "PRIVMSG #a :hi");
    }

    #[test]
    fn the_hint_names_every_switching_key() {
        for binding in ["Alt-←/→", "Alt-b/f", "Ctrl-P/N", "Esc", "Ctrl-C"] {
            assert!(HINT.contains(binding), "{binding}");
        }
    }
}
