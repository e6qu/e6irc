//! Taking the configured nickname back from a ghost.
//!
//! A session the upstream never saw end — the process crashed, or the link
//! died without a `QUIT` — keeps its nickname until the upstream's ping
//! timeout reaps it. The next dial meets it as a 433. The driver then
//! registers once under [`alternative_nick`] and, from the welcome on, works
//! to take the configured nickname back: with SASL it asks NickServ to
//! `REGAIN` it, and in any case it watches the nickname (`MONITOR` where the
//! upstream offers it, `ISON` every [`NickRegainTiming::poll`] otherwise) and
//! says `NICK` as soon as it is free. It stops at the first definite refusal
//! and after [`NickRegainTiming::window`] (DESIGN §10.3).
//!
//! This is the state of one such wait, fed the upstream's lines and the clock
//! by the driver. It decides what to send; the driver sends it, relays what
//! is not consumed here, and sees the rename that ends the wait.

use std::time::Duration;

use e6irc_client::{NetworkNames, OwnedMessage, RegistrationRejection};
use tokio::time::Instant;

use super::upstream_identity::UpstreamNick;

/// How a driver paces taking its nickname back. Production values are the
/// [`Default`]; tests shrink them to run the whole wait in real time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NickRegainTiming {
    /// How often an upstream without `MONITOR` is asked (`ISON`) whether the
    /// nickname is free, and how long a refused `NICK` waits before the next.
    pub poll: Duration,
    /// How long the wait lasts. Longer than the four minutes a Solanum-family
    /// server takes to reap a client that stopped answering, so a ghost of
    /// this driver's own session always ends inside it; a holder that
    /// outlasts it is someone else.
    pub window: Duration,
}

impl Default for NickRegainTiming {
    fn default() -> Self {
        Self {
            poll: Duration::from_secs(15),
            window: Duration::from_secs(300),
        }
    }
}

/// The nickname registration falls back to while the configured one is held:
/// the configured nickname with `_` appended, or — when that could exceed the
/// upstream's `NICKLEN`, which is unknown until after the welcome — with its
/// last character replaced. Nine characters is the floor every server takes
/// (RFC 1459), and a ghost proves the configured length is accepted, so the
/// alternative is never longer than the larger of the two. A server that
/// truncated it would welcome the configured nickname's prefix, a name nobody
/// chose, and the welcome check refuses that.
pub(super) fn alternative_nick(configured: &UpstreamNick) -> String {
    const EVERY_SERVERS_NICKLEN: usize = 9;
    let configured = configured.as_str();
    if configured.chars().count() < EVERY_SERVERS_NICKLEN {
        return format!("{configured}_");
    }
    let mut alternative: String = configured.chars().collect();
    let last = alternative
        .pop()
        .expect("a configured nickname is never empty");
    alternative.push(if last == '_' { '-' } else { '_' });
    alternative
}

/// What the upstream was asked to do about the nickname.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Watch {
    /// The welcome burst is still arriving; its end says whether the upstream
    /// offers `MONITOR`.
    Burst,
    /// `MONITOR +`: the upstream says when the nickname goes offline.
    Monitor,
    /// No `MONITOR`: the nickname is asked about with `ISON` at `next`.
    Ison { next: Instant },
}

/// Where the NickServ `REGAIN` stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Services {
    /// Not authenticated: services would refuse it, so it is not asked.
    NotAsked,
    /// Authenticated; asked when the welcome burst ends.
    ToAsk,
    /// Asked; its answer is read from NickServ's notices.
    Asked,
    /// Answered, whatever it said; the watch goes on.
    Answered,
}

/// The driver's own `NICK` back to the configured nickname.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Attempt {
    /// None outstanding. `free` is the latest word on whether the nickname is
    /// free; the next `NICK` is sent no sooner than `not_before`, so no answer
    /// of the upstream can make the driver send one per line.
    Idle { not_before: Instant, free: bool },
    /// Sent; the rename or a refusal of it is awaited.
    Sent,
}

/// What one line or tick asks of the driver.
#[derive(Debug, Default)]
pub(super) struct Step {
    /// Lines to write upstream, in order.
    pub(super) send: Vec<String>,
    /// The line was the wait's own business (an answer to its `MONITOR`,
    /// `ISON` or `NICK`), not the session's: nobody else is shown it.
    pub(super) consumed: bool,
    /// The wait is over and the nickname is not coming back.
    pub(super) refused: Option<RegistrationRejection>,
}

/// One wait for the configured nickname.
#[derive(Debug)]
pub(super) struct NickRegain {
    configured: String,
    alternative: String,
    timing: NickRegainTiming,
    began: Instant,
    watch: Watch,
    services: Services,
    attempt: Attempt,
}

impl NickRegain {
    /// Begin waiting, registered as `alternative`, for `configured`; NickServ
    /// is asked only when the connection is `authenticated`.
    pub(super) fn new(
        configured: &str,
        alternative: &str,
        authenticated: bool,
        timing: NickRegainTiming,
        now: Instant,
    ) -> Self {
        Self {
            configured: configured.to_owned(),
            alternative: alternative.to_owned(),
            timing,
            began: now,
            watch: Watch::Burst,
            services: if authenticated {
                Services::ToAsk
            } else {
                Services::NotAsked
            },
            attempt: Attempt::Idle {
                not_before: now,
                free: false,
            },
        }
    }

    /// The nickname being waited for.
    pub(super) fn configured(&self) -> &str {
        &self.configured
    }

    /// When [`NickRegain::on_tick`] next has something to do.
    pub(super) fn wake(&self) -> Instant {
        let mut wake = self.began + self.timing.window;
        match self.watch {
            Watch::Burst => wake = wake.min(self.began + self.timing.poll),
            Watch::Ison { next } => wake = wake.min(next),
            Watch::Monitor => {}
        }
        if let Attempt::Idle {
            not_before,
            free: true,
        } = self.attempt
        {
            wake = wake.min(not_before);
        }
        wake
    }

    /// What the clock asks: the end of the wait, a poll, a retried `NICK`.
    /// `isupport` is the welcome burst's 005 tokens so far.
    pub(super) fn on_tick(&mut self, now: Instant, isupport: &[String]) -> Step {
        let mut step = Step::default();
        if now >= self.began + self.timing.window {
            step.refused = Some(RegistrationRejection::not_regained(
                &self.configured,
                &self.alternative,
                self.timing.window,
            ));
            return step;
        }
        match self.watch {
            // A burst that never ends (no 376 or 422) is waited for no longer
            // than one poll.
            Watch::Burst if now >= self.began + self.timing.poll => {
                self.start_watching(now, isupport, &mut step);
            }
            Watch::Ison { next } if now >= next => {
                step.send.push(format!("ISON {}", self.configured));
                self.watch = Watch::Ison {
                    next: now + self.timing.poll,
                };
            }
            Watch::Burst | Watch::Ison { .. } | Watch::Monitor => {}
        }
        if let Attempt::Idle { free: true, .. } = self.attempt {
            self.try_nick(now, &mut step);
        }
        step
    }

    /// Read one upstream line for what it says about the nickname.
    pub(super) fn on_line(
        &mut self,
        message: &OwnedMessage,
        names: &NetworkNames,
        isupport: &[String],
        now: Instant,
    ) -> Step {
        let mut step = Step::default();
        match message.command.as_str() {
            // The burst's end: now the upstream's 005 is known.
            "376" | "422" if self.watch == Watch::Burst => {
                self.start_watching(now, isupport, &mut step);
            }
            // RPL_MONONLINE / RPL_MONOFFLINE: `<me> :<target>[,<target>...]`.
            "730" | "731" if self.names_configured(message, names, ',') => {
                step.consumed = true;
                let free = message.command == "731";
                if let Attempt::Idle { not_before, .. } = self.attempt {
                    self.attempt = Attempt::Idle { not_before, free };
                }
                if free {
                    self.try_nick(now, &mut step);
                }
            }
            // ERR_MONLISTFULL: no room to watch it; ask instead.
            "734" if self.watch == Watch::Monitor => {
                step.consumed = true;
                self.watch = Watch::Ison { next: now };
            }
            // RPL_ISON: `<me> :<nick> <nick>...`, naming those online.
            "303" if matches!(self.watch, Watch::Ison { .. }) => {
                step.consumed = true;
                let free = !self.names_configured(message, names, ' ');
                if let Attempt::Idle { not_before, .. } = self.attempt {
                    self.attempt = Attempt::Idle { not_before, free };
                }
                if free {
                    self.try_nick(now, &mut step);
                }
            }
            // A refusal of our `NICK`: held (433), colliding (436), delayed
            // after its last holder (437), or refused for now (435 banned
            // while in a channel, 438 too fast, 447 changes not allowed).
            // Each can end; the next attempt waits a poll.
            "433" | "435" | "436" | "437" | "438" | "447"
                if self.refuses_our_nick(message, names) =>
            {
                step.consumed = true;
                self.attempt = Attempt::Idle {
                    not_before: now + self.timing.poll,
                    // 437 is the nickname already free but delayed.
                    free: message.command == "437",
                };
            }
            // The upstream will never take this nickname from this session.
            "432" if self.refuses_our_nick(message, names) => {
                step.consumed = true;
                step.refused = Some(RegistrationRejection::regain_refused(
                    &self.configured,
                    message
                        .params
                        .last()
                        .map_or("erroneous nickname", String::as_str),
                ));
            }
            "NOTICE" if self.services == Services::Asked && from_nickserv(message, names) => {
                let said = message.params.last().map_or("", String::as_str);
                match ServicesAnswer::read(said) {
                    ServicesAnswer::Refused => {
                        step.refused = Some(RegistrationRejection::regain_refused(
                            &self.configured,
                            &plain_text(said),
                        ));
                    }
                    ServicesAnswer::Free => {
                        self.services = Services::Answered;
                        if let Attempt::Idle { not_before, .. } = self.attempt {
                            self.attempt = Attempt::Idle {
                                not_before,
                                free: true,
                            };
                        }
                        self.try_nick(now, &mut step);
                    }
                    ServicesAnswer::Settled => self.services = Services::Answered,
                    ServicesAnswer::Unrelated => {}
                }
            }
            _ => {}
        }
        step
    }

    /// The lines that end the wait once the nickname is back: the watch is
    /// withdrawn.
    pub(super) fn finished(&self) -> Vec<String> {
        match self.watch {
            Watch::Monitor => vec![format!("MONITOR - {}", self.configured)],
            Watch::Burst | Watch::Ison { .. } => Vec::new(),
        }
    }

    fn start_watching(&mut self, now: Instant, isupport: &[String], step: &mut Step) {
        if self.services == Services::ToAsk {
            step.send
                .push(format!("PRIVMSG NickServ :REGAIN {}", self.configured));
            self.services = Services::Asked;
        }
        let monitor = isupport
            .iter()
            .any(|token| token.split('=').next() == Some("MONITOR"));
        if monitor {
            step.send.push(format!("MONITOR + {}", self.configured));
            self.watch = Watch::Monitor;
        } else {
            step.send.push(format!("ISON {}", self.configured));
            self.watch = Watch::Ison {
                next: now + self.timing.poll,
            };
        }
    }

    fn try_nick(&mut self, now: Instant, step: &mut Step) {
        match self.attempt {
            Attempt::Idle { not_before, .. } if now >= not_before => {
                step.send.push(format!("NICK {}", self.configured));
                self.attempt = Attempt::Sent;
            }
            Attempt::Idle { not_before, .. } => {
                self.attempt = Attempt::Idle {
                    not_before,
                    free: true,
                };
            }
            Attempt::Sent => {}
        }
    }

    /// Whether the trailing list of `message` (split by `separator`, each
    /// entry a nickname or a `nick!user@host`) names the configured nickname.
    fn names_configured(
        &self,
        message: &OwnedMessage,
        names: &NetworkNames,
        separator: char,
    ) -> bool {
        message.params.last().is_some_and(|list| {
            list.split(separator)
                .map(|entry| entry.split('!').next().unwrap_or(entry))
                .any(|nick| names.eq(nick, &self.configured))
        })
    }

    /// Whether `message` refuses the `NICK` this wait sent.
    fn refuses_our_nick(&self, message: &OwnedMessage, names: &NetworkNames) -> bool {
        self.attempt == Attempt::Sent
            && e6irc_client::numeric_subject(message)
                .is_some_and(|subject| names.eq(subject, &self.configured))
    }
}

fn from_nickserv(message: &OwnedMessage, names: &NetworkNames) -> bool {
    message.source.as_deref().is_some_and(|source| {
        let nick = source.split('!').next().unwrap_or(source);
        names.eq(nick, "NickServ")
    })
}

/// A services notice without its formatting (bold, underline, colour), which
/// Atheme and Anope wrap nicknames in.
fn plain_text(said: &str) -> String {
    let mut plain = String::with_capacity(said.len());
    let mut characters = said.chars().peekable();
    while let Some(character) = characters.next() {
        match character {
            '\x03' => {
                // A colour code: up to two digits, then an optional
                // background of up to two.
                for _ in 0..2 {
                    characters.next_if(char::is_ascii_digit);
                }
                if characters.peek() == Some(&',') {
                    characters.next();
                    for _ in 0..2 {
                        characters.next_if(char::is_ascii_digit);
                    }
                }
            }
            character if character.is_control() => {}
            character => plain.push(character),
        }
    }
    plain
}

/// What NickServ said to `REGAIN`, as Atheme (Libera.Chat, OFTC's successor
/// deployments) and Anope word it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServicesAnswer {
    /// The nickname belongs to another account: "Invalid password for X",
    /// "Access denied", "You may not regain X".
    Refused,
    /// Nobody holds it: "X is not online".
    Free,
    /// Answered without settling who may hold it: regained (the services
    /// rename follows), not registered, or a command these services lack. The
    /// watch goes on either way.
    Settled,
    /// Not an answer to the `REGAIN`.
    Unrelated,
}

impl ServicesAnswer {
    fn read(said: &str) -> Self {
        let said = plain_text(said).to_lowercase();
        let says = |phrases: &[&str]| phrases.iter().any(|phrase| said.contains(phrase));
        if says(&[
            "invalid password",
            "access denied",
            "you may not",
            "you do not have access",
            "not authorized",
            "permission denied",
        ]) {
            Self::Refused
        } else if says(&["is not online", "is not in use"]) {
            Self::Free
        } else if says(&[
            "regained",
            "has been released",
            "has been ghosted",
            "not a registered nick",
            "is not registered",
            "isn't registered",
            "unknown command",
            "is not a valid command",
            "invalid command",
        ]) {
            Self::Settled
        } else {
            Self::Unrelated
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(text: &str) -> OwnedMessage {
        OwnedMessage::from(&e6irc_proto::message::Message::parse(text).expect("a test line"))
    }

    fn timing() -> NickRegainTiming {
        NickRegainTiming {
            poll: Duration::from_secs(10),
            window: Duration::from_secs(100),
        }
    }

    fn nick(text: &str) -> UpstreamNick {
        text.parse().expect("a test nickname")
    }

    /// The alternative never outgrows what the upstream is known to take: the
    /// RFC 1459 floor, or the configured nickname's own length.
    #[test]
    fn the_alternative_fits_every_nicklen_the_configured_nickname_fits() {
        assert_eq!(alternative_nick(&nick("alice")), "alice_");
        assert_eq!(alternative_nick(&nick("abcdefgh")), "abcdefgh_");
        assert_eq!(alternative_nick(&nick("abcdefghi")), "abcdefgh_");
        assert_eq!(
            alternative_nick(&nick("sixteen_chars_ab")),
            "sixteen_chars_a_"
        );
        assert_eq!(alternative_nick(&nick("underscore_")), "underscore-");
        assert_eq!(alternative_nick(&nick("héééééééé")), "hééééééé_");
        for configured in ["a", "alice", "abcdefghi", "underscore_", "x_________"] {
            let alternative = alternative_nick(&nick(configured));
            assert_ne!(alternative, configured);
            assert!(alternative.chars().count() <= configured.chars().count().max(9));
            alternative
                .parse::<UpstreamNick>()
                .expect("a valid nickname");
        }
    }

    /// Authenticated, on an upstream with `MONITOR`: at the burst's end it
    /// asks NickServ and watches; the ghost going offline is answered with
    /// one `NICK`, and the answers are the wait's own.
    #[test]
    fn with_monitor_the_nickname_is_taken_when_it_goes_offline() {
        let names = NetworkNames::default();
        let now = Instant::now();
        let isupport = vec!["MONITOR=100".to_owned()];
        let mut regain = NickRegain::new("alice", "alice_", true, timing(), now);
        let step = regain.on_line(&line(":up 376 alice_ :End of MOTD"), &names, &isupport, now);
        assert!(!step.consumed, "the burst's end is the session's");
        assert_eq!(
            step.send,
            ["PRIVMSG NickServ :REGAIN alice", "MONITOR + alice"]
        );
        let online = regain.on_line(&line(":up 730 alice_ :alice!u@h"), &names, &isupport, now);
        assert!(online.consumed && online.send.is_empty());
        let offline = regain.on_line(&line(":up 731 alice_ :Alice"), &names, &isupport, now);
        assert!(offline.consumed);
        assert_eq!(offline.send, ["NICK alice"]);
        let again = regain.on_line(&line(":up 731 alice_ :alice"), &names, &isupport, now);
        assert!(again.send.is_empty(), "one NICK outstanding at a time");
        assert_eq!(regain.finished(), ["MONITOR - alice"]);
    }

    /// Without `MONITOR` it polls with `ISON`, never faster than the poll,
    /// and a lost race waits a poll before the next `NICK`.
    #[test]
    fn without_monitor_the_nickname_is_polled_and_retried_at_the_poll() {
        let names = NetworkNames::default();
        let now = Instant::now();
        let mut regain = NickRegain::new("alice", "alice_", false, timing(), now);
        let step = regain.on_line(&line(":up 422 alice_ :No MOTD"), &names, &[], now);
        assert_eq!(step.send, ["ISON alice"], "no REGAIN without SASL");
        let held = regain.on_line(&line(":up 303 alice_ :alice"), &names, &[], now);
        assert!(held.consumed && held.send.is_empty());
        assert!(
            regain
                .on_tick(now + Duration::from_secs(5), &[])
                .send
                .is_empty()
        );
        let later = now + Duration::from_secs(10);
        assert_eq!(regain.on_tick(later, &[]).send, ["ISON alice"]);
        let free = regain.on_line(&line(":up 303 alice_ :"), &names, &[], later);
        assert_eq!(free.send, ["NICK alice"]);
        let lost = regain.on_line(
            &line(":up 433 alice_ alice :Nickname is already in use"),
            &names,
            &[],
            later,
        );
        assert!(lost.consumed && lost.send.is_empty() && lost.refused.is_none());
        let free = regain.on_line(&line(":up 303 alice_ :"), &names, &[], later);
        assert!(free.send.is_empty(), "the next NICK waits a poll");
        let retry = later + Duration::from_secs(10);
        assert_eq!(regain.wake(), retry);
        assert_eq!(
            regain.on_tick(retry, &[]).send,
            ["ISON alice", "NICK alice"]
        );
    }

    /// A services answer that the nickname is another account's ends the
    /// wait; one that it is unregistered does not.
    #[test]
    fn services_refusal_ends_the_wait_and_other_answers_do_not() {
        let names = NetworkNames::default();
        let now = Instant::now();
        let mut regain = NickRegain::new("alice", "alice_", true, timing(), now);
        regain.on_line(&line(":up 376 alice_ :End"), &names, &[], now);
        let unrelated = regain.on_line(
            &line(":NickServ!s@services NOTICE alice_ :Welcome to the network"),
            &names,
            &[],
            now,
        );
        assert!(unrelated.refused.is_none() && !unrelated.consumed);
        let refused = regain.on_line(
            &line(":NickServ!s@services NOTICE alice_ :Invalid password for \x02alice\x02."),
            &names,
            &[],
            now,
        );
        let rejection = refused.refused.expect("a definite refusal");
        assert_eq!(
            rejection.refusal(),
            e6irc_client::RegistrationRefusal::NicknameRegainRefused
        );
        assert_eq!(
            rejection.diagnostic(),
            "alice cannot be regained: Invalid password for alice."
        );
        assert!(!refused.consumed, "the owner sees services' own words");

        let mut unregistered = NickRegain::new("alice", "alice_", true, timing(), now);
        unregistered.on_line(&line(":up 376 alice_ :End"), &names, &[], now);
        let answer = unregistered.on_line(
            &line(
                ":NickServ!s@services NOTICE alice_ :\x02alice\x02 is not a registered nickname.",
            ),
            &names,
            &[],
            now,
        );
        assert!(answer.refused.is_none());
        let later = unregistered.on_line(
            &line(":NickServ!s@services NOTICE alice_ :Invalid password for alice."),
            &names,
            &[],
            now,
        );
        assert!(later.refused.is_none(), "only the answer to REGAIN counts");
    }

    /// Nobody gives the nickname up within the window: the wait ends with a
    /// refusal that takes the ordinary schedule for a nickname in use.
    #[test]
    fn a_holder_that_outlasts_the_window_ends_the_wait() {
        let now = Instant::now();
        let mut regain = NickRegain::new("alice", "alice_", false, timing(), now);
        assert_eq!(
            regain.wake(),
            now + Duration::from_secs(10),
            "the burst is waited a poll"
        );
        let step = regain.on_tick(now + Duration::from_secs(10), &[]);
        assert_eq!(
            step.send,
            ["ISON alice"],
            "an endless burst is not waited out"
        );
        let end = now + Duration::from_secs(100);
        let rejection = regain.on_tick(end, &[]).refused.expect("the window ended");
        assert_eq!(
            rejection.refusal(),
            e6irc_client::RegistrationRefusal::NicknameInUse
        );
        assert_eq!(
            rejection.diagnostic(),
            "alice was still in use 100s after registering as alice_"
        );
    }

    #[test]
    fn a_refused_nick_other_than_ours_is_not_the_waits() {
        let names = NetworkNames::default();
        let now = Instant::now();
        let mut regain = NickRegain::new("alice", "alice_", false, timing(), now);
        let step = regain.on_line(&line(":up 433 alice_ bob :in use"), &names, &[], now);
        assert!(!step.consumed, "no NICK of ours was outstanding");
        let erroneous = regain.on_line(&line(":up 432 alice_ alice :Erroneous"), &names, &[], now);
        assert!(
            erroneous.refused.is_none(),
            "no NICK of ours was outstanding"
        );
    }
}
