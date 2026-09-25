//! How a bridge shows provider accounts on IRC.
//!
//! A bridge relays posts from many provider accounts into one IRC session, and
//! echoes the owner's own posts under the owner's provider account. An IRC
//! client decides "this line is mine" by the source nick, so a relayed sender
//! shown under the owner's nick is read as something the owner said, and two
//! senders shown under one nick are one person to every client. Provider
//! *names* cannot be the key: a Matrix localpart is unique only on its own
//! homeserver, a Slack display name and a Discord webhook's username are free
//! text anyone sets. [`BridgedSenders`] keys every account by the provider's own
//! stable id and hands out nicks so that no other account is ever shown under
//! the owner's nick, and no two accounts it is currently showing share one.

use std::collections::HashMap;

use e6irc_proto::casemap::CaseMapping;

use super::irc_driver::SelfIdentity;
use crate::recency::Recency;

/// Senders one bridge session keeps a nick for. Past it the least recently
/// seen sender is forgotten; if it posts again it is given a nick afresh. The
/// owner's nick is never among those handed out, whatever was forgotten.
const MAX_BRIDGED_SENDERS: usize = 4_096;

/// Longest nick a bridge shows, matching [`crate::sanitize::nick_token`].
const MAX_BRIDGED_NICK: usize = 30;

/// A provider account as the bridge learned it.
#[derive(Debug, Clone, Copy)]
pub(crate) struct ProviderAccount<'a> {
    /// The provider's stable, unique id for the account: a Matrix user id, a
    /// Slack user or bot id, a Discord user id. Two accounts never share one.
    pub(crate) id: &'a str,
    /// What the provider calls the account; becomes the nick when free.
    pub(crate) name: &'a str,
    /// The prefix's user part.
    pub(crate) user: &'a str,
    /// The prefix's host part: where the account lives (a Matrix homeserver)
    /// or the platform.
    pub(crate) host: &'a str,
}

impl ProviderAccount<'_> {
    fn shown_as(&self, nick: String) -> SelfIdentity {
        SelfIdentity {
            nick,
            user: crate::sanitize::nick_token(self.user),
            host: host_token(self.host),
        }
    }
}

/// A host for the prefix position: the characters a hostname uses, anything
/// else replaced, bounded like a DNS label run.
fn host_token(raw: &str) -> String {
    let mut out: String = raw
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-') {
                c
            } else {
                '-'
            }
        })
        .take(63)
        .collect();
    if out.is_empty() {
        out.push('-');
    }
    out
}

/// The nicks one bridge session shows, by provider account id.
pub(crate) struct BridgedSenders {
    own_id: String,
    own: SelfIdentity,
    /// Account id → the name its nick was derived from, and how it is shown.
    shown: HashMap<String, (String, SelfIdentity)>,
    /// Folded nick → the account id holding it.
    holders: HashMap<String, String>,
    /// The keys of `shown`, least recently seen first — a stamp per relayed
    /// post, not a search of every shown sender.
    recency: Recency<String>,
}

impl BridgedSenders {
    /// The directory for a session logged in as `own`: the owner's identity is
    /// fixed here, and is what the session's nick and every echo use.
    pub(crate) fn new(own: ProviderAccount<'_>) -> Self {
        Self {
            own_id: own.id.to_string(),
            own: own.shown_as(crate::sanitize::nick_token(own.name)),
            shown: HashMap::new(),
            holders: HashMap::new(),
            recency: Recency::default(),
        }
    }

    /// The owner's identity: the session's nick and the prefix of its echoes.
    pub(crate) fn own(&self) -> &SelfIdentity {
        &self.own
    }

    /// How `account` is shown. The owner's own account is shown as the owner;
    /// any other gets its name as a nick when that is neither the owner's nick
    /// nor one another shown account holds, and a numbered variant otherwise.
    /// An account keeps its nick while its name stays the same; a renamed one
    /// (or one whose name was unknown before) is given one for the new name.
    pub(crate) fn identity(&mut self, account: ProviderAccount<'_>) -> SelfIdentity {
        if account.id == self.own_id {
            return self.own.clone();
        }
        let base = crate::sanitize::nick_token(account.name);
        let id = account.id.to_string();
        match self.shown.get(&id) {
            Some((named, shown)) if *named == base => {
                let shown = shown.clone();
                self.recency.touch(&id);
                return shown;
            }
            Some((_, renamed)) => {
                self.holders.remove(&fold(&renamed.nick));
                self.shown.remove(&id);
                self.recency.remove(&id);
            }
            None => {}
        }
        if self.shown.len() >= MAX_BRIDGED_SENDERS {
            let oldest = self
                .recency
                .pop_oldest()
                .expect("recency holds every shown sender");
            let (_, forgotten) = self
                .shown
                .remove(&oldest)
                .expect("recency holds only shown senders");
            self.holders.remove(&fold(&forgotten.nick));
        }
        let shown = account.shown_as(self.free_nick(&base));
        self.holders.insert(fold(&shown.nick), id.clone());
        self.shown.insert(id.clone(), (base, shown.clone()));
        self.recency.touch(&id);
        shown
    }

    /// `base` if no one holds it, else the first free `base|N`.
    fn free_nick(&self, base: &str) -> String {
        let own = fold(&self.own.nick);
        let taken = |nick: &str| {
            let folded = fold(nick);
            folded == own || self.holders.contains_key(&folded)
        };
        if !taken(base) {
            return base.to_string();
        }
        (2u32..)
            .map(|n| {
                let suffix = format!("|{n}");
                let keep = MAX_BRIDGED_NICK.saturating_sub(suffix.len());
                let stem: String = base.chars().take(keep).collect();
                format!("{stem}{suffix}")
            })
            .find(|candidate| !taken(candidate))
            .expect("at most MAX_BRIDGED_SENDERS + 1 nicks are held")
    }
}

fn fold(nick: &str) -> String {
    CaseMapping::Rfc1459.casefold(nick)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn account<'a>(id: &'a str, name: &'a str, host: &'a str) -> ProviderAccount<'a> {
        ProviderAccount {
            id,
            name,
            user: name,
            host,
        }
    }

    fn prefix(identity: &SelfIdentity) -> String {
        format!("{}!{}@{}", identity.nick, identity.user, identity.host)
    }

    #[test]
    fn no_other_account_is_ever_shown_as_the_owner() {
        let mut senders =
            BridgedSenders::new(account("@alice:home.example", "alice", "home.example"));
        let own = prefix(senders.own());
        assert_eq!(own, "alice!alice@home.example");
        // The owner's own account, seen again, is the owner.
        assert_eq!(
            prefix(&senders.identity(account("@alice:home.example", "alice", "home.example"))),
            own
        );
        // Same localpart on another homeserver, and every case and
        // sanitization spelling of the owner's nick, is someone else.
        for (id, name) in [
            ("@alice:evil.example", "alice"),
            ("@ALICE:evil.example", "ALICE"),
            ("@alice:other.example", "alice"),
        ] {
            let shown = senders.identity(account(id, name, "evil.example"));
            assert_ne!(fold(&shown.nick), fold(&senders.own().nick), "{shown:?}");
            assert_ne!(prefix(&shown), own);
        }
    }

    #[test]
    fn two_accounts_with_one_name_get_two_nicks_and_keep_them() {
        let mut senders = BridgedSenders::new(account("U0", "me", "slack"));
        let first = senders.identity(account("U1", "bob", "slack"));
        let second = senders.identity(account("U2", "Bob", "slack"));
        assert_eq!(first.nick, "bob");
        assert_eq!(second.nick, "Bob|2");
        // Stable for as long as each is shown.
        assert_eq!(senders.identity(account("U2", "Bob", "slack")), second);
        assert_eq!(senders.identity(account("U1", "bob", "slack")), first);
        // A literal name that equals a generated one does not take it.
        assert_eq!(
            senders.identity(account("U3", "Bob|2", "slack")).nick,
            "Bob|2|2"
        );
        // A rename frees the old nick and takes the new name.
        assert_eq!(
            senders.identity(account("U1", "carol", "slack")).nick,
            "carol"
        );
        assert_eq!(senders.identity(account("U4", "bob", "slack")).nick, "bob");
    }

    #[test]
    fn a_forgotten_sender_frees_its_nick_but_never_the_owners() {
        let mut senders = BridgedSenders::new(account("U0", "me", "slack"));
        for index in 0..MAX_BRIDGED_SENDERS {
            senders.identity(account(
                &format!("U{}", index + 1),
                &format!("n{index}"),
                "slack",
            ));
        }
        let late = senders.identity(account("late", "me", "slack"));
        assert_ne!(fold(&late.nick), fold("me"));
        assert!(senders.shown.len() <= MAX_BRIDGED_SENDERS);
        assert_eq!(senders.holders.len(), senders.shown.len());
        senders.assert_consistent();
    }

    /// The least recently *seen* sender is the one forgotten: seeing one
    /// again protects it, and the indexes agree with a recount after every
    /// kind of change — a new sender, a repeat, a rename, an eviction.
    #[test]
    fn eviction_follows_recency_and_indexes_stay_consistent() {
        let mut senders = BridgedSenders::new(account("U0", "me", "slack"));
        for index in 0..MAX_BRIDGED_SENDERS {
            senders.identity(account(
                &format!("U{index}x"),
                &format!("n{index}"),
                "slack",
            ));
        }
        senders.assert_consistent();
        // Seen again: now the most recent, so U1x is the oldest.
        senders.identity(account("U0x", "n0", "slack"));
        senders.assert_consistent();
        // A rename keeps the sender shown and makes it the most recent.
        assert_eq!(
            senders.identity(account("U1x", "renamed", "slack")).nick,
            "renamed"
        );
        senders.assert_consistent();
        senders.identity(account("new", "fresh", "slack"));
        senders.assert_consistent();
        assert!(senders.shown.contains_key("U0x"), "seen again, kept");
        assert!(senders.shown.contains_key("U1x"), "renamed, kept");
        assert!(!senders.shown.contains_key("U2x"), "least recently seen");
        assert!(senders.recency.len() <= MAX_BRIDGED_SENDERS);
    }

    impl BridgedSenders {
        fn assert_consistent(&self) {
            assert_eq!(self.recency.len(), self.shown.len());
            assert!(self.shown.keys().all(|id| self.recency.contains(id)));
            let holders: HashMap<String, String> = self
                .shown
                .iter()
                .map(|(id, (_, shown))| (fold(&shown.nick), id.clone()))
                .collect();
            assert_eq!(self.holders, holders);
        }
    }
}
