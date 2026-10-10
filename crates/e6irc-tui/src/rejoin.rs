//! What a reconnect joins again: the channels this client is confirmed in,
//! each with the key it last joined with.
//!
//! A key is a channel password. It is kept in this process's memory only,
//! for as long as the process runs, and never written anywhere: it is what a
//! `+k` channel needs to be rejoined after the connection drops, and nothing
//! else reads it.

use std::collections::BTreeSet;

use e6irc_client::{NetworkNames, OwnedMessage};

/// Keys remembered at most. Every one was typed by this client's user, so the
/// bound is generous; past it the oldest is forgotten.
const MAX_KEYS: usize = 256;

/// The channels to join on the next connection, and their keys.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Rejoin {
    /// Channels whose own JOIN the server confirmed, as it spelled them.
    channels: BTreeSet<String>,
    /// The key each channel was last joined with, oldest first. A key is
    /// remembered when the JOIN that carries it is sent: the server's
    /// confirmation does not repeat it.
    keys: Vec<(String, String)>,
}

impl<const N: usize> From<[&str; N]> for Rejoin {
    fn from(channels: [&str; N]) -> Self {
        Self {
            channels: channels.into_iter().map(str::to_owned).collect(),
            keys: Vec::new(),
        }
    }
}

impl Rejoin {
    /// The first connection's channel.
    pub fn initial(channel: String) -> Self {
        Self {
            channels: BTreeSet::from([channel]),
            keys: Vec::new(),
        }
    }

    /// Whether `channel`, spelled exactly so, is to be rejoined.
    pub fn contains(&self, channel: &str) -> bool {
        self.channels.contains(channel)
    }

    pub fn len(&self) -> usize {
        self.channels.len()
    }

    pub fn is_empty(&self) -> bool {
        self.channels.is_empty()
    }

    /// Each channel to join, with the key to join it with, under `names`.
    pub fn to_join(&self, names: &NetworkNames) -> Vec<(String, Option<String>)> {
        self.channels
            .iter()
            .map(|channel| (channel.clone(), self.key(names, channel).map(str::to_owned)))
            .collect()
    }

    fn key(&self, names: &NetworkNames, channel: &str) -> Option<&str> {
        self.keys
            .iter()
            .find(|(keyed, _)| names.eq(keyed, channel))
            .map(|(_, key)| key.as_str())
    }

    /// Remember the keys a `JOIN` line about to be sent carries
    /// (`JOIN #a,#b keyA,keyB`): the last JOIN said for a channel is the one
    /// a reconnect repeats, so one without a key forgets an earlier key.
    pub fn note_sent(&mut self, names: &NetworkNames, line: &str) {
        let mut words = line.split(' ').filter(|word| !word.is_empty());
        if !words
            .next()
            .is_some_and(|command| command.eq_ignore_ascii_case("JOIN"))
        {
            return;
        }
        let Some(channels) = words.next() else {
            return;
        };
        let mut keys = words.next().unwrap_or("").split(',');
        for channel in channels.split(',').filter(|channel| !channel.is_empty()) {
            self.keys.retain(|(keyed, _)| !names.eq(keyed, channel));
            if let Some(key) = keys.next().filter(|key| !key.is_empty()) {
                if self.keys.len() == MAX_KEYS {
                    self.keys.remove(0);
                }
                self.keys.push((channel.to_owned(), key.to_owned()));
            }
        }
    }

    /// The server refused `channel`: it is not rejoined, and its key is
    /// forgotten.
    pub fn refused(&mut self, names: &NetworkNames, channel: &str) {
        self.remove(names, channel);
    }

    /// Keep the set in step with the server: an own JOIN adds the channel
    /// (one entry under any spelling), an own PART or KICK removes it with
    /// its key, and an own NICK changes the name the others are recognised
    /// under.
    pub fn track(&mut self, own_nick: &mut String, names: &NetworkNames, message: &OwnedMessage) {
        if message.command == "KICK"
            && message
                .params
                .get(1)
                .is_some_and(|nick| names.eq(nick, own_nick))
        {
            if let Some(channel) = message.params.first() {
                self.remove(names, channel);
            }
            return;
        }
        let source_nick = message
            .source
            .as_deref()
            .and_then(|source| source.split('!').next());
        if !source_nick.is_some_and(|nick| names.eq(nick, own_nick)) {
            return;
        }
        match (message.command.as_str(), message.params.first()) {
            // A JOIN of a channel already held under another spelling is the
            // same channel: one entry, or a reconnect joins it twice.
            ("JOIN", Some(channel))
                if !self.channels.iter().any(|held| names.eq(held, channel)) =>
            {
                self.channels.insert(channel.clone());
            }
            ("PART", Some(channel)) => self.remove(names, channel),
            ("NICK", Some(nick)) => own_nick.clone_from(nick),
            _ => {}
        }
    }

    fn remove(&mut self, names: &NetworkNames, channel: &str) {
        self.channels.retain(|held| !names.eq(held, channel));
        self.keys.retain(|(keyed, _)| !names.eq(keyed, channel));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(raw: &str) -> OwnedMessage {
        OwnedMessage::from(&e6irc_proto::message::Message::parse(raw).unwrap())
    }

    /// A keyed channel is rejoined with the key it was joined with — the one
    /// the JOIN carried, since the server's confirmation does not repeat it —
    /// and the key goes with the channel when it is left.
    #[test]
    fn a_keyed_channel_is_rejoined_with_its_key_until_it_is_left() {
        let names = NetworkNames::default();
        let mut nick = "me".to_owned();
        let mut rejoin = Rejoin::initial("#home".into());
        rejoin.note_sent(&names, "JOIN #Locked,#open,#other sesame,,");
        rejoin.track(&mut nick, &names, &message(":me!u@h JOIN #locked"));
        rejoin.track(&mut nick, &names, &message(":me!u@h JOIN #open"));
        assert_eq!(
            rejoin.to_join(&names),
            [
                ("#home".to_owned(), None),
                ("#locked".to_owned(), Some("sesame".to_owned())),
                ("#open".to_owned(), None),
            ]
        );
        // The last JOIN said is the one repeated.
        rejoin.note_sent(&names, "JOIN #locked opened");
        assert_eq!(rejoin.to_join(&names)[1].1.as_deref(), Some("opened"));
        rejoin.track(&mut nick, &names, &message(":me!u@h PART #LOCKED"));
        assert!(!rejoin.contains("#locked"));
        // Joined again without a key, it is rejoined without one.
        rejoin.track(&mut nick, &names, &message(":me!u@h JOIN #locked"));
        assert_eq!(rejoin.to_join(&names)[1], ("#locked".to_owned(), None));
        // Lines that are not a JOIN remember nothing.
        rejoin.note_sent(&names, "PRIVMSG #open :JOIN #open key");
        assert_eq!(rejoin.to_join(&names)[2], ("#open".to_owned(), None));
    }

    #[test]
    fn remembered_keys_are_bounded() {
        let names = NetworkNames::default();
        let mut rejoin = Rejoin::default();
        for i in 0..MAX_KEYS + 5 {
            rejoin.note_sent(&names, &format!("JOIN #c{i} key{i}"));
        }
        assert_eq!(rejoin.keys.len(), MAX_KEYS);
        assert_eq!(rejoin.keys[0].0, "#c5", "the oldest went first");
    }
}
