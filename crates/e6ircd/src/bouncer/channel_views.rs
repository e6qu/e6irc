//! What an upstream session has told the bouncer about each channel it is in
//! beyond the membership itself: the topic and the member list, followed line
//! by line. The session's live state and the ring's head state (§10.1) keep
//! one each, so an attaching client is shown a channel's topic and members
//! from what the bouncer already knows — the soju and ZNC way — instead of
//! the upstream being asked again for every channel on every attach.

use std::collections::HashMap;

use e6irc_client::NetworkNames;
use e6irc_proto::message::Message;

use super::UpstreamFeatures;

/// Most channel memberships one session's views hold, over all its channels.
/// The member lists are the upstream's to send, and a tenant may point a
/// network at any server, so without a bound one hostile upstream grows this
/// shared daemon's memory at will; a channel past it keeps its topic and its
/// member list becomes unknown, which the bouncer then asks the upstream for.
/// A heavy user of Libera.Chat — a hundred channels, some of thousands —
/// stays well within it.
pub const MAX_TRACKED_MEMBERSHIPS: usize = 20_000;

/// The topic, as far as the channel's lines have said.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) enum Topic {
    /// Nothing said yet.
    #[default]
    Unknown,
    /// The channel has none (`331`, or a `TOPIC` that cleared it).
    Unset,
    Set {
        text: String,
        /// Who set it and when (Unix seconds), as `333` or the `TOPIC`
        /// line said.
        by: Option<String>,
        at: Option<String>,
    },
}

/// One member: its nick as the network spells it, and the membership modes it
/// holds (letters of the network's `PREFIX`).
#[derive(Debug, Clone, PartialEq, Eq)]
struct Member {
    nick: String,
    modes: String,
}

/// A channel's member list.
#[derive(Debug, Clone, PartialEq, Eq)]
enum MemberList {
    /// Arriving: the `353` lines after our `JOIN` (or a later `NAMES` the
    /// session was sent), until `366`.
    Receiving(HashMap<String, Member>),
    /// Complete, and followed since by every `JOIN`, `PART`, `KICK`, `QUIT`,
    /// `NICK` and membership `MODE`.
    Complete(HashMap<String, Member>),
    /// Not known: past [`MAX_TRACKED_MEMBERSHIPS`].
    Unknown,
}

impl MemberList {
    fn members_mut(&mut self) -> Option<&mut HashMap<String, Member>> {
        match self {
            Self::Receiving(members) | Self::Complete(members) => Some(members),
            Self::Unknown => None,
        }
    }

    fn len(&self) -> usize {
        match self {
            Self::Receiving(members) | Self::Complete(members) => members.len(),
            Self::Unknown => 0,
        }
    }
}

/// What is known of one channel.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ChannelView {
    topic: Topic,
    /// The `353` channel type (`=` public, `@` secret, `*` private).
    symbol: char,
    members: MemberList,
}

impl ChannelView {
    fn joined() -> Self {
        Self {
            topic: Topic::Unknown,
            symbol: '=',
            members: MemberList::Receiving(HashMap::new()),
        }
    }

    /// The topic, as far as it is known.
    pub(super) fn topic(&self) -> &Topic {
        &self.topic
    }

    /// Whether the member list is complete, and so can be told as it is.
    pub(super) fn members_known(&self) -> bool {
        matches!(self.members, MemberList::Complete(_))
    }

    /// The member list as `353` lines (`:<server> 353 <nick> <symbol>
    /// <channel> :<members>`) and its `366`, each within one IRC line, when
    /// the list is complete; members sorted as the network folds them.
    pub(super) fn names_reply(
        &self,
        server: &str,
        nick: &str,
        channel: &str,
        features: &UpstreamFeatures,
    ) -> Option<Vec<String>> {
        let MemberList::Complete(members) = &self.members else {
            return None;
        };
        let prefix = Prefix::of(features);
        let mut shown: Vec<(&String, String)> = members
            .iter()
            .map(|(folded, member)| {
                (
                    folded,
                    format!("{}{}", prefix.symbol(&member.modes), member.nick),
                )
            })
            .collect();
        shown.sort_by_key(|(folded, _)| *folded);
        let head = format!(":{server} 353 {nick} {} {channel} :", self.symbol);
        let mut lines = Vec::new();
        let mut line = head.clone();
        for (_, member) in shown {
            if line.len() > head.len()
                && line.len() + 1 + member.len() + 2 > e6irc_proto::message::MAX_LINE_LEN
            {
                lines.push(std::mem::replace(&mut line, head.clone()));
            }
            if line.len() > head.len() {
                line.push(' ');
            }
            line.push_str(&member);
        }
        if line.len() > head.len() {
            lines.push(line);
        }
        let end = format!(":{server} 366 {nick} {channel} :");
        lines.push(format!(
            "{end}{}",
            crate::core::fit_trailing(&end, "End of /NAMES list")
        ));
        Some(lines)
    }

    /// The topic as `332` (and `333`, when who set it is known), or `331`
    /// when the channel has none; `None` while it is not known.
    pub(super) fn topic_reply(
        &self,
        server: &str,
        nick: &str,
        channel: &str,
    ) -> Option<Vec<String>> {
        match &self.topic {
            Topic::Unknown => None,
            Topic::Unset => {
                let head = format!(":{server} 331 {nick} {channel} :");
                Some(vec![format!(
                    "{head}{}",
                    crate::core::fit_trailing(&head, "No topic is set")
                )])
            }
            Topic::Set { text, by, at } => {
                let head = format!(":{server} 332 {nick} {channel} :");
                let mut lines = vec![format!("{head}{}", crate::core::fit_trailing(&head, text))];
                if let (Some(by), Some(at)) = (by, at) {
                    lines.push(format!(":{server} 333 {nick} {channel} {by} {at}"));
                }
                Some(lines)
            }
        }
    }
}

/// The network's membership modes and the symbols that show them, most
/// powerful first (`PREFIX=(ov)@+`).
struct Prefix {
    modes: Vec<char>,
    symbols: Vec<char>,
}

impl Prefix {
    fn of(features: &UpstreamFeatures) -> Self {
        let prefix = isupport_value(features, "PREFIX").unwrap_or("(ov)@+");
        let (modes, symbols) = prefix
            .strip_prefix('(')
            .and_then(|rest| rest.split_once(')'))
            .unwrap_or(("ov", "@+"));
        Self {
            modes: modes.chars().collect(),
            symbols: symbols.chars().collect(),
        }
    }

    /// The symbol of the most powerful of `modes`, or nothing.
    fn symbol(&self, modes: &str) -> String {
        self.modes
            .iter()
            .zip(&self.symbols)
            .find(|(mode, _)| modes.contains(**mode))
            .map_or_else(String::new, |(_, symbol)| symbol.to_string())
    }

    /// A `353` entry as its nick and the modes its symbols show.
    fn split<'entry>(&self, entry: &'entry str) -> (&'entry str, String) {
        let nick = entry.trim_start_matches(|c| self.symbols.contains(&c));
        let modes = entry[..entry.len() - nick.len()]
            .chars()
            .filter_map(|symbol| {
                self.symbols
                    .iter()
                    .position(|known| *known == symbol)
                    .map(|index| self.modes[index])
            })
            .collect();
        // `userhost-in-names` shows `nick!user@host`; the nick is the member.
        let nick = nick.split_once('!').map_or(nick, |(nick, _)| nick);
        (nick, modes)
    }
}

/// The value of ISUPPORT token `name`, when the network advertised one.
fn isupport_value<'features>(
    features: &'features UpstreamFeatures,
    name: &str,
) -> Option<&'features str> {
    features.isupport.iter().find_map(|token| {
        token
            .strip_prefix(name)
            .and_then(|rest| rest.strip_prefix('='))
    })
}

/// The changes one channel `MODE` line makes, each with the argument it
/// takes: which modes take one is the network's to say (`CHANMODES` and
/// `PREFIX`), read with RFC 2811's defaults when it has said nothing.
pub(super) fn channel_mode_changes<'line, S: AsRef<str>>(
    features: &UpstreamFeatures,
    modes: &str,
    arguments: &'line [S],
) -> Vec<(bool, char, Option<&'line str>)> {
    let chanmodes = isupport_value(features, "CHANMODES").unwrap_or("beI,k,l,imnpst");
    let membership: Vec<char> = Prefix::of(features).modes;
    let mut kinds = chanmodes.split(',');
    let (always, parameter, when_set) = (
        kinds.next().unwrap_or(""),
        kinds.next().unwrap_or(""),
        kinds.next().unwrap_or(""),
    );
    let mut arguments = arguments.iter().map(AsRef::as_ref);
    let mut adding = true;
    let mut changes = Vec::new();
    for mode in modes.chars() {
        match mode {
            '+' => adding = true,
            '-' => adding = false,
            mode => {
                let takes = always.contains(mode)
                    || parameter.contains(mode)
                    || membership.contains(&mode)
                    || (adding && when_set.contains(mode));
                let argument = if takes { arguments.next() } else { None };
                changes.push((adding, mode, argument));
            }
        }
    }
    changes
}

/// The views of every channel a session is in, keyed by the network's fold
/// of the channel name.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(super) struct ChannelViews {
    channels: HashMap<String, ChannelView>,
    /// Members held over all channels, bounded by
    /// [`MAX_TRACKED_MEMBERSHIPS`].
    memberships: usize,
}

impl ChannelViews {
    /// The view of the channel `folded`, when the session is in it and it is
    /// followed.
    pub(super) fn get(&self, folded: &str) -> Option<&ChannelView> {
        self.channels.get(folded)
    }

    pub(super) fn clear(&mut self) {
        self.channels.clear();
        self.memberships = 0;
    }

    /// Key every view under `names`, the network's naming rules now;
    /// `channels` are the session's channels under the keys the views had.
    pub(super) fn rekey(
        &mut self,
        names: &NetworkNames,
        channels: &HashMap<String, super::upstream_identity::ConfirmedChannel>,
    ) {
        self.channels = std::mem::take(&mut self.channels)
            .into_iter()
            .filter_map(|(folded, mut view)| {
                let display = channels.get(&folded)?.as_str();
                if let Some(members) = view.members.members_mut() {
                    *members = std::mem::take(members)
                        .into_values()
                        .map(|member| (names.fold(&member.nick), member))
                        .collect();
                }
                Some((names.fold(display), view))
            })
            .collect();
        self.memberships = self.channels.values().map(|view| view.members.len()).sum();
    }

    /// The session joined `folded`: its list and topic follow.
    pub(super) fn joined(&mut self, folded: String) {
        self.left(&folded);
        self.channels.insert(folded, ChannelView::joined());
    }

    /// The session left `folded`.
    pub(super) fn left(&mut self, folded: &str) {
        if let Some(view) = self.channels.remove(folded) {
            self.memberships -= view.members.len();
        }
    }

    /// Follow one line of the session. `own` is the session's nick before
    /// the line; its own membership changes were applied by the caller.
    pub(super) fn observe(
        &mut self,
        message: &Message<'_>,
        names: &NetworkNames,
        features: &UpstreamFeatures,
        own: &str,
    ) {
        let source = message.source.as_ref().map(|source| source.name);
        let from_us = source.is_some_and(|source| names.eq(source, own));
        let param = |index: usize| message.params.get(index).copied();
        let channels = |index: usize| -> Vec<String> {
            param(index)
                .map(|list| {
                    list.split(',')
                        .filter(|name| !name.is_empty())
                        .map(|name| names.fold(name))
                        .collect()
                })
                .unwrap_or_default()
        };
        match message.command.to_ascii_uppercase().as_str() {
            "JOIN" => {
                if let Some(nick) = source.filter(|_| !from_us) {
                    for channel in channels(0) {
                        self.add_member(&channel, nick, String::new(), names);
                    }
                }
            }
            "PART" if !from_us => {
                if let Some(nick) = source {
                    for channel in channels(0) {
                        self.remove_member(&channel, nick, names);
                    }
                }
            }
            "KICK" => {
                let (kicked_channels, targets) = (channels(0), param(1).unwrap_or(""));
                let targets: Vec<&str> = targets.split(',').collect();
                for (index, channel) in kicked_channels.iter().enumerate() {
                    let target = targets
                        .get(index)
                        .or(targets.first())
                        .copied()
                        .unwrap_or("");
                    if !names.eq(target, own) {
                        self.remove_member(channel, target, names);
                    }
                }
            }
            "QUIT" if !from_us => {
                if let Some(nick) = source {
                    let folded = names.fold(nick);
                    let mut removed = 0;
                    for view in self.channels.values_mut() {
                        if let Some(members) = view.members.members_mut()
                            && members.remove(&folded).is_some()
                        {
                            removed += 1;
                        }
                    }
                    self.memberships -= removed;
                }
            }
            "NICK" => {
                if let (Some(old), Some(new)) = (source, param(0)) {
                    let (old, folded_new) = (names.fold(old), names.fold(new));
                    for view in self.channels.values_mut() {
                        if let Some(members) = view.members.members_mut()
                            && let Some(mut member) = members.remove(&old)
                        {
                            member.nick = new.to_string();
                            members.insert(folded_new.clone(), member);
                        }
                    }
                }
            }
            // RPL_NAMREPLY: `353 <nick> [<symbol>] <channel> :<members>`.
            "353" if message.params.len() >= 3 => {
                let count = message.params.len();
                let channel = names.fold(message.params[count - 2]);
                let symbol = (count >= 4)
                    .then(|| message.params[count - 3].chars().next())
                    .flatten();
                let prefix = Prefix::of(features);
                let Some(view) = self.channels.get_mut(&channel) else {
                    return;
                };
                if let Some(symbol) = symbol {
                    view.symbol = symbol;
                }
                // A list after a complete one is a new list.
                if let MemberList::Complete(members) = &mut view.members {
                    self.memberships -= members.len();
                    view.members = MemberList::Receiving(HashMap::new());
                }
                for entry in message.params[count - 1]
                    .split(' ')
                    .filter(|entry| !entry.is_empty())
                {
                    let (nick, modes) = prefix.split(entry);
                    if !nick.is_empty() {
                        self.add_member(&channel, nick, modes, names);
                    }
                }
            }
            // RPL_ENDOFNAMES: `366 <nick> <channel> :End of /NAMES list`.
            "366" => {
                if let Some(view) =
                    param(1).and_then(|channel| self.channels.get_mut(&names.fold(channel)))
                    && let MemberList::Receiving(members) = &mut view.members
                {
                    view.members = MemberList::Complete(std::mem::take(members));
                }
            }
            // RPL_NOTOPIC, RPL_TOPIC, RPL_TOPICWHOTIME.
            "331" | "332" | "333" => {
                let Some(view) =
                    param(1).and_then(|channel| self.channels.get_mut(&names.fold(channel)))
                else {
                    return;
                };
                match message.command {
                    "331" => view.topic = Topic::Unset,
                    "332" => {
                        view.topic = Topic::Set {
                            text: message.params.last().copied().unwrap_or("").to_string(),
                            by: None,
                            at: None,
                        };
                    }
                    _ => {
                        if let Topic::Set { by, at, .. } = &mut view.topic {
                            *by = param(2).map(str::to_string);
                            *at = param(3).map(str::to_string);
                        }
                    }
                }
            }
            "TOPIC" => {
                let Some(view) =
                    param(0).and_then(|channel| self.channels.get_mut(&names.fold(channel)))
                else {
                    return;
                };
                let text = param(1).unwrap_or("");
                view.topic = if text.is_empty() {
                    Topic::Unset
                } else {
                    Topic::Set {
                        text: text.to_string(),
                        by: source.map(str::to_string),
                        at: message
                            .tag("time")
                            .and_then(|tag| tag.value.as_deref())
                            .and_then(e6irc_proto::time::parse_server_time_millis)
                            .map(|millis| (millis.as_millis() / 1000).to_string()),
                    }
                };
            }
            "MODE" => {
                let (Some(channel), Some(modes)) = (param(0), param(1)) else {
                    return;
                };
                let Some(view) = self.channels.get_mut(&names.fold(channel)) else {
                    return;
                };
                let Some(members) = view.members.members_mut() else {
                    return;
                };
                let membership = Prefix::of(features).modes;
                for (adding, mode, argument) in
                    channel_mode_changes(features, modes, &message.params[2..])
                {
                    let (true, Some(nick)) = (membership.contains(&mode), argument) else {
                        continue;
                    };
                    if let Some(member) = members.get_mut(&names.fold(nick)) {
                        if adding && !member.modes.contains(mode) {
                            member.modes.push(mode);
                        } else if !adding {
                            member.modes.retain(|held| held != mode);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn add_member(&mut self, channel: &str, nick: &str, modes: String, names: &NetworkNames) {
        let Some(view) = self.channels.get_mut(channel) else {
            return;
        };
        let full = self.memberships >= MAX_TRACKED_MEMBERSHIPS;
        let held = view.members.len();
        let Some(members) = view.members.members_mut() else {
            return;
        };
        let folded = names.fold(nick);
        if let Some(member) = members.get_mut(&folded) {
            for mode in modes.chars() {
                if !member.modes.contains(mode) {
                    member.modes.push(mode);
                }
            }
            return;
        }
        if full {
            // Past the bound this channel's list is no longer known; what it
            // held is given back.
            view.members = MemberList::Unknown;
            self.memberships -= held;
            return;
        }
        members.insert(
            folded,
            Member {
                nick: nick.to_string(),
                modes,
            },
        );
        self.memberships += 1;
    }

    fn remove_member(&mut self, channel: &str, nick: &str, names: &NetworkNames) {
        if let Some(members) = self
            .channels
            .get_mut(channel)
            .and_then(|view| view.members.members_mut())
            && members.remove(&names.fold(nick)).is_some()
        {
            self.memberships -= 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn features(tokens: &[&str]) -> UpstreamFeatures {
        UpstreamFeatures {
            isupport: tokens.iter().map(|token| token.to_string()).collect(),
            ..UpstreamFeatures::default()
        }
    }

    fn observe(views: &mut ChannelViews, features: &UpstreamFeatures, line: &str) {
        let message = Message::parse(line).expect("a test line");
        views.observe(&message, &NetworkNames::default(), features, "me");
    }

    /// A channel's list is what its `353`s said, followed through every change
    /// of membership, and told back in the network's own prefixes.
    #[test]
    fn a_member_list_follows_its_channel() {
        let features = features(&["PREFIX=(qov)~@+"]);
        let mut views = ChannelViews::default();
        views.joined("#room".into());
        for line in [
            ":srv 332 me #Room :the topic",
            ":srv 333 me #Room setter 1700000000",
            ":srv 353 me = #Room :~boss @op +voice me",
            ":srv 353 me = #Room :plain",
        ] {
            observe(&mut views, &features, line);
        }
        let view = views.get("#room").expect("followed");
        assert!(!view.members_known(), "not complete before its 366");
        observe(
            &mut views,
            &features,
            ":srv 366 me #Room :End of /NAMES list",
        );
        for line in [
            ":new!u@h JOIN #Room",
            ":plain!u@h PART #Room :bye",
            ":op!u@h NICK :op2",
            ":boss!u@h MODE #Room +v-q new boss",
            ":boss!u@h KICK #Room voice :out",
            ":boss!u@h TOPIC #Room :newer",
        ] {
            observe(&mut views, &features, line);
        }
        let view = views.get("#room").expect("followed");
        assert_eq!(
            view.names_reply("*bnc*", "me", "#Room", &features),
            Some(vec![
                ":*bnc* 353 me = #Room :boss me +new @op2".to_string(),
                ":*bnc* 366 me #Room :End of /NAMES list".to_string(),
            ])
        );
        assert_eq!(
            view.topic_reply("*bnc*", "me", "#Room"),
            Some(vec![":*bnc* 332 me #Room :newer".to_string()])
        );
        observe(&mut views, &features, ":boss!u@h QUIT :gone");
        assert_eq!(views.memberships, 3);
    }

    /// The views hold at most [`MAX_TRACKED_MEMBERSHIPS`]: a channel whose list
    /// would pass it is no longer known, and what it held is given back.
    #[test]
    fn member_lists_are_bounded() {
        let features = features(&[]);
        let mut views = ChannelViews::default();
        views.joined("#big".into());
        views.joined("#small".into());
        observe(&mut views, &features, ":srv 353 me = #small :me you");
        observe(&mut views, &features, ":srv 366 me #small :End");
        let mut sent = 0;
        while views
            .get("#big")
            .is_some_and(|view| view.members.len() == sent)
        {
            let batch: Vec<String> = (sent..sent + 50).map(|n| format!("n{n}")).collect();
            observe(
                &mut views,
                &features,
                &format!(":srv 353 me = #big :{}", batch.join(" ")),
            );
            sent += 50;
            assert!(views.memberships <= MAX_TRACKED_MEMBERSHIPS);
        }
        assert_eq!(
            views.get("#big").map(|view| &view.members),
            Some(&MemberList::Unknown)
        );
        assert_eq!(views.memberships, 2, "the other channel's list is kept");
        assert!(views.get("#small").is_some_and(ChannelView::members_known));
    }
}
