//! How one network names things: which targets are channels (`CHANTYPES`)
//! and when two names are the same (`CASEMAPPING`), as its `RPL_ISUPPORT`
//! (005) declares them. Every native client compares names and classifies
//! targets through one [`NetworkNames`], so none of them hard-codes RFC 1459
//! and `#&` while the network says otherwise.

use e6irc_proto::casemap::CaseMapping;
use e6irc_proto::isupport::IsupportToken;

use crate::OwnedMessage;

/// The channel prefixes assumed until the network's 005 says otherwise
/// (RFC 1459: `#` for network channels, `&` for server-local ones).
pub const DEFAULT_CHANTYPES: &str = "#&";

/// A network's naming rules: its case mapping and its channel prefixes.
///
/// Until a 005 arrives, and after one retracts a token (`-CASEMAPPING`,
/// `-CHANTYPES`), the defaults hold: `rfc1459` and `#&`. A `CASEMAPPING` this
/// crate does not know (`rfc7613`, `rfc3454`, …) compares names as `ascii` —
/// the ASCII letters every mapping folds, and nothing else — and is kept as
/// [`NetworkNames::unrecognised_casemapping`] so a client can say so rather
/// than guess silently.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkNames {
    casemapping: CaseMapping,
    chantypes: String,
    unrecognised_casemapping: Option<String>,
}

impl Default for NetworkNames {
    fn default() -> Self {
        Self {
            casemapping: CaseMapping::Rfc1459,
            chantypes: DEFAULT_CHANTYPES.to_owned(),
            unrecognised_casemapping: None,
        }
    }
}

/// What a 005 line changed about a network's naming rules.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct NamesChanged {
    /// The case mapping differs from before: names that were equal may no
    /// longer be, and the other way round.
    pub casemapping: bool,
    /// The channel prefixes differ from before.
    pub chantypes: bool,
}

impl NetworkNames {
    /// The `CASEMAPPING` value the network declared when it is not one this
    /// crate knows; names are then compared as `ascii`.
    pub fn unrecognised_casemapping(&self) -> Option<&str> {
        self.unrecognised_casemapping.as_deref()
    }

    /// Whether `target` names a channel on this network: it starts with one of
    /// the network's channel prefixes.
    pub fn is_channel(&self, target: &str) -> bool {
        target
            .chars()
            .next()
            .is_some_and(|first| self.chantypes.contains(first))
    }

    /// Whether `a` and `b` are the same name on this network.
    pub fn eq(&self, a: &str, b: &str) -> bool {
        self.casemapping.eq(a, b)
    }

    /// `name` in the network's canonical case, for keying.
    pub fn fold(&self, name: &str) -> String {
        self.casemapping.casefold(name)
    }

    /// Adopt the `CASEMAPPING` and `CHANTYPES` a 005 declares; any other
    /// message changes nothing. Tokens sit between the nick and the trailing
    /// "are supported by this server".
    pub fn adopt_isupport(&mut self, message: &OwnedMessage) -> NamesChanged {
        let before = self.clone();
        if message.command == "005" {
            let tokens = message
                .params
                .get(1..message.params.len().saturating_sub(1))
                .unwrap_or_default();
            for token in tokens
                .iter()
                .filter_map(|raw| IsupportToken::parse(raw).ok())
            {
                self.adopt_token(&token);
            }
        }
        NamesChanged {
            casemapping: self.casemapping != before.casemapping,
            chantypes: self.chantypes != before.chantypes,
        }
    }

    fn adopt_token(&mut self, token: &IsupportToken<'_>) {
        let value = token.value.as_deref().unwrap_or("");
        match (token.name, token.negated) {
            ("CASEMAPPING", true) => {
                self.casemapping = CaseMapping::Rfc1459;
                self.unrecognised_casemapping = None;
            }
            ("CASEMAPPING", false) => match CaseMapping::from_isupport_token(value) {
                Some(mapping) => {
                    self.casemapping = mapping;
                    self.unrecognised_casemapping = None;
                }
                None => {
                    self.casemapping = CaseMapping::Ascii;
                    self.unrecognised_casemapping = Some(crate::bounded_diagnostic(value));
                }
            },
            ("CHANTYPES", true) => DEFAULT_CHANTYPES.clone_into(&mut self.chantypes),
            // `CHANTYPES=` (or a bare `CHANTYPES`): the network has no channels.
            ("CHANTYPES", false) => value.clone_into(&mut self.chantypes),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn isupport(tokens: &str) -> OwnedMessage {
        let line = format!(":srv 005 me {tokens} :are supported by this server");
        OwnedMessage::from(&e6irc_proto::message::Message::parse(&line).unwrap())
    }

    #[test]
    fn defaults_are_rfc1459_and_hash_ampersand() {
        let names = NetworkNames::default();
        assert!(names.is_channel("#a") && names.is_channel("&a"));
        assert!(!names.is_channel("!a") && !names.is_channel("nick") && !names.is_channel(""));
        assert!(names.eq("#a[", "#A{"));
        assert!(names.eq("~x", "^X"));
    }

    /// On an `ascii` network `#a[` and `#a{` are two channels.
    #[test]
    fn an_ascii_network_keeps_brackets_and_braces_apart() {
        let mut names = NetworkNames::default();
        let changed = names.adopt_isupport(&isupport("CASEMAPPING=ascii CHANTYPES=#"));
        assert!(changed.casemapping && changed.chantypes);
        assert!(!names.eq("#a[", "#a{"));
        assert!(names.eq("#ABC", "#abc"));
        assert_ne!(names.fold("#a["), names.fold("#a{"));
        assert!(!names.is_channel("&local"), "only # is a channel here");
        assert_eq!(names.unrecognised_casemapping(), None);
    }

    #[test]
    fn strict_rfc1459_in_either_spelling_keeps_tilde_and_caret_apart() {
        for spelling in ["rfc1459-strict", "strict-rfc1459"] {
            let mut names = NetworkNames::default();
            names.adopt_isupport(&isupport(&format!("CASEMAPPING={spelling}")));
            assert_eq!(names.casemapping, CaseMapping::Rfc1459Strict);
            assert!(names.eq("#a[", "#a{"));
            assert!(!names.eq("~x", "^x"));
        }
    }

    #[test]
    fn an_unknown_mapping_compares_as_ascii_and_says_so() {
        let mut names = NetworkNames::default();
        names.adopt_isupport(&isupport("CASEMAPPING=rfc7613"));
        assert_eq!(names.casemapping, CaseMapping::Ascii);
        assert_eq!(names.unrecognised_casemapping(), Some("rfc7613"));
        names.adopt_isupport(&isupport("-CASEMAPPING"));
        assert_eq!(names, NetworkNames::default());
    }

    #[test]
    fn chantypes_are_taken_as_declared_and_retracted_to_the_default() {
        let mut names = NetworkNames::default();
        names.adopt_isupport(&isupport("CHANTYPES=#!+"));
        assert!(names.is_channel("!abc") && names.is_channel("+x") && !names.is_channel("&x"));
        names.adopt_isupport(&isupport("CHANTYPES="));
        assert!(!names.is_channel("#x"), "a network without channels");
        let changed = names.adopt_isupport(&isupport("-CHANTYPES"));
        assert!(changed.chantypes && !changed.casemapping);
        assert!(names.is_channel("&x"));
        assert_eq!(
            names.adopt_isupport(&isupport("NETWORK=x")),
            NamesChanged::default()
        );
    }
}
