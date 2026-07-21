//! Numeric replies. Codes and names per the Modern IRC numerics list
//! (https://modern.ircdocs.horse/#numerics) restricted to the surface
//! this server implements; Solanum-specific choices are noted inline.

macro_rules! numerics {
    ($($name:ident = $code:literal),+ $(,)?) => {
        $(pub const $name: u16 = $code;)+

        /// Symbolic name for a known numeric code.
        pub fn name(code: u16) -> Option<&'static str> {
            match code {
                $($code => Some(stringify!($name)),)+
                _ => None,
            }
        }

        #[cfg(test)]
        const ALL: &[(u16, &str)] = &[$(($code, stringify!($name))),+];
    };
}

numerics! {
    RPL_WELCOME = 1,
    RPL_YOURHOST = 2,
    RPL_CREATED = 3,
    RPL_MYINFO = 4,
    RPL_ISUPPORT = 5,
    RPL_UMODEIS = 221,
    RPL_LUSERCLIENT = 251,
    RPL_LUSEROP = 252,
    RPL_LUSERUNKNOWN = 253,
    RPL_LUSERCHANNELS = 254,
    RPL_LUSERME = 255,
    RPL_STATSUPTIME = 242,
    RPL_ENDOFSTATS = 219,
    RPL_ADMINME = 256,
    RPL_ADMINLOC1 = 257,
    RPL_ADMINLOC2 = 258,
    RPL_ADMINEMAIL = 259,
    RPL_LOCALUSERS = 265,
    RPL_GLOBALUSERS = 266,
    RPL_USERHOST = 302,
    RPL_USERIP = 340,
    RPL_ISON = 303,
    RPL_VERSION = 351,
    RPL_LINKS = 364,
    RPL_ENDOFLINKS = 365,
    RPL_AWAY = 301,
    RPL_UNAWAY = 305,
    RPL_NOWAWAY = 306,
    RPL_WHOISUSER = 311,
    RPL_WHOISSERVER = 312,
    RPL_WHOISOPERATOR = 313,
    RPL_ENDOFWHO = 315,
    RPL_WHOISIDLE = 317,
    RPL_ENDOFWHOIS = 318,
    RPL_WHOISCHANNELS = 319,
    RPL_WHOWASUSER = 314,
    RPL_ENDOFWHOWAS = 369,
    ERR_WASNOSUCHNICK = 406,
    RPL_LISTSTART = 321,
    RPL_LIST = 322,
    RPL_LISTEND = 323,
    RPL_CHANNELMODEIS = 324,
    RPL_CREATIONTIME = 329,
    RPL_WHOISACCOUNT = 330,
    RPL_WHOISBOT = 335,
    RPL_NOTOPIC = 331,
    RPL_TOPIC = 332,
    RPL_TOPICWHOTIME = 333,
    RPL_WHOISACTUALLY = 338,
    RPL_INVITING = 341,
    RPL_INVITELIST = 346,
    RPL_ENDOFINVITELIST = 347,
    RPL_EXCEPTLIST = 348,
    RPL_ENDOFEXCEPTLIST = 349,
    RPL_WHOREPLY = 352,
    RPL_NAMREPLY = 353,
    RPL_WHOSPCRPL = 354,
    RPL_ENDOFNAMES = 366,
    RPL_BANLIST = 367,
    RPL_ENDOFBANLIST = 368,
    RPL_INFO = 371,
    RPL_MOTD = 372,
    RPL_ENDOFINFO = 374,
    RPL_MOTDSTART = 375,
    RPL_ENDOFMOTD = 376,
    RPL_YOUREOPER = 381,
    RPL_TIME = 391,
    RPL_VISIBLEHOST = 396,
    ERR_INVALIDCAPCMD = 410,
    ERR_NOSUCHNICK = 401,
    ERR_NOSUCHSERVER = 402,
    ERR_NOSUCHCHANNEL = 403,
    ERR_CANNOTSENDTOCHAN = 404,
    ERR_TOOMANYCHANNELS = 405,
    ERR_TOOMANYTARGETS = 407,
    ERR_NOORIGIN = 409,
    ERR_NORECIPIENT = 411,
    ERR_NOTEXTTOSEND = 412,
    ERR_INPUTTOOLONG = 417,
    ERR_UNKNOWNCOMMAND = 421,
    ERR_NOMOTD = 422,
    ERR_NONICKNAMEGIVEN = 431,
    ERR_ERRONEUSNICKNAME = 432,
    ERR_NICKNAMEINUSE = 433,
    ERR_USERNOTINCHANNEL = 441,
    ERR_NOTONCHANNEL = 442,
    ERR_USERONCHANNEL = 443,
    ERR_NOTREGISTERED = 451,
    ERR_NEEDMOREPARAMS = 461,
    ERR_ALREADYREGISTERED = 462,
    ERR_PASSWDMISMATCH = 464,
    ERR_YOUREBANNEDCREEP = 465,
    ERR_KEYSET = 467,
    ERR_CHANNELISFULL = 471,
    ERR_UNKNOWNMODE = 472,
    ERR_INVITEONLYCHAN = 473,
    ERR_BANNEDFROMCHAN = 474,
    ERR_BADCHANNELKEY = 475,
    ERR_BANLISTFULL = 478,
    ERR_NOPRIVILEGES = 481,
    ERR_CHANOPRIVSNEEDED = 482,
    ERR_INVALIDKEY = 525,
    ERR_INVALIDMODEPARAM = 696,
    ERR_UMODEUNKNOWNFLAG = 501,
    ERR_USERSDONTMATCH = 502,
    RPL_QUIETLIST = 728,
    RPL_ENDOFQUIETLIST = 729,
    RPL_HELPSTART = 704,
    RPL_HELPTXT = 705,
    RPL_ENDOFHELP = 706,
    RPL_KNOCK = 710,
    RPL_KNOCKDLVR = 711,
    ERR_CHANOPEN = 713,
    ERR_KNOCKONCHAN = 714,
    RPL_MONONLINE = 730,
    RPL_MONOFFLINE = 731,
    RPL_MONLIST = 732,
    RPL_ENDOFMONLIST = 733,
    ERR_MONLISTFULL = 734,
    RPL_LOGGEDIN = 900,
    RPL_LOGGEDOUT = 901,
    ERR_NICKLOCKED = 902,
    RPL_SASLSUCCESS = 903,
    ERR_SASLFAIL = 904,
    ERR_SASLTOOLONG = 905,
    ERR_SASLABORTED = 906,
    ERR_SASLALREADY = 907,
    RPL_SASLMECHS = 908,
}

/// A numeric as it appears on the wire: zero-padded three digits.
pub fn code_str(code: u16) -> String {
    format!("{code:03}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    #[test]
    fn spot_checks() {
        assert_eq!(RPL_WELCOME, 1);
        assert_eq!(RPL_ISUPPORT, 5);
        assert_eq!(RPL_NAMREPLY, 353);
        assert_eq!(RPL_WHOSPCRPL, 354); // WHOX reply, heavily used on Libera
        assert_eq!(ERR_NICKNAMEINUSE, 433);
        assert_eq!(RPL_SASLSUCCESS, 903);
        assert_eq!(RPL_MONONLINE, 730);
        assert_eq!(ERR_INPUTTOOLONG, 417);
    }

    #[test]
    fn name_lookup() {
        assert_eq!(name(1), Some("RPL_WELCOME"));
        assert_eq!(name(354), Some("RPL_WHOSPCRPL"));
        assert_eq!(name(999), None);
        assert_eq!(name(0), None);
    }

    #[test]
    fn codes_are_unique_and_in_range() {
        let mut seen = HashSet::new();
        for &(code, sym) in ALL {
            assert!(seen.insert(code), "duplicate numeric {code} ({sym})");
            assert!((1..=999).contains(&code), "{sym} out of range");
        }
    }

    #[test]
    fn wire_form_is_zero_padded() {
        assert_eq!(code_str(1), "001");
        assert_eq!(code_str(43), "043");
        assert_eq!(code_str(433), "433");
    }
}
