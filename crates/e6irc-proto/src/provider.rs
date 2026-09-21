//! Constants of the chat providers the bouncer bridges to, shared by the
//! bridge drivers (`e6ircd`) and the external qualification campaigns
//! (`e6irc-qualification`), so a campaign proves exactly what the driver asks
//! the provider for. No I/O.

/// The gateway intents the Discord bridge identifies with: `GUILDS` (bit 0),
/// `GUILD_MESSAGES` (bit 9) and `MESSAGE_CONTENT` (bit 15, privileged — the
/// bot's application must have it switched on, or the gateway closes with
/// 4014). A campaign that identified with fewer proved a session the driver
/// never opens.
pub const DISCORD_GATEWAY_INTENTS: u64 = (1 << 0) | (1 << 9) | (1 << 15);
