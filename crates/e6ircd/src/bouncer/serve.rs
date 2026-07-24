//! BNC listener glue: a registry of always-on networks and the
//! per-client serve loop. A client must authenticate with SASL PLAIN
//! against its account, then selects a network from the `nick/network`
//! suffix; the loop greets it as the bouncer and hands off to `attach`.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use sqlx::PgPool;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use super::{NetworkConfig, NetworkHandle, attach};
use crate::config::NetworkEntry;
use e6irc_proto::framing::{LineBuffer, LineEvent};
use e6irc_proto::message::Message;

/// Registry key: the owning account (`None` = shared) and the network
/// name the client selects with the `/network` suffix.
///
/// The account is stored casefolded. Every caller happens to pass the stored
/// `accounts.name` today, so raw strings would match — but a key that is only
/// correct while every producer remembers to spell it the same way is the wrong
/// kind of correct. A miss here does not error: `get` falls through to the
/// shared network, so a mismatch would silently attach a client to the
/// operator's network instead of its own. [`NetworkKey::new`] is the only way
/// to build one, so that cannot drift.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct NetworkKey {
    owner: Option<String>,
    name: String,
}

impl NetworkKey {
    fn new(owner: Option<&str>, name: &str) -> Self {
        Self {
            owner: owner.map(|o| e6irc_proto::casemap::CaseMapping::Rfc1459.casefold(o)),
            name: name.to_string(),
        }
    }
}

/// All active networks, each running an always-on driver, keyed by
/// `(owner, name)`. Mutable at runtime so accounts can add and remove
/// their own networks. When a database is present, each network's
/// upstream lines are persisted and its recent backlog is restored on
/// start.
pub struct Registry {
    networks: Mutex<HashMap<NetworkKey, Slot>>,
    pool: Option<PgPool>,
}

/// A registered network: its driver handle plus the persistence task that
/// mirrors upstream lines to the database.
struct Slot {
    handle: Arc<NetworkHandle>,
    persistence: Option<tokio::task::JoinHandle<()>>,
}

impl Slot {
    /// Stop the driver authoritatively and the persistence task with it.
    ///
    /// The driver observes `handle.shutdown()` regardless of who still holds a
    /// command sender — an attached client clones `commands`, so relying on
    /// refcount alone would keep the upstream connection (and its decrypted
    /// SASL password) alive until the last client detached. The persistence
    /// task is aborted too so it stops writing for a network that is gone.
    fn stop(self) {
        self.handle.shutdown();
        if let Some(task) = self.persistence {
            task.abort();
        }
    }
}

/// How many recent lines to restore into a network's buffer at start.
const PRELOAD_LIMIT: i64 = 1000;

impl Registry {
    /// Start a driver per configured (server-level) network. `pool`, when
    /// present, enables buffer persistence and backlog restore; `core`
    /// (the in-process handles) is required for any `local` network.
    pub fn start(
        entries: &[NetworkEntry],
        pool: Option<PgPool>,
        core: super::CoreHandles,
    ) -> Result<Self, String> {
        use crate::config::NetworkKind;
        let registry = Self {
            networks: Mutex::new(HashMap::new()),
            pool,
        };
        for e in entries {
            let config = NetworkConfig {
                addr: e.addr.clone(),
                tls: e.tls,
                nick: e.nick.clone(),
                realname: e.realname.clone().unwrap_or_else(|| e.nick.clone()),
                autojoin: e.autojoin.clone(),
                buffer_cap: e.buffer_cap,
                sasl: match (&e.sasl_account, &e.sasl_password) {
                    (Some(a), Some(p)) => Some((a.clone(), p.clone())),
                    _ => None,
                },
            };
            let driver: Box<dyn super::NetworkDriver> = match e.kind {
                NetworkKind::Irc => Box::new(super::IrcDriver::new(config)),
                NetworkKind::Local => Box::new(super::LocalDriver::new(core.clone(), config)),
                NetworkKind::Matrix => {
                    #[cfg(feature = "matrix")]
                    {
                        Box::new(super::MatrixDriver::new(super::MatrixConfig {
                            homeserver: e.addr.clone(),
                            user: e.nick.clone(),
                            password: e.sasl_password.clone().unwrap_or_default(),
                            rooms: e.autojoin.clone(),
                            buffer_cap: e.buffer_cap,
                        }))
                    }
                    #[cfg(not(feature = "matrix"))]
                    {
                        return Err(format!(
                            "network '{}' is kind=matrix but this binary was built \
                             without the `matrix` feature",
                            e.name
                        ));
                    }
                }
                NetworkKind::Discord => {
                    #[cfg(feature = "discord")]
                    {
                        Box::new(super::DiscordDriver::new(super::DiscordConfig {
                            token: e.sasl_password.clone().unwrap_or_default(),
                            api_base: e.addr.clone(),
                            channels: e.autojoin.clone(),
                            buffer_cap: e.buffer_cap,
                        }))
                    }
                    #[cfg(not(feature = "discord"))]
                    {
                        return Err(format!(
                            "network '{}' is kind=discord but this binary was built \
                             without the `discord` feature",
                            e.name
                        ));
                    }
                }
                NetworkKind::Slack => {
                    #[cfg(feature = "slack")]
                    {
                        Box::new(super::SlackDriver::new(super::SlackConfig {
                            bot_token: e.sasl_account.clone().unwrap_or_default(),
                            app_token: e.sasl_password.clone().unwrap_or_default(),
                            api_base: e.addr.clone(),
                            channels: e.autojoin.clone(),
                            buffer_cap: e.buffer_cap,
                        }))
                    }
                    #[cfg(not(feature = "slack"))]
                    {
                        return Err(format!(
                            "network '{}' is kind=slack but this binary was built \
                             without the `slack` feature",
                            e.name
                        ));
                    }
                }
            };
            registry.add(e.owner.as_deref(), &e.name, driver);
        }
        Ok(registry)
    }

    /// Start a driver for `(owner, name)` and register it, replacing any
    /// existing driver under that key (the old handle drops, stopping it).
    /// With a database, restore recent backlog and persist new lines.
    pub fn add(&self, owner: Option<&str>, name: &str, driver: Box<dyn super::NetworkDriver>) {
        let key = NetworkKey::new(owner, name);
        let handle = Arc::new(driver.start());
        // The persistence task keys `bnc_buffer` rows by the same casefolded
        // owner the registry uses, so a buffer cannot be written under one
        // spelling and looked up under another.
        let persistence = self.pool.clone().map(|pool| {
            spawn_persistence(pool, key.owner.clone(), key.name.clone(), handle.clone())
        });
        let slot = Slot {
            handle,
            persistence,
        };
        // Replacing a key must stop the old driver, not leak it.
        if let Some(old) = self
            .networks
            .lock()
            .expect("registry poisoned")
            .insert(key, slot)
        {
            old.stop();
        }
    }

    /// Remove `owner`'s network `name`, stopping its driver. Returns
    /// whether a network was removed.
    pub fn remove(&self, owner: Option<&str>, name: &str) -> bool {
        let removed = self
            .networks
            .lock()
            .expect("registry poisoned")
            .remove(&NetworkKey::new(owner, name));
        match removed {
            Some(slot) => {
                slot.stop();
                true
            }
            None => false,
        }
    }

    /// Resolve a network the authenticated `account` may attach to: its
    /// own network of that name, else a shared (ownerless) one. A network
    /// owned by a different account is not visible and returns `None`.
    pub fn get(&self, account: &str, name: &str) -> Option<Arc<NetworkHandle>> {
        let networks = self.networks.lock().expect("registry poisoned");
        networks
            .get(&NetworkKey::new(Some(account), name))
            .or_else(|| networks.get(&NetworkKey::new(None, name)))
            .map(|slot| slot.handle.clone())
    }
}

/// Restore a network's persisted backlog into its buffer, then persist
/// every new upstream line. Subscribes before the backlog read so no
/// line broadcast during the read is lost (up to the channel's backlog).
fn spawn_persistence(
    pool: PgPool,
    owner: Option<String>,
    network: String,
    handle: Arc<NetworkHandle>,
) -> tokio::task::JoinHandle<()> {
    use super::DriverEvent;
    let owner_key = owner.unwrap_or_else(|| "*".to_string());
    tokio::spawn(async move {
        let mut events = handle.subscribe();
        if let Ok(lines) =
            crate::db::recent_bnc_lines(&pool, &owner_key, &network, PRELOAD_LIMIT).await
        {
            handle.preload_front(lines);
        }
        // This task is the only writer for this network, so counting its own
        // appends is what makes the amortized trim reach every network — see
        // `db::BNC_TRIM_INTERVAL`.
        let mut since_trim = 0u64;
        loop {
            match events.recv().await {
                Ok(DriverEvent::Line(line)) => {
                    if let Err(e) =
                        crate::db::persist_bnc_line(&pool, &owner_key, &network, &line).await
                    {
                        eprintln!("bnc: buffer persist failed for {owner_key}/{network}: {e}");
                        continue;
                    }
                    since_trim += 1;
                    if since_trim >= crate::db::BNC_TRIM_INTERVAL {
                        since_trim = 0;
                        if let Err(e) =
                            crate::db::trim_bnc_buffer(&pool, &owner_key, &network).await
                        {
                            eprintln!("bnc: buffer trim failed for {owner_key}/{network}: {e}");
                        }
                    }
                }
                Ok(_) => {}
                // A persistence lag means upstream lines were never written:
                // the stored backlog now has a gap. Surface it rather than
                // dropping it silently.
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    eprintln!(
                        "bnc: persistence lagged for {owner_key}/{network}; {n} upstream \
                         line(s) missing from stored backlog"
                    );
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

/// Outcome of the BNC registration handshake.
enum Registered {
    /// Client authenticated as `account` and selected `network`, negotiating
    /// `caps` (which message tags it may receive on attach).
    Ok {
        account: String,
        network: String,
        caps: super::AttachCaps,
    },
    /// The client hung up or violated the handshake; the loop returns.
    Closed,
}

/// Serve one BNC client: authenticate it with SASL PLAIN against the
/// account store, pick the network from the `nick/network` suffix,
/// greet, and attach. The client's NICK/USER are consumed here (the
/// driver owns the upstream registration).
pub async fn bnc_serve<S>(
    stream: S,
    registry: Arc<Registry>,
    pool: &PgPool,
    server_name: &str,
) -> std::io::Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut read, mut write) = tokio::io::split(stream);

    // Bound the pre-attach handshake: a client that connects and never
    // completes registration (sends nothing, or authenticates but never ends
    // CAP negotiation) must not hold a task + socket indefinitely.
    let (account, network, caps) = match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        handshake(&mut read, &mut write, pool, server_name),
    )
    .await
    {
        Ok(Ok(Registered::Ok {
            account,
            network,
            caps,
        })) => (account, network, caps),
        Ok(Ok(Registered::Closed)) => return Ok(()),
        Ok(Err(e)) => return Err(e),
        Err(_) => return Ok(()), // handshake timed out
    };

    let Some(handle) = registry.get(&account, &network) else {
        let _ = write
            .write_all(
                format!(":{server_name} NOTICE * :Unknown network '{network}'.\r\n").as_bytes(),
            )
            .await;
        return Ok(());
    };

    // Complete the client's registration burst (001 + end-of-MOTD) so it
    // considers itself registered, then attach.
    let ident = format!("{account}/{network}");
    for line in [
        format!(":{server_name} 001 {ident} :Welcome to e6irc BNC, attached to '{network}'"),
        format!(":{server_name} 422 {ident} :MOTD is on the upstream network"),
    ] {
        write.write_all(line.as_bytes()).await?;
        write.write_all(b"\r\n").await?;
    }
    write.flush().await?;

    let joined = read.unsplit(write);
    attach(joined, &handle, caps).await
}

/// Drive registration to a `Registered` verdict. Requires a successful
/// SASL PLAIN exchange before the client is allowed to attach: an
/// unauthenticated CAP END or a bad credential closes the connection.
async fn handshake<R, W>(
    read: &mut R,
    write: &mut W,
    pool: &PgPool,
    server_name: &str,
) -> std::io::Result<Registered>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    let mut framing = LineBuffer::new(e6irc_proto::message::MAX_CLIENT_FRAME_LEN);
    let mut buf = vec![0u8; 4096];
    let mut events = Vec::new();

    let mut nick: Option<String> = None;
    let mut have_user = false;
    let mut cap_open = false;
    let mut awaiting_payload = false;
    let mut account: Option<String> = None;
    let mut caps = super::AttachCaps::default();

    loop {
        // Registration is complete only once the client has a nick, has
        // sent USER, has authenticated, and has closed CAP negotiation.
        if nick.is_some() && have_user && account.is_some() && !cap_open {
            break;
        }
        let n = read.read(&mut buf).await?;
        if n == 0 {
            return Ok(Registered::Closed);
        }
        framing.feed(&buf[..n], &mut events);
        for ev in events.drain(..) {
            let LineEvent::Line(line) = ev else { continue };
            let Ok(text) = std::str::from_utf8(&line) else {
                continue;
            };
            let Ok(msg) = Message::parse(text) else {
                continue;
            };
            match msg.command.to_ascii_uppercase().as_str() {
                "NICK" => nick = msg.params.first().map(|s| s.to_string()),
                "USER" => have_user = true,
                "CAP" => {
                    cap_open = true;
                    handle_cap(write, server_name, &msg, &mut cap_open, &mut caps).await?;
                }
                "AUTHENTICATE" => {
                    let arg = msg.params.first().copied().unwrap_or("");
                    if !awaiting_payload {
                        // Mechanism selection. Only PLAIN is offered.
                        if arg.eq_ignore_ascii_case("PLAIN") {
                            awaiting_payload = true;
                            write.write_all(b"AUTHENTICATE +\r\n").await?;
                        } else {
                            reject_sasl(write, server_name).await?;
                        }
                    } else {
                        awaiting_payload = false;
                        match verify_plain(pool, arg).await {
                            Some(acct) => {
                                write
                                    .write_all(
                                        format!(
                                            ":{server_name} 900 * * {acct} :You are now logged in as {acct}\r\n\
                                             :{server_name} 903 * :SASL authentication successful\r\n"
                                        )
                                        .as_bytes(),
                                    )
                                    .await?;
                                account = Some(acct);
                            }
                            None => reject_sasl(write, server_name).await?,
                        }
                    }
                }
                _ => {}
            }
        }

        // A client that finished CAP + registration without ever
        // authenticating is refused rather than silently attached. A
        // SASL exchange still in flight (awaiting_payload) is not yet a
        // failure.
        if nick.is_some() && have_user && !cap_open && !awaiting_payload && account.is_none() {
            let _ = write
                .write_all(
                    format!(
                        ":{server_name} NOTICE * :Authentication required — attach with SASL PLAIN.\r\n"
                    )
                    .as_bytes(),
                )
                .await;
            return Ok(Registered::Closed);
        }
    }

    let raw = nick.expect("checked");
    let account = account.expect("checked");
    let Some((_user, network)) = raw.split_once('/') else {
        let _ = write
            .write_all(
                format!(
                    ":{server_name} NOTICE * :Connect as <nick>/<network>; known networks are listed in the server config.\r\n"
                )
                .as_bytes(),
            )
            .await;
        return Ok(Registered::Closed);
    };
    Ok(Registered::Ok {
        account,
        network: network.to_string(),
        caps,
    })
}

/// Answer a CAP command. Advertises only `sasl`; `cap_open` tracks
/// whether negotiation is still in progress (cleared on CAP END).
async fn handle_cap<W>(
    write: &mut W,
    server_name: &str,
    msg: &Message<'_>,
    cap_open: &mut bool,
    caps: &mut super::AttachCaps,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    // `server-time`/`message-tags`/`account-tag` gate which tags a client is
    // sent from the (fully-tagged) backlog; `sasl` authenticates the attach.
    let known = |c: &str| matches!(c, "sasl" | "server-time" | "message-tags" | "account-tag");
    match msg
        .params
        .first()
        .map(|s| s.to_ascii_uppercase())
        .as_deref()
    {
        Some("LS") | Some("LIST") => {
            write
                .write_all(
                    format!(
                        ":{server_name} CAP * LS :sasl server-time message-tags account-tag\r\n"
                    )
                    .as_bytes(),
                )
                .await?;
        }
        Some("REQ") => {
            let req = msg.params.get(1).copied().unwrap_or("");
            // REQ is atomic: ACK only when every requested cap is known.
            let all_known = !req.is_empty() && req.split_whitespace().all(known);
            if all_known {
                for c in req.split_whitespace() {
                    match c {
                        "server-time" => caps.server_time = true,
                        "message-tags" => caps.message_tags = true,
                        "account-tag" => caps.account_tag = true,
                        _ => {}
                    }
                }
            }
            let verb = if all_known { "ACK" } else { "NAK" };
            write
                .write_all(format!(":{server_name} CAP * {verb} :{req}\r\n").as_bytes())
                .await?;
        }
        Some("END") => *cap_open = false,
        _ => {}
    }
    Ok(())
}

async fn reject_sasl<W>(write: &mut W, server_name: &str) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    write
        .write_all(format!(":{server_name} 904 * :SASL authentication failed\r\n").as_bytes())
        .await
}

/// Verify a SASL PLAIN payload (`base64(authzid \0 authcid \0 passwd)`)
/// against the account store. Returns the canonical account name.
async fn verify_plain(pool: &PgPool, payload: &str) -> Option<String> {
    let raw = e6irc_proto::base64::decode(payload)?;
    let mut parts = raw.splitn(3, |&b| b == 0);
    let _authzid = parts.next()?;
    let authcid = std::str::from_utf8(parts.next()?).ok()?;
    let passwd = std::str::from_utf8(parts.next()?).ok()?;
    // A DB failure is not an auth rejection (verify_credentials' contract):
    // fail closed, but surface the error instead of silently masking it as a
    // bad password.
    match crate::db::verify_credentials(pool, authcid, passwd).await {
        Ok(name) => name,
        Err(e) => {
            eprintln!("bnc: credential check failed (database error): {e}");
            None
        }
    }
}

#[cfg(test)]
mod key_tests {
    use super::*;

    #[test]
    fn registry_key_folds_the_owner_so_casing_cannot_miss() {
        // A miss does not error: `get` falls through to the shared network, so
        // an owner spelled differently than it was registered would silently
        // attach a client to the operator's network instead of its own.
        let registered = NetworkKey::new(Some("Alice"), "libera");
        assert_eq!(registered, NetworkKey::new(Some("alice"), "libera"));
        assert_eq!(registered, NetworkKey::new(Some("ALICE"), "libera"));
        // RFC1459 folds these too, and nicks may contain them.
        assert_eq!(
            NetworkKey::new(Some("Ali[ce]"), "n"),
            NetworkKey::new(Some("ali{ce}"), "n")
        );
        // A different account is still a different key, and the shared owner
        // stays distinct from any account.
        assert_ne!(registered, NetworkKey::new(Some("bob"), "libera"));
        assert_ne!(registered, NetworkKey::new(None, "libera"));
        // The network name is a selector the owner chose, not an identity, and
        // is matched exactly.
        assert_ne!(registered, NetworkKey::new(Some("alice"), "Libera"));
    }
}
