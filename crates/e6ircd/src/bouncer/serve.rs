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
type NetworkKey = (Option<String>, String);

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
/// mirrors upstream lines to the database. The persistence task holds a
/// strong handle, so it must be aborted when the network is removed or
/// replaced — otherwise it pins the driver's command channel and the
/// driver never stops.
struct Slot {
    handle: Arc<NetworkHandle>,
    persistence: Option<tokio::task::JoinHandle<()>>,
}

impl Slot {
    /// Stop the persistence task so it releases its handle; combined with
    /// dropping `handle`, this lets the driver observe its command channel
    /// close and exit.
    fn stop(self) {
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
    pub fn start(entries: &[NetworkEntry], pool: Option<PgPool>, core: super::CoreHandles) -> Self {
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
                        eprintln!(
                            "network '{}' is kind=matrix but this binary was built \
                             without the `matrix` feature; skipping",
                            e.name
                        );
                        continue;
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
                        eprintln!(
                            "network '{}' is kind=discord but this binary was built \
                             without the `discord` feature; skipping",
                            e.name
                        );
                        continue;
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
                        eprintln!(
                            "network '{}' is kind=slack but this binary was built \
                             without the `slack` feature; skipping",
                            e.name
                        );
                        continue;
                    }
                }
            };
            registry.add(e.owner.clone(), e.name.clone(), driver);
        }
        registry
    }

    /// Start a driver for `(owner, name)` and register it, replacing any
    /// existing driver under that key (the old handle drops, stopping it).
    /// With a database, restore recent backlog and persist new lines.
    pub fn add(&self, owner: Option<String>, name: String, driver: Box<dyn super::NetworkDriver>) {
        let handle = Arc::new(driver.start());
        let persistence = self
            .pool
            .clone()
            .map(|pool| spawn_persistence(pool, owner.clone(), name.clone(), handle.clone()));
        let slot = Slot {
            handle,
            persistence,
        };
        // Replacing a key must stop the old driver, not leak it.
        if let Some(old) = self
            .networks
            .lock()
            .expect("registry poisoned")
            .insert((owner, name), slot)
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
            .remove(&(owner.map(str::to_string), name.to_string()));
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
            .get(&(Some(account.to_string()), name.to_string()))
            .or_else(|| networks.get(&(None, name.to_string())))
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
        loop {
            match events.recv().await {
                Ok(DriverEvent::Line(line)) => {
                    if let Err(e) =
                        crate::db::persist_bnc_line(&pool, &owner_key, &network, &line).await
                    {
                        eprintln!("bnc: buffer persist failed for {owner_key}/{network}: {e}");
                    }
                }
                Ok(_) => {}
                Err(tokio::sync::broadcast::error::RecvError::Lagged(_)) => {}
                Err(tokio::sync::broadcast::error::RecvError::Closed) => break,
            }
        }
    })
}

/// Outcome of the BNC registration handshake.
enum Registered {
    /// Client authenticated as `account` and selected `network`.
    Ok { account: String, network: String },
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

    let (account, network) = match handshake(&mut read, &mut write, pool, server_name).await? {
        Registered::Ok { account, network } => (account, network),
        Registered::Closed => return Ok(()),
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
    attach(joined, &handle).await
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
    let mut framing = LineBuffer::new(4096 + 510);
    let mut buf = vec![0u8; 4096];
    let mut events = Vec::new();

    let mut nick: Option<String> = None;
    let mut have_user = false;
    let mut cap_open = false;
    let mut awaiting_payload = false;
    let mut account: Option<String> = None;

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
                    handle_cap(write, server_name, &msg, &mut cap_open).await?;
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
    })
}

/// Answer a CAP command. Advertises only `sasl`; `cap_open` tracks
/// whether negotiation is still in progress (cleared on CAP END).
async fn handle_cap<W>(
    write: &mut W,
    server_name: &str,
    msg: &Message<'_>,
    cap_open: &mut bool,
) -> std::io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    match msg
        .params
        .first()
        .map(|s| s.to_ascii_uppercase())
        .as_deref()
    {
        Some("LS") | Some("LIST") => {
            write
                .write_all(format!(":{server_name} CAP * LS :sasl\r\n").as_bytes())
                .await?;
        }
        Some("REQ") => {
            let req = msg.params.get(1).copied().unwrap_or("");
            // ACK sasl (the only cap we offer); NAK anything else.
            let verb = if req.split_whitespace().all(|c| c == "sasl") && !req.is_empty() {
                "ACK"
            } else {
                "NAK"
            };
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
    crate::db::verify_credentials(pool, authcid, passwd)
        .await
        .ok()
        .flatten()
}
