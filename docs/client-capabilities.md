# Client capability matrix

This matrix states the supported client contract. It is not a certification of
named third-party clients. The checked protocol surface is the compatibility
claim.

| Client or path | Baseline | Enhanced behavior | Evidence |
|---|---|---|---|
| Generic IRC client | RFC 1459 registration, channels, direct messages, services, and common modes | It can use any advertised IRCv3 capability that it implements | Core, socket, irctest, property, and fuzz suites |
| IRCv3 client or bot | Same baseline | Negotiates the server's `CAP LS` surface; unsupported requests receive `NAK` | Core capability and Libera-snapshot tests |
| BNC attach client | SASL PLAIN plus `NICK` and `USER` | `server-time`, `message-tags`, `account-tag`, `echo-message`, `batch`, `draft/chathistory`, `draft/read-marker`, and `cap-notify` (implied by `CAP LS 302`) | PostgreSQL listener and attach journeys |
| `e6irc` CLI | Anonymous, SASL password (SCRAM-SHA-512/256 or PLAIN, strongest offered), or OAUTHBEARER | `send` requires `echo-message` to confirm delivery; `history` requires `batch draft/chathistory server-time` | Socket, API, executable, and PostgreSQL journeys |
| `e6irc-tui` | Same authentication paths as the CLI | Requires `batch draft/chathistory server-time`; requires `draft/read-marker` unless disabled | Duplex, fuzz, and pseudo-terminal journeys |
| Web chat | Browser session and `/api/v1` | REST history and `/ws/ui`; it does not depend on IRC `CAP` | Three-engine browser and API-contract journeys |

**BNC attach CAP LS:** `sasl server-time message-tags account-tag echo-message batch draft/chathistory draft/read-marker cap-notify`

The BNC requires a negotiated `sasl` capability before it accepts
`AUTHENTICATE`. A capability request is atomic. `CAP LIST` reports enabled
capabilities, not the offered list.

CHATHISTORY replays a message with the client-only tags it was delivered with
(`+draft/reply`, `+draft/react`, …) and replays reactions and other `TAGMSG`s,
to a client that negotiated `message-tags` — on the server and, from the raw
lines it stores, on the bouncer. A client without `message-tags` receives
neither, and its pages count only the lines it can receive; `CHATHISTORY
TARGETS` dates each buffer for it by the newest line it can receive, and leaves
out a buffer whose only activity in the window is `TAGMSG`s. Typing indicators
(`+typing`, `+draft/typing`) are live only: they are never replayed. REST
history serves text messages only.

The CLI, the TUI and the web chat read which targets are channels and which
names are the same from the network's `005`: `CHANTYPES` (default `#&`) and
`CASEMAPPING` (default `rfc1459`). `rfc1459`, `rfc1459-strict` (or
`strict-rfc1459`) and `ascii` are known; any other mapping (`rfc7613`, …) is
compared as `ascii` — the letters every mapping folds — and the client says so.

`LIST` takes Libera's conditions (`ELIST=CMNTU`): `>n` / `<n` members,
`C<n` / `C>n` and `T<n` / `T>n` for a channel created, or its topic set, less
or more than `n` minutes ago, a channel-name glob such as `#rust*` or `*bot*`,
and `!glob` to leave names out — comma-separated, up to seven, all of which
must hold (`LIST #rust*,>10,!*-offtopic`). A secret channel is listed only to
its members. The reply is paced to the client's send queue (`SAFELIST`), so a
client that lists every channel is never disconnected for it; a second `LIST`
while one is still arriving aborts the first with a `/LIST aborted` notice.

`WHO *` and a `WHO` of a large channel are paced the same way. A `WHO` sent
while an earlier one is still arriving is answered after it; one that would
leave more waiting than the send queue holds is answered `263 WHO :Please wait
a while and try again.` and its `315`, and can be sent again once the first
has arrived.

## Qualification boundary

The server is tested against the Libera-compatible protocol surface, not against
every release of every named client. The opt-in probes for Libera, OFTC, and
Ergo establish that the shared native client can register and reconnect over
public TLS; they do not make public services part of CI. Matrix has a
self-hosted CI oracle. Discord, Slack, other identity providers, and public
networks need controlled external qualification evidence.
