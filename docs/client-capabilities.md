# Client capability matrix

This matrix states the supported client contract. It is not a certification of
named third-party clients. The checked protocol surface is the compatibility
claim.

| Client or path | Baseline | Enhanced behavior | Evidence |
|---|---|---|---|
| Generic IRC client | RFC 1459 registration, channels, direct messages, services, and common modes | It can use any advertised IRCv3 capability that it implements | Core, socket, irctest, property, and fuzz suites |
| IRCv3 client or bot | Same baseline | Negotiates the server's `CAP LS` surface; unsupported requests receive `NAK` | Core capability and Libera-snapshot tests |
| BNC attach client | SASL PLAIN plus `NICK` and `USER` | `server-time`, `message-tags`, `account-tag`, `echo-message`, `batch`, `draft/chathistory`, and `draft/read-marker` | PostgreSQL listener and attach journeys |
| `e6irc` CLI | Anonymous, SASL PLAIN, or OAUTHBEARER | `history` requires `batch draft/chathistory server-time` | Socket, API, executable, and PostgreSQL journeys |
| `e6irc-tui` | Same authentication paths as the CLI | Requires `batch draft/chathistory server-time`; requires `draft/read-marker` unless disabled | Duplex, fuzz, and pseudo-terminal journeys |
| Web chat | Browser session and `/api/v1` | REST history and `/ws/ui`; it does not depend on IRC `CAP` | Three-engine browser and API-contract journeys |

**BNC attach CAP LS:** `sasl server-time message-tags account-tag echo-message batch draft/chathistory draft/read-marker`

The BNC requires a negotiated `sasl` capability before it accepts
`AUTHENTICATE`. A capability request is atomic. `CAP LIST` reports enabled
capabilities, not the offered list.

## Qualification boundary

The server is tested against the Libera-compatible protocol surface, not against
every release of every named client. The opt-in probes for Libera, OFTC, and
Ergo establish that the shared native client can register over public TLS; they
do not make public services part of CI. Matrix has a self-hosted CI oracle.
Discord, Slack, other identity providers, and public-network credentials need
controlled external qualification.
