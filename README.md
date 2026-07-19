# e6irc

A monolithic Rust IRC ecosystem: one server binary that is at once a
modern **IRCv3 daemon**, a versioned **REST API**, an **OIDC** web
backend for a bundled HTMX/Vite web client, and a per-user **BNC host**
(always-on bouncer sessions to external IRC networks, plus bridges to
non-IRC services such as Matrix) — shipped alongside native **CLI** and
**TUI** clients.

Single server = the whole network (no server-to-server linking).
Designed for **~100k+ concurrent connections** on one machine, with
**Libera.Chat compatibility** as an explicit target: clients and scripts
written against Libera should work unchanged against e6ircd.

> License: **AGPL-3.0-or-later**. Every compiled-in dependency must be
> AGPL-compatible; compliance is enforced in CI with `cargo-deny`.

## What's in the box

| Crate | Binary | What it is |
|-------|--------|-----------|
| `e6ircd` | `e6ircd` | The server: IRCv3 daemon + REST API + web backend + OIDC RP + BNC host + Matrix bridge |
| `e6irc-cli` | `e6irc` | Command-line client (send/tail/raw, SASL, one-shot REST calls) |
| `e6irc-tui` | `e6irc-tui` | Terminal client (ratatui, multi-buffer, scrollback) |
| `e6irc-client` | — | Async client library shared by the CLI/TUI and the load harness |
| `e6irc-proto` | — | IRC message framing and parsing |
| `e6irc-queue` | — | The core's async work queue (loom-checked) |
| `e6irc-load` | `e6irc-load` | Load harness for the concurrency/fan-out targets |

## Highlights

- **IRCv3**: SASL (PLAIN + OAUTHBEARER), message tags, labeled responses,
  batch, CHATHISTORY, MONITOR, echo-message, account-tag, extended-join,
  setname, away-notify, bot mode, and the common channel modes —
  conformance-tested against the [irctest](https://github.com/progval/irctest)
  suite in CI and live-verified against Libera/OFTC/Ergo.
- **HTTP layer**: OIDC code+PKCE multi-provider login, opaque web
  sessions, personal access tokens, an OpenAPI 3.1 spec, and
  IRCv3-over-WebSocket — all in-process on an optional listener.
- **BNC**: per-account always-on networks with backlog persistence and
  replay, SASL to upstreams, encrypted credential storage, and a pluggable
  driver SPI. A **Matrix** bridge ships behind a feature flag; the local
  in-process network gives always-on presence with no external socket.
- **Web client**: server-rendered HTMX pages (login, account) plus a live
  `/ws/ui` socket that streams upstream lines as out-of-band fragments.
  Static assets deploy either from a CDN or embedded into the binary
  behind the `embed-web` feature.
- **Cross-platform**: Linux, macOS, and Windows on both x86_64 and
  aarch64 — no cell in the matrix is a second-class port; CI builds and
  tests all of them.

## Build & run

```sh
# Server (needs a recent stable Rust toolchain)
cargo build --release -p e6ircd
./target/release/e6ircd --config e6ircd.toml

# CLI client
cargo build --release -p e6irc-cli
./target/release/e6irc --addr 127.0.0.1:6667 send '#chan' 'hello'
```

Optional features: `embed-web` (bake the built web client into the
binary) and `matrix` (the Matrix bridge). See `DESIGN.md` for the full
architecture and `PLAN.md` for the phase-by-phase status.

## Development

Engineering conventions live in `AGENTS.md` (the boy-scout rule and
scope law) and `DESIGN.md` §2 (the quality laws: no silent no-ops, no
silent fallbacks, provenance required, make bug classes unrepresentable).
Before you stop, the tree must be green: `cargo fmt --all --check`,
`cargo clippy --workspace --all-targets` (in each feature config),
`cargo test --workspace`, `cargo deny check`, and `tools/check-noops.sh`.

## License

Copyright (C) the e6irc authors. This program is free software: you can
redistribute it and/or modify it under the terms of the GNU Affero
General Public License as published by the Free Software Foundation,
either version 3 of the License, or (at your option) any later version.
See [`LICENSE`](LICENSE).
