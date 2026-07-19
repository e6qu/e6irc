# Solanum (differential oracle)

A reference build of **Solanum**, the IRCd that Libera.Chat runs, used
only as a differential oracle for e6irc conformance work. Not part of the
e6irc build or default CI.

## Provenance

- **Source:** https://github.com/solanum-ircd/solanum
- **Pinned commit:** `48db98ab2b4191ba75047a74c79a353e4f82bf5a` (2026-07-15)
  — see `ARG SOLANUM_REF` in `Dockerfile`.
- **License:** GPL-2.0-or-later (Solanum is GPLv2+; `LICENSE` in the
  upstream tree). Built and run as a separate process/container — its
  code is **not** linked into or distributed with e6irc, so its license
  does not affect e6irc's AGPL-3.0-or-later distribution.

## Build notes

Solanum is compiled from source (there is no official image). The
Dockerfile pins a Debian **bullseye** base on purpose: newer glibc
(bookworm+) exports `arc4random` but not `arc4random_stir`, so Solanum's
bundled `librb` fails to link; bullseye's older glibc makes Solanum use
its own arc4random (which defines the symbol). `libltdl-dev` is needed at
build time and `libltdl7` at runtime; Solanum refuses to run as root, so
it runs as an unprivileged user.

`ircd.conf` is a minimal boot config for the harness (plain listener on
6667, throttling/limits relaxed so a few scripted clients can connect in
quick succession). Solanum's `authd` wants a working resolver in the
container; give the container DNS via your Docker/compose networking as
needed.
