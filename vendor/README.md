# vendor/

Third-party material vendored into the repository. **None of this is part
of the shipped e6irc build** — nothing here is compiled into `e6ircd` or
the client binaries. It exists only to test and document compatibility.

Every vendored item is isolated in its own subdirectory with a
`README.md` recording its **source**, **license**, and **provenance**
(pinned version/commit + checksum where applicable), per the project
provenance rule (DESIGN §2).

## Layout

- `tests/` — vendored test material.
  - `tests/external-oracles/` — reference IRC implementations run as
    differential **oracles** (e.g. Solanum in Docker) plus the harness
    that drives them. Built/run on demand for conformance work; never a
    build or default-CI dependency.
  - `tests/irctest/` — hookup for the external [irctest] protocol
    conformance suite (the suite itself is cloned at a pinned commit).
  - `tests/libera-snapshot/` — a captured snapshot of Libera.Chat's
    greeting, used as a deterministic offline fixture for the ISUPPORT
    differential test.

Live compatibility against Libera and other public servers is checked by
**light-touch, opt-in** integration tests (see
`crates/e6ircd/tests/live_compat.rs`) that make a single brief connection
and read the greeting — they are `#[ignore]`d so they never run in normal
CI or put load on live services.

[irctest]: https://github.com/progval/irctest
