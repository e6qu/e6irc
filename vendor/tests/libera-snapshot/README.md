# Libera.Chat greeting snapshot

A captured snapshot of Libera.Chat's connection greeting — the `CAP LS
302` reply and full `RPL_ISUPPORT` (005) burst — used as a **deterministic
offline fixture** for the ISUPPORT differential test
(`crates/e6ircd/tests/libera_compat.rs`): e6ircd's advertised tokens must
match Libera's for every shared token, with whitelisted exceptions.

Why a snapshot rather than a live connection: this test runs in normal CI
and must be deterministic and offline (no network flakiness, no load on
Libera). The live check — connecting to Libera and other public servers
for real — is the opt-in, light-touch `live_compat.rs` suite.

- **Source:** captured from `irc.libera.chat:6697` (server
  `tantalum.libera.chat`); Libera runs Solanum.
- **License:** server protocol output, not a creative work; used solely
  as a compatibility oracle.
- **Full provenance** (retrieval method, date, sha256, refresh
  procedure): see `PROVENANCE.md` in this directory.
