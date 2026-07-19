# Vendored compatibility reference data

Per the project provenance rule (DESIGN §2): every vendored artifact
records its source, retrieval method, date, and checksum, and none of
these files participate in the build — they are test/reference inputs
for the Libera.Chat compatibility contract (DESIGN §7.7).

## libera-greeting.txt

- **What**: the live connection greeting of Libera.Chat — `CAP LS 302`
  reply, full `RPL_ISUPPORT` (005) burst, LUSERS and MOTD — as sent by
  server `tantalum.libera.chat`.
- **Retrieved**: 2026-07-18T18:48Z, by connecting to
  `irc.libera.chat:6697` (TLS) with
  `CAP LS 302` / `NICK` / `USER` / `CAP END` / `QUIT`, via
  `openssl s_client`.
- **Normalization**: the one-off capture nickname is replaced with the
  placeholder `E6NICK`; everything else is verbatim.
- **sha256**: `057d390c60535bfd6dd9752181416ae679ad39489a60bce876be25673ae307ec`
- **License**: server banner/protocol output, not a creative work; used
  solely as a compatibility test oracle.
- **Refresh procedure**: re-run the capture (any unregistered nick),
  re-apply the nick normalization, update the checksum and date here.
