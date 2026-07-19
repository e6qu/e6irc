# External oracles

Reference IRC implementations run as **differential oracles**: the same
scripted client sessions are played against e6ircd and against a
reference server, and the normalized transcripts are diffed. Divergences
fail unless whitelisted with a written reason.

These are **opt-in developer tools**, not part of the build or default
CI: e6irc is an independent implementation, and an oracle is only a
cross-check, never a dependency.

## Contents

- `solanum/` — Solanum (the ircd Libera.Chat runs), built from a pinned
  source commit in Docker. See `solanum/README.md` for source + license.
- `diff_sessions.py` — the differential runner. Plays the scenarios
  against two servers (`--ours HOST:PORT --reference HOST:PORT`) and diffs
  normalized output against `diff_whitelist.toml`.

## Running the Solanum differential

```
cd vendor/tests/external-oracles/solanum
docker compose up -d --build          # build + start Solanum on :16697
# start e6ircd on some port, then:
python3 ../diff_sessions.py \
  --ours 127.0.0.1:<e6ircd-port> \
  --reference 127.0.0.1:16697 \
  --normalize "<e6ircd-server-name>,solanum.diff.example,DiffNet"
docker compose down
```

Adding another oracle: drop it in its own subdirectory with a `README.md`
(source, license, pinned version) and point `diff_sessions.py` at it.
