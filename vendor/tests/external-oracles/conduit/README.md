# Conduit (Matrix homeserver oracle)

A lightweight single-binary [Matrix] homeserver, used as the live target
for the `matrix` bridge's integration test (`crates/e6ircd/tests/matrix.rs`).
Not part of the e6irc build; CI's `matrix-bridge` job runs this same image
with this directory's `conduit.toml`.

## Provenance

- **Source / image:** `matrixconduit/matrix-conduit:v0.9.0`
  (https://gitlab.com/famedly/conduit), pulled through Google's Docker Hub
  mirror (`mirror.gcr.io`) and pinned by index digest, the one Docker Hub
  serves — the one
  digest `docker-compose.yml` and ci.yml both name
  (`tools/check-image-pins.py` holds them to it).
- **License:** Apache-2.0 (Conduit). Run as a separate container; not
  linked into or distributed with e6irc.

## Use

```
docker compose -f vendor/tests/external-oracles/conduit/docker-compose.yml up -d
E6IRC_TEST_MATRIX_URL=http://127.0.0.1:16167 \
  cargo test --locked -p e6ircd --features matrix --test matrix -- --ignored --nocapture
docker compose -f vendor/tests/external-oracles/conduit/docker-compose.yml down
```

`conduit.toml` enables open registration (test-only) so the test can
create its bot + peer users; the server_name is `localhost`.

[Matrix]: https://spec.matrix.org/latest/client-server-api/
