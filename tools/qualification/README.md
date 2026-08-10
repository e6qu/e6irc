# External qualification

`e6irc-qualification` writes one new JSON evidence file for a live probe. It
never writes credential values. The file has a source revision, executable
digest, host, target, workload, budgets, start/end times, phase results, and a
closed `passed`, `rejected`, or `failed` outcome. Only every required phase
passed can produce `passed`.

Build it with `cargo build --release -p e6irc-qualification`. Every command
needs a non-secret target identifier, source revision, host, executable, new
output path, workload and budget values, and a probe:

```text
e6irc-qualification KIND --target TARGET --source REVISION --host HOST \
  --executable PATH --output EVIDENCE --workload NAME=VALUE \
  --budget NAME=VALUE --probe PATH [-- PROBE_ARGS...]
```

Kinds are `discord`, `slack`, `oidc`, `public-irc`, and `scale`. Discord
requires `E6IRC_DISCORD_BOT_TOKEN`; Slack requires
`E6IRC_SLACK_BOT_TOKEN` and `E6IRC_SLACK_APP_TOKEN`; OIDC requires
`E6IRC_OIDC_CLIENT_SECRET`. A missing variable writes a rejected record and
does not start the probe. Values are never included in output.

A probe writes this exact JSON to `$E6IRC_QUALIFICATION_PROBE_REPORT`:

```json
{"authentication":"passed","delivery":"passed","reconnect":"passed","cleanup":"passed","persistence":"passed"}
```

Each value is `passed`, `rejected`, `failed`, or `not_applicable`. The runner
permits `not_applicable` only for phases that do not apply to that kind. A
probe exit failure, missing report, or malformed report becomes a failed
record. Use a new output path for every run.

`external-probe.sh` starts an operator-owned executable named by
`E6IRC_DISCORD_PROBE`, `E6IRC_SLACK_PROBE`, or `E6IRC_OIDC_PROBE`. Keep that
executable and credentials outside this repository. It receives only the
target, kind, report path, and inherited credential environment.

`public-irc-probe.sh` runs the ignored Libera, OFTC, or Ergo interoperability
probe for targets `libera`, `oftc`, or `ergo`. It makes two sequential TLS
sessions to prove registration, reconnect, and cleanup. `scale-probe.sh`
wraps `e6irc-load`; `qualify-linux.sh` writes its load result, host provenance,
and common qualification evidence together.

Local oracles prove the probe contract. They do not qualify a commercial
provider, public network, or tuned host. Publish a passed claim only with its
recorded evidence file.
