# External qualification

`e6irc-qualification` writes one new JSON evidence file for a live probe. It
never writes credential values. The file has a source revision, executable
digest, host, target, workload, budgets, start/end times, phase results, and a
closed `passed`, `rejected`, or `failed` outcome. Only every required phase
passed can produce `passed`.

Build it with `cargo build --release -p e6irc-qualification`. Every command
needs a non-secret target identifier, source revision, host, executable, new
output path, workload, and budget values:

```text
e6irc-qualification KIND --target TARGET --source REVISION --host HOST \
  --executable PATH --output EVIDENCE --workload NAME=VALUE \
  --budget NAME=VALUE
```

Kinds are `discord`, `slack`, `oidc`, `public-irc`, and `scale`. Discord
requires `E6IRC_DISCORD_BOT_TOKEN` and `E6IRC_DISCORD_CHANNEL_ID`; Slack
requires `E6IRC_SLACK_BOT_TOKEN`, `E6IRC_SLACK_APP_TOKEN`, and
`E6IRC_SLACK_CHANNEL_ID`; OIDC requires `E6IRC_OIDC_CLIENT_ID` and
`E6IRC_OIDC_CLIENT_SECRET`. A missing variable writes a rejected record and
does not start a network request. Values are never included in output.

Discord performs channel authentication, two gateway sessions, message post,
read-back, and deletion. Slack performs `auth.test`, two Socket Mode sessions,
message post, thread read-back, and deletion. OIDC verifies the discovered
issuer, gets two client-credential tokens, introspects one, and revokes it.
The optional
`E6IRC_DISCORD_API_BASE` and `E6IRC_SLACK_API_BASE` values select a compatible
test or provider endpoint; they must be credential-free HTTPS URLs. HTTP is
accepted only for a loopback test oracle. Evidence records every required
environment-variable name, never its value.

`public-irc` and `scale` need their supplied probe path. A probe writes this
exact JSON, with the runner-provided challenge, to
`$E6IRC_QUALIFICATION_PROBE_REPORT`:

```json
{"challenge":"...","authentication":"passed","delivery":"passed","reconnect":"passed","cleanup":"passed","persistence":"passed"}
```

Each value is `passed`, `rejected`, `failed`, `not_applicable`, or `not_run`.
The runner accepts `not_applicable` only for phases that do not apply to that
kind. `not_run` records a required phase that the campaign did not reach; it
can never pass. A probe exit failure, missing report, or malformed report
writes `not_run` for every applicable phase and a failed record. Use a new
output path for every run.

`public-irc-probe.sh` runs the ignored Libera, OFTC, or Ergo interoperability
probe for targets `libera`, `oftc`, or `ergo`. It makes two sequential TLS
sessions to prove registration, reconnect, and cleanup. `scale-probe.sh`
wraps `e6irc-load`; `qualify-linux.sh` writes its load result, host provenance,
and common qualification evidence together.

## Live campaigns

Set the listed credential variables only in the campaign environment. For a
Discord workspace, set `E6IRC_DISCORD_BOT_TOKEN` and
`E6IRC_DISCORD_CHANNEL_ID`, then run `e6irc-qualification discord` with the
common arguments above. For Slack, set `E6IRC_SLACK_BOT_TOKEN`,
`E6IRC_SLACK_APP_TOKEN`, and `E6IRC_SLACK_CHANNEL_ID`, then run
`e6irc-qualification slack`. For an issuer, set `E6IRC_OIDC_CLIENT_ID` and
`E6IRC_OIDC_CLIENT_SECRET`, use its credential-free issuer URL as `--target`,
then run `e6irc-qualification oidc`. The process exits 3 and writes rejected
evidence when required configuration is absent.

For public IRC, add `--probe tools/qualification/public-irc-probe.sh`. For a
tuned Linux host, use `tools/load/qualify-linux.sh`; it supplies the scale
probe and its measured load result.

The runner creates an isolated report directory and accepts only its fresh
challenge. It records an executable digest, never a local path. Local oracles
prove the adapter contract. They do not qualify a commercial provider, public
network, or tuned host. Publish a passed claim only with retained evidence.
