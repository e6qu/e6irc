# External qualification

`e6irc-qualification` writes one new JSON evidence file for a live probe. It
never writes credential values. The file has a source revision, executable
digest, host, target, workload, budgets, start/end times, phase results, and a
closed `passed`, `rejected`, or `failed` outcome. Only every required phase
passed can produce `passed`.

Use `e6irc-qualification verify EVIDENCE` before retaining or publishing a
file. It accepts only the current closed schema, valid non-secret metadata,
valid phase applicability, and an outcome that matches the recorded phases.

Build it with `cargo build --release -p e6irc-qualification`. Every command
needs a non-secret target identifier, source revision, host, executable, new
output path, workload, and budget values:

```text
e6irc-qualification KIND --target TARGET --source REVISION --host HOST \
  --executable PATH --output EVIDENCE --workload NAME=VALUE \
  --budget NAME=VALUE
```

Kinds are `discord`, `slack`, `oidc`, `public-irc`, and `scale`. Discord uses
`discord.com` as `--target`; Slack uses `slack.com`. Discord
requires `E6IRC_DISCORD_BOT_TOKEN` and `E6IRC_DISCORD_CHANNEL_ID`; Slack
requires `E6IRC_SLACK_BOT_TOKEN`, `E6IRC_SLACK_APP_TOKEN`, and
`E6IRC_SLACK_CHANNEL_ID`; OIDC requires `E6IRC_OIDC_CLIENT_ID` and
`E6IRC_OIDC_CLIENT_SECRET`. A missing variable writes a rejected record and
does not start a network request. Values are never included in output.

Discord performs channel authentication, two gateway sessions, message post,
read-back, and deletion. Slack performs `auth.test`, two Socket Mode sessions,
message post, thread read-back, and deletion. OIDC verifies the discovered
issuer, gets two client-credential tokens, introspects one, and revokes it.
Provider HTTP endpoints use HTTPS and provider WebSocket endpoints use WSS.
Loopback oracles may use HTTP and WS. OIDC metadata cannot cross between those
trust domains. Provider-signed WebSocket query parameters stay in memory.
The adapter tests can select credential-free loopback or provider endpoints.
The external command rejects custom Discord and Slack endpoints. It always
uses the public provider endpoint. Evidence records every required
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

## GitHub dispatch

Run **External qualification** from the Actions page. It is manual only. Pick
one campaign and supply non-secret target, host, workload, and budget values.
Use `discord.com` or `slack.com` for those provider campaigns.
The scale campaign measures its host itself and does not use `host`.
The workflow sets provider credentials only from these repository secrets:

- `E6IRC_DISCORD_BOT_TOKEN`, `E6IRC_DISCORD_CHANNEL_ID`
- `E6IRC_SLACK_BOT_TOKEN`, `E6IRC_SLACK_APP_TOKEN`, `E6IRC_SLACK_CHANNEL_ID`
- `E6IRC_OIDC_CLIENT_ID`, `E6IRC_OIDC_CLIENT_SECRET`

The workflow never sets a Discord or Slack test endpoint. These campaigns use
the public provider endpoints. Missing credentials or required inputs fail the
run and do not create a passed record. A verified evidence file is the only
uploaded artifact. Rejected and failed campaigns retain verified evidence too.

The `scale` campaign runs only on a self-hosted runner with the
`qualification-scale` label. Start the target `e6ircd` there first. Set
`target` to its listener address and provide `scale_arguments` in this order:
`ADDR SERVER_PID CORE_WORKERS CLIENTS CHANNELS BURST MIN_CONNECT_RATE
MIN_FANOUT_RATE MAX_P99_MS MAX_RSS_BYTES_PER_CONNECTION`. The first value must
equal `target`. The host checks in `qualify-linux.sh` reject an untuned or
wrong-process run.
